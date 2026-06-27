//! Windows registry mechanics: enumerating installed programs from the Uninstall
//! keys, and the low-level read/exists/delete primitives used by the scanner and
//! the safety layer.
//!
//! Everything addresses keys by their *physical* path (WOW6432Node spelled out)
//! and opens with `KEY_WOW64_64KEY`, so a 64-bit `oxidize` always sees the exact
//! key it intends to back up or delete — no WOW64 redirection surprises.

use std::io;

use winreg::enums::*;
use winreg::types::FromRegValue;
use winreg::RegKey;

use crate::model::{Hive, Program, RegistrySource, RegistryView};
use crate::util;

/// The three registry locations that hold uninstall entries:
///   * HKLM 64-bit (native),
///   * HKLM 32-bit (physically under WOW6432Node),
///   * HKCU (per-user installs).
const SOURCES: [RegistrySource; 3] = [
    RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
    RegistrySource::new(Hive::LocalMachine, RegistryView::Wow6432),
    RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
];

/// Wrap a predefined hive (no handle to close).
fn predef(hive: Hive) -> RegKey {
    match hive {
        Hive::LocalMachine => RegKey::predef(HKEY_LOCAL_MACHINE),
        Hive::CurrentUser => RegKey::predef(HKEY_CURRENT_USER),
    }
}

/// Open a key for reading in the 64-bit physical view. Returns `None` if it does
/// not exist or cannot be opened.
pub fn open_read(hive: Hive, subpath: &str) -> Option<RegKey> {
    predef(hive)
        .open_subkey_with_flags(subpath, KEY_READ | KEY_WOW64_64KEY)
        .ok()
}

/// Does this key exist (and is it readable)?
pub fn key_exists(hive: Hive, subpath: &str) -> bool {
    open_read(hive, subpath).is_some()
}

/// Names of the immediate child keys of `subpath`. Empty if the key is missing.
pub fn enum_subkeys(hive: Hive, subpath: &str) -> Vec<String> {
    match open_read(hive, subpath) {
        Some(key) => key.enum_keys().filter_map(Result::ok).collect(),
        None => Vec::new(),
    }
}

/// `(name, data)` pairs for the string-typed values directly under `subpath`
/// (REG_SZ / REG_EXPAND_SZ). Non-string values are skipped. Used to inspect
/// autostart (`Run`) entries.
pub fn enum_string_values(hive: Hive, subpath: &str) -> Vec<(String, String)> {
    let Some(key) = open_read(hive, subpath) else {
        return Vec::new();
    };
    key.enum_values()
        .filter_map(Result::ok)
        .filter_map(|(name, value)| String::from_reg_value(&value).ok().map(|s| (name, s)))
        .collect()
}

/// Read an optional string value, treating "missing" and "empty" as `None`.
fn opt_string(key: &RegKey, name: &str) -> Option<String> {
    match key.get_value::<String, _>(name) {
        Ok(s) => {
            let s = s.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        Err(_) => None,
    }
}

/// Read an optional `REG_DWORD` value as `u32`.
fn opt_u32(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

/// Build a [`Program`] from one Uninstall subkey. Returns `None` for entries
/// without a `DisplayName` (patches, components, stubs).
fn read_program(source: RegistrySource, key_name: String, sub: &RegKey) -> Option<Program> {
    let display_name = opt_string(sub, "DisplayName")?;

    let is_system_component = opt_u32(sub, "SystemComponent").unwrap_or(0) == 1;
    let is_windows_installer = opt_u32(sub, "WindowsInstaller").unwrap_or(0) == 1;
    let install_date = opt_string(sub, "InstallDate").map(|d| util::format_install_date(&d));

    Some(Program {
        registry_key: key_name,
        source,
        display_name,
        display_version: opt_string(sub, "DisplayVersion"),
        publisher: opt_string(sub, "Publisher"),
        install_date,
        install_location: opt_string(sub, "InstallLocation"),
        display_icon: opt_string(sub, "DisplayIcon"),
        estimated_size_kb: opt_u32(sub, "EstimatedSize"),
        uninstall_string: opt_string(sub, "UninstallString"),
        quiet_uninstall_string: opt_string(sub, "QuietUninstallString"),
        url_info_about: opt_string(sub, "URLInfoAbout"),
        is_windows_installer,
        is_system_component,
    })
}

/// Enumerate every installed program across all three registry sources.
///
/// `include_system` controls whether entries flagged `SystemComponent == 1`
/// (hidden OS components) are included; by default they are filtered out, as in
/// the Windows "Apps & features" list.
pub fn enumerate_installed_programs(include_system: bool) -> Vec<Program> {
    let mut programs = Vec::new();

    for source in SOURCES {
        let Some(root) = open_read(source.hive, source.view.uninstall_base()) else {
            continue;
        };
        for key_name in root.enum_keys().filter_map(Result::ok) {
            let Ok(sub) = root.open_subkey_with_flags(&key_name, KEY_READ | KEY_WOW64_64KEY) else {
                continue;
            };
            if let Some(program) = read_program(source, key_name, &sub) {
                if program.is_system_component && !include_system {
                    continue;
                }
                programs.push(program);
            }
        }
    }

    programs.sort_by(|a, b| {
        a.display_name
            .to_lowercase()
            .cmp(&b.display_name.to_lowercase())
            .then_with(|| a.display_version.cmp(&b.display_version))
    });
    programs
}

/// Delete a registry key and everything beneath it. Requires `DELETE` access
/// (HKLM keys need elevation). The literal subpath is used, so WOW6432Node keys
/// are removed exactly.
pub fn delete_key_tree(hive: Hive, subpath: &str) -> io::Result<()> {
    predef(hive).delete_subkey_all(subpath)
}

/// Delete a single named value under `subpath`.
pub fn delete_value(hive: Hive, subpath: &str, value_name: &str) -> io::Result<()> {
    // RegDeleteValue needs only KEY_SET_VALUE (least privilege).
    let key = predef(hive).open_subkey_with_flags(subpath, KEY_SET_VALUE | KEY_WOW64_64KEY)?;
    key.delete_value(value_name)
}

/// Whether a value of the given name exists under `subpath`.
pub fn value_exists(hive: Hive, subpath: &str, value_name: &str) -> bool {
    open_read(hive, subpath)
        .map(|k| k.get_raw_value(value_name).is_ok())
        .unwrap_or(false)
}
