//! Registry access: enumerating installed programs from the Uninstall keys,
//! plus the read, exists and delete primitives the scanner and the safety
//! layer use.
//!
//! Every key is addressed by its physical path, with WOW6432Node spelled out,
//! and opened with `KEY_WOW64_64KEY`, so the key we read is the key we later
//! back up and delete.

use std::io;

use winreg::enums::*;
use winreg::types::FromRegValue;
use winreg::{RegKey, RegValue};

use crate::model::{Hive, Program, RegistrySource, RegistryView};
use crate::util;

/// The three locations that hold uninstall entries.
const SOURCES: [RegistrySource; 3] = [
    RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
    RegistrySource::new(Hive::LocalMachine, RegistryView::Wow6432),
    RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
];

fn predef(hive: Hive) -> RegKey {
    match hive {
        Hive::LocalMachine => RegKey::predef(HKEY_LOCAL_MACHINE),
        Hive::CurrentUser => RegKey::predef(HKEY_CURRENT_USER),
    }
}

/// Open a key for reading in the 64-bit view. `None` if missing or unreadable.
pub fn open_read(hive: Hive, subpath: &str) -> Option<RegKey> {
    predef(hive)
        .open_subkey_with_flags(subpath, KEY_READ | KEY_WOW64_64KEY)
        .ok()
}

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

/// `(name, data)` pairs for the string values directly under `subpath`
/// (REG_SZ and REG_EXPAND_SZ). Other types are skipped.
pub fn enum_string_values(hive: Hive, subpath: &str) -> Vec<(String, String)> {
    let Some(key) = open_read(hive, subpath) else {
        return Vec::new();
    };
    key.enum_values()
        .filter_map(Result::ok)
        .filter_map(|(name, value)| as_text(&value).map(|s| (name, clean_string(s))))
        .collect()
}

/// Read one string value (REG_SZ or REG_EXPAND_SZ, unexpanded).
pub fn read_string(hive: Hive, subpath: &str, name: &str) -> Option<String> {
    let key = open_read(hive, subpath)?;
    opt_string(&key, name)
}

/// Read one DWORD value.
pub fn read_u32(hive: Hive, subpath: &str, name: &str) -> Option<u32> {
    let key = open_read(hive, subpath)?;
    opt_u32(&key, name)
}

/// Read a value with its raw type, so it can be written back unchanged.
pub fn read_raw(hive: Hive, subpath: &str, name: &str) -> Option<RegValue<'static>> {
    open_read(hive, subpath)?.get_raw_value(name).ok()
}

/// The value as text, for the two string types only. `REG_MULTI_SZ` keeps
/// its entries apart with NUL bytes, which no string round-trips, so it goes
/// back as raw bytes.
pub fn as_text(value: &RegValue) -> Option<String> {
    match value.vtype {
        REG_SZ | REG_EXPAND_SZ => String::from_reg_value(value).ok(),
        _ => None,
    }
}

/// Write a raw value (type preserved). Needs `KEY_SET_VALUE`.
pub fn write_raw(hive: Hive, subpath: &str, name: &str, value: &RegValue) -> io::Result<()> {
    let key = predef(hive).open_subkey_with_flags(subpath, KEY_SET_VALUE | KEY_WOW64_64KEY)?;
    key.set_raw_value(name, value)
}

/// A registry string the way Windows reads it: up to the first NUL, then
/// trimmed. Installers do write a NUL in the middle, Roblox's `DisplayName`
/// among them, and the list and `--json` would carry it through.
fn clean_string(s: String) -> String {
    match s.find('\0') {
        Some(i) => s[..i].trim().to_string(),
        None => s.trim().to_string(),
    }
}

fn opt_string(key: &RegKey, name: &str) -> Option<String> {
    match key.get_value::<String, _>(name) {
        Ok(s) => {
            let s = clean_string(s);
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        Err(_) => None,
    }
}

fn opt_u32(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

/// Build a [`Program`] from one Uninstall subkey. `None` for entries without
/// a `DisplayName` (patches, components, stubs).
fn read_program(source: RegistrySource, key_name: String, sub: &RegKey) -> Option<Program> {
    let display_name = opt_string(sub, "DisplayName")?;

    Some(Program {
        registry_key: key_name,
        source,
        display_name,
        display_version: opt_string(sub, "DisplayVersion"),
        publisher: opt_string(sub, "Publisher"),
        install_date: opt_string(sub, "InstallDate").and_then(|d| util::parse_install_date(&d)),
        install_location: opt_string(sub, "InstallLocation"),
        display_icon: opt_string(sub, "DisplayIcon"),
        // A recorded size of zero is the installer saying nothing, not a
        // program that takes no space.
        estimated_size_kb: opt_u32(sub, "EstimatedSize").filter(|kb| *kb > 0),
        uninstall_string: opt_string(sub, "UninstallString"),
        quiet_uninstall_string: opt_string(sub, "QuietUninstallString"),
        url_info_about: opt_string(sub, "URLInfoAbout"),
        is_windows_installer: opt_u32(sub, "WindowsInstaller").unwrap_or(0) == 1,
        is_system_component: opt_u32(sub, "SystemComponent").unwrap_or(0) == 1,
    })
}

/// Every installed program across the three sources, sorted by name.
/// `include_system` also returns entries flagged `SystemComponent`, which the
/// Windows "Apps" list hides.
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

/// Delete a key and everything beneath it. HKLM keys need elevation. The
/// parent is opened in the 64-bit view first, so the key that goes is the key
/// that was read: `RegDeleteTree` on its own follows the process's own view,
/// which would redirect a 32-bit build into `WOW6432Node`.
pub fn delete_key_tree(hive: Hive, subpath: &str) -> io::Result<()> {
    match subpath.rsplit_once('\\') {
        Some((parent, leaf)) => predef(hive)
            .open_subkey_with_flags(parent, KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY)?
            .delete_subkey_all(leaf),
        None => predef(hive).delete_subkey_all(subpath),
    }
}

/// True only when the key is genuinely not there. A key we may not open is
/// not an absent key, and must not be reported as one already gone.
pub fn key_absent(hive: Hive, subpath: &str) -> bool {
    matches!(
        predef(hive).open_subkey_with_flags(subpath, KEY_READ | KEY_WOW64_64KEY),
        Err(e) if e.kind() == io::ErrorKind::NotFound
    )
}

/// Delete a single value under `subpath`.
pub fn delete_value(hive: Hive, subpath: &str, value_name: &str) -> io::Result<()> {
    let key = predef(hive).open_subkey_with_flags(subpath, KEY_SET_VALUE | KEY_WOW64_64KEY)?;
    key.delete_value(value_name)
}

/// True if the key is there and holds neither subkeys nor values.
pub fn key_is_empty(hive: Hive, subpath: &str) -> bool {
    match open_read(hive, subpath) {
        Some(key) => key.enum_keys().next().is_none() && key.enum_values().next().is_none(),
        None => false,
    }
}

/// True only when the value is genuinely not there, the same way
/// [`key_absent`] answers for a key.
pub fn value_absent(hive: Hive, subpath: &str, value_name: &str) -> bool {
    match predef(hive).open_subkey_with_flags(subpath, KEY_READ | KEY_WOW64_64KEY) {
        Err(e) => e.kind() == io::ErrorKind::NotFound,
        Ok(key) => {
            matches!(key.get_raw_value(value_name), Err(e) if e.kind() == io::ErrorKind::NotFound)
        }
    }
}

pub fn value_exists(hive: Hive, subpath: &str, value_name: &str) -> bool {
    open_read(hive, subpath)
        .map(|k| k.get_raw_value(value_name).is_ok())
        .unwrap_or(false)
}
