//! Windows' own records about a program: the tray icon settings, the sound
//! device picked for it, taskbar and Start usage, the shortcut history, the
//! compatibility notes and the cached display name. Each names a file by its
//! path. Once the folder that holds the file goes, the record points nowhere,
//! so it goes too; one whose file is already missing goes when the path
//! names the product.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::{exe_missing, path_names_product, same_vendor};
use crate::model::{Confidence, Hive, Leftover, LeftoverKind, ScanTarget};
use crate::{registry, system};

const NOTIFY_ICONS: &str = r"Control Panel\NotifyIconSettings";
const SOUND_DEVICES: &str =
    r"Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore";
const FEATURE_USAGE: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage";
const FEATURE_USAGE_KINDS: [&str; 5] = [
    "AppSwitched",
    "ShowJumpView",
    "AppBadgeUpdated",
    "AppLaunch",
    "TrayButtonClicked",
];
const START_TILES: &str = r"Software\Microsoft\Windows\CurrentVersion\Start\TileProperties";
const SHORTCUT_HISTORY: &str = r"Software\Microsoft\Windows\CurrentVersion\UFH\SHC";
const COMPAT_STORE: &str =
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store";
const COMPAT_LAYERS: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
const NAME_CACHE: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
const NAME_FIELD: &str = ".FriendlyAppName";
const COMPANY_FIELD: &str = ".ApplicationCompany";

/// Which files go: those inside a removed folder but not inside another
/// program's install folder, and missing ones whose path names the product.
struct Gone<'a> {
    dirs: &'a [PathBuf],
    others: &'a [PathBuf],
    target: &'a ScanTarget,
}

impl Gone<'_> {
    fn covers(&self, path: &str) -> bool {
        let Some(p) = resolve(path) else {
            return false;
        };
        let inside = |list: &[PathBuf]| list.iter().any(|d| system::path_under(&p, d));
        if inside(self.others) {
            return false;
        }
        inside(self.dirs) || (exe_missing(&p) && path_names_product(&p, self.target))
    }
}

/// Every record of the current user that names a file `gone` covers.
/// `vendor_alone`: nothing else of the publisher's is installed, so files
/// Windows remembers as theirs are this program's.
pub(super) fn scan_windows_records(
    target: &ScanTarget,
    removed: &[PathBuf],
    other_installs: &[PathBuf],
    vendor_alone: bool,
) -> Vec<Leftover> {
    let gone = Gone {
        dirs: removed,
        others: other_installs,
        target,
    };
    let hive = Hive::CurrentUser;
    let mut out = Vec::new();

    // One key per tray icon, the file in its `ExecutablePath`.
    for sub in registry::enum_subkeys(hive, NOTIFY_ICONS) {
        let key = format!(r"{NOTIFY_ICONS}\{sub}");
        if registry::read_string(hive, &key, "ExecutablePath").is_some_and(|p| gone.covers(&p)) {
            out.push(Leftover::reg_key(
                hive,
                key,
                Confidence::High,
                "tray icon settings of the program",
            ));
        }
    }

    // One key per program and device, the file inside the default value.
    for sub in registry::enum_subkeys(hive, SOUND_DEVICES) {
        let key = format!(r"{SOUND_DEVICES}\{sub}");
        let names_gone = registry::read_string(hive, &key, "")
            .and_then(|v| sound_device_file(&v).map(str::to_string))
            .and_then(|device_path| device_to_drive(&device_path))
            .is_some_and(|p| gone.covers(&p));
        if names_gone {
            out.push(Leftover::reg_key(
                hive,
                key,
                Confidence::High,
                "the sound device chosen for the program",
            ));
        }
    }

    // Values named by the file's path.
    let mut by_name = |base: String, reason: &str, strip: fn(&str) -> &str| {
        for name in registry::enum_value_names(hive, &base) {
            if gone.covers(strip(&name)) {
                out.push(Leftover::reg_value(
                    hive,
                    base.clone(),
                    name,
                    Confidence::High,
                    reason,
                ));
            }
        }
    };
    for kind in FEATURE_USAGE_KINDS {
        by_name(
            format!(r"{FEATURE_USAGE}\{kind}"),
            "taskbar usage record of the program",
            |n| n,
        );
    }
    by_name(
        COMPAT_STORE.to_string(),
        "compatibility record of the program",
        |n| n,
    );
    by_name(
        COMPAT_LAYERS.to_string(),
        "compatibility settings of the program",
        |n| n,
    );
    by_name(
        NAME_CACHE.to_string(),
        "the program's name as Windows cached it",
        cached_name_file,
    );

    // The cached name also keeps each file's company. A file of the vendor's
    // that is gone, typically an installer that was run once, still has its
    // entries here; one that is still in Downloads is the installer itself.
    if vendor_alone {
        if let Some(publisher) = target.publisher.as_deref() {
            out.extend(vendor_files(publisher));
        }
    }

    // Start keeps one key per part of the path under `W~<drive>`, so the
    // records of everything in a folder sit in that folder's subtree:
    // `W~C:\Apps\Quillmark\app.exe` lies inside `W~C:\Apps\Quillmark`.
    for dir in outermost(removed) {
        if other_installs.iter().any(|o| system::path_under(o, dir)) {
            continue;
        }
        let path = dir.to_string_lossy();
        let key = format!(r"{START_TILES}\W~{}", path.trim_end_matches('\\'));
        if registry::key_exists(hive, &key) {
            out.push(Leftover::reg_key(
                hive,
                key,
                Confidence::High,
                "Start menu records of the program",
            ));
        }
    }

    // A shortcut and the file it opened, kept as a list.
    for (name, entries) in registry::enum_multi_values(hive, SHORTCUT_HISTORY) {
        let entries: Vec<&str> = entries
            .iter()
            .map(String::as_str)
            .filter(|e| !e.is_empty())
            .collect();
        if !entries.is_empty() && entries.iter().all(|e| gone.covers(e)) {
            out.push(Leftover::reg_value(
                hive,
                SHORTCUT_HISTORY,
                name,
                Confidence::High,
                "shortcut history of the program",
            ));
        }
    }
    out
}

/// The cached names of the vendor's files that are gone, and the vendor's
/// files still waiting in Downloads.
fn vendor_files(publisher: &str) -> Vec<Leftover> {
    let hive = Hive::CurrentUser;
    let downloads = super::env_dir("USERPROFILE").map(|p| p.join("Downloads"));
    let mut out = Vec::new();
    for (name, company) in registry::enum_string_values(hive, NAME_CACHE) {
        let Some(file) = name.strip_suffix(COMPANY_FIELD) else {
            continue;
        };
        if !same_vendor(&company, publisher) {
            continue;
        }
        let path = Path::new(file);
        if !path.is_absolute() {
            continue;
        }
        if path.exists() {
            if downloads
                .as_deref()
                .is_some_and(|d| system::path_under(path, d))
                && path.is_file()
            {
                out.push(Leftover::fs(
                    LeftoverKind::File,
                    path.to_path_buf(),
                    Confidence::Medium,
                    "the vendor's file in Downloads, most likely the installer",
                    std::fs::metadata(path).ok().map(|m| m.len()),
                    false,
                ));
            }
            continue;
        }
        for field in [COMPANY_FIELD, NAME_FIELD] {
            let value = format!("{file}{field}");
            if registry::value_exists(hive, NAME_CACHE, &value) {
                out.push(Leftover::reg_value(
                    hive,
                    NAME_CACHE,
                    value,
                    Confidence::High,
                    "the name Windows cached for a removed file of the vendor's",
                ));
            }
        }
    }
    out
}

/// The folders not inside another folder of the list.
fn outermost(dirs: &[PathBuf]) -> Vec<&PathBuf> {
    let mut out: Vec<&PathBuf> = Vec::new();
    for d in dirs {
        let inside_other = dirs
            .iter()
            .any(|o| system::path_under(d, o) && !system::path_under(o, d));
        if !inside_other && !out.iter().any(|o| system::path_under(d, o)) {
            out.push(d);
        }
    }
    out
}

/// The file inside a sound device choice:
/// `{2}.\\?\<device>|\Device\HarddiskVolume3\<path>%b{<guid>}`.
fn sound_device_file(value: &str) -> Option<&str> {
    let (_, rest) = value.split_once('|')?;
    let path = rest.split_once("%b").map_or(rest, |(p, _)| p);
    (!path.is_empty()).then_some(path)
}

/// A cached display name is stored under the file's path plus a field name:
/// `C:\x\app.exe.FriendlyAppName`.
fn cached_name_file(name: &str) -> &str {
    match name.rsplit_once('.') {
        Some((file, field))
            if !field.is_empty()
                && field.chars().all(|c| c.is_ascii_alphabetic())
                && file.contains('\\') =>
        {
            file
        }
        _ => name,
    }
}

/// A path as a drive path. Records may start with a known-folder id
/// (`{6D809377-...}\App\app.exe`) instead of the drive; anything that is not
/// a full path is no file to judge.
fn resolve(path: &str) -> Option<PathBuf> {
    let path = path.trim().trim_matches('"');
    if let Some(rest) = path.strip_prefix('{') {
        let (id, tail) = rest.split_once('}')?;
        let base = known_folder(id)?;
        return Some(base.join(tail.trim_start_matches('\\')));
    }
    let p = Path::new(path);
    p.is_absolute().then(|| p.to_path_buf())
}

/// The known folders that records use in place of a drive path.
fn known_folder(id: &str) -> Option<PathBuf> {
    let var = match id.to_ascii_uppercase().as_str() {
        "6D809377-6AF0-444B-8957-A3773F02200E" => "ProgramW6432",
        "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E" => "ProgramFiles(x86)",
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" => "LOCALAPPDATA",
        "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D" => "APPDATA",
        "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97" => "ProgramData",
        _ => return None,
    };
    super::env_dir(var)
}

/// `\Device\HarddiskVolume3\Users\x` as `C:\Users\x`.
fn device_to_drive(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    drive_devices().iter().find_map(|(drive, device)| {
        let device = device.to_ascii_lowercase();
        lower
            .strip_prefix(&device)
            .filter(|rest| rest.starts_with('\\'))
            .map(|_| format!("{drive}{}", &path[device.len()..]))
    })
}

/// Each drive letter with the device it stands for.
fn drive_devices() -> &'static [(String, String)] {
    static DEVICES: OnceLock<Vec<(String, String)>> = OnceLock::new();
    DEVICES.get_or_init(|| {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
        let mut out = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let wide: Vec<u16> = drive.encode_utf16().chain(Some(0)).collect();
            let mut buf = [0u16; 512];
            // SAFETY: `wide` is NUL-terminated and `buf` outlives the call.
            let n = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut buf)) } as usize;
            if n == 0 {
                continue;
            }
            let end = buf[..n].iter().position(|&c| c == 0).unwrap_or(n);
            out.push((drive, String::from_utf16_lossy(&buf[..end])));
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sound_device_choice_names_its_file() {
        let v = r"{2}.\\?\usb#vid_05ac&pid_110a&mi_00#{6994ad04-93ef-11d0-a3cc-00a0c9223196}\msft_topo/00010000|\Device\HarddiskVolume3\Users\jdoe\AppData\Local\Quillmark\app.exe%b{00000000-0000-0000-0000-000000000000}";
        assert_eq!(
            sound_device_file(v),
            Some(r"\Device\HarddiskVolume3\Users\jdoe\AppData\Local\Quillmark\app.exe")
        );
        assert_eq!(sound_device_file("no separator"), None);
    }

    #[test]
    fn only_the_outermost_folders_are_kept() {
        let dirs = vec![
            PathBuf::from(r"C:\Users\jdoe\AppData\Local\Quillmark\Versions\v1"),
            PathBuf::from(r"C:\Users\jdoe\AppData\Local\Quillmark"),
            PathBuf::from(r"C:\Users\jdoe\AppData\Local\quillmark\"),
            PathBuf::from(r"C:\Users\jdoe\AppData\Local\Temp\Quillmark"),
        ];
        let kept: Vec<&PathBuf> = outermost(&dirs);
        assert_eq!(kept, vec![&dirs[1], &dirs[3]]);
    }

    #[test]
    fn a_cached_name_drops_its_field() {
        assert_eq!(
            cached_name_file(r"C:\Apps\Quillmark\app.exe.FriendlyAppName"),
            r"C:\Apps\Quillmark\app.exe"
        );
        assert_eq!(
            cached_name_file(r"@%SystemRoot%\system32\shell32.dll,-1"),
            r"@%SystemRoot%\system32\shell32.dll,-1"
        );
    }

    #[test]
    fn only_full_paths_and_known_folders_resolve() {
        assert_eq!(
            resolve(r"C:\Apps\app.exe"),
            Some(PathBuf::from(r"C:\Apps\app.exe"))
        );
        assert_eq!(resolve("Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"), None);
        assert_eq!(
            resolve(r"{00000000-0000-0000-0000-000000000000}\x.exe"),
            None
        );
        if let Some(local) = super::super::env_dir("LOCALAPPDATA") {
            assert_eq!(
                resolve(r"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}\Quillmark\app.exe"),
                Some(local.join(r"Quillmark\app.exe"))
            );
        }
    }

    #[test]
    fn a_device_path_maps_to_its_drive() {
        let Some((drive, device)) = drive_devices().first().cloned() else {
            return;
        };
        assert_eq!(
            device_to_drive(&format!(r"{device}\Apps\app.exe")),
            Some(format!(r"{drive}\Apps\app.exe"))
        );
        assert_eq!(device_to_drive(r"\Device\NoSuchVolume\x"), None);
    }
}
