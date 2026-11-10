//! Windows' own records about a program: the tray icon settings, the sound
//! device picked for it, taskbar and Start usage, the shortcut history, the
//! compatibility notes and the cached display name. Each names a file by its
//! path. Once the folder that holds the file goes, the record points nowhere,
//! so it goes too; one whose file is already missing goes when the path
//! names the product. Notification settings and some usage records name the
//! program by its app id instead, and a COM class by the file it starts.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::{exe_missing, path_names_product, same_vendor, score_product};
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
const NOTIFICATION_SETTINGS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings";
const NOTIFICATION_BACKUP: &str =
    r"Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup";
const APP_ID_CLASSES: &str = r"Software\Classes\AppUserModelId";
const COM_CLASSES: &str = r"Software\Classes\CLSID";
const COM_SERVERS: [&str; 2] = ["LocalServer32", "InprocServer32"];
/// How deep and how far the walk through Start's path records goes.
const TILE_WALK_DEPTH: usize = 31;
const TILE_WALK_KEYS: usize = 31_000;

/// Which files go: those inside a removed folder or removed themselves, but
/// not inside another program's install folder, and missing ones whose path
/// names the product.
struct Gone<'a> {
    dirs: &'a [PathBuf],
    files: &'a [PathBuf],
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
        inside(self.dirs)
            || inside(self.files)
            || (exe_missing(&p) && path_names_product(&p, self.target))
    }
}

/// Every record of the current user that names a file `gone` covers.
/// `removed` are the folders that go, `removed_files` the single files.
/// `vendor_alone`: nothing else of the publisher's is installed, so files
/// Windows remembers as theirs are this program's. `program_gone`: the
/// program is no longer installed, so the records under its app id are left
/// over too.
pub(super) fn scan_windows_records(
    target: &ScanTarget,
    removed: &[PathBuf],
    removed_files: &[PathBuf],
    other_installs: &[PathBuf],
    vendor_alone: bool,
    program_gone: bool,
) -> Vec<Leftover> {
    let gone = Gone {
        dirs: removed,
        files: removed_files,
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

    // Start keeps one key per part of the path under `W~<root>`, so the
    // records of everything in a folder sit in that folder's subtree:
    // `W~C:\Apps\Quillmark\app.exe` lies inside `W~C:\Apps\Quillmark`.
    let folders = known_folder_dirs();
    for dir in outermost(removed) {
        if other_installs.iter().any(|o| system::path_under(o, dir)) {
            continue;
        }
        for root in tile_roots(dir, &folders) {
            let key = format!(r"{START_TILES}\{root}");
            if registry::key_exists(hive, &key) {
                out.push(Leftover::reg_key(
                    hive,
                    key,
                    Confidence::High,
                    "Start menu records of the program",
                ));
            }
        }
    }
    // The same records of a folder that was already gone before the scan.
    out.extend(tiles_of_missing_folders(hive, START_TILES, &gone));
    out.extend(com_classes(hive, COM_CLASSES, &gone));
    if program_gone {
        out.extend(app_id_records(hive, &AppIdPlaces::current(), target));
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

/// Start's records of paths that no longer exist and that `gone` covers.
/// Each `W~` root stands for a drive (`W~C:`) or a known folder
/// (`W~{6D809377-...}`), and each key below it for one part of the path.
fn tiles_of_missing_folders(hive: Hive, base: &str, gone: &Gone) -> Vec<Leftover> {
    let mut out = Vec::new();
    let mut budget = TILE_WALK_KEYS;
    for sub in registry::enum_subkeys(hive, base) {
        let Some(root) = sub.strip_prefix("W~") else {
            continue;
        };
        let start = if root.len() == 2 && root.ends_with(':') {
            Some(PathBuf::from(format!(r"{root}\")))
        } else if root.starts_with('{') && root.ends_with('}') {
            resolve(root)
        } else {
            None
        };
        if let Some(start) = start.filter(|p| p.is_dir()) {
            let key = format!(r"{base}\{sub}");
            walk_tiles(hive, &key, &start, gone, 0, &mut budget, &mut out);
        }
    }
    out
}

fn walk_tiles(
    hive: Hive,
    key: &str,
    path: &Path,
    gone: &Gone,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<Leftover>,
) {
    if depth >= TILE_WALK_DEPTH {
        return;
    }
    for name in registry::enum_subkeys(hive, key) {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let child_key = format!(r"{key}\{name}");
        let child = path.join(&name);
        if child.exists() {
            if child.is_dir() {
                walk_tiles(hive, &child_key, &child, gone, depth + 1, budget, out);
            }
        } else if gone.covers(&child.to_string_lossy()) {
            out.push(Leftover::reg_key(
                hive,
                child_key,
                Confidence::High,
                "Start menu records of the program",
            ));
        } else {
            // Everything below a missing path is missing too, and a part
            // further down may name the product.
            walk_tiles(hive, &child_key, &child, gone, depth + 1, budget, out);
        }
    }
}

/// A COM class whose servers are all files that go, such as the class a
/// program registers so its notifications can start it.
fn com_classes(hive: Hive, base: &str, gone: &Gone) -> Vec<Leftover> {
    let mut out = Vec::new();
    for sub in registry::enum_subkeys(hive, base) {
        if !(sub.starts_with('{') && sub.ends_with('}')) {
            continue;
        }
        let key = format!(r"{base}\{sub}");
        let servers: Vec<PathBuf> = COM_SERVERS
            .iter()
            .filter_map(|server| registry::read_string(hive, &format!(r"{key}\{server}"), ""))
            .filter_map(|command| system::command_exe(&command))
            .collect();
        if !servers.is_empty() && servers.iter().all(|p| gone.covers(&p.to_string_lossy())) {
            out.push(Leftover::reg_key(
                hive,
                key,
                Confidence::High,
                "a COM class that starts the program's file",
            ));
        }
    }
    out
}

/// Where Windows keeps records under a program's app id.
struct AppIdPlaces {
    /// Keys named by the app id, each with its reason.
    keys: Vec<(String, &'static str)>,
    /// Start's records, under `W~` and the app id.
    tiles: String,
    /// Keys whose values are named by the app id.
    usage: Vec<String>,
}

impl AppIdPlaces {
    fn current() -> Self {
        AppIdPlaces {
            keys: vec![
                (
                    NOTIFICATION_SETTINGS.to_string(),
                    "notification settings of the program",
                ),
                (
                    NOTIFICATION_BACKUP.to_string(),
                    "notification settings of the program",
                ),
                (
                    APP_ID_CLASSES.to_string(),
                    "the program's app id registration",
                ),
            ],
            tiles: START_TILES.to_string(),
            usage: FEATURE_USAGE_KINDS
                .iter()
                .map(|kind| format!(r"{FEATURE_USAGE}\{kind}"))
                .collect(),
        }
    }
}

/// The records Windows keeps under the app id of a program that is gone.
fn app_id_records(hive: Hive, places: &AppIdPlaces, target: &ScanTarget) -> Vec<Leftover> {
    let mut out = Vec::new();
    for (base, reason) in &places.keys {
        for id in registry::enum_subkeys(hive, base) {
            if app_id_is_programs(&id, target) {
                out.push(Leftover::reg_key(
                    hive,
                    format!(r"{base}\{id}"),
                    Confidence::High,
                    *reason,
                ));
            }
        }
    }
    for sub in registry::enum_subkeys(hive, &places.tiles) {
        if sub
            .strip_prefix("W~")
            .is_some_and(|id| app_id_is_programs(id, target))
        {
            out.push(Leftover::reg_key(
                hive,
                format!(r"{}\{sub}", places.tiles),
                Confidence::High,
                "Start menu records of the program",
            ));
        }
    }
    for base in &places.usage {
        for name in registry::enum_value_names(hive, base) {
            if app_id_is_programs(&name, target) {
                out.push(Leftover::reg_value(
                    hive,
                    base.clone(),
                    name,
                    Confidence::High,
                    "taskbar usage record of the program",
                ));
            }
        }
    }
    out
}

/// An app id such as `com.brightway.lumen.windows`: dotted words, one of
/// them the product and another the vendor. Paths and packaged app ids
/// (`Vendor.App_hash!App`) are not this kind of name.
fn app_id_is_programs(id: &str, target: &ScanTarget) -> bool {
    if id.is_empty() || !id.contains('.') || id.contains(['\\', '/', '!', ' ']) {
        return false;
    }
    let words: Vec<String> = id.split('.').map(str::to_lowercase).collect();
    let is_vendor = |w: &String| target.publisher_tokens.contains(w);
    let product = words.iter().position(|w| {
        !is_vendor(w) && matches!(score_product(w, target), Some((Confidence::High, _)))
    });
    product.is_some_and(|i| {
        words
            .iter()
            .enumerate()
            .any(|(j, w)| j != i && is_vendor(w))
    })
}

/// The company Windows cached for the files it shows as `name`: the
/// `FriendlyAppName` of a file equals the product, and the same file's
/// `ApplicationCompany` names the vendor. The company most files share wins.
pub(super) fn cached_company(name: &str) -> Option<String> {
    company_among(
        name,
        &registry::enum_string_values(Hive::CurrentUser, NAME_CACHE),
    )
}

fn company_among(name: &str, values: &[(String, String)]) -> Option<String> {
    let wanted = crate::util::significant_tokens(name);
    if wanted.is_empty() {
        return None;
    }
    let mut counts: Vec<(String, usize)> = Vec::new();
    for (value, shown) in values {
        let Some(file) = value.strip_suffix(NAME_FIELD) else {
            continue;
        };
        if crate::util::significant_tokens(shown) != wanted {
            continue;
        }
        let company_value = format!("{file}{COMPANY_FIELD}");
        let Some((_, company)) = values.iter().find(|(v, _)| *v == company_value) else {
            continue;
        };
        let company = company.trim();
        if company.is_empty() {
            continue;
        }
        match counts.iter_mut().find(|(c, _)| c == company) {
            Some((_, n)) => *n += 1,
            None => counts.push((company.to_string(), 1)),
        }
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(c, _)| c)
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

/// The known folders that records use in place of a drive path, each with
/// the variable that holds its location.
const KNOWN_FOLDERS: [(&str, &str); 5] = [
    ("6D809377-6AF0-444B-8957-A3773F02200E", "ProgramW6432"),
    ("7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E", "ProgramFiles(x86)"),
    ("F1B32785-6FBA-4FCF-9D55-7B8E7F157091", "LOCALAPPDATA"),
    ("3EB685DB-65F9-4CF6-A03A-E3EF65729F3D", "APPDATA"),
    ("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97", "ProgramData"),
];

fn known_folder(id: &str) -> Option<PathBuf> {
    let (_, var) = KNOWN_FOLDERS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(id))?;
    super::env_dir(var)
}

/// Each known folder's id with where it is on this machine.
fn known_folder_dirs() -> Vec<(&'static str, PathBuf)> {
    KNOWN_FOLDERS
        .iter()
        .filter_map(|(id, var)| Some((*id, super::env_dir(var)?)))
        .collect()
}

/// The keys Start may file a folder's records under: `W~` and the drive
/// path, and for a folder inside a known folder also `W~{id}` and the rest
/// of the path, the way machine-wide programs are recorded
/// (`W~{6D809377-...}\Quillmark\quillmark.exe`).
fn tile_roots(dir: &Path, folders: &[(&str, PathBuf)]) -> Vec<String> {
    let path = dir.to_string_lossy();
    let path = path.trim_end_matches('\\');
    let mut out = vec![format!("W~{path}")];
    for (id, base) in folders {
        let base = base.to_string_lossy();
        let base = base.trim_end_matches('\\');
        let rest = path
            .get(..base.len())
            .filter(|head| !base.is_empty() && head.eq_ignore_ascii_case(base))
            .and_then(|_| path[base.len()..].strip_prefix('\\'))
            .filter(|rest| !rest.is_empty());
        if let Some(rest) = rest {
            out.push(format!(r"W~{{{id}}}\{rest}"));
        }
    }
    out
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

    /// A name no real file has, so that "missing" holds on any machine.
    fn unique(name: &str) -> String {
        use std::hash::{BuildHasher, Hasher};
        let n = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        format!("{name} {n:016x}")
    }

    #[test]
    fn a_file_that_goes_by_itself_counts_as_gone() {
        let target = super::super::name_target("Quillmark", Some("Quill Labs"));
        let menu = format!(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\{}",
            unique("Writer")
        );
        let shortcut = format!(r"{menu}\Writer.lnk");
        let app = format!(r"C:\{}\writer.exe", unique("Apps"));
        let other = format!(r"C:\{}", unique("Other Tool"));
        let theirs = format!(r"{other}\tool.lnk");
        let files = [PathBuf::from(&shortcut), PathBuf::from(&theirs)];
        let others = [PathBuf::from(&other)];
        let gone = Gone {
            dirs: &[],
            files: &files,
            others: &others,
            target: &target,
        };
        // The listed file, however it is written, and nothing beside it.
        assert!(gone.covers(&shortcut));
        assert!(gone.covers(&shortcut.to_uppercase().replace('\\', "/")));
        assert!(!gone.covers(&format!(r"{menu}\Reader.lnk")));
        assert!(!gone.covers(&menu));
        // Neither a file in a folder that stays.
        assert!(!gone.covers(&app));
        // Nor one inside another program's install folder.
        assert!(!gone.covers(&theirs));

        // A shortcut history entry, the shortcut and the file it opened, is
        // all gone once both are: the folder goes and so does the shortcut.
        let dirs = [Path::new(&app).parent().unwrap().to_path_buf()];
        let gone = Gone {
            dirs: &dirs,
            ..gone
        };
        assert!([shortcut.as_str(), app.as_str()]
            .iter()
            .all(|e| gone.covers(e)));
        // Without the shortcut on the list, it is not.
        let gone = Gone { files: &[], ..gone };
        assert!(!gone.covers(&shortcut));
    }

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
    fn the_cached_company_of_the_product_names_the_vendor() {
        let v = |n: &str, d: &str| (n.to_string(), d.to_string());
        let values = vec![
            v(
                r"C:\Users\jdoe\Downloads\QuillSetup.exe.FriendlyAppName",
                "Quillmark",
            ),
            v(
                r"C:\Users\jdoe\Downloads\QuillSetup.exe.ApplicationCompany",
                "Quill Labs Ltd",
            ),
            v(
                r"C:\Apps\Quillmark\quill.exe.FriendlyAppName",
                "Quillmark 2",
            ),
            v(
                r"C:\Apps\Quillmark\quill.exe.ApplicationCompany",
                "Quill Labs Ltd",
            ),
            v(r"C:\Apps\Other\q.exe.FriendlyAppName", "Quillmark"),
            v(r"C:\Apps\Other\q.exe.ApplicationCompany", "Someone Else"),
            v(r"C:\Apps\Inkwell\ink.exe.FriendlyAppName", "Inkwell"),
            v(r"C:\Apps\Inkwell\ink.exe.ApplicationCompany", "Inkwell Inc"),
        ];
        assert_eq!(
            company_among("Quillmark", &values).as_deref(),
            Some("Quill Labs Ltd")
        );
        assert_eq!(
            company_among("Inkwell", &values).as_deref(),
            Some("Inkwell Inc")
        );
        assert_eq!(company_among("Nothing Here", &values), None);
        // A name with no company beside it says nothing.
        assert_eq!(
            company_among("Lonely", &[v(r"C:\a\l.exe.FriendlyAppName", "Lonely")]),
            None
        );
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

    const PROGRAMS: &str = "6D809377-6AF0-444B-8957-A3773F02200E";
    const PROGRAMS_X86: &str = "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E";
    const LOCAL: &str = "F1B32785-6FBA-4FCF-9D55-7B8E7F157091";

    fn folders() -> Vec<(&'static str, PathBuf)> {
        vec![
            (PROGRAMS, PathBuf::from(r"C:\Program Files")),
            (PROGRAMS_X86, PathBuf::from(r"C:\Program Files (x86)\")),
            (LOCAL, PathBuf::from(r"C:\Users\jdoe\AppData\Local")),
        ]
    }

    #[test]
    fn a_folder_in_program_files_has_its_tiles_under_the_known_folder_too() {
        assert_eq!(
            tile_roots(Path::new(r"C:\Program Files\Quillmark"), &folders()),
            vec![
                r"W~C:\Program Files\Quillmark".to_string(),
                format!(r"W~{{{PROGRAMS}}}\Quillmark"),
            ]
        );
        assert_eq!(
            tile_roots(
                Path::new(r"c:\program files (x86)\Quill Labs\Quillmark\"),
                &folders()
            ),
            vec![
                r"W~c:\program files (x86)\Quill Labs\Quillmark".to_string(),
                format!(r"W~{{{PROGRAMS_X86}}}\Quill Labs\Quillmark"),
            ]
        );
        assert_eq!(
            tile_roots(
                Path::new(r"C:\Users\jdoe\AppData\Local\Quillmark"),
                &folders()
            ),
            vec![
                r"W~C:\Users\jdoe\AppData\Local\Quillmark".to_string(),
                format!(r"W~{{{LOCAL}}}\Quillmark"),
            ]
        );
    }

    #[test]
    fn only_folders_inside_a_known_folder_get_its_id() {
        // The known folder itself, a name that only starts like it and a
        // folder elsewhere keep the drive path alone.
        for dir in [
            r"C:\Program Files",
            r"C:\Program Files\",
            r"C:\Program Files Extra\Quillmark",
            r"D:\Apps\Quillmark",
        ] {
            assert_eq!(
                tile_roots(Path::new(dir), &folders()),
                vec![format!("W~{}", dir.trim_end_matches('\\'))],
                "{dir}"
            );
        }
    }

    #[test]
    fn a_known_folder_tile_resolves_back_to_its_folder() {
        for (id, base) in known_folder_dirs() {
            let dir = base.join("Quillmark");
            let wanted = format!(r"W~{{{id}}}\Quillmark");
            let roots = tile_roots(&dir, &known_folder_dirs());
            assert!(roots.contains(&wanted), "{roots:?}");
            assert_eq!(resolve(&wanted["W~".len()..]), Some(dir));
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

    /// A stand-in key under the current user's hive, gone again after the test.
    struct TestKey(String);

    impl Drop for TestKey {
        fn drop(&mut self) {
            let _ = registry::delete_key_tree(Hive::CurrentUser, &self.0);
        }
    }

    fn set_value(key: &str, name: &str, value: &str) {
        let (k, _) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .create_subkey(key)
            .unwrap();
        k.set_value(name, &value).unwrap();
    }

    fn subpaths(items: &[Leftover]) -> Vec<String> {
        let mut paths: Vec<String> = items
            .iter()
            .map(|l| match &l.value_name {
                Some(v) => format!("{} : {v}", l.subpath.clone().unwrap_or_default()),
                None => l.subpath.clone().unwrap_or_default(),
            })
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn an_app_id_names_the_program_by_product_and_vendor() {
        let target = super::super::name_target("Lumen", Some("Brightway Labs"));
        assert!(app_id_is_programs("com.brightway.lumen.windows", &target));
        assert!(app_id_is_programs("Brightway.Lumen", &target));
        // Another product of the vendor's, or the product without its vendor.
        assert!(!app_id_is_programs("com.brightway.other", &target));
        assert!(!app_id_is_programs("lumen.app", &target));
        assert!(!app_id_is_programs("com.brightway", &target));
        // A packaged app, a path or a name without dots is another kind.
        assert!(!app_id_is_programs("Brightway.Lumen_x1y2z3!App", &target));
        assert!(!app_id_is_programs(r"C:\Apps\brightway.lumen.exe", &target));
        assert!(!app_id_is_programs("BrightwayLumen", &target));
    }

    #[test]
    fn the_records_under_a_gone_programs_app_id_go() {
        let root = TestKey(format!(r"Software\OxidizeAppIdTest{}", std::process::id()));
        let base = |name: &str| format!(r"{}\{name}", root.0);
        let places = AppIdPlaces {
            keys: vec![(base("Settings"), "notification settings of the program")],
            tiles: base("Tiles"),
            usage: vec![base("Usage")],
        };
        let ours = "com.brightway.lumen.windows";
        let theirs = "com.brightway.other";
        for id in [ours, theirs] {
            set_value(&format!(r"{}\{id}", base("Settings")), "Enabled", "0");
            set_value(&format!(r"{}\W~{id}", base("Tiles")), "x", "1");
            set_value(&base("Usage"), id, "1");
        }
        set_value(&format!(r"{}\W~C:\Apps", base("Tiles")), "x", "1");

        let target = super::super::name_target("Lumen", Some("Brightway Labs"));
        let found = app_id_records(Hive::CurrentUser, &places, &target);
        assert_eq!(
            subpaths(&found),
            vec![
                format!(r"{}\{ours}", base("Settings")),
                format!(r"{}\W~{ours}", base("Tiles")),
                format!(r"{} : {ours}", base("Usage")),
            ]
        );
    }

    #[test]
    fn the_start_records_of_a_missing_folder_named_after_the_product_go() {
        let root = TestKey(format!(r"Software\OxidizeTileTest{}", std::process::id()));
        let files = crate::backup::TestDir::new("oxidize_tile_test");
        let vendor = files.join("Brightway");
        std::fs::create_dir_all(vendor.join("Lumen Live")).unwrap();
        std::fs::write(vendor.join("Lumen Live").join("notes.txt"), "").unwrap();

        // `W~C:` and then one key per part of the path.
        let vendor_s = vendor.to_string_lossy().to_string();
        let (drive, rest) = vendor_s.split_once('\\').unwrap();
        let tiles = format!(r"{}\W~{drive}\{rest}", root.0);
        for record in [
            r"Lumen\Lumen.exe",
            r"Other\tool.exe",
            r"Old\Lumen\Lumen.exe",
            r"Lumen Live\notes.txt",
        ] {
            set_value(&format!(r"{tiles}\{record}"), "Category", "0");
        }

        let target = super::super::name_target("Lumen", Some("Brightway Labs"));
        let gone = Gone {
            dirs: &[],
            files: &[],
            others: &[],
            target: &target,
        };
        let found = tiles_of_missing_folders(Hive::CurrentUser, &root.0, &gone);
        assert_eq!(
            subpaths(&found),
            vec![format!(r"{tiles}\Lumen"), format!(r"{tiles}\Old\Lumen")]
        );
    }

    #[test]
    fn a_com_class_that_only_starts_files_that_go_goes() {
        let root = TestKey(format!(r"Software\OxidizeComTest{}", std::process::id()));
        let files = crate::backup::TestDir::new("oxidize_com_test");
        let kept = files.join("Other").join("other.exe");
        std::fs::create_dir_all(kept.parent().unwrap()).unwrap();
        std::fs::write(&kept, "").unwrap();
        let missing = files
            .join(unique("Brightway"))
            .join("Lumen")
            .join("Lumen.exe");
        let missing = missing.to_string_lossy().to_string();
        let kept = kept.to_string_lossy().to_string();
        let class = |id: &str, server: &str| format!(r"{}\{{{id}}}\{server}", root.0);

        set_value(
            &class("1-GONE", "LocalServer32"),
            "",
            &format!("\"{missing}\" -ToastActivated"),
        );
        set_value(&class("2-KEPT", "LocalServer32"), "", &kept);
        set_value(&class("3-MIXED", "LocalServer32"), "", &missing);
        set_value(&class("3-MIXED", "InprocServer32"), "", &kept);
        set_value(&class("4-NONE", "ProgID"), "", "Lumen.Document");
        set_value(
            &format!(r"{}\NotAClass\LocalServer32", root.0),
            "",
            &missing,
        );

        let target = super::super::name_target("Lumen", Some("Brightway Labs"));
        let gone = Gone {
            dirs: &[],
            files: &[],
            others: &[],
            target: &target,
        };
        let found = com_classes(Hive::CurrentUser, &root.0, &gone);
        assert_eq!(subpaths(&found), vec![format!(r"{}\{{1-GONE}}", root.0)]);
    }
}
