//! Leftovers that point at a program from outside its own folders and keys:
//! link types, shortcuts, temp folders and the uninstall entries of its
//! parts. Where a command or a shortcut leads counts before its name.

use std::fs;
use std::path::{Path, PathBuf};

use super::{
    dir_contains, env_dir, exe_missing, fs_denied, is_exact_product, locate_exe, matches_publisher,
    norm_path_key, other_program_install_dirs, own_install_folder, path_names_product,
    path_within_shared_dir, push_dir_leftover, score_product, Snapshot,
};
use crate::model::{Confidence, Hive, Leftover, LeftoverKind, Program, ScanTarget};
use crate::{lnk, registry, system, util};

/// Where each hive keeps its own classes. The machine's `Classes` key is the
/// same for 32-bit and 64-bit programs, so one read covers both.
const CLASSES_ROOTS: [(Hive, &str); 2] = [
    (Hive::CurrentUser, r"Software\Classes"),
    (Hive::LocalMachine, r"SOFTWARE\Classes"),
];

/// Where Windows records the handler picked for a link type.
const URL_CHOICES: &str = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations";

/// Can this be the name of a link type such as `example-player://`? File
/// types (`.txt`) and class ids (`{...}`) cannot, which skips most of the
/// thousands of keys under `Classes` without opening them.
fn scheme_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Does a handler's command run something of the program's? A command into
/// the install folder does, and so does one whose file is gone from a path
/// that names the product. Whatever runs from the Windows folder is never a
/// program's, whoever registered it.
fn match_handler(command: &str, target: &ScanTarget, inside: &str) -> Option<(Confidence, String)> {
    let exe = system::command_exe(command)?;
    if system::in_windows_dir(&exe) {
        return None;
    }
    let exe = locate_exe(&exe);
    if system::in_windows_dir(&exe) {
        return None;
    }
    if let Some(loc) = own_install_folder(target) {
        if exe.is_absolute() && system::path_under(&exe, loc) {
            return Some((Confidence::High, inside.to_string()));
        }
    }
    if exe_missing(&exe) && path_names_product(&exe, target) {
        return Some((Confidence::High, "points to a missing file".to_string()));
    }
    None
}

/// Match the command of a link type's handler.
fn match_link_handler(command: &str, target: &ScanTarget) -> Option<(Confidence, String)> {
    match_handler(command, target, "link handler inside the install folder")
}

/// Is a handler choice recorded for this link type? Windows keeps one for
/// the types several programs can open, such as web and mail links. Such a
/// key is the machine's, whatever its command runs now.
fn shared_scheme(scheme: &str) -> bool {
    registry::key_exists(Hive::CurrentUser, &format!(r"{URL_CHOICES}\{scheme}"))
}

/// Link types whose handler runs the program: the whole key of each. Only
/// keys that carry `URL Protocol` are link types, and only theirs have their
/// command read.
pub(super) fn scan_link_handlers(target: &ScanTarget) -> Vec<Leftover> {
    let mut out = Vec::new();
    for (hive, base) in CLASSES_ROOTS {
        for scheme in registry::enum_subkeys(hive, base) {
            if !scheme_name(&scheme) {
                continue;
            }
            let key = format!(r"{base}\{scheme}");
            if !registry::value_exists(hive, &key, "URL Protocol") {
                continue;
            }
            let command = registry::read_string(hive, &format!(r"{key}\shell\open\command"), "");
            let Some((conf, reason)) = command
                .as_deref()
                .and_then(|c| match_link_handler(c, target))
            else {
                continue;
            };
            if !shared_scheme(&scheme) {
                out.push(Leftover::reg_key(hive, key, conf, reason));
            }
        }
    }
    out
}

/// Can this be a program's own file type class? Programs name theirs
/// `Vendor.Type`, often with a version (`ExamplePlayer.Project.2`). Windows'
/// shared classes (`Folder`, `Directory`, `*`, `exefile` ...) have no dot and
/// hold every program's verbs, so they never count; nor do extensions and
/// class ids.
fn file_type_name(name: &str) -> bool {
    !name.starts_with('.')
        && !name.starts_with('{')
        && name
            .split_once('.')
            .is_some_and(|(head, tail)| !head.is_empty() && !tail.is_empty())
}

/// Match the open command of a file type or an open-with entry.
fn match_opener(command: &str, target: &ScanTarget, inside: &str) -> Option<(Confidence, String)> {
    match_handler(command, target, inside)
}

/// The file types the program opens: each class named after the product
/// whose open command runs from its install folder, its open-with entry under
/// `Applications`, and the extensions' `OpenWithProgids` values that name one
/// of those classes. The extension keys themselves are shared and stay.
pub(super) fn scan_file_types(target: &ScanTarget) -> Vec<Leftover> {
    let mut out = Vec::new();
    for (hive, base) in CLASSES_ROOTS {
        let children = registry::enum_subkeys(hive, base);
        let mut ours: Vec<String> = Vec::new();
        for name in &children {
            // Only classes named after the product have their command read:
            // reading every class would take seconds.
            if !file_type_name(name) || score_product(name, target).is_none() {
                continue;
            }
            let key = format!(r"{base}\{name}");
            // A link type is the link handler step's.
            if registry::value_exists(hive, &key, "URL Protocol") {
                continue;
            }
            let command = registry::read_string(hive, &format!(r"{key}\shell\open\command"), "");
            if let Some((conf, reason)) = command
                .as_deref()
                .and_then(|c| match_opener(c, target, "file type opened from the install folder"))
            {
                out.push(Leftover::reg_key(hive, key, conf, reason));
                ours.push(name.clone());
            }
        }

        let apps = format!(r"{base}\Applications");
        for exe in registry::enum_subkeys(hive, &apps) {
            if !target.exe_names.contains(&exe.to_lowercase()) {
                continue;
            }
            let key = format!(r"{apps}\{exe}");
            let command = registry::read_string(hive, &format!(r"{key}\shell\open\command"), "");
            if let Some((conf, reason)) = command
                .as_deref()
                .and_then(|c| match_opener(c, target, "open-with entry inside the install folder"))
            {
                out.push(Leftover::reg_key(hive, key, conf, reason));
            }
        }

        if ours.is_empty() {
            continue;
        }
        for ext in children.iter().filter(|n| n.starts_with('.')) {
            let sub = format!(r"{base}\{ext}\OpenWithProgids");
            let Some(key) = registry::open_read(hive, &sub) else {
                continue;
            };
            for (value, _) in key.enum_values().flatten() {
                if ours.iter().any(|p| p.eq_ignore_ascii_case(&value)) {
                    out.push(Leftover::reg_value(
                        hive,
                        sub.clone(),
                        value,
                        Confidence::High,
                        "opens with the program's file type",
                    ));
                }
            }
        }
    }
    out
}

/// The folders whose shortcuts are read: the Start menu of the user and of
/// the machine, and the desktop of both.
fn shortcut_roots() -> Vec<PathBuf> {
    const START_MENU: &str = r"Microsoft\Windows\Start Menu\Programs";
    [
        env_dir("APPDATA").map(|p| p.join(START_MENU)),
        env_dir("ProgramData").map(|p| p.join(START_MENU)),
        env_dir("USERPROFILE").map(|p| p.join("Desktop")),
        env_dir("PUBLIC").map(|p| p.join("Desktop")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Does a shortcut lead into the program's install folder? Its file name
/// says nothing here, so a shortcut called "Start" is found as well.
fn match_shortcut(link_target: &Path, target: &ScanTarget) -> Option<(Confidence, String)> {
    let loc = own_install_folder(target)?;
    if !link_target.is_absolute() || system::in_windows_dir(link_target) {
        return None;
    }
    system::path_under(link_target, loc)
        .then(|| (Confidence::High, "shortcut to the program".to_string()))
}

/// Shortcuts in `root` and in its subfolders two levels down whose target is
/// inside the install folder. A subfolder whose name marks a shared place is
/// not entered.
fn scan_shortcuts_in(root: &Path, target: &ScanTarget, out: &mut Vec<Leftover>) {
    if target.install_location.is_none() {
        return;
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if ft.is_dir() {
                let shared = path
                    .strip_prefix(root)
                    .map(path_within_shared_dir)
                    .unwrap_or(true);
                if depth < 2 && !shared {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            let is_link = path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
            if !ft.is_file() || !is_link {
                continue;
            }
            let Some(link_target) = lnk::target_of(&path) else {
                continue;
            };
            if let Some((conf, reason)) = match_shortcut(&link_target, target) {
                let size = entry.metadata().map(|m| m.len()).ok();
                out.push(Leftover::fs(
                    LeftoverKind::File,
                    path,
                    conf,
                    reason,
                    size,
                    false,
                ));
            }
        }
    }
}

/// Shortcuts in the Start menu and on the desktop that lead into the
/// program's install folder, whatever they are called.
pub(super) fn scan_shortcuts(target: &ScanTarget) -> Vec<Leftover> {
    let mut out = Vec::new();
    for root in shortcut_roots() {
        scan_shortcuts_in(&root, target, &mut out);
    }
    out
}

/// Folders in `root` named after the product. Only a folder named exactly
/// like it is sure to be its own; any other match is likely at most, since
/// installers and updaters unpack under all kinds of names. A folder another
/// program is installed in stays.
fn scan_temp_dir(root: &Path, target: &ScanTarget, snap: &Snapshot) -> Vec<Leftover> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    let others = other_program_install_dirs(target.registry.as_ref(), snap.programs());
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        // Shared names, and a folder named after the vendor rather than the
        // product, are not the product's, here as everywhere else.
        if fs_denied(&name)
            || (matches_publisher(&name, target) && !is_exact_product(&name, target))
        {
            continue;
        }
        let path = entry.path();
        let key = norm_path_key(&path);
        let holds_install = others
            .iter()
            .chain(target.install_location.as_ref())
            .any(|o| dir_contains(&key, &norm_path_key(o)));
        if holds_install {
            continue;
        }
        let hit = if is_exact_product(&name, target) && !target.vendor_is_shared {
            Some((
                Confidence::High,
                "exact name, in the temp folder".to_string(),
            ))
        } else {
            score_product(&name, target)
                .map(|(_, reason)| (Confidence::Medium, format!("{reason}, in the temp folder")))
        };
        if let Some((conf, reason)) = hit {
            push_dir_leftover(&mut out, path, conf, reason, snap.roots());
        }
    }
    out
}

/// The program's folders in the user's temp folder.
pub(super) fn scan_temp_folders(target: &ScanTarget, snap: &Snapshot) -> Vec<Leftover> {
    match env_dir("LOCALAPPDATA") {
        Some(local) => scan_temp_dir(&local.join("Temp"), target, snap),
        None => Vec::new(),
    }
}

/// Is another uninstall entry a broken part of the program? It has to point
/// into the install folder, by its uninstaller, icon or recorded folder, and
/// its uninstaller has to be gone. An entry whose uninstaller is still there
/// can still remove what it installed, so it stays.
fn stale_uninstall_entry(
    entry: &Program,
    loc: &Path,
    exists: impl Fn(&Path) -> bool,
) -> Option<(Confidence, String)> {
    let as_path = |s: &str| PathBuf::from(util::expand_env_vars(s).trim().trim_matches('"'));
    let uninstaller = locate_exe(&system::command_exe(entry.uninstall_string.as_deref()?)?);
    if !uninstaller.is_absolute() || system::in_windows_dir(&uninstaller) || exists(&uninstaller) {
        return None;
    }
    let icon = entry
        .display_icon
        .as_deref()
        .map(|i| as_path(i.split(',').next().unwrap_or(i)));
    let folder = entry.install_location.as_deref().map(as_path);
    let points_in = [Some(uninstaller), icon, folder]
        .into_iter()
        .flatten()
        .any(|p| p.is_absolute() && system::path_under(&p, loc));
    points_in.then(|| {
        (
            Confidence::High,
            "uninstall entry pointing to a missing file".to_string(),
        )
    })
}

/// Other uninstall entries left pointing into the program's folder with
/// their uninstaller gone.
pub(super) fn scan_stale_uninstall_entries(target: &ScanTarget, snap: &Snapshot) -> Vec<Leftover> {
    let Some(loc) = own_install_folder(target) else {
        return Vec::new();
    };
    snap.programs()
        .iter()
        .filter(|p| {
            target
                .registry
                .as_ref()
                .is_none_or(|(key, source)| !(p.registry_key == *key && p.source == *source))
        })
        .filter_map(|p| {
            let (conf, reason) = stale_uninstall_entry(p, loc, Path::exists)?;
            let subpath = format!(r"{}\{}", p.source.view.uninstall_base(), p.registry_key);
            Some(Leftover::reg_key(p.source.hive, subpath, conf, reason))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::name_target;

    const HOME: &str = r"C:\Program Files\Quillmark";

    fn quillmark(install: Option<&str>) -> ScanTarget {
        let mut t = name_target("Quillmark", Some("Example Studio"));
        t.install_location = install.map(PathBuf::from);
        t
    }

    /// A shortcut file that points to `path`, with only a header and the
    /// LinkInfo that holds the local path.
    fn shortcut_bytes(path: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(0x4Cu32.to_le_bytes());
        bytes.extend([
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        bytes.extend(0x2u32.to_le_bytes());
        bytes.resize(76, 0);

        let volume: Vec<u8> = [0x11u32, 3, 0, 0x10]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .chain([0])
            .collect();
        let base_at = 0x1C + volume.len();
        let suffix_at = base_at + path.len() + 1;
        let size = suffix_at + 1;
        for field in [size, 0x1C, 1, 0x1C, base_at, 0, suffix_at] {
            bytes.extend(u32::try_from(field).unwrap().to_le_bytes());
        }
        bytes.extend(&volume);
        bytes.extend(path.as_bytes());
        bytes.extend([0, 0]);
        bytes.extend([0, 0, 0, 0]);
        bytes
    }

    #[test]
    fn a_shortcut_into_the_install_folder_is_the_programs_whatever_its_name() {
        let root =
            std::env::temp_dir().join(format!("oxidize_shortcut_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let deep = root.join(r"Tools\Group");
        let too_deep = deep.join("Deeper");
        fs::create_dir_all(&too_deep).unwrap();
        let ours = format!(r"{HOME}\quillmark.exe");
        let write = |dir: &Path, name: &str, to: &str| {
            fs::write(dir.join(name), shortcut_bytes(to)).unwrap();
        };
        write(&root, "Start.lnk", &ours);
        write(&deep, "Writer.lnk", &ours);
        write(&too_deep, "Hidden.lnk", &ours);
        write(&root, "Other.lnk", r"C:\Program Files\Other Tool\tool.exe");
        write(&root, "Quillmark.txt", &ours);

        let mut out = Vec::new();
        scan_shortcuts_in(&root, &quillmark(Some(HOME)), &mut out);
        let mut found: Vec<String> = out
            .iter()
            .map(|l| {
                Path::new(&l.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        found.sort();
        assert_eq!(found, ["Start.lnk", "Writer.lnk"]);
        assert!(out
            .iter()
            .all(|l| l.confidence == Confidence::High && l.reason == "shortcut to the program"));

        // Without a recorded folder there is nothing to point into.
        let mut out = Vec::new();
        scan_shortcuts_in(&root, &quillmark(None), &mut out);
        assert!(out.is_empty());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_shortcut_to_windows_is_never_the_programs() {
        let windows = system::windows_dir();
        let mut t = quillmark(None);
        t.install_location = Some(windows.clone());
        assert!(match_shortcut(&windows.join("notepad.exe"), &t).is_none());
        let t = quillmark(Some(HOME));
        assert!(match_shortcut(Path::new("quillmark.exe"), &t).is_none());
        assert!(match_shortcut(&Path::new(HOME).join("quillmark.exe"), &t).is_some());
    }

    #[test]
    fn a_temp_folder_is_sure_only_when_named_exactly_like_the_product() {
        let root = std::env::temp_dir().join(format!("oxidize_temp_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for folder in [
            "Quillmark",
            "Quillmark Setup 2",
            "Other Tool",
            "quillmark.log",
        ] {
            fs::create_dir_all(root.join(folder)).unwrap();
        }
        fs::create_dir_all(root.join(r"Shared Quillmark Cache\Example Studio Tool")).unwrap();
        fs::write(root.join("quillmark.tmp"), b"").unwrap();

        let snap = Snapshot::with_programs(Vec::new());
        let t = quillmark(Some(HOME));
        let mut found: Vec<(String, Confidence)> = scan_temp_dir(&root, &t, &snap)
            .into_iter()
            .map(|l| {
                let name = Path::new(&l.path).file_name().unwrap().to_string_lossy();
                (name.to_string(), l.confidence)
            })
            .collect();
        found.sort();
        assert!(found.contains(&("Quillmark".to_string(), Confidence::High)));
        assert!(found.contains(&("Quillmark Setup 2".to_string(), Confidence::Medium)));
        assert!(!found
            .iter()
            .any(|(n, _)| n == "Other Tool" || n == "quillmark.tmp"));

        // A folder another program is installed in is left alone.
        let holder = root.join("Shared Quillmark Cache");
        let mut entry = crate::model::Program {
            registry_key: "Example Studio Tool".to_string(),
            source: crate::model::RegistrySource::new(
                Hive::CurrentUser,
                crate::model::RegistryView::Native64,
            ),
            display_name: "Example Studio Tool".to_string(),
            display_version: None,
            publisher: None,
            install_date: None,
            install_location: Some(holder.join("Example Studio Tool").display().to_string()),
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        };
        let snap = Snapshot::with_programs(vec![entry.clone()]);
        let found = scan_temp_dir(&root, &t, &snap);
        assert!(
            !found.iter().any(|l| Path::new(&l.path) == holder),
            "{found:?}"
        );
        entry.install_location = None;
        let snap = Snapshot::with_programs(vec![entry]);
        let found = scan_temp_dir(&root, &t, &snap);
        assert!(
            found.iter().any(|l| Path::new(&l.path) == holder),
            "{found:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    fn entry(uninstall: Option<&str>, icon: Option<&str>, folder: Option<&str>) -> Program {
        Program {
            registry_key: "Quillmark Helper".to_string(),
            source: crate::model::RegistrySource::new(
                Hive::CurrentUser,
                crate::model::RegistryView::Native64,
            ),
            display_name: "Quillmark Helper".to_string(),
            display_version: None,
            publisher: None,
            install_date: None,
            install_location: folder.map(str::to_string),
            display_icon: icon.map(str::to_string),
            estimated_size_kb: None,
            uninstall_string: uninstall.map(str::to_string),
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    #[test]
    fn an_uninstall_entry_into_the_folder_with_its_uninstaller_gone_is_stale() {
        let loc = Path::new(HOME);
        let inside = format!(r#""{HOME}\helper\uninst.exe" /S"#);
        let gone = |_: &Path| false;
        let there = |_: &Path| true;
        let want = Some((
            Confidence::High,
            "uninstall entry pointing to a missing file".to_string(),
        ));
        assert_eq!(
            stale_uninstall_entry(&entry(Some(&inside), None, None), loc, gone),
            want
        );
        // An uninstaller kept elsewhere, with the icon or the folder inside.
        let cached = r#""C:\ProgramData\Example Cache\setup-7f3a.exe" /uninstall"#;
        let icon = format!(r"{HOME}\helper\helper.exe,0");
        assert_eq!(
            stale_uninstall_entry(&entry(Some(cached), Some(&icon), None), loc, gone),
            want
        );
        assert_eq!(
            stale_uninstall_entry(&entry(Some(cached), None, Some(HOME)), loc, gone),
            want
        );
        // An uninstaller that is still there can do its job.
        assert!(stale_uninstall_entry(&entry(Some(&inside), None, None), loc, there).is_none());
        // Nothing points into the folder.
        assert!(stale_uninstall_entry(&entry(Some(cached), None, None), loc, gone).is_none());
        // No uninstaller, or one Windows runs, says nothing.
        assert!(stale_uninstall_entry(&entry(None, Some(&icon), Some(HOME)), loc, gone).is_none());
        let msi = "MsiExec.exe /X{2D7E0D49-0001-0000-0000-000000000000}";
        assert!(stale_uninstall_entry(&entry(Some(msi), None, Some(HOME)), loc, gone).is_none());
    }

    #[test]
    fn only_class_names_can_be_file_types() {
        for name in ["Quillmark.Document", "Quillmark.Project.2"] {
            assert!(file_type_name(name), "{name}");
        }
        for name in [
            ".qmk",
            "{4D2F086C-6EA3-101B-A2A3-00AA00494A6A}",
            "Applications",
            "Folder",
            "Directory",
            "Drive",
            "*",
            "exefile",
            "SystemFileAssociations",
            "quillmark",
            "Quillmark.",
            "",
        ] {
            assert!(!file_type_name(name), "{name}");
        }
    }

    #[test]
    fn a_file_type_opened_from_the_install_folder_is_the_programs() {
        let t = quillmark(Some(HOME));
        let inside = "file type opened from the install folder";
        let hit = match_opener(&format!(r#""{HOME}\quillmark.exe" "%1""#), &t, inside);
        assert_eq!(hit, Some((Confidence::High, inside.to_string())));
        // Another program opening the same kind of file is not a reason.
        let other = r#""C:\Program Files\Other Tool\tool.exe" "%1""#;
        assert!(match_opener(other, &t, inside).is_none());
    }

    #[test]
    fn only_link_type_names_are_read() {
        for name in ["example-player", "exampleplayer", "ex+s.1"] {
            assert!(scheme_name(name), "{name}");
        }
        for name in [".mp3", "{4D2F086C-6EA3-101B-A2A3-00AA00494A6A}", "1abc", ""] {
            assert!(!scheme_name(name), "{name}");
        }
    }

    #[test]
    fn a_link_handler_in_the_install_folder_is_the_programs() {
        let t = quillmark(Some(HOME));
        let hit = match_link_handler(&format!(r#""{HOME}\quillmark.exe" --open "%1""#), &t);
        assert_eq!(
            hit,
            Some((
                Confidence::High,
                "link handler inside the install folder".to_string()
            ))
        );
        // Unquoted, with spaces in the path.
        assert!(match_link_handler(&format!(r"{HOME}\bin\quillmark.exe %1"), &t).is_some());
    }

    #[test]
    fn a_link_handler_elsewhere_is_left_alone() {
        let t = quillmark(Some(HOME));
        for command in [r#""C:\Program Files\Other Tool\tool.exe" "%1""#, ""] {
            assert!(match_link_handler(command, &t).is_none(), "{command}");
        }
        // Whatever Windows runs is Windows', even with the program's folder
        // in its arguments.
        let windows = system::windows_dir();
        let command = format!(
            r#""{}" url.dll,FileProtocolHandler "{HOME}\quillmark.exe" %1"#,
            windows.join(r"System32\rundll32.exe").display()
        );
        assert!(match_link_handler(&command, &t).is_none());
        assert!(match_link_handler("rundll32.exe url.dll,FileProtocolHandler %1", &t).is_none());
    }

    #[test]
    fn a_link_handler_whose_file_is_gone_is_found_by_its_path() {
        // No recorded folder: the path still names the product.
        let t = quillmark(None);
        let gone = r#""C:\Program Files\Quillmark 7f3a\quillmark.exe" "%1""#;
        assert_eq!(
            match_link_handler(gone, &t),
            Some((Confidence::High, "points to a missing file".to_string()))
        );
        // A path that does not name it says nothing.
        let other = r#""C:\Program Files\Other Tool 7f3a\tool.exe" "%1""#;
        assert!(match_link_handler(other, &t).is_none());
        // A bare name nothing answers to is unknown, not missing.
        assert!(match_link_handler("quillmark7f3a.exe %1", &t).is_none());
    }

    #[test]
    fn a_link_handler_matches_by_path_not_by_name() {
        // A file of the product's name that is still there, somewhere else,
        // is someone else's copy.
        let dir = std::env::temp_dir().join(format!("oxidize_links_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("quillmark.exe");
        std::fs::write(&exe, b"").unwrap();

        let t = quillmark(Some(HOME));
        let elsewhere = match_link_handler(&format!(r#""{}" "%1""#, exe.display()), &t);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(elsewhere.is_none());
    }
}
