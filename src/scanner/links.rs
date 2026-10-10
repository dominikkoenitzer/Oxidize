//! Leftovers that point at a program from outside its own folders and keys:
//! the link types it answers to. Each step goes by where a command or a
//! shortcut leads, not by what it is called.

use std::fs;
use std::path::{Path, PathBuf};

use super::{env_dir, exe_missing, locate_exe, path_names_product, path_within_shared_dir};
use crate::model::{Confidence, Hive, Leftover, LeftoverKind, ScanTarget};
use crate::{lnk, registry, system};

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
    if let Some(loc) = &target.install_location {
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
    let loc = target.install_location.as_deref()?;
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
