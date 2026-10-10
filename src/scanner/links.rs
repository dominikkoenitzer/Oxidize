//! Leftovers that point at a program from outside its own folders and keys:
//! the link types it answers to. Each step goes by where a command or a
//! shortcut leads, not by what it is called.

use super::{exe_missing, locate_exe, path_names_product};
use crate::model::{Confidence, Hive, Leftover, ScanTarget};
use crate::{registry, system};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::name_target;
    use std::path::PathBuf;

    const HOME: &str = r"C:\Program Files\Quillmark";

    fn quillmark(install: Option<&str>) -> ScanTarget {
        let mut t = name_target("Quillmark", Some("Example Studio"));
        t.install_location = install.map(PathBuf::from);
        t
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
