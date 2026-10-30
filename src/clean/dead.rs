//! Whether a folder of a removed program is dead: no file in it changed for
//! `DEAD_DAYS` days or is held open, nothing runs from it, and no git
//! repository lies in it or above it. Only such a folder may be deleted
//! outright instead of moved into a backup, and it is asked again right
//! before it goes.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::files::{self, Kind, Probe, Rule};

/// No file in a dead folder changed for this many days.
pub const DEAD_DAYS: u64 = 30;

/// Is the folder at `dir` dead? Anything that cannot be read or opened
/// makes the answer no. A link inside is never followed; removing the
/// folder removes only the link. A cloud placeholder or another file whose
/// data may live elsewhere makes the answer no.
pub fn proven_dead(dir: &Path, now: SystemTime, running: &[PathBuf]) -> bool {
    let Ok(meta) = fs::symlink_metadata(dir) else {
        return false;
    };
    if !meta.is_dir()
        || files::is_link(&meta)
        || files::is_repository(dir)
        || files::repository_above(dir, &mut HashMap::new()).is_some()
        || running
            .iter()
            .any(|exe| crate::system::path_under(exe, dir))
    {
        return false;
    }
    let rule = Rule {
        min_age: Some(super::days_ago(DEAD_DAYS)),
        ..Rule::default()
    };
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                return false;
            };
            match files::kind(&meta) {
                Kind::Link => continue,
                Kind::StandIn => return false,
                Kind::Plain => {}
            }
            if meta.is_dir() {
                if files::is_repository(&path) {
                    return false;
                }
                stack.push(path);
            } else if !files::old_enough(&meta, &rule, now) || files::probe(&path) != Probe::Free {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::super::files::tests::{age, file_aged, fixture, mark};
    use super::*;

    #[test]
    fn a_folder_untouched_for_a_month_is_dead() {
        let root = fixture("dead_old");
        file_aged(&root.join(r"Quillmark\bin\quill.dll"), 10, 90);
        file_aged(&root.join(r"Quillmark\settings.ini"), 10, 40);
        assert!(proven_dead(&root.join("Quillmark"), SystemTime::now(), &[]));
    }

    #[test]
    fn one_file_changed_this_month_keeps_the_folder_alive() {
        let root = fixture("dead_recent");
        file_aged(&root.join(r"Quillmark\bin\quill.dll"), 10, 90);
        file_aged(&root.join(r"Quillmark\cache\today.bin"), 10, 2);
        assert!(!proven_dead(
            &root.join("Quillmark"),
            SystemTime::now(),
            &[]
        ));
    }

    #[test]
    fn a_program_running_from_the_folder_keeps_it_alive() {
        let root = fixture("dead_running");
        let exe = root.join(r"Quillmark\quill.exe");
        file_aged(&exe, 10, 90);
        assert!(!proven_dead(
            &root.join("Quillmark"),
            SystemTime::now(),
            &[exe]
        ));
    }

    #[test]
    fn a_file_held_open_keeps_the_folder_alive() {
        let root = fixture("dead_open");
        let file = root.join(r"Quillmark\quill.log");
        file_aged(&file, 10, 90);
        let _open = fs::File::open(&file).unwrap();
        assert!(!proven_dead(
            &root.join("Quillmark"),
            SystemTime::now(),
            &[]
        ));
    }

    #[test]
    fn a_git_repository_inside_keeps_the_folder_alive() {
        let root = fixture("dead_repo");
        file_aged(&root.join(r"Quillmark\plugins\one\code.txt"), 10, 90);
        fs::create_dir_all(root.join(r"Quillmark\plugins\one\.git")).unwrap();
        assert!(!proven_dead(
            &root.join("Quillmark"),
            SystemTime::now(),
            &[]
        ));
    }

    #[test]
    fn an_offline_or_pinned_file_keeps_the_folder_from_being_proven() {
        for (name, letter) in [("dead_offline", 'O'), ("dead_pinned", 'P')] {
            let root = fixture(name);
            let dir = root.join("Quillmark");
            file_aged(&dir.join(r"bin\quill.dll"), 10, 90);
            let file = dir.join("synced.dat");
            file_aged(&file, 10, 90);
            mark(&file, letter);
            age(&file, 90);
            assert!(!proven_dead(&dir, SystemTime::now(), &[]), "{name}");
        }
    }

    #[test]
    fn a_folder_that_is_gone_is_not_dead() {
        let root = fixture("dead_gone");
        assert!(!proven_dead(
            &root.join("Quillmark"),
            SystemTime::now(),
            &[]
        ));
    }
}
