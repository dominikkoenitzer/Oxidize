//! Whether a folder given as a temp folder really is one.
//!
//! `std::env::temp_dir()` reads `TMP`, then `TEMP`, and without either
//! falls back to the user's profile, and after that to the Windows folder.
//! The temp clean takes every file there not changed for a week, so a temp
//! folder is checked against the folders Windows keeps before anything in
//! it is looked at.

use std::path::{Path, PathBuf};

use super::protect::{key_of, under};
use crate::scanner::env_dir;
use crate::system::{self, Known};

/// What a temp folder is checked against.
#[derive(Debug, Clone, Default)]
pub struct TempCheck {
    /// Folders Windows keeps for the user and the machine. A temp folder is
    /// none of them, holds none of them and lies in none of them, except in
    /// one of `homes`.
    pub kept: Vec<PathBuf>,
    /// Where a temp folder may lie inside a kept folder: the user's
    /// `AppData\Local\Temp`, and the Windows folder's `Temp` and
    /// `SystemTemp`.
    pub homes: Vec<PathBuf>,
    /// The user's profile, named as such when it is given as the temp
    /// folder.
    pub profile: Option<PathBuf>,
}

impl TempCheck {
    /// The check for this PC, asking Windows where its folders are and
    /// taking the environment's word only as well, never instead.
    pub fn this_pc() -> &'static TempCheck {
        static CHECK: std::sync::OnceLock<TempCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            let windows = system::windows_dir();
            let local =
                system::known_folder(Known::LocalAppData).or_else(|| env_dir("LOCALAPPDATA"));
            let profile = system::known_folder(Known::Profile).or_else(|| env_dir("USERPROFILE"));
            let mut kept: Vec<PathBuf> = system::known_folders().to_vec();
            for var in [
                "USERPROFILE",
                "PUBLIC",
                "LOCALAPPDATA",
                "APPDATA",
                "ProgramData",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramW6432",
            ] {
                kept.extend(env_dir(var));
            }
            kept.push(windows.clone());
            kept.extend(
                profile
                    .iter()
                    .filter_map(|p| p.parent().map(Path::to_path_buf)),
            );
            // Oxidize's own folder holds every backup and the protected list.
            kept.extend(local.iter().map(|l| l.join("Oxidize")));
            kept.extend(env_dir("LOCALAPPDATA").map(|l| l.join("Oxidize")));
            let mut homes = vec![windows.join("Temp"), windows.join("SystemTemp")];
            homes.extend(local.iter().map(|l| l.join("Temp")));
            TempCheck {
                kept,
                homes,
                profile,
            }
        })
    }

    /// Why `root` is not a temp folder, or None when it is one. A folder
    /// that is not there holds nothing and passes.
    pub fn refusal(&self, root: &Path) -> Option<String> {
        let shown = root.display();
        if !root.is_absolute() {
            return Some(format!("{shown} is not a full path"));
        }
        if !root.exists() {
            return None;
        }
        let key = key_of(root);
        if is_volume_root(&key) {
            return Some(format!("{shown} is the root of a drive"));
        }
        if self.profile.as_deref().is_some_and(|p| key_of(p) == key) {
            return Some(format!("{shown} is your profile folder"));
        }
        let kept: Vec<(&PathBuf, String)> = self
            .kept
            .iter()
            .map(|f| (f, key_of(f)))
            .filter(|(_, k)| !k.is_empty())
            .collect();
        if kept.iter().any(|(_, k)| *k == key) {
            return Some(format!("{shown} is a folder Windows keeps"));
        }
        if let Some((f, _)) = kept.iter().find(|(_, k)| under(k, &key)) {
            return Some(format!("{shown} holds {}", f.display()));
        }
        let at_home = self
            .homes
            .iter()
            .map(|h| key_of(h))
            .any(|h| key == h || under(&key, &h));
        if at_home {
            return None;
        }
        // The deepest folder it lies in names the place best.
        kept.iter()
            .filter(|(_, k)| !is_volume_root(k) && under(&key, k))
            .max_by_key(|(_, k)| k.len())
            .map(|(f, _)| format!("{shown} lies inside {}", f.display()))
    }
}

/// Is `key` a drive, a volume or a share as a whole?
fn is_volume_root(key: &str) -> bool {
    let parts = |s: &str| s.split('\\').filter(|p| !p.is_empty()).count();
    match key.strip_prefix("\\\\") {
        Some(share) => parts(share) <= 2,
        None => parts(key) <= 1,
    }
}

/// Why `root` may not be cleaned as a temp folder, by the given check or by
/// this PC's own, or None when both let it pass.
pub fn refusal(root: &Path, own: &TempCheck) -> Option<String> {
    own.refusal(root)
        .or_else(|| TempCheck::this_pc().refusal(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean::files::tests::fixture;

    /// A profile laid out in a test folder, and the check that knows it.
    fn profile(name: &str) -> (PathBuf, TempCheck) {
        let root = fixture(name).join("me");
        let local = root.join(r"AppData\Local");
        for d in [
            local.join("Temp"),
            local.join("Oxidize"),
            root.join(r"AppData\Roaming"),
            root.join("Documents"),
            root.join("Downloads"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let check = TempCheck {
            kept: vec![
                root.clone(),
                local.clone(),
                root.join(r"AppData\Roaming"),
                root.join("Documents"),
                root.join("Downloads"),
                local.join("Oxidize"),
            ],
            homes: vec![local.join("Temp")],
            profile: Some(root.clone()),
        };
        (root, check)
    }

    #[test]
    fn only_a_folder_in_a_temp_place_passes() {
        let (me, check) = profile("temp_root_places");
        let local = me.join(r"AppData\Local");
        assert_eq!(check.refusal(&local.join("Temp")), None);
        let inner = local.join(r"Temp\Setup 1");
        std::fs::create_dir_all(&inner).unwrap();
        assert_eq!(check.refusal(&inner), None);
        // A folder that is not there holds nothing.
        assert_eq!(check.refusal(&local.join("Temp2")), None);
        let refused = |p: &Path, says: &str| {
            let why = check
                .refusal(p)
                .unwrap_or_else(|| panic!("{} passed", p.display()));
            assert!(why.contains(says), "{why}");
        };
        refused(&me, "your profile folder");
        refused(&me.join("AppData"), "holds");
        refused(&local, "is a folder Windows keeps");
        refused(&local.join("Oxidize"), "is a folder Windows keeps");
        refused(&me.join("Documents"), "is a folder Windows keeps");
        let projects = me.join("Projects");
        std::fs::create_dir_all(&projects).unwrap();
        refused(&projects, "lies inside");
        let under_docs = me.join(r"Documents\Temp");
        std::fs::create_dir_all(&under_docs).unwrap();
        refused(&under_docs, "lies inside");
        refused(Path::new("Temp"), "not a full path");
        refused(Path::new(""), "not a full path");
        let _ = std::fs::remove_dir_all(me.parent().unwrap());
    }

    #[test]
    fn a_drive_or_a_share_as_a_whole_is_never_a_temp_folder() {
        for key in [
            "c:",
            "d:",
            "volume{0b1d2e3f}",
            r"\\server\share",
            r"\\server",
        ] {
            assert!(is_volume_root(key), "{key}");
        }
        for key in [r"c:\temp", r"\\server\share\temp", r"volume{0b1d2e3f}\temp"] {
            assert!(!is_volume_root(key), "{key}");
        }
        let check = TempCheck::default();
        let drive = system::windows_dir()
            .ancestors()
            .last()
            .unwrap()
            .to_path_buf();
        assert!(check.refusal(&drive).unwrap().contains("root of a drive"));
    }

    #[test]
    fn this_pc_refuses_its_profile_and_its_windows_folders_and_takes_its_temp() {
        let check = TempCheck::this_pc();
        assert_eq!(check.refusal(&std::env::temp_dir()), None);
        let profile = system::known_folder(Known::Profile).unwrap();
        assert!(check
            .refusal(&profile)
            .unwrap()
            .contains("your profile folder"));
        let windows = system::windows_dir();
        assert!(check.refusal(&windows).is_some());
        assert!(check.refusal(&windows.join("System32")).is_some());
        assert!(check.refusal(&windows.join("WinSxS")).is_some());
        assert_eq!(check.refusal(&windows.join("Temp")), None);
        let local = system::known_folder(Known::LocalAppData).unwrap();
        assert!(check.refusal(&local).is_some());
        assert!(check.refusal(local.parent().unwrap()).is_some());
        for folder in system::known_folders() {
            if folder.exists() {
                assert!(check.refusal(folder).is_some(), "{}", folder.display());
            }
        }
    }

    /// What the temp clean takes on this PC in a process started with the
    /// environment the parent test gave it. Run only by that test.
    #[test]
    #[ignore]
    fn temp_root_of_a_child_process() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let places = crate::clean::Places::this_pc();
        let root = places.user_temp.unwrap();
        let verdict = refusal(&root, &TempCheck::default()).unwrap_or_else(|| "ok".to_string());
        println!("TEMP_ROOT={}", root.display());
        println!("VERDICT={verdict}");
    }

    const CHILD: &str = "OXIDIZE_TEMP_ROOT_CHILD";

    /// Run the test above in a child process with `env` set (None removes
    /// the variable) and return the temp folder it took and the verdict.
    fn child(env: &[(&str, Option<&str>)]) -> (PathBuf, String) {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "clean::temp_root::tests::temp_root_of_a_child_process",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1");
        for (name, value) in env {
            match value {
                Some(v) => cmd.env(name, v),
                None => cmd.env_remove(name),
            };
        }
        let out = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(out.status.success(), "{text}");
        let line = |name: &str| {
            text.lines()
                .find_map(|l| l.split_once(name).map(|(_, value)| value))
                .unwrap_or_else(|| panic!("no {name} in {text}"))
                .trim()
                .to_string()
        };
        (PathBuf::from(line("TEMP_ROOT=")), line("VERDICT="))
    }

    #[test]
    fn without_tmp_and_temp_the_profile_is_refused() {
        let profile = system::known_folder(Known::Profile).unwrap();
        let profile_text = profile.display().to_string();
        let cases: [&[(&str, Option<&str>)]; 2] = [
            &[("TMP", None), ("TEMP", None)],
            &[("TMP", Some(&profile_text)), ("TEMP", Some(&profile_text))],
        ];
        for env in cases {
            let (root, verdict) = child(env);
            // Windows falls back to the profile, as the check expects.
            assert_eq!(key_of(&root), key_of(&profile), "{env:?}");
            assert!(
                verdict.contains("your profile folder"),
                "{env:?}: {verdict}"
            );
        }
        // Set but empty, the folder Windows answers with is no full path
        // at all, which would be read from the current folder.
        let (root, verdict) = child(&[("TMP", Some("")), ("TEMP", Some(""))]);
        assert_ne!(verdict, "ok", "{}", root.display());
        assert!(!root.is_absolute() || key_of(&root) == key_of(&profile));
        // The same child with the usual variables takes the usual folder.
        let (root, verdict) = child(&[]);
        assert_eq!(key_of(&root), key_of(&std::env::temp_dir()));
        assert_eq!(verdict, "ok");
    }
}
