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
