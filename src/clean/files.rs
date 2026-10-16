//! Walking a folder for files the cleaner may delete, and deleting them.
//!
//! A walk never follows a link or a junction, never enters a protected
//! folder, and counts every file it leaves with the reason. The deletion
//! checks each file again right before it goes: still there, still old
//! enough, still not protected.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::protect::{self, Protected};
use super::{Kept, KeptReason};

/// Which files of a walk qualify.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rule {
    /// Only files neither written nor created for at least this long.
    pub min_age: Option<Duration>,
    /// Only files with one of these extensions, lower case without the dot.
    pub extensions: Option<&'static [&'static str]>,
    /// Whether a file held open by another program is told apart before
    /// anything is deleted. Off where the files cannot be opened anyway.
    pub probe_in_use: bool,
}

/// A file or an emptied folder the cleaner would delete.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    pub bytes: u64,
    pub dir: bool,
}

/// What one walk found.
#[derive(Debug, Clone, Default)]
pub struct Walk {
    pub candidates: Vec<Candidate>,
    pub kept: Vec<Kept>,
}

impl Walk {
    pub fn files(&self) -> usize {
        self.candidates.iter().filter(|c| !c.dir).count()
    }

    pub fn bytes(&self) -> u64 {
        self.candidates.iter().map(|c| c.bytes).sum()
    }
}

/// What deleting a walk's candidates did.
#[derive(Debug, Clone, Default)]
pub struct Deleted {
    pub freed: u64,
    pub files: usize,
    pub kept: Vec<Kept>,
}

/// The time the file last changed in place: written or created, whichever
/// is later. A file unpacked from an archive keeps the old write time of
/// the archive's copy, but its creation time says when it arrived.
fn last_change(meta: &fs::Metadata) -> Option<SystemTime> {
    let written = meta.modified().ok();
    let created = meta.created().ok();
    match (written, created) {
        (Some(w), Some(c)) => Some(w.max(c)),
        (w, c) => w.or(c),
    }
}

/// Is a file with this metadata old enough for the rule? A file whose times
/// cannot be read is not.
fn old_enough(meta: &fs::Metadata, rule: &Rule, now: SystemTime) -> bool {
    let Some(min) = rule.min_age else {
        return true;
    };
    match last_change(meta) {
        Some(t) => now.duration_since(t).map(|age| age >= min).unwrap_or(false),
        None => false,
    }
}

/// The rule's age in whole days, for the reason a file stays.
fn days(rule: &Rule) -> u64 {
    rule.min_age.map(|d| d.as_secs() / 86_400).unwrap_or(0)
}

fn extension_fits(path: &Path, rule: &Rule) -> bool {
    match rule.extensions {
        None => true,
        Some(list) => path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| list.contains(&e.to_lowercase().as_str()))
            .unwrap_or(false),
    }
}

/// How an open for deletion went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    Free,
    InUse,
    Denied,
}

/// Open the file for deletion without sharing it, and close it again at
/// once. Another program holding it open makes the open fail; nothing is
/// read or written.
#[cfg(windows)]
pub fn probe(path: &Path) -> Probe {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x0001_0000;
    // Opens the reparse point itself, never what it points to.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    match fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(_) => Probe::Free,
        Err(e) => classify(&e),
    }
}

#[cfg(not(windows))]
pub fn probe(_path: &Path) -> Probe {
    Probe::Free
}

/// Sharing and lock violations mean another program has the file open.
fn classify(e: &std::io::Error) -> Probe {
    match e.raw_os_error() {
        Some(32) | Some(33) => Probe::InUse,
        _ => Probe::Denied,
    }
}

/// Walk `root`, a folder or a single file, under `rule`. `root` itself is
/// never a candidate: the folder stays, only what is in it goes.
pub fn walk(root: &Path, rule: &Rule, protected: &Protected, now: SystemTime) -> Walk {
    let mut out = Walk::default();
    let Ok(meta) = fs::symlink_metadata(root) else {
        return out;
    };
    let root_key = protect::key_of(root);
    if protected.covers_key(&root_key) {
        add(&mut out.kept, KeptReason::Protected, 1, 0);
        return out;
    }
    if meta.is_file() {
        consider_file(root.to_path_buf(), &meta, rule, now, &mut out);
        return out;
    }
    if !meta.is_dir() || is_link(&meta) {
        return out;
    }
    // Folders are listed after their contents, deepest last in the list, so
    // reversing it later removes children before their parents.
    let mut stack = vec![(root.to_path_buf(), root_key)];
    let mut dirs = Vec::new();
    while let Some((dir, key)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                add(&mut out.kept, KeptReason::Unreadable, 1, 0);
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let child = protect::child_key(&key, &entry.file_name());
            if protected.covers_key(&child) {
                add(&mut out.kept, KeptReason::Protected, 1, 0);
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if is_link(&meta) {
                continue;
            }
            if meta.is_dir() {
                if old_enough(&meta, rule, now) {
                    dirs.push(path.clone());
                }
                stack.push((path, child));
            } else {
                consider_file(path, &meta, rule, now, &mut out);
            }
        }
    }
    for dir in dirs {
        out.candidates.push(Candidate {
            path: dir,
            bytes: 0,
            dir: true,
        });
    }
    out
}

fn consider_file(path: PathBuf, meta: &fs::Metadata, rule: &Rule, now: SystemTime, out: &mut Walk) {
    if !extension_fits(&path, rule) {
        return;
    }
    let bytes = meta.len();
    if !old_enough(meta, rule, now) {
        add(&mut out.kept, KeptReason::Recent(days(rule)), 1, bytes);
        return;
    }
    if rule.probe_in_use {
        match probe(&path) {
            Probe::Free => {}
            Probe::InUse => {
                add(&mut out.kept, KeptReason::InUse, 1, bytes);
                return;
            }
            Probe::Denied => {
                add(&mut out.kept, KeptReason::AccessDenied, 1, bytes);
                return;
            }
        }
    }
    out.candidates.push(Candidate {
        path,
        bytes,
        dir: false,
    });
}

/// A symbolic link, a junction or another reparse point. Never followed,
/// never deleted.
fn is_link(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Delete the candidates of a walk. Files go first; a folder goes only when
/// it is empty afterwards.
pub fn delete(
    candidates: &[Candidate],
    rule: &Rule,
    protected: &Protected,
    now: SystemTime,
) -> Deleted {
    let mut out = Deleted::default();
    for c in candidates.iter().filter(|c| !c.dir) {
        if protected.covers(&c.path) {
            add(&mut out.kept, KeptReason::Protected, 1, c.bytes);
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&c.path) else {
            // Gone since the analysis: nothing to free, nothing to report.
            continue;
        };
        if is_link(&meta) || !meta.is_file() {
            continue;
        }
        let bytes = meta.len();
        if !old_enough(&meta, rule, now) {
            add(&mut out.kept, KeptReason::Recent(days(rule)), 1, bytes);
            continue;
        }
        match delete_file(&c.path, &meta) {
            Ok(()) => {
                out.freed += bytes;
                out.files += 1;
            }
            Err(e) => {
                let reason = match classify(&e) {
                    Probe::InUse => KeptReason::InUse,
                    _ => KeptReason::AccessDenied,
                };
                add(&mut out.kept, reason, 1, bytes);
            }
        }
    }
    for c in candidates.iter().filter(|c| c.dir).rev() {
        if protected.touches(&c.path) {
            continue;
        }
        // Only an empty folder goes, and never through a link.
        if let Ok(meta) = fs::symlink_metadata(&c.path) {
            if meta.is_dir() && !is_link(&meta) {
                let _ = fs::remove_dir(&c.path);
            }
        }
    }
    out
}

/// Delete one file. A read-only one has the flag taken off first, as
/// Windows' own cleanup does.
fn delete_file(path: &Path, meta: &fs::Metadata) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if meta.permissions().readonly() => {
            let mut perms = meta.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            if fs::set_permissions(path, perms).is_err() {
                return Err(e);
            }
            fs::remove_file(path)
        }
        Err(e) => Err(e),
    }
}

/// Count `count` items and `bytes` under `reason`.
pub(super) fn add(kept: &mut Vec<Kept>, reason: KeptReason, count: usize, bytes: u64) {
    match kept.iter_mut().find(|k| k.reason == reason) {
        Some(k) => {
            k.count += count;
            k.bytes += bytes;
        }
        None => kept.push(Kept {
            reason,
            count,
            bytes,
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs::FileTimes;

    /// A fresh folder under the temp folder for one test.
    pub fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("oxidize_clean_{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    /// Write a file of `len` bytes last changed `days` ago.
    pub fn file_aged(path: &Path, len: usize, days: u64) {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(path, vec![b'x'; len]).unwrap();
        age(path, days);
    }

    /// Set the write and creation time of a file or folder to `days` ago.
    pub fn age(path: &Path, days: u64) {
        use std::os::windows::fs::{FileTimesExt, OpenOptionsExt};
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let t = SystemTime::now() - Duration::from_secs(days * 86_400);
        let f = fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        f.set_times(FileTimes::new().set_modified(t).set_created(t))
            .unwrap();
    }

    fn week() -> Rule {
        Rule {
            min_age: Some(Duration::from_secs(7 * 86_400)),
            extensions: None,
            probe_in_use: true,
        }
    }

    fn kept(walk: &[Kept], reason: KeptReason) -> (usize, u64) {
        walk.iter()
            .find(|k| k.reason == reason)
            .map(|k| (k.count, k.bytes))
            .unwrap_or((0, 0))
    }

    #[test]
    fn only_files_unchanged_for_a_week_qualify() {
        let root = fixture("age");
        file_aged(&root.join("old.tmp"), 100, 8);
        file_aged(&root.join("new.tmp"), 7, 2);
        file_aged(&root.join("sub").join("old.log"), 50, 30);
        age(&root.join("sub"), 30);
        let walk = walk(&root, &week(), &Protected::default(), SystemTime::now());
        assert_eq!(walk.files(), 2);
        assert_eq!(walk.bytes(), 150);
        assert_eq!(kept(&walk.kept, KeptReason::Recent(7)), (1, 7));

        let done = delete(
            &walk.candidates,
            &week(),
            &Protected::default(),
            SystemTime::now(),
        );
        assert_eq!((done.files, done.freed), (2, 150));
        assert!(root.join("new.tmp").exists());
        assert!(!root.join("old.tmp").exists());
        // The folder was emptied and is old, so it went too.
        assert!(!root.join("sub").exists());
        // The root folder itself always stays.
        assert!(root.is_dir());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_written_since_the_analysis_stays() {
        let root = fixture("rewritten");
        file_aged(&root.join("a.tmp"), 10, 10);
        let walk = walk(&root, &week(), &Protected::default(), SystemTime::now());
        assert_eq!(walk.files(), 1);
        fs::write(root.join("a.tmp"), "now").unwrap();
        let done = delete(
            &walk.candidates,
            &week(),
            &Protected::default(),
            SystemTime::now(),
        );
        assert_eq!(done.files, 0);
        assert_eq!(kept(&done.kept, KeptReason::Recent(7)).0, 1);
        assert!(root.join("a.tmp").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_another_program_holds_open_is_reported_and_kept() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = fixture("locked");
        file_aged(&root.join("held.tmp"), 40, 9);
        file_aged(&root.join("free.tmp"), 2, 9);
        // Read sharing only, the way a program keeps its log open.
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(root.join("held.tmp"))
            .unwrap();
        let w = walk(&root, &week(), &Protected::default(), SystemTime::now());
        assert_eq!(kept(&w.kept, KeptReason::InUse), (1, 40));
        assert_eq!(w.files(), 1);

        // Opened only after the analysis: the deletion reports it the same.
        let all = Rule {
            probe_in_use: false,
            ..week()
        };
        let w = walk(&root, &all, &Protected::default(), SystemTime::now());
        assert_eq!(w.files(), 2);
        let done = delete(
            &w.candidates,
            &all,
            &Protected::default(),
            SystemTime::now(),
        );
        assert_eq!(done.files, 1);
        assert_eq!(kept(&done.kept, KeptReason::InUse), (1, 40));
        assert!(root.join("held.tmp").exists());
        drop(held);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn protected_folders_and_files_are_not_entered_or_deleted() {
        let root = fixture("protected");
        file_aged(&root.join("tools").join("script.py"), 10, 40);
        age(&root.join("tools"), 40);
        file_aged(&root.join("notes.md"), 10, 40);
        file_aged(&root.join("junk.tmp"), 10, 40);
        let protected = Protected::new([
            root.join("tools").display().to_string(),
            root.join("NOTES.MD").display().to_string(),
        ]);
        let w = walk(&root, &week(), &protected, SystemTime::now());
        assert_eq!(w.files(), 1);
        assert_eq!(kept(&w.kept, KeptReason::Protected).0, 2);
        assert!(w
            .candidates
            .iter()
            .all(|c| !c.path.starts_with(root.join("tools"))));

        // A list made before the folder was protected is checked again.
        let unprotected = walk(&root, &week(), &Protected::default(), SystemTime::now());
        let done = delete(
            &unprotected.candidates,
            &week(),
            &protected,
            SystemTime::now(),
        );
        assert_eq!(done.files, 1);
        assert!(root.join("tools").join("script.py").exists());
        assert!(root.join("notes.md").exists());
        assert!(!root.join("junk.tmp").exists());

        // A protected root is not walked at all.
        let whole = Protected::new([root.display().to_string()]);
        assert!(walk(&root, &week(), &whole, SystemTime::now())
            .candidates
            .is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_extension_rule_takes_only_those_files() {
        let root = fixture("ext");
        file_aged(&root.join("app.dmp"), 30, 0);
        file_aged(&root.join("APP2.DMP"), 20, 0);
        file_aged(&root.join("readme.txt"), 5, 0);
        let rule = Rule {
            min_age: None,
            extensions: Some(&["dmp"]),
            probe_in_use: true,
        };
        let w = walk(&root, &rule, &Protected::default(), SystemTime::now());
        assert_eq!((w.files(), w.bytes()), (2, 50));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_junction_is_neither_followed_nor_deleted() {
        let root = fixture("junction");
        let outside = fixture("junction_target");
        file_aged(&outside.join("keep.txt"), 10, 40);
        let link = root.join("link");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(made.status.success());
        let w = walk(&root, &week(), &Protected::default(), SystemTime::now());
        assert!(w.candidates.is_empty(), "{:?}", w.candidates);
        delete(
            &w.candidates,
            &week(),
            &Protected::default(),
            SystemTime::now(),
        );
        assert!(outside.join("keep.txt").exists());
        let _ = fs::remove_dir(&link);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_read_only_file_is_deleted_too() {
        let root = fixture("readonly");
        let path = root.join("ro.tmp");
        file_aged(&path, 3, 10);
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&path, perms).unwrap();
        let w = walk(&root, &week(), &Protected::default(), SystemTime::now());
        let done = delete(
            &w.candidates,
            &week(),
            &Protected::default(),
            SystemTime::now(),
        );
        assert_eq!(done.files, 1);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&root);
    }
}
