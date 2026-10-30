//! Stale build output: folders a build or package tool marked as a cache
//! with a `CACHEDIR.TAG` file, outside the temp folders, with nothing in
//! them changed for `BUILD_DAYS` days. The tool makes them again when it
//! needs them. One inside a git checkout goes only while git says the
//! checkout holds no uncommitted work.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

use super::files;
use super::protect::{self, Protected};
use super::windows::Tools;
use super::KeptReason;

/// Nothing in a stale build folder changed for this many days.
pub const BUILD_DAYS: u64 = 30;

/// How many folders deep below a root the search looks.
const DEPTH: usize = 6;

const TAG: &str = "CACHEDIR.TAG";

/// What a cache directory tag starts with, as the Cache Directory Tagging
/// convention has it.
const SIGNATURE: &[u8; 43] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// A build folder that would go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildFolder {
    pub path: PathBuf,
    pub bytes: u64,
    /// Whole days since anything in it changed.
    pub unchanged_days: u64,
    /// The git checkout it lies in, which held no uncommitted work.
    pub checkout: Option<PathBuf>,
}

/// Does `dir` hold a real cache directory tag? A tag that is a link, or
/// does not start with the signature, does not count.
pub fn is_tagged(dir: &Path) -> bool {
    let tag = dir.join(TAG);
    let Ok(meta) = fs::symlink_metadata(&tag) else {
        return false;
    };
    if !meta.is_file() || files::is_link(&meta) {
        return false;
    }
    let mut head = [0u8; 43];
    fs::File::open(&tag)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && &head == SIGNATURE
}

/// The tagged folders under `roots`, at most `DEPTH` folders down. Links
/// are never followed, `.git` folders and protected ones never entered,
/// and nothing in or under `skip` is looked at. A tagged folder is not
/// searched further.
pub fn find(roots: &[PathBuf], skip: &[PathBuf], protected: &Protected) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let skip: Vec<String> = skip.iter().map(|s| protect::key_of(s)).collect();
    for root in roots {
        let mut stack = vec![(root.clone(), protect::key_of(root), 0usize)];
        while let Some((dir, key, depth)) = stack.pop() {
            if skip.iter().any(|s| key == *s || protect::under(&key, s)) {
                continue;
            }
            if is_tagged(&dir) {
                out.push(dir);
                continue;
            }
            if depth == DEPTH || protected.covers_key(&key) {
                continue;
            }
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.eq_ignore_ascii_case(".git") {
                    continue;
                }
                let path = entry.path();
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_dir() && !files::is_link(&meta) {
                    let child = protect::child_key(&key, &name);
                    stack.push((path, child, depth + 1));
                }
            }
        }
    }
    out.sort();
    out
}

/// Bytes, and the latest change of anything in a folder, the folder
/// itself included.
struct Contents {
    bytes: u64,
    newest: SystemTime,
    repository: bool,
}

/// What `dir` holds. None when any of it cannot be read.
fn contents(dir: &Path) -> Option<Contents> {
    let meta = fs::symlink_metadata(dir).ok()?;
    let mut out = Contents {
        bytes: 0,
        newest: files::last_change(&meta)?,
        repository: false,
    };
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).ok()? {
            let path = entry.ok()?.path();
            let meta = fs::symlink_metadata(&path).ok()?;
            if files::is_link(&meta) {
                continue;
            }
            out.newest = out.newest.max(files::last_change(&meta)?);
            if meta.is_dir() {
                out.repository |= files::is_repository(&path);
                stack.push(path);
            } else {
                out.bytes += meta.len();
            }
        }
    }
    Some(out)
}

/// Where a build folder was found and what it is checked with.
pub struct Check<'a> {
    pub now: SystemTime,
    pub protected: &'a Protected,
    /// Running with administrator rights: git is not run then, since a
    /// checkout's own settings can make it start other programs.
    pub elevated: bool,
    pub tools: &'a dyn Tools,
    /// Each checkout's answer, asked once.
    pub checkouts: HashMap<PathBuf, Option<bool>>,
}

/// May the tagged folder `dir` go? Asked by the analysis and again right
/// before it goes. When it stays, says why, with its bytes where they are
/// known.
pub fn assess(dir: &Path, check: &mut Check) -> Result<BuildFolder, (KeptReason, u64)> {
    if check.protected.touches(dir) {
        return Err((KeptReason::Protected, 0));
    }
    let meta = fs::symlink_metadata(dir).map_err(|_| (KeptReason::Unreadable, 0))?;
    if !meta.is_dir() || files::is_link(&meta) || !is_tagged(dir) {
        return Err((
            KeptReason::Failed("no longer marked as a cache".to_string()),
            0,
        ));
    }
    let c = contents(dir).ok_or((KeptReason::Unreadable, 0))?;
    if c.repository || files::is_repository(dir) {
        return Err((KeptReason::Repository, c.bytes));
    }
    let age = check.now.duration_since(c.newest).unwrap_or_default();
    if age < super::days_ago(BUILD_DAYS) {
        return Err((KeptReason::Recent(BUILD_DAYS), c.bytes));
    }
    let checkout = files::repository_above(dir, &mut HashMap::new());
    if let Some(repo) = &checkout {
        let tools = check.tools;
        let elevated = check.elevated;
        let dirty = *check
            .checkouts
            .entry(repo.clone())
            .or_insert_with(|| (!elevated).then(|| tools.uncommitted(repo)).flatten());
        match dirty {
            Some(false) => {}
            Some(true) => return Err((KeptReason::Uncommitted, c.bytes)),
            None => return Err((KeptReason::CheckoutUnknown, c.bytes)),
        }
    }
    Ok(BuildFolder {
        path: dir.to_path_buf(),
        bytes: c.bytes,
        unchanged_days: age.as_secs() / super::DAY,
        checkout,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::files::tests::{age, file_aged, fixture};
    use super::*;

    /// A build folder at `dir`: a tag and `bytes` of output, everything in it
    /// last changed `days` ago. Says how many bytes it holds.
    pub fn cache(dir: &Path, bytes: usize, days: u64) -> u64 {
        let mut tag = SIGNATURE.to_vec();
        tag.extend_from_slice(b"\n# made by a build tool\n");
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(TAG), &tag).unwrap();
        file_aged(&dir.join(r"debug\deps\out.bin"), bytes, days);
        age_tree(dir, days);
        (bytes + tag.len()) as u64
    }

    /// Set every file and folder under `dir`, `dir` too, to `days` ago.
    pub fn age_tree(dir: &Path, days: u64) {
        for e in fs::read_dir(dir).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                age_tree(&e.path(), days);
            } else {
                age(&e.path(), days);
            }
        }
        age(dir, days);
    }

    #[test]
    fn only_a_tag_with_the_signature_counts() {
        let root = fixture("build_tag");
        cache(&root.join("real"), 10, 60);
        fs::create_dir_all(root.join("wrong")).unwrap();
        fs::write(root.join(r"wrong\CACHEDIR.TAG"), "a note about caches").unwrap();
        fs::create_dir_all(root.join("short")).unwrap();
        fs::write(root.join(r"short\CACHEDIR.TAG"), &SIGNATURE[..20]).unwrap();
        fs::create_dir_all(root.join(r"folder\CACHEDIR.TAG")).unwrap();
        assert!(is_tagged(&root.join("real")));
        for name in ["wrong", "short", "folder", "missing"] {
            assert!(!is_tagged(&root.join(name)), "{name}");
        }
    }

    #[test]
    fn the_search_stops_at_a_tag_and_never_enters_skipped_folders() {
        let root = fixture("build_find");
        let target = root.join(r"code\app\target");
        cache(&target, 10, 60);
        cache(&target.join("inner"), 10, 60);
        cache(&root.join(r"Temp\build\target"), 10, 60);
        cache(&root.join(r"code\lib\.git\target"), 10, 60);
        cache(&root.join(r"Kept\target"), 10, 60);
        let protected = Protected::new([root.join("Kept").display().to_string()]);
        let found = find(&[root.to_path_buf()], &[root.join("Temp")], &protected);
        assert_eq!(found, [target]);
    }

    #[test]
    fn the_search_goes_six_folders_deep() {
        let root = fixture("build_depth");
        let deep = root.join(r"1\2\3\4\5\target");
        let deeper = root.join(r"a\b\c\d\e\f\target");
        cache(&deep, 10, 60);
        cache(&deeper, 10, 60);
        let found = find(&[root.to_path_buf()], &[], &Protected::default());
        assert_eq!(found, [deep]);
    }
}
