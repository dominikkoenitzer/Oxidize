//! Folders and files the cleaner never touches, set by the user.
//!
//! The list lives in `%LOCALAPPDATA%\Oxidize\protected.txt`, one path per
//! line. Lines starting with `#` are comments, and `%VAR%` references are
//! expanded when the list is read. A protected path is left alone with all it
//! holds, and a folder that holds one is never removed as a whole.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::util;

/// The file name under `%LOCALAPPDATA%\Oxidize`.
pub const FILE_NAME: &str = "protected.txt";

const HEADER: &str = "\
# Folders and files `oxidize clean` never touches, one per line.
# %VAR% references such as %TEMP% are expanded.
";

/// The protected paths, as written and as compared.
#[derive(Debug, Clone, Default)]
pub struct Protected {
    /// Each entry as the user wrote it.
    entries: Vec<String>,
    /// The same, expanded and normalised for comparing.
    keys: Vec<String>,
    /// Lines of the file that protect nothing: a drive root, or not a full
    /// path. They go back into the file as they were, so a save never
    /// loses what the user wrote.
    idle: Vec<String>,
}

/// Why an entry is not taken onto the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAdded {
    Empty,
    /// Already listed, perhaps written another way.
    Listed,
    /// It would protect everything on the drive.
    DriveRoot,
    /// Not a full path once `%VAR%` references are expanded, so it would
    /// name a different folder for every folder Oxidize runs from.
    NotFullPath,
}

impl Protected {
    pub fn new(entries: impl IntoIterator<Item = String>) -> Self {
        let mut p = Protected::default();
        for e in entries {
            p.add(&e);
        }
        p
    }

    /// The entries as written, in order.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add one entry. Returns false when it is not taken.
    pub fn add(&mut self, entry: &str) -> bool {
        self.try_add(entry).is_ok()
    }

    /// Add one entry, or say why it is not taken.
    pub fn try_add(&mut self, entry: &str) -> Result<(), NotAdded> {
        // A list saved by an editor that writes a byte order mark starts
        // with one, and it would make the first folder a name nothing has.
        let entry = entry.trim_start_matches('\u{feff}');
        let entry = entry.trim().trim_matches('"').trim();
        if entry.is_empty() {
            return Err(NotAdded::Empty);
        }
        let path = util::expand_env_vars(entry);
        if !Path::new(&path).is_absolute() {
            return Err(NotAdded::NotFullPath);
        }
        let key = key_of(Path::new(&path));
        if key.len() <= 3 {
            // A drive root would protect everything on it; the list is for
            // folders, so such a line is ignored rather than honoured.
            return Err(NotAdded::DriveRoot);
        }
        if self.keys.contains(&key) {
            return Err(NotAdded::Listed);
        }
        self.entries.push(entry.to_string());
        self.keys.push(key);
        Ok(())
    }

    /// Remove an entry as written. Returns false when it was not listed.
    pub fn remove(&mut self, entry: &str) -> bool {
        match self.entries.iter().position(|e| e == entry) {
            Some(i) => {
                self.entries.remove(i);
                self.keys.remove(i);
                true
            }
            None => false,
        }
    }

    /// Is `path` protected, or inside something protected?
    pub fn covers(&self, path: &Path) -> bool {
        // Nothing listed covers nothing, and asking Windows for the real
        // name of every file costs more than the delete.
        !self.keys.is_empty() && self.covers_key(&key_of(path))
    }

    /// `covers` for a path already turned into a key, so a walk through
    /// thousands of files does not ask Windows for each real name.
    pub fn covers_key(&self, key: &str) -> bool {
        self.keys.iter().any(|k| key == k || under(key, k))
    }

    /// The entry, as written, that covers `path`: the path itself or the
    /// nearest protected folder it is in. None when nothing listed covers it.
    pub fn covered_by(&self, path: &Path) -> Option<&str> {
        let p = key_of(path);
        self.keys
            .iter()
            .zip(&self.entries)
            .filter(|(k, _)| p == **k || under(&p, k))
            .max_by_key(|(k, _)| k.len())
            .map(|(_, e)| e.as_str())
    }

    /// The entries, as written, that lie inside `path`. The rest of such a
    /// folder is cleaned, but it is never removed as a whole.
    pub fn inside(&self, path: &Path) -> Vec<&str> {
        let p = key_of(path);
        self.keys
            .iter()
            .zip(&self.entries)
            .filter(|(k, _)| under(k, &p))
            .map(|(_, e)| e.as_str())
            .collect()
    }

    /// Does `path` hold something protected, itself included? Such a folder
    /// is never removed as a whole.
    pub fn touches(&self, path: &Path) -> bool {
        let p = key_of(path);
        self.keys
            .iter()
            .any(|k| p == *k || under(&p, k) || under(k, &p))
    }

    /// The list as the file stores it.
    pub fn to_file_text(&self) -> String {
        let mut text = HEADER.to_string();
        for e in self.entries.iter().chain(&self.idle) {
            text.push_str(e);
            text.push('\n');
        }
        text
    }

    /// Read the list from the text of the file.
    pub fn from_file_text(text: &str) -> Self {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut p = Protected::default();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if let Err(NotAdded::DriveRoot | NotAdded::NotFullPath) = p.try_add(line) {
                p.idle.push(line.to_string());
            }
        }
        p
    }
}

/// `%LOCALAPPDATA%\Oxidize\protected.txt`.
pub fn file_path() -> Result<PathBuf> {
    let local = crate::scanner::env_dir("LOCALAPPDATA")
        .context("LOCALAPPDATA is not set to a full path")?;
    Ok(local.join("Oxidize").join(FILE_NAME))
}

/// The user's list. A missing file is an empty list.
pub fn load() -> Result<Protected> {
    load_from(&file_path()?)
}

pub fn load_from(path: &Path) -> Result<Protected> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Protected::from_file_text(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Protected::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write the user's list.
pub fn save(list: &Protected) -> Result<()> {
    save_to(list, &file_path()?)
}

pub fn save_to(list: &Protected, path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Written beside the file and renamed over it, so a crash never leaves
    // half a list, which would leave the rest unprotected.
    let tmp = path.with_extension("txt.new");
    std::fs::write(&tmp, list.to_file_text())
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// A path the way it is compared: the real name where it exists, lower
/// case, backslashes, no `\\?\` prefix, and no trailing separators, dots or
/// spaces, which Windows ignores.
///
/// A path that does not exist (yet, or any more) takes the real name of the
/// deepest folder of it that does: the Recycle Bin remembers where a file
/// was, and a protected folder reached through a junction has to cover it
/// by either name.
pub fn key_of(path: &Path) -> String {
    let real = real_name(path);
    let s = real.to_string_lossy().to_lowercase().replace('/', "\\");
    let s = s
        .strip_prefix("\\\\?\\unc\\")
        .map(|rest| format!("\\\\{rest}"))
        .unwrap_or_else(|| s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string());
    s.split('\\')
        .map(|part| part.trim_end_matches(['.', ' ']))
        .collect::<Vec<_>>()
        .join("\\")
        .trim_end_matches('\\')
        .to_string()
}

/// `path` with the real name of its deepest existing part, and the rest
/// as written.
fn real_name(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    let mut at = path;
    while let Some(parent) = at.parent() {
        match at.file_name() {
            Some(name) => rest.push(name),
            None => break,
        }
        if let Ok(real) = std::fs::canonicalize(parent) {
            return rest.iter().rev().fold(real, |p, part| p.join(part));
        }
        at = parent;
    }
    path.to_path_buf()
}

/// The key of `name` inside the folder whose key is `parent`.
pub fn child_key(parent: &str, name: &std::ffi::OsStr) -> String {
    let name = name.to_string_lossy().to_lowercase();
    format!("{parent}\\{}", name.trim_end_matches(['.', ' ']))
}

/// Is `p` strictly inside `dir`? Both are keys.
pub(crate) fn under(p: &str, dir: &str) -> bool {
    p.len() > dir.len() && p.starts_with(dir) && p.as_bytes()[dir.len()] == b'\\'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_protected_folder_covers_what_it_holds_and_nothing_beside_it() {
        let p = Protected::new([r"C:\Work\Keep".to_string()]);
        assert!(p.covers(Path::new(r"C:\Work\Keep")));
        assert!(p.covers(Path::new(r"c:/work/keep/inner/file.txt")));
        assert!(p.covers(Path::new(r"C:\Work\Keep\")));
        assert!(p.covers(Path::new(r"C:\Work\Keep.")));
        assert!(!p.covers(Path::new(r"C:\Work\Keeper")));
        assert!(!p.covers(Path::new(r"C:\Work")));
        // The folder above holds it, so it is never removed whole.
        assert!(p.touches(Path::new(r"C:\Work")));
        assert!(!p.touches(Path::new(r"C:\Other")));
    }

    #[test]
    fn a_check_names_the_entry_that_covers_a_path_and_no_look_alike() {
        // A folder is not protected because others that start like it are.
        let p = Protected::new([
            r"C:\T\wt-tools".to_string(),
            r"C:\T\wt.old".to_string(),
            r"C:\T\pw".to_string(),
            r"C:\T\pw\cache".to_string(),
        ]);
        assert_eq!(p.covered_by(Path::new(r"C:\T\wt")), None);
        assert_eq!(p.covered_by(Path::new(r"C:\T\wt\repo\node_modules")), None);
        assert_eq!(p.covered_by(Path::new(r"C:\T\pwx")), None);
        assert_eq!(
            p.covered_by(Path::new(r"c:/t/WT-tools/a")),
            Some(r"C:\T\wt-tools")
        );
        // The nearest folder answers, not the first one listed.
        assert_eq!(
            p.covered_by(Path::new(r"C:\T\pw\cache\x")),
            Some(r"C:\T\pw\cache")
        );
        assert_eq!(
            p.covered_by(Path::new(r"C:\T\pw\launch.mjs")),
            Some(r"C:\T\pw")
        );
        assert_eq!(p.inside(Path::new(r"C:\T")).len(), 4);
        assert_eq!(p.inside(Path::new(r"C:\T\pw")), [r"C:\T\pw\cache"]);
        assert!(p.inside(Path::new(r"C:\T\wt")).is_empty());
        assert!(Protected::default()
            .covered_by(Path::new(r"C:\T"))
            .is_none());
    }

    #[test]
    fn the_file_keeps_comments_out_and_expands_variables() {
        std::env::set_var("OXIDIZE_PROTECT_TEST", r"C:\Data");
        let p = Protected::from_file_text(
            "# comment\n\n%OXIDIZE_PROTECT_TEST%\\tools\n  \"C:\\Quoted Folder\"  \nC:\\\nC:\\Data\\tools\n",
        );
        assert_eq!(
            p.entries(),
            [r"%OXIDIZE_PROTECT_TEST%\tools", r"C:\Quoted Folder"]
        );
        assert!(p.covers(Path::new(r"C:\Data\tools\a")));
        assert!(p.covers(Path::new(r"C:\quoted folder")));
        // A drive root is not a folder to protect and would cover everything.
        assert!(!p.covers(Path::new(r"C:\Else")));
        let back = Protected::from_file_text(&p.to_file_text());
        assert_eq!(back.entries(), p.entries());
    }

    #[test]
    fn an_entry_that_is_not_a_full_path_protects_nothing() {
        let mut p = Protected::default();
        for entry in [
            r"Work\Keep",
            r"%OXIDIZE_PROTECT_NEVER_SET%\Keep",
            r"\Work\Keep",
            r"C:Work\Keep",
        ] {
            assert_eq!(p.try_add(entry), Err(NotAdded::NotFullPath), "{entry}");
        }
        assert!(p.is_empty());
        assert_eq!(p.try_add(r"C:\"), Err(NotAdded::DriveRoot));
        assert_eq!(p.try_add(r"C:\Work\Keep"), Ok(()));
        assert_eq!(p.try_add(r"c:\work\keep\"), Err(NotAdded::Listed));
        assert_eq!(p.try_add(" \"\" "), Err(NotAdded::Empty));
    }

    #[test]
    fn a_line_that_protects_nothing_is_kept_when_the_list_is_saved() {
        let mut p = Protected::from_file_text(
            "C:\\Keep\nWork\\Keep\n%OXIDIZE_PROTECT_NEVER_SET%\\Docs\nC:\\\n",
        );
        assert_eq!(p.entries(), [r"C:\Keep"]);
        let here = std::env::current_dir().unwrap();
        assert!(!p.covers(&here.join(r"Work\Keep\a.txt")));
        assert!(p.add(r"C:\Also"));
        assert!(p.remove(r"C:\Keep"));
        let saved = p.to_file_text();
        let lines: Vec<&str> = saved.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            lines,
            [
                r"C:\Also",
                r"Work\Keep",
                r"%OXIDIZE_PROTECT_NEVER_SET%\Docs",
                r"C:\"
            ]
        );
        assert_eq!(Protected::from_file_text(&saved).to_file_text(), saved);
    }

    #[test]
    fn a_list_saved_with_a_byte_order_mark_protects_its_first_folder() {
        let p = Protected::from_file_text("\u{feff}C:\\Keep\r\nC:\\Also\r\n");
        assert_eq!(p.entries(), [r"C:\Keep", r"C:\Also"]);
        assert!(p.covers(Path::new(r"C:\Keep\a.txt")));
        assert!(p.covers(Path::new(r"C:\Also\b.txt")));
        // A comment right after the mark stays a comment.
        let p = Protected::from_file_text("\u{feff}# mine\nC:\\Keep\n");
        assert_eq!(p.entries(), [r"C:\Keep"]);
    }

    #[test]
    fn a_path_that_is_gone_is_covered_by_the_real_name_of_its_folder() {
        let dir = crate::backup::TestDir::new("oxidize_protect_junction_test");
        let real = dir.join("real");
        std::fs::create_dir_all(real.join("keep")).unwrap();
        let link = dir.join("link");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .unwrap();
        assert!(made.status.success());
        // Protected by the junction's name, asked about by the real one,
        // for a file that is no longer there; and the other way round.
        let by_link = Protected::new([link.join("keep").display().to_string()]);
        assert!(by_link.covers(&real.join("keep").join("gone.txt")));
        assert!(by_link.covers(&real.join("keep").join("gone").join("deeper.txt")));
        let by_real = Protected::new([real.join("keep").display().to_string()]);
        assert!(by_real.covers(&link.join("keep").join("gone.txt")));
        assert!(!by_real.covers(&link.join("other.txt")));
    }

    #[test]
    fn the_list_is_saved_and_read_back() {
        let dir = crate::backup::TestDir::new("oxidize_protect_save_test");
        let file = dir.join("Oxidize").join(FILE_NAME);
        assert!(load_from(&file).unwrap().is_empty());
        let mut p = Protected::default();
        assert!(p.add(r"C:\One"));
        assert!(!p.add(r"c:\one\"));
        assert!(p.add(r"C:\Two"));
        assert!(p.remove(r"C:\One"));
        assert!(!p.remove(r"C:\One"));
        save_to(&p, &file).unwrap();
        assert_eq!(load_from(&file).unwrap().entries(), [r"C:\Two"]);
    }
}
