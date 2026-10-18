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

    /// Add one entry. Returns false when it is empty or already listed.
    pub fn add(&mut self, entry: &str) -> bool {
        // A list saved by an editor that writes a byte order mark starts
        // with one, and it would make the first folder a name nothing has.
        let entry = entry.trim_start_matches('\u{feff}');
        let entry = entry.trim().trim_matches('"').trim();
        if entry.is_empty() {
            return false;
        }
        let key = key_of(Path::new(&util::expand_env_vars(entry)));
        if key.len() <= 3 || self.keys.contains(&key) {
            // A drive root would protect everything on it; the list is for
            // folders, so such a line is ignored rather than honoured.
            return false;
        }
        self.entries.push(entry.to_string());
        self.keys.push(key);
        true
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
        self.covers_key(&key_of(path))
    }

    /// `covers` for a path already turned into a key, so a walk through
    /// thousands of files does not ask Windows for each real name.
    pub fn covers_key(&self, key: &str) -> bool {
        self.keys.iter().any(|k| key == k || under(key, k))
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
        for e in &self.entries {
            text.push_str(e);
            text.push('\n');
        }
        text
    }

    /// Read the list from the text of the file.
    pub fn from_file_text(text: &str) -> Self {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        Protected::new(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        )
    }
}

/// `%LOCALAPPDATA%\Oxidize\protected.txt`.
pub fn file_path() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .context("LOCALAPPDATA is not set")?;
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
pub fn key_of(path: &Path) -> String {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
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

/// The key of `name` inside the folder whose key is `parent`.
pub fn child_key(parent: &str, name: &std::ffi::OsStr) -> String {
    let name = name.to_string_lossy().to_lowercase();
    format!("{parent}\\{}", name.trim_end_matches(['.', ' ']))
}

/// Is `p` strictly inside `dir`? Both are keys.
fn under(p: &str, dir: &str) -> bool {
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
    fn the_list_is_saved_and_read_back() {
        let dir = std::env::temp_dir().join("oxidize_protect_save_test");
        let _ = std::fs::remove_dir_all(&dir);
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
        let _ = std::fs::remove_dir_all(&dir);
    }
}
