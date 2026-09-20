//! Reversible removal. Each removal run gets a folder under
//! `%LOCALAPPDATA%\Oxidize\backups\<timestamp> <program>` with:
//!
//! * `registry\*.reg`: keys exported with `reg.exe export` and validated
//!   before the delete is allowed;
//! * `files\<Drive>\<original path>`: quarantined files and folders, moved
//!   there rather than deleted;
//! * `tasks\*.xml`: scheduled task definitions;
//! * `manifest.json`: what was removed and how to put it back, which is what
//!   `oxidize restore` reads.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Hive, LeftoverKind};
use crate::system::{self, TaskInfo};

pub const MANIFEST: &str = "manifest.json";

/// How to undo one removal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Undo {
    /// `reg import` the file.
    RegImport { file: PathBuf },
    /// Move a quarantined path back to where it was.
    MoveBack { from: PathBuf, to: PathBuf },
    /// Re-create a task from its XML.
    TaskImport { name: String, file: PathBuf },
    /// Put an entry back on the `Path` variable, where it was.
    PathAdd {
        hive: Hive,
        entry: String,
        #[serde(default)]
        index: Option<usize>,
    },
    /// Write a string value back with the type it had. An expandable value
    /// written back as a plain string stops expanding `%VAR%`.
    ValueWrite {
        hive: Hive,
        subpath: String,
        name: String,
        data: String,
        #[serde(default = "reg_sz")]
        vtype: u32,
    },
    /// Write a value back with its original type and bytes.
    RawValueWrite {
        hive: Hive,
        subpath: String,
        name: String,
        vtype: u32,
        bytes: Vec<u8>,
    },
}

/// Manifests that predate the type field only ever held `REG_SZ`.
fn reg_sz() -> u32 {
    winreg::enums::RegType::REG_SZ as u32
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub kind: LeftoverKind,
    /// The display path shown at removal time.
    pub path: String,
    pub undo: Undo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub program: String,
    pub created: String,
    pub entries: Vec<ManifestEntry>,
}

pub struct BackupSession {
    root: PathBuf,
    manifest: Manifest,
}

impl BackupSession {
    pub fn new(program_label: &str) -> Result<BackupSession> {
        let base = backups_base()?;
        let now = chrono::Local::now();
        let stem = format!(
            "{} {}",
            now.format("%Y-%m-%d %H%M%S"),
            sanitize(program_label)
        );
        // The stamp is only accurate to the second, and two removals of the
        // same program can fall inside one. Sharing a folder would overwrite
        // the first manifest and strand what it holds.
        let mut root = base.join(&stem);
        let mut n = 2;
        while root.exists() {
            root = base.join(format!("{stem} ({n})"));
            n += 1;
        }
        fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
        Ok(BackupSession {
            root,
            manifest: Manifest {
                program: program_label.to_string(),
                created: now.to_rfc3339(),
                entries: Vec::new(),
            },
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The backup's name as shown by `oxidize backups`.
    pub fn name(&self) -> String {
        self.root
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    fn record(&mut self, kind: LeftoverKind, path: &str, undo: Undo) -> Result<()> {
        self.manifest.entries.push(ManifestEntry {
            kind,
            path: path.to_string(),
            undo,
        });
        let json = serde_json::to_string_pretty(&self.manifest)?;
        // Written beside the real file and renamed over it: a manifest half
        // written by a crash would take every earlier entry down with it.
        let tmp = self.root.join("manifest.json.new");
        fs::write(&tmp, json).context("writing manifest")?;
        fs::rename(&tmp, self.root.join(MANIFEST)).context("replacing manifest")?;
        Ok(())
    }

    /// Export a key (with its subtree) to a validated `.reg` file. For a
    /// value-level leftover pass the containing key.
    pub fn backup_registry_key(
        &mut self,
        kind: LeftoverKind,
        display: &str,
        hive: Hive,
        subpath: &str,
    ) -> Result<PathBuf> {
        let dir = self.root.join("registry");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

        let key = format!("{}\\{}", hive.short_name(), subpath);
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let out_file = dir.join(format!("{}_{:016x}.reg", sanitize(&key), hasher.finish()));
        if out_file.exists() {
            // Same key backed up twice in one run (a key and one of its
            // values, say): the first export already covers it.
            return Ok(out_file);
        }

        // Anything left behind by a failed export would be taken for a good
        // backup by the shortcut above on the next call.
        if let Err(e) = export_registry_key(hive, subpath, &out_file)
            .and_then(|()| validate_reg_file(&out_file, hive, subpath))
        {
            let _ = fs::remove_file(&out_file);
            return Err(e).with_context(|| format!("backing up {} to {}", key, out_file.display()));
        }
        self.record(
            kind,
            display,
            Undo::RegImport {
                file: out_file.clone(),
            },
        )?;
        Ok(out_file)
    }

    /// Record one value with its type. Text stays readable in the manifest,
    /// anything else keeps its raw bytes.
    pub fn backup_value(
        &mut self,
        kind: LeftoverKind,
        display: &str,
        hive: Hive,
        subpath: &str,
        name: &str,
        value: &winreg::RegValue,
    ) -> Result<()> {
        let vtype = value.vtype.clone() as u32;
        let undo = match crate::registry::as_text(value) {
            Some(data) => Undo::ValueWrite {
                hive,
                subpath: subpath.to_string(),
                name: name.to_string(),
                data,
                vtype,
            },
            None => Undo::RawValueWrite {
                hive,
                subpath: subpath.to_string(),
                name: name.to_string(),
                vtype,
                bytes: value.bytes.to_vec(),
            },
        };
        self.record(kind, display, undo)
    }

    pub fn backup_path_entry(
        &mut self,
        display: &str,
        hive: Hive,
        entry: &str,
        index: usize,
    ) -> Result<()> {
        self.record(
            LeftoverKind::PathEntry,
            display,
            Undo::PathAdd {
                hive,
                entry: entry.to_string(),
                index: Some(index),
            },
        )
    }

    pub fn backup_task(&mut self, display: &str, task: &TaskInfo) -> Result<()> {
        let dir = self.root.join("tasks");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut hasher = DefaultHasher::new();
        task.name.hash(&mut hasher);
        let out = dir.join(format!(
            "{}_{:016x}.xml",
            sanitize(task.name.trim_start_matches('\\')),
            hasher.finish()
        ));
        system::export_task(task, &out)?;
        self.record(
            LeftoverKind::ScheduledTask,
            display,
            Undo::TaskImport {
                name: task.name.clone(),
                file: out,
            },
        )
    }

    /// Move a file or folder into quarantine, keeping its path layout.
    pub fn quarantine(&mut self, kind: LeftoverKind, original: &Path) -> Result<PathBuf> {
        let dest = self.quarantine_dest(original);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }

        move_path(original, &dest)?;
        // Without its manifest entry the item is gone as far as restore is
        // concerned, so a failure here has to put it back where it was.
        if let Err(e) = self.record(
            kind,
            &original.display().to_string(),
            Undo::MoveBack {
                from: dest.clone(),
                to: original.to_path_buf(),
            },
        ) {
            let _ = move_path(&dest, original);
            return Err(e);
        }
        Ok(dest)
    }

    /// `C:\ProgramData\Foo` becomes `<backup>\files\C\ProgramData\Foo`.
    fn quarantine_dest(&self, original: &Path) -> PathBuf {
        let mut dest = self.root.join("files");
        let s = original.to_string_lossy();
        let rel = if s.len() >= 2 && s.as_bytes()[1] == b':' {
            dest.push(&s[0..1]);
            s[2..].trim_start_matches(['\\', '/']).to_string()
        } else {
            s.trim_start_matches(['\\', '/']).to_string()
        };
        dest.push(rel);
        dest
    }
}

/// `%LOCALAPPDATA%\Oxidize\backups`.
pub fn backups_base() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .context("LOCALAPPDATA is not set")?;
    Ok(local.join("Oxidize").join("backups"))
}

/// One existing backup folder.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    pub name: String,
    pub path: PathBuf,
    pub program: String,
    pub created: String,
    pub items: usize,
    pub size_bytes: u64,
}

/// Every backup, newest first.
pub fn list_backups() -> Result<Vec<BackupInfo>> {
    let base = backups_base()?;
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(&base) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let manifest = read_manifest(&path).ok();
        out.push(BackupInfo {
            program: manifest
                .as_ref()
                .map(|m| m.program.clone())
                .unwrap_or_default(),
            created: manifest
                .as_ref()
                .map(|m| m.created.clone())
                .unwrap_or_default(),
            items: manifest.as_ref().map(|m| m.entries.len()).unwrap_or(0),
            size_bytes: crate::scanner::dir_size(&path),
            name,
            path,
        });
    }
    out.sort_by(|a, b| b.name.cmp(&a.name));
    Ok(out)
}

pub fn read_manifest(dir: &Path) -> Result<Manifest> {
    let text = fs::read_to_string(dir.join(MANIFEST))
        .with_context(|| format!("no manifest in {}", dir.display()))?;
    serde_json::from_str(&text).context("reading manifest")
}

/// Resolve a backup by exact name, or by a unique substring of its name or
/// program.
pub fn find_backup(name: &str) -> Result<BackupInfo> {
    let all = list_backups()?;
    if let Some(b) = all.iter().find(|b| b.name.eq_ignore_ascii_case(name)) {
        return Ok(b.clone());
    }
    let needle = name.to_lowercase();
    let hits: Vec<&BackupInfo> = all
        .iter()
        .filter(|b| {
            b.name.to_lowercase().contains(&needle) || b.program.to_lowercase().contains(&needle)
        })
        .collect();
    match hits.len() {
        0 => bail!("no backup matches \"{name}\""),
        1 => Ok(hits[0].clone()),
        n => bail!("\"{name}\" matches {n} backups; use the full name from `oxidize backups`"),
    }
}

pub fn delete_backup(info: &BackupInfo) -> Result<()> {
    let base = backups_base()?;
    if !info.path.starts_with(&base) {
        bail!("refusing to delete outside the backups folder");
    }
    fs::remove_dir_all(&info.path).with_context(|| format!("deleting {}", info.path.display()))
}

/// `reg.exe export <ROOT\subpath> <out_file> /y /reg:64`, with a watchdog
/// because `reg export` occasionally hangs.
fn export_registry_key(hive: Hive, subpath: &str, out_file: &Path) -> Result<()> {
    let key_arg = format!("{}\\{}", hive.short_name(), subpath);
    let mut cmd = Command::new(system::system32("reg.exe"));
    cmd.arg("export")
        .arg(&key_arg)
        .arg(out_file)
        .arg("/y")
        .arg("/reg:64");

    let status = run_with_timeout(cmd, Duration::from_secs(30))
        .with_context(|| format!("running reg export for {key_arg}"))?;
    if !status.success() {
        bail!(
            "reg export of {key_arg} failed ({}); the key may be missing or unreadable",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "terminated".to_string())
        );
    }
    Ok(())
}

/// `reg.exe import <file>`.
pub fn import_registry_file(file: &Path) -> Result<()> {
    let mut cmd = Command::new(system::system32("reg.exe"));
    cmd.arg("import").arg(file).arg("/reg:64");
    let status = run_with_timeout(cmd, Duration::from_secs(60))
        .with_context(|| format!("running reg import for {}", file.display()))?;
    if !status.success() {
        bail!("reg import of {} failed", file.display());
    }
    Ok(())
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<std::process::ExitStatus> {
    let mut child = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawning child process")?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("process timed out after {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A real `.reg` v5 backup of the expected key: UTF-16 LE BOM, the version
/// header, and the `[HKEY_...\subpath]` section.
fn validate_reg_file(path: &Path, hive: Hive, subpath: &str) -> Result<()> {
    let bytes = fs::read(path).context("reading backup file")?;
    if bytes.len() < 2 || bytes[0] != 0xFF || bytes[1] != 0xFE {
        bail!("missing UTF-16 LE byte-order mark");
    }
    let text = system::decode_utf16_or_utf8(&bytes).to_lowercase();
    if !text.contains("windows registry editor version 5.00") {
        bail!("missing 'Windows Registry Editor Version 5.00' header");
    }
    let section = format!("[{}\\{}]", hive.full_name(), subpath).to_lowercase();
    let at_line_start = text
        .match_indices(&section)
        .any(|(i, _)| i == 0 || text.as_bytes()[i - 1] == b'\n');
    if !at_line_start {
        bail!(
            "backup does not contain the section [{}\\{}]",
            hive.full_name(),
            subpath
        );
    }
    Ok(())
}

/// Move a file or folder. `rename` cannot cross volumes, so quarantining
/// something on `D:` falls back to copy then delete, and the copy is rolled
/// back if the original will not go. Restore takes the same route home.
pub fn move_path(from: &Path, to: &Path) -> Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    copy_recursive(from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    if let Err(e) = remove_path(from) {
        let _ = remove_path(to);
        return Err(anyhow::Error::new(e))
            .with_context(|| format!("removing {} (copy rolled back)", from.display()));
    }
    Ok(())
}

pub fn remove_path(p: &Path) -> std::io::Result<()> {
    if p.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

fn copy_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    }
    Ok(())
}

/// Replace characters that are invalid in Windows file names, bound length.
fn sanitize(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    out = out.trim_matches([' ', '.']).to_string();
    if out.chars().count() > 80 {
        out = out.chars().take(80).collect();
    }
    if out.is_empty() {
        out.push_str("item");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_invalid_chars() {
        assert_eq!(sanitize(r"HKLM\SOFTWARE\App:1"), "HKLM_SOFTWARE_App_1");
        assert_eq!(sanitize(""), "item");
    }

    #[test]
    fn validates_a_real_reg_export() {
        let content =
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\SOFTWARE\\OxidizeTest]\r\n\"x\"=\"y\"\r\n";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in content.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let path = std::env::temp_dir().join("oxidize_validate_test.reg");
        fs::write(&path, &bytes).unwrap();

        assert!(validate_reg_file(&path, Hive::CurrentUser, r"SOFTWARE\OxidizeTest").is_ok());
        assert!(validate_reg_file(&path, Hive::CurrentUser, r"SOFTWARE\Other").is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_manifest_without_a_type_reads_as_reg_sz() {
        let json = r#"{"program":"X","created":"now","entries":[{"kind":"RegistryValue",
            "path":"HKCU\\Run : X","undo":{"ValueWrite":{"hive":"CurrentUser",
            "subpath":"SOFTWARE","name":"X","data":"y"}}}]}"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        match &m.entries[0].undo {
            Undo::ValueWrite { vtype, .. } => assert_eq!(*vtype, reg_sz()),
            other => panic!("unexpected undo: {other:?}"),
        }
    }

    #[test]
    fn two_sessions_in_one_second_get_their_own_folder() {
        let base = backups_base().unwrap();
        let first = BackupSession::new("Oxidize Session Test").unwrap();
        let second = BackupSession::new("Oxidize Session Test").unwrap();
        assert_ne!(first.root(), second.root());
        assert!(second.name().ends_with("(2)"));
        let _ = fs::remove_dir_all(first.root());
        let _ = fs::remove_dir_all(second.root());
        // Leave no empty backups folder behind on a machine that had none.
        let _ = fs::remove_dir(&base);
        let _ = fs::remove_dir(base.parent().unwrap());
    }

    #[test]
    fn manifest_round_trips() {
        let m = Manifest {
            program: "X".into(),
            created: "now".into(),
            entries: vec![ManifestEntry {
                kind: LeftoverKind::PathEntry,
                path: "PATH entry C:\\x".into(),
                undo: Undo::PathAdd {
                    hive: Hive::CurrentUser,
                    entry: "C:\\x".into(),
                    index: Some(0),
                },
            }],
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entries.len(), 1);
    }
}
