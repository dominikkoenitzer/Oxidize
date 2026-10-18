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

use crate::exit::Failure;
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
    /// When everything in it was put back, if it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<String>,
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
        let root = unused_root(&base, &stem);
        fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
        Ok(BackupSession {
            root,
            manifest: Manifest {
                program: program_label.to_string(),
                created: now.to_rfc3339(),
                entries: Vec::new(),
                restored: None,
            },
        })
    }

    /// Go on writing into the backup at `root`, so one restore puts back
    /// what both removals took.
    pub fn resume(root: &Path, program_label: &str) -> Result<BackupSession> {
        let manifest = if root.join(MANIFEST).exists() {
            read_manifest(root)?
        } else {
            fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
            Manifest {
                program: program_label.to_string(),
                created: chrono::Local::now().to_rfc3339(),
                entries: Vec::new(),
                restored: None,
            }
        };
        Ok(BackupSession {
            root: root.to_path_buf(),
            manifest,
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
        write_manifest(&self.root, &self.manifest)
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

        if let Err(e) = move_path(original, &dest) {
            if e.downcast_ref::<PartialMove>().is_none() {
                return Err(e);
            }
            // Part of the original is gone and the copy is the only whole
            // version, so restore has to know where it is.
            self.record(
                kind,
                &original.display().to_string(),
                Undo::MoveBack {
                    from: dest.clone(),
                    to: original.to_path_buf(),
                },
            )?;
            return Err(e).context("partially removed");
        }
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

/// The stamp is only accurate to the second, and two removals of the same
/// program can fall inside one. Sharing a folder would overwrite the first
/// manifest and strand what it holds.
fn unused_root(base: &Path, stem: &str) -> PathBuf {
    let mut root = base.join(stem);
    let mut n = 2;
    while root.exists() {
        root = base.join(format!("{stem} ({n})"));
        n += 1;
    }
    root
}

/// `%LOCALAPPDATA%\Oxidize\backups`.
#[cfg(not(test))]
pub fn backups_base() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .context("LOCALAPPDATA is not set")?;
    Ok(local.join("Oxidize").join("backups"))
}

/// The tests make and restore backups of their own. They go to a folder of
/// this test run, never among the real ones, where a run that fails halfway
/// would leave them listed for the user to restore.
#[cfg(test)]
pub fn backups_base() -> Result<PathBuf> {
    Ok(std::env::temp_dir()
        .join(format!("oxidize-test-run-{}", std::process::id()))
        .join("backups"))
}

/// One existing backup folder.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    /// Stable id for scripts: the folder name, which is unique and which
    /// `oxidize restore <id>` takes as an exact match.
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub program: String,
    pub created: String,
    pub items: usize,
    pub size_bytes: u64,
    /// When everything in it was put back, or null.
    pub restored: Option<String>,
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
            restored: manifest.as_ref().and_then(|m| m.restored.clone()),
            size_bytes: crate::scanner::dir_size(&path),
            id: name.clone(),
            name,
            path,
        });
    }
    sort_newest_first(&mut out);
    Ok(out)
}

/// Newest first by the time in the manifest, then by name. The name starts
/// with the time too, but only to the second.
fn sort_newest_first(backups: &mut [BackupInfo]) {
    let time = |b: &BackupInfo| chrono::DateTime::parse_from_rfc3339(&b.created).ok();
    backups.sort_by(|a, b| time(b).cmp(&time(a)).then_with(|| b.name.cmp(&a.name)));
}

/// Write a backup's manifest. It goes beside the real file and is renamed
/// over it: a manifest half written by a crash would take every earlier
/// entry down with it.
fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<()> {
    let json = serde_json::to_string_pretty(manifest)?;
    let tmp = dir.join("manifest.json.new");
    fs::write(&tmp, json).context("writing manifest")?;
    fs::rename(&tmp, dir.join(MANIFEST)).context("replacing manifest")?;
    Ok(())
}

/// Note in a backup's manifest that everything in it was put back.
pub fn mark_restored(dir: &Path) -> Result<()> {
    let mut manifest = read_manifest(dir)?;
    manifest.restored = Some(chrono::Local::now().to_rfc3339());
    write_manifest(dir, &manifest)
}

pub fn read_manifest(dir: &Path) -> Result<Manifest> {
    let text = fs::read_to_string(dir.join(MANIFEST))
        .with_context(|| format!("no manifest in {}", dir.display()))?;
    serde_json::from_str(&text).context("reading manifest")
}

/// Resolve a backup by exact name, or by a unique substring of its name or
/// program.
pub fn find_backup(name: &str) -> Result<BackupInfo> {
    pick_backup(&list_backups()?, name)
}

fn pick_backup(all: &[BackupInfo], name: &str) -> Result<BackupInfo> {
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
        0 => Err(Failure::not_found(format!("no backup matches \"{name}\"")).into()),
        1 => Ok(hits[0].clone()),
        n => Err(Failure::ambiguous(format!(
            "\"{name}\" matches {n} backups; use the full name from `oxidize backups`"
        ))
        .into()),
    }
}

/// The publisher an earlier removal of `program` recorded: the uninstall
/// entry it exported names it. The newest backup that has one wins.
pub fn recorded_publisher(program: &str) -> Option<String> {
    let wanted = crate::util::significant_tokens(program);
    if wanted.is_empty() {
        return None;
    }
    list_backups().ok()?.into_iter().find_map(|b| {
        if crate::util::significant_tokens(&b.program) != wanted {
            return None;
        }
        let entries = fs::read_dir(b.path.join("registry")).ok()?;
        entries.flatten().find_map(|e| {
            let bytes = fs::read(e.path()).ok()?;
            uninstall_publisher(&system::decode_utf16_or_utf8(&bytes))
        })
    })
}

/// `"Publisher"="..."` in an exported uninstall entry.
fn uninstall_publisher(reg: &str) -> Option<String> {
    let mut in_uninstall = false;
    for line in reg.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_uninstall = line
                .to_ascii_lowercase()
                .contains(r"\currentversion\uninstall\");
            continue;
        }
        if !in_uninstall {
            continue;
        }
        if let Some(rest) = line.strip_prefix("\"Publisher\"=\"") {
            let value = rest.strip_suffix('"')?;
            let value = value.replace("\\\"", "\"").replace("\\\\", "\\");
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
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

/// A move whose copy is complete but whose source could only be partly
/// deleted. The copy at `to` is then the one whole version left and is kept.
#[derive(Debug)]
pub struct PartialMove {
    pub from: PathBuf,
    pub to: PathBuf,
    pub error: std::io::Error,
}

impl std::fmt::Display for PartialMove {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} was only partly removed ({}); the full copy is kept at {}",
            self.from.display(),
            self.error,
            self.to.display()
        )
    }
}

impl std::error::Error for PartialMove {}

/// Move a file or folder. `rename` cannot cross volumes, so quarantining
/// something on `D:` falls back to copy then delete, and the copy is rolled
/// back if the original will not go. Restore takes the same route home.
///
/// A delete that fails partway (a locked file inside a folder) has already
/// taken part of the original, so the copy is kept and a [`PartialMove`] is
/// returned instead.
pub fn move_path(from: &Path, to: &Path) -> Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    copy_recursive(from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    if let Err(e) = remove_path(from) {
        if !still_whole(from, to) {
            return Err(anyhow::Error::new(PartialMove {
                from: from.to_path_buf(),
                to: to.to_path_buf(),
                error: e,
            }));
        }
        let _ = remove_path(to);
        return Err(anyhow::Error::new(e))
            .with_context(|| format!("removing {} (copy rolled back)", from.display()));
    }
    Ok(())
}

/// Everything in the copy is still at the original. Anything missing, or
/// anything that cannot be read, counts as a delete that got started.
fn still_whole(original: &Path, copy: &Path) -> bool {
    if fs::symlink_metadata(original).is_err() {
        return false;
    }
    let Ok(meta) = fs::symlink_metadata(copy) else {
        return false;
    };
    if !meta.is_dir() {
        return true;
    }
    let Ok(entries) = fs::read_dir(copy) else {
        return false;
    };
    entries.into_iter().all(|entry| match entry {
        Ok(entry) => still_whole(&original.join(entry.file_name()), &entry.path()),
        Err(_) => false,
    })
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
        // The clock decides whether two real sessions share a stamp, so the
        // numbering is checked on a stamp that is taken for certain.
        let taken = std::env::temp_dir().join("oxidize_taken_root_test");
        let _ = fs::remove_dir_all(&taken);
        fs::create_dir_all(taken.join("2026-01-01 120000 X")).unwrap();
        assert_eq!(
            unused_root(&taken, "2026-01-01 120000 X"),
            taken.join("2026-01-01 120000 X (2)")
        );
        fs::create_dir_all(taken.join("2026-01-01 120000 X (2)")).unwrap();
        assert_eq!(
            unused_root(&taken, "2026-01-01 120000 X"),
            taken.join("2026-01-01 120000 X (3)")
        );
        let _ = fs::remove_dir_all(&taken);

        let base = backups_base().unwrap();
        let first = BackupSession::new("Oxidize Session Test").unwrap();
        let second = BackupSession::new("Oxidize Session Test").unwrap();
        assert_ne!(first.root(), second.root());
        let _ = fs::remove_dir_all(first.root());
        let _ = fs::remove_dir_all(second.root());
        // Leave no empty backups folder behind on a machine that had none.
        let _ = fs::remove_dir(&base);
        let _ = fs::remove_dir(base.parent().unwrap());
    }

    /// A folder whose last file is held open without delete sharing: rename
    /// and the delete both fail on it, the delete only after the first file
    /// is gone.
    fn folder_with_a_locked_file(root: &Path) -> (PathBuf, fs::File) {
        use std::os::windows::fs::OpenOptionsExt;
        let _ = fs::remove_dir_all(root);
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), "first").unwrap();
        fs::write(src.join("z.txt"), "last").unwrap();
        // Read sharing so the copy can read it, no delete sharing.
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(src.join("z.txt"))
            .unwrap();
        (src, held)
    }

    #[test]
    fn a_move_that_fails_partway_keeps_the_copy() {
        let root = std::env::temp_dir().join("oxidize_partial_move_test");
        let (src, held) = folder_with_a_locked_file(&root);
        let dst = root.join("dst");

        let err = move_path(&src, &dst).unwrap_err();
        assert!(err.downcast_ref::<PartialMove>().is_some(), "{err:#}");
        // Part of the original is gone, so the copy is the only full one.
        assert!(!src.join("a.txt").exists());
        assert_eq!(fs::read_to_string(dst.join("a.txt")).unwrap(), "first");
        assert_eq!(fs::read_to_string(dst.join("z.txt")).unwrap(), "last");

        drop(held);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_move_that_deletes_nothing_rolls_the_copy_back() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = std::env::temp_dir().join("oxidize_untouched_move_test");
        let _ = fs::remove_dir_all(&root);
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("only.txt"), "only").unwrap();
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(src.join("only.txt"))
            .unwrap();
        let dst = root.join("dst");

        let err = move_path(&src, &dst).unwrap_err();
        assert!(err.downcast_ref::<PartialMove>().is_none(), "{err:#}");
        assert!(src.join("only.txt").exists());
        assert!(!dst.exists());

        drop(held);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_partial_quarantine_is_recorded_and_reported() {
        let base = backups_base().unwrap();
        let root = std::env::temp_dir().join("oxidize_partial_quarantine_test");
        let (src, held) = folder_with_a_locked_file(&root);
        let mut session = BackupSession::new("Oxidize Partial Test").unwrap();

        let err = session
            .quarantine(LeftoverKind::Directory, &src)
            .unwrap_err();
        assert!(format!("{err:#}").contains("partially removed"), "{err:#}");
        let manifest = read_manifest(session.root()).unwrap();
        assert_eq!(manifest.entries.len(), 1);
        match &manifest.entries[0].undo {
            Undo::MoveBack { from, to } => {
                assert_eq!(to, &src);
                assert!(from.join("a.txt").exists());
                assert!(from.join("z.txt").exists());
            }
            other => panic!("unexpected undo: {other:?}"),
        }

        drop(held);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(session.root());
        let _ = fs::remove_dir(&base);
        let _ = fs::remove_dir(base.parent().unwrap());
    }

    #[test]
    fn the_publisher_comes_from_an_exported_uninstall_entry() {
        let reg = "Windows Registry Editor Version 5.00\r\n\r\n\
            [HKEY_CURRENT_USER\\SOFTWARE\\Example\\Settings]\r\n\
            \"Publisher\"=\"Not This One\"\r\n\r\n\
            [HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\quillmark]\r\n\
            \"DisplayName\"=\"Quillmark\"\r\n\
            \"Publisher\"=\"Quill \\\"&\\\" Ink Ltd\"\r\n";
        assert_eq!(
            uninstall_publisher(reg).as_deref(),
            Some("Quill \"&\" Ink Ltd")
        );
        assert_eq!(
            uninstall_publisher("[HKEY_CURRENT_USER\\Software]\r\n"),
            None
        );
    }

    #[test]
    fn manifest_round_trips() {
        let m = Manifest {
            program: "X".into(),
            created: "now".into(),
            restored: None,
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

    fn info(name: &str, program: &str, created: &str) -> BackupInfo {
        BackupInfo {
            id: name.to_string(),
            name: name.to_string(),
            path: PathBuf::from(name),
            program: program.to_string(),
            created: created.to_string(),
            items: 1,
            size_bytes: 0,
            restored: None,
        }
    }

    #[test]
    fn backups_list_newest_first() {
        let mut all = vec![
            info(
                "2026-10-09 080000 Example Player",
                "Example Player",
                "2026-10-09T08:00:00+02:00",
            ),
            info("no manifest", "", ""),
            info(
                "2026-10-10 120000 Example Player (10)",
                "Example Player",
                "2026-10-10T12:00:00.9+02:00",
            ),
            info(
                "2026-10-10 120000 Example Player (9)",
                "Example Player",
                "2026-10-10T12:00:00.5+02:00",
            ),
            // An hour later in UTC, though the local stamp reads earlier.
            info(
                "2026-10-25 020000 Example Tool",
                "Example Tool",
                "2026-10-25T02:30:00+01:00",
            ),
            info(
                "2026-10-25 024500 Example Tool",
                "Example Tool",
                "2026-10-25T02:45:00+02:00",
            ),
        ];
        sort_newest_first(&mut all);
        let names: Vec<&str> = all.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "2026-10-25 020000 Example Tool",
                "2026-10-25 024500 Example Tool",
                "2026-10-10 120000 Example Player (10)",
                "2026-10-10 120000 Example Player (9)",
                "2026-10-09 080000 Example Player",
                "no manifest",
            ]
        );
    }

    #[test]
    fn a_backup_id_picks_exactly_that_backup() {
        let all = vec![
            info("2026-10-10 120000 Example Player (2)", "Example Player", ""),
            info("2026-10-10 120000 Example Player", "Example Player", ""),
        ];
        for b in &all {
            assert_eq!(b.id, b.name);
            assert_eq!(pick_backup(&all, &b.id).unwrap().name, b.name);
        }
        let err = pick_backup(&all, "Example Player").unwrap_err();
        assert_eq!(crate::exit::outcome(&err).code, "ambiguous");
        let err = pick_backup(&all, "Nothing").unwrap_err();
        assert_eq!(crate::exit::outcome(&err).code, "not_found");

        let json = serde_json::to_value(&all[0]).unwrap();
        for field in [
            "id",
            "name",
            "path",
            "program",
            "created",
            "items",
            "size_bytes",
            "restored",
        ] {
            assert!(json.get(field).is_some(), "{field}");
        }
    }
}
