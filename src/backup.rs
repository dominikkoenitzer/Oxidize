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
    RegImport {
        file: PathBuf,
        /// The key it was exported from, `HKEY_...\subpath`. Restore
        /// imports nothing outside it. Older manifests have none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },
    /// Move a quarantined path back to where it was.
    MoveBack {
        from: PathBuf,
        to: PathBuf,
        /// The delete stopped partway, so part of the original stayed where
        /// it was. Older manifests have none and read as a whole move.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        partial: bool,
    },
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
                key: Some(format!("{}\\{}", hive.full_name(), subpath)),
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
                    partial: true,
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
                partial: false,
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
    let local = crate::scanner::env_dir("LOCALAPPDATA")
        .context("LOCALAPPDATA is not set to a full path")?;
    Ok(local.join("Oxidize").join("backups"))
}

/// The tests make and restore backups of their own. They go to a folder of
/// this test run, never among the real ones, where a run that fails halfway
/// would leave them listed for the user to restore.
///
/// Each test runs on its own thread and gets its own folder, so one test's
/// `TestCleanup` never removes the folder while another test creates a backup.
#[cfg(test)]
pub fn backups_base() -> Result<PathBuf> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static TEST: usize = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    let test = TEST.with(|n| *n);
    Ok(std::env::temp_dir()
        .join(format!("oxidize-test-run-{}-{test}", std::process::id()))
        .join("backups"))
}

/// Removes a test's folders when it ends, passed or failed, and its backups folder once empty.
#[cfg(test)]
pub(crate) struct TestCleanup(pub Vec<PathBuf>);

#[cfg(test)]
impl Drop for TestCleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_dir_all(path);
        }
        if let Ok(base) = backups_base() {
            let _ = fs::remove_dir(&base);
            if let Some(run) = base.parent() {
                let _ = fs::remove_dir(run);
            }
        }
    }
}

/// `<name>_<process id>` in TEMP: a test's name for this run, so two runs at once never share it.
#[cfg(test)]
pub(crate) fn test_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{name}_{}", std::process::id()))
}

/// A test's own folder at `test_path`, removed when the test ends, passed or failed.
#[cfg(test)]
pub(crate) struct TestDir(PathBuf);

#[cfg(test)]
impl TestDir {
    /// Clears the path; the test creates the folder when it needs it.
    pub(crate) fn new(name: &str) -> TestDir {
        let path = test_path(name);
        let _ = fs::remove_dir_all(&path);
        TestDir(path)
    }
}

#[cfg(test)]
impl std::ops::Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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
    // As a part of a name, an empty one would match every backup.
    if name.trim().is_empty() {
        return Err(Failure::usage("give a name; an empty one would match everything").into());
    }
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

/// Does the `.reg` file at `path` write only into `key` and below it, and
/// is `key` one a removal could have taken? A backup sits in the user's own
/// folder and can be restored as administrator, so a file that writes
/// anywhere else, deletes keys, or stands for a key every program shares is
/// refused before `reg import` sees it. Without a recorded key (an older
/// backup) the file's first section is taken for it.
pub fn reg_file_in_scope(path: &Path, key: Option<&str>) -> Result<()> {
    let bytes = fs::read(path).context("reading backup file")?;
    let text = system::decode_utf16_or_utf8(&bytes);
    if !text
        .to_lowercase()
        .contains("windows registry editor version 5.00")
    {
        bail!("not a registry export");
    }
    let sections: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix('[').and_then(|l| l.strip_suffix(']')))
        .collect();
    let Some(first) = sections.first() else {
        bail!("the export holds no key");
    };
    let root = key.unwrap_or(first).to_lowercase();
    let sub = ["hkey_current_user\\", "hkey_local_machine\\"]
        .iter()
        .find_map(|h| root.strip_prefix(h));
    let Some(sub) = sub else {
        bail!("{root} is in neither hive a removal takes from");
    };
    if crate::registry::is_shared_root_key(sub) {
        bail!("{root} is a key every program shares");
    }
    for section in &sections {
        let s = section.to_lowercase();
        if s.starts_with('-') {
            bail!("the export deletes [{section}]");
        }
        if s != root && !s.starts_with(&format!("{root}\\")) {
            bail!("the export writes [{section}], outside {root}");
        }
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
    let to_was_there = fs::symlink_metadata(to).is_ok();
    if let Err(e) = copy_recursive(from, to) {
        // A copy that stopped halfway is no copy; left there it would stand in for the original.
        if !to_was_there {
            let _ = remove_path(to);
        }
        return Err(anyhow::Error::new(e))
            .with_context(|| format!("copying {} to {}", from.display(), to.display()));
    }
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
pub(crate) fn still_whole(original: &Path, copy: &Path) -> bool {
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

/// Delete a file or folder that has no backup: all of a folder, or none of
/// it. Each file in it is opened alone and marked for deletion before any
/// of it goes, so a file another program has open, or a program file that
/// runs, keeps the whole folder. Links inside go as links.
#[cfg(windows)]
pub fn remove_whole(p: &Path) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(p)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return remove_path(p);
    }
    let (mut dirs, mut marked) = (Vec::new(), Vec::new());
    if let Err(e) = hold(p, &mut dirs, &mut marked) {
        for f in &marked {
            let _ = mark(f, false);
        }
        return Err(e);
    }
    // Closing the last handle deletes each file.
    drop(marked);
    // A folder comes after everything in it, so the last one held goes first.
    while let Some(d) = dirs.pop() {
        mark(&d, true)?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_whole(p: &Path) -> std::io::Result<()> {
    remove_path(p)
}

/// Test seams in the whole delete. Each test runs on its own thread.
#[cfg(all(test, windows))]
pub(crate) mod hooks {
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    type Hook = Box<dyn Fn(&Path)>;

    thread_local! {
        static BEFORE_OPEN: RefCell<Option<Hook>> = RefCell::new(None);
        static NO_POSIX: Cell<bool> = const { Cell::new(false) };
    }

    /// Run `f` on each folder right before it is opened for deletion.
    pub(crate) fn before_open(f: impl Fn(&Path) + 'static) {
        BEFORE_OPEN.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    /// Act as a file system without POSIX delete.
    pub(crate) fn refuse_posix() {
        NO_POSIX.with(|c| c.set(true));
    }

    pub(super) fn posix_refused() -> bool {
        NO_POSIX.with(Cell::get)
    }

    pub(super) fn opening(dir: &Path) {
        BEFORE_OPEN.with(|h| {
            if let Some(f) = h.borrow().as_ref() {
                f(dir);
            }
        });
    }
}

/// Open the folder `dir` and everything in it for deletion, each folder
/// before what it holds, and mark every file. Stops at the first that will
/// not open or take the mark.
#[cfg(windows)]
fn hold(dir: &Path, dirs: &mut Vec<fs::File>, marked: &mut Vec<fs::File>) -> std::io::Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        #[cfg(test)]
        hooks::opening(&d);
        // Read sharing lets the folder be listed; a program working in it
        // holds it without delete sharing, and the open fails.
        let held = open_for_delete(&d, 1)?;
        // Held without delete sharing, it can no longer be swapped for a link.
        real_folder(&held, (d == dir).then_some(dir))?;
        dirs.push(held);
        for entry in fs::read_dir(&d)? {
            let path = entry?.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() && !meta.file_type().is_symlink() {
                stack.push(path);
                continue;
            }
            let file = open_for_delete(&path, 0)?;
            mark(&file, true)?;
            marked.push(file);
        }
    }
    Ok(())
}

/// Refuse a held folder that is a link or no folder, and the top folder
/// when the handle leads to another place than the path `top`.
#[cfg(windows)]
fn real_folder(held: &fs::File, top: Option<&Path>) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_NAME_NORMALIZED,
    };
    let handle = HANDLE(held.as_raw_handle());
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(|e| std::io::Error::from_raw_os_error(e.code().0 & 0xFFFF))?;
    if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(std::io::Error::other(
            "the folder changed while it was being deleted",
        ));
    }
    let Some(top) = top else {
        return Ok(());
    };
    let mut buf = vec![0u16; 32_768];
    let n = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(std::io::Error::last_os_error());
    }
    if same_place(&String::from_utf16_lossy(&buf[..n]), &long_name(top)?) {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "the path to the folder goes through a link",
        ))
    }
}

/// `p` as a full path with its short 8.3 names spelled out.
#[cfg(windows)]
fn long_name(p: &Path) -> std::io::Result<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetLongPathNameW;
    let full = std::path::absolute(p)?;
    let wide: Vec<u16> = full
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = vec![0u16; 32_768];
    let n = unsafe { GetLongPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf)) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&buf[..n]))
}

/// Whether two full paths name the same place, with or without the `\\?\`
/// prefix, in any case.
#[cfg(windows)]
fn same_place(a: &str, b: &str) -> bool {
    fn plain(s: &str) -> String {
        let s = s.replace('/', r"\");
        let s = match s.strip_prefix(r"\\?\UNC\") {
            Some(rest) => format!(r"\\{rest}"),
            None => s.strip_prefix(r"\\?\").unwrap_or(&s).to_string(),
        };
        s.trim_end_matches('\\').to_lowercase()
    }
    plain(a) == plain(b)
}

/// Open `path` itself for deletion, never what a link points to.
#[cfg(windows)]
fn open_for_delete(path: &Path, share: u32) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Mark an open file or folder to go when it is closed, read-only or not,
/// or take the mark back. A program file that runs refuses the mark.
/// Where the file system has no POSIX delete, such as FAT, the plain mark
/// is used, and a read-only file refuses it.
#[cfg(windows)]
fn mark(file: &fs::File, delete: bool) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{FileDispositionInfoEx, SetFileInformationByHandle};
    const DELETE: u32 = 0x1;
    const POSIX_SEMANTICS: u32 = 0x2;
    const IGNORE_READONLY_ATTRIBUTE: u32 = 0x10;
    let handle = HANDLE(file.as_raw_handle());
    let flags: u32 = if delete {
        DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE
    } else {
        0
    };
    #[cfg(test)]
    if hooks::posix_refused() {
        return plain_mark(handle, delete);
    }
    let posix = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            (&flags as *const u32).cast(),
            4,
        )
    }
    .map_err(|e| std::io::Error::from_raw_os_error(e.code().0 & 0xFFFF));
    // The codes for a request the file system does not know.
    match posix {
        Err(e) if matches!(e.raw_os_error(), Some(87 | 50 | 1)) => plain_mark(handle, delete),
        other => other,
    }
}

/// The mark every file system knows. The file goes when its last handle
/// closes, and the mark can be taken back until then.
#[cfg(windows)]
fn plain_mark(handle: windows::Win32::Foundation::HANDLE, delete: bool) -> std::io::Result<()> {
    use windows::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    let info = FILE_DISPOSITION_INFO { DeleteFile: delete };
    unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|e| std::io::Error::from_raw_os_error(e.code().0 & 0xFFFF))
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
    if out.chars().count() > 80 {
        out = out.chars().take(80).collect();
    }
    // Windows drops a folder name's trailing space, so a path built on to the name as written misses.
    out = out.trim_matches([' ', '.']).to_string();
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
        let dir = TestDir::new("oxidize_validate_test");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("export.reg");
        fs::write(&path, &bytes).unwrap();

        assert!(validate_reg_file(&path, Hive::CurrentUser, r"SOFTWARE\OxidizeTest").is_ok());
        assert!(validate_reg_file(&path, Hive::CurrentUser, r"SOFTWARE\Other").is_err());
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
        let taken = test_path("oxidize_taken_root_test");
        let _ = fs::remove_dir_all(&taken);
        let mut cleanup = TestCleanup(vec![taken.clone()]);
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

        let first = BackupSession::new("Oxidize Session Test").unwrap();
        cleanup.0.push(first.root().to_path_buf());
        let second = BackupSession::new("Oxidize Session Test").unwrap();
        cleanup.0.push(second.root().to_path_buf());
        assert_ne!(first.root(), second.root());
    }

    #[test]
    fn another_tests_guard_never_takes_the_backups_folder_from_a_new_backup() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let _cleanup = TestCleanup(Vec::new());
        // Another test ending over and over, as many do while this one runs.
        let stop = Arc::new(AtomicBool::new(false));
        let other = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    drop(TestCleanup(Vec::new()));
                }
            })
        };
        let mut failed = Vec::new();
        for _ in 0..500 {
            match BackupSession::new("Oxidize Shared Folder Test") {
                Ok(session) => {
                    let _ = fs::remove_dir_all(session.root());
                }
                Err(e) => failed.push(format!("{e:#}")),
            }
        }
        stop.store(true, Ordering::Relaxed);
        other.join().unwrap();
        assert_eq!(failed.first(), None, "{} of 500 failed", failed.len());
    }

    #[test]
    fn a_long_name_cut_after_a_space_still_takes_a_backup() {
        let root = test_path("oxidize_long_name_test");
        let _ = fs::remove_dir_all(&root);
        let mut cleanup = TestCleanup(vec![root.clone()]);
        fs::create_dir_all(&root).unwrap();
        let file = root.join("leftover.txt");
        fs::write(&file, "kept").unwrap();

        // The 80th character is a space, so the cut name ends in one.
        let label = format!("Oxidize Long Name Test{} more words", "x".repeat(57));
        let mut session = BackupSession::new(&label).unwrap();
        cleanup.0.push(session.root().to_path_buf());

        let dest = session.quarantine(LeftoverKind::File, &file).unwrap();
        assert_eq!(fs::read_to_string(dest).unwrap(), "kept");
        assert!(session.root().join(MANIFEST).exists());
        assert!(!session.name().ends_with([' ', '.']));
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
        // Declared before the held file, so it is closed when the guard runs.
        let root = TestDir::new("oxidize_partial_move_test");
        let (src, held) = folder_with_a_locked_file(&root);
        let dst = root.join("dst");

        let err = move_path(&src, &dst).unwrap_err();
        assert!(err.downcast_ref::<PartialMove>().is_some(), "{err:#}");
        // Part of the original is gone, so the copy is the only full one.
        assert!(!src.join("a.txt").exists());
        assert_eq!(fs::read_to_string(dst.join("a.txt")).unwrap(), "first");
        assert_eq!(fs::read_to_string(dst.join("z.txt")).unwrap(), "last");

        drop(held);
    }

    #[test]
    fn a_move_that_deletes_nothing_rolls_the_copy_back() {
        use std::os::windows::fs::OpenOptionsExt;
        // Declared before the held file, so it is closed when the guard runs.
        let root = TestDir::new("oxidize_untouched_move_test");
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
    }

    #[test]
    fn a_folder_with_a_file_held_open_is_not_deleted_at_all() {
        // Declared before the held file, so it is closed when the guard runs.
        let root = TestDir::new("oxidize_whole_locked_test");
        let (src, held) = folder_with_a_locked_file(&root);
        remove_whole(&src).unwrap_err();
        assert_eq!(fs::read_to_string(src.join("a.txt")).unwrap(), "first");
        drop(held);

        // Open with delete sharing, as most programs open files.
        let shared = fs::File::open(src.join("z.txt")).unwrap();
        remove_whole(&src).unwrap_err();
        assert!(src.join("a.txt").exists() && src.join("z.txt").exists());
        drop(shared);

        remove_whole(&src).unwrap();
        assert!(!src.exists());
    }

    #[test]
    fn a_folder_a_program_runs_from_is_not_deleted_at_all() {
        let root = TestDir::new("oxidize_whole_running_test");
        let src = root.join("src");
        fs::create_dir_all(src.join("data")).unwrap();
        fs::write(src.join(r"data\a.txt"), "first").unwrap();
        let exe = src.join("quill.exe");
        fs::copy(crate::system::system32("PING.EXE"), &exe).unwrap();
        let mut child = std::process::Command::new(&exe)
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let result = remove_whole(&src);
        child.kill().unwrap();
        child.wait().unwrap();
        result.unwrap_err();
        assert_eq!(
            fs::read_to_string(src.join(r"data\a.txt")).unwrap(),
            "first"
        );
        assert!(exe.exists());
    }

    #[test]
    fn a_whole_folder_goes_with_read_only_files_and_links_left_unfollowed() {
        let root = TestDir::new("oxidize_whole_test");
        let src = root.join("src");
        let outside = root.join("outside");
        fs::create_dir_all(src.join(r"a\b")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("kept.txt"), "kept").unwrap();
        let locked = src.join(r"a\b\locked.txt");
        fs::write(&locked, "read only").unwrap();
        let mut perms = fs::metadata(&locked).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&locked, perms).unwrap();
        let made = std::process::Command::new(crate::system::system32("cmd.exe"))
            .args(["/c", "mklink", "/J"])
            .arg(src.join(r"a\link"))
            .arg(&outside)
            .output()
            .unwrap();
        assert!(made.status.success());

        remove_whole(&src).unwrap();
        assert!(!src.exists());
        assert_eq!(
            fs::read_to_string(outside.join("kept.txt")).unwrap(),
            "kept"
        );
    }

    fn junction(link: &Path, target: &Path) {
        let made = std::process::Command::new(crate::system::system32("cmd.exe"))
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(made.status.success());
    }

    #[test]
    fn a_folder_swapped_for_a_link_during_the_delete_is_not_followed() {
        let root = TestDir::new("oxidize_whole_swap_test");
        let src = root.join("src");
        let outside = root.join("outside");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), "first").unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("kept.txt"), "kept").unwrap();
        // After `src` is listed, `sub` turns into a link to `outside`.
        let swap = outside.clone();
        hooks::before_open(move |d| {
            if d.ends_with("sub") && !d.is_symlink() {
                fs::remove_dir(d).unwrap();
                junction(d, &swap);
            }
        });

        remove_whole(&src).unwrap_err();
        assert_eq!(
            fs::read_to_string(outside.join("kept.txt")).unwrap(),
            "kept"
        );
        assert_eq!(fs::read_to_string(src.join("a.txt")).unwrap(), "first");
    }

    #[test]
    fn a_folder_reached_through_a_link_is_not_deleted() {
        let root = TestDir::new("oxidize_whole_through_test");
        let real = root.join("real");
        fs::create_dir_all(real.join("src")).unwrap();
        fs::write(real.join(r"src\a.txt"), "first").unwrap();
        junction(&root.join("link"), &real);

        remove_whole(&root.join(r"link\src")).unwrap_err();
        assert_eq!(
            fs::read_to_string(real.join(r"src\a.txt")).unwrap(),
            "first"
        );
    }

    #[test]
    fn without_posix_delete_a_whole_folder_still_goes() {
        let root = TestDir::new("oxidize_whole_plain_test");
        let src = root.join("src");
        fs::create_dir_all(src.join(r"a\b")).unwrap();
        fs::write(src.join("top.txt"), "top").unwrap();
        fs::write(src.join(r"a\b\deep.txt"), "deep").unwrap();
        hooks::refuse_posix();

        remove_whole(&src).unwrap();
        assert!(!src.exists());
    }

    #[test]
    fn without_posix_delete_a_folder_with_a_file_held_open_stays_whole() {
        // Declared before the held file, so it is closed when the guard runs.
        let root = TestDir::new("oxidize_whole_plain_locked_test");
        let (src, held) = folder_with_a_locked_file(&root);
        hooks::refuse_posix();

        remove_whole(&src).unwrap_err();
        assert_eq!(fs::read_to_string(src.join("a.txt")).unwrap(), "first");
        drop(held);
    }

    #[test]
    fn without_posix_delete_a_read_only_file_keeps_the_folder_whole() {
        let root = TestDir::new("oxidize_whole_plain_read_only_test");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), "first").unwrap();
        let locked = src.join("z.txt");
        fs::write(&locked, "read only").unwrap();
        let mut perms = fs::metadata(&locked).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&locked, perms.clone()).unwrap();
        hooks::refuse_posix();

        remove_whole(&src).unwrap_err();
        assert_eq!(fs::read_to_string(src.join("a.txt")).unwrap(), "first");
        assert!(locked.exists());
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&locked, perms).unwrap();
    }

    #[test]
    fn the_same_place_is_found_under_any_spelling() {
        assert!(same_place(r"\\?\C:\Users\Ann\Temp\", "c:/users/ann/temp"));
        assert!(same_place(r"\\?\UNC\server\share\x", r"\\server\share\x"));
        assert!(!same_place(r"\\?\D:\dev\x", r"C:\dev\x"));
    }

    #[test]
    fn a_partial_quarantine_is_recorded_and_reported() {
        let root = test_path("oxidize_partial_quarantine_test");
        // Declared before the held file, so it is closed when the guard runs.
        let mut cleanup = TestCleanup(vec![root.clone()]);
        let (src, held) = folder_with_a_locked_file(&root);
        let mut session = BackupSession::new("Oxidize Partial Test").unwrap();
        cleanup.0.push(session.root().to_path_buf());

        let err = session
            .quarantine(LeftoverKind::Directory, &src)
            .unwrap_err();
        assert!(format!("{err:#}").contains("partially removed"), "{err:#}");
        let manifest = read_manifest(session.root()).unwrap();
        assert_eq!(manifest.entries.len(), 1);
        match &manifest.entries[0].undo {
            Undo::MoveBack { from, to, partial } => {
                assert!(partial);
                assert_eq!(to, &src);
                assert!(from.join("a.txt").exists());
                assert!(from.join("z.txt").exists());
            }
            other => panic!("unexpected undo: {other:?}"),
        }

        drop(held);
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
    fn a_copy_that_stops_halfway_is_not_left_behind() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = test_path("oxidize_halfway_copy_test");
        let _cleanup = TestCleanup(vec![root.clone()]);
        let _ = fs::remove_dir_all(&root);
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), "first").unwrap();
        fs::write(src.join("z.txt"), "last").unwrap();
        // No sharing at all: the rename fails on it, and so does the copy, after `a.txt`.
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(src.join("z.txt"))
            .unwrap();
        let dst = root.join("dst");

        let err = move_path(&src, &dst).unwrap_err();
        assert!(err.downcast_ref::<PartialMove>().is_none(), "{err:#}");
        assert!(!dst.exists());
        assert_eq!(fs::read_to_string(src.join("a.txt")).unwrap(), "first");
        // A folder that was there before the copy is not the copy's to take.
        let earlier = root.join("earlier");
        fs::create_dir_all(&earlier).unwrap();
        fs::write(earlier.join("kept.txt"), "kept").unwrap();
        move_path(&src, &earlier).unwrap_err();
        assert_eq!(
            fs::read_to_string(earlier.join("kept.txt")).unwrap(),
            "kept"
        );
        drop(held);
        assert_eq!(fs::read_to_string(src.join("z.txt")).unwrap(), "last");
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

    #[test]
    fn a_move_back_written_before_partial_moves_were_marked_reads_as_whole() {
        let old = r#"{"MoveBack":{"from":"C:\\B\\files\\C\\Foo","to":"C:\\Foo"}}"#;
        let undo: Undo = serde_json::from_str(old).unwrap();
        assert!(matches!(undo, Undo::MoveBack { partial: false, .. }));
        // A whole move is written as before; only a partial one carries the mark.
        assert_eq!(serde_json::to_string(&undo).unwrap(), old);
        let partial = Undo::MoveBack {
            from: r"C:\B\files\C\Foo".into(),
            to: r"C:\Foo".into(),
            partial: true,
        };
        let json = serde_json::to_string(&partial).unwrap();
        assert!(json.contains(r#""partial":true"#), "{json}");
        let back: Undo = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Undo::MoveBack { partial: true, .. }));
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

    #[test]
    fn an_empty_name_picks_no_backup() {
        let all = vec![info(
            "2026-10-10 120000 Example Player",
            "Example Player",
            "",
        )];
        for name in ["", "  "] {
            let err = pick_backup(&all, name).unwrap_err();
            assert_eq!(crate::exit::outcome(&err).code, "usage", "{name:?}");
        }
    }
}
