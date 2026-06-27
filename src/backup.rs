//! Reversible-deletion support.
//!
//! Registry keys are backed up by shelling out to `reg.exe export` — the OS's
//! own serializer, whose output is guaranteed to round-trip back through
//! `reg import`. We validate the produced file (BOM + header + non-empty)
//! *before* allowing any delete, so we never destroy a key without a verified
//! backup. The export runs under a watchdog because `reg export` is known to
//! occasionally hang.
//!
//! Files and folders are not deleted outright by default: they are *moved* into
//! a quarantine folder inside the backup directory (a rename when on the same
//! volume, a recursive copy otherwise), which the user can simply move back.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::model::Hive;

/// A backup directory for one Oxidize operation. Created under
/// `%LOCALAPPDATA%\Oxidize\backups\<timestamp>_<program>`.
pub struct BackupSession {
    root: PathBuf,
    registry_dir: PathBuf,
    files_dir: PathBuf,
}

impl BackupSession {
    /// Create a new backup session directory for the given program label.
    pub fn new(program_label: &str) -> Result<BackupSession> {
        let base = backups_base()?;
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let root = base.join(format!("{stamp}_{}", sanitize(program_label)));
        fs::create_dir_all(&root)
            .with_context(|| format!("creating backup directory {}", root.display()))?;
        Ok(BackupSession {
            registry_dir: root.join("registry"),
            files_dir: root.join("files"),
            root,
        })
    }

    /// The backup root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Back up a registry key (and its whole subtree) to a `.reg` file. For a
    /// value-level leftover, pass the key that contains the value — the export
    /// captures the value too. Returns the path of the validated backup file.
    pub fn backup_registry_key(&self, hive: Hive, subpath: &str) -> Result<PathBuf> {
        fs::create_dir_all(&self.registry_dir)
            .with_context(|| format!("creating {}", self.registry_dir.display()))?;

        // The sanitized name can collide (truncation, char folding), so append a
        // hash of the full key path to keep each backup distinct, and never
        // overwrite an existing backup file.
        let key = format!("{}\\{}", hive.short_name(), subpath);
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let out_file = self.registry_dir.join(format!(
            "{}_{:016x}.reg",
            sanitize(&key),
            hasher.finish()
        ));
        if out_file.exists() {
            bail!(
                "backup target {} already exists; refusing to overwrite",
                out_file.display()
            );
        }

        export_registry_key(hive, subpath, &out_file)?;
        validate_reg_file(&out_file, hive, subpath)
            .with_context(|| format!("backup validation failed for {}", out_file.display()))?;
        Ok(out_file)
    }

    /// Move a file or directory into the quarantine area, preserving its
    /// original path layout. Returns the new (quarantined) location.
    pub fn quarantine(&self, original: &Path) -> Result<PathBuf> {
        let dest = self.quarantine_dest(original);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating quarantine path {}", parent.display()))?;
        }

        // Fast path: rename works within the same volume.
        match fs::rename(original, &dest) {
            Ok(()) => Ok(dest),
            Err(_) => {
                // Cross-volume (or other) failure: copy then remove. If the
                // remove fails (e.g. a locked file), roll back the copy so we
                // don't leave a confusing duplicate and a half-done state.
                copy_recursive(original, &dest)
                    .with_context(|| format!("copying {} to quarantine", original.display()))?;
                if let Err(e) = remove_path(original) {
                    let _ = remove_path(&dest);
                    return Err(anyhow::Error::new(e)).with_context(|| {
                        format!(
                            "removing original {} (quarantine copy rolled back)",
                            original.display()
                        )
                    });
                }
                Ok(dest)
            }
        }
    }

    /// Map an original path to its quarantine destination, e.g.
    /// `C:\ProgramData\Foo` → `<backup>\files\C\ProgramData\Foo`.
    fn quarantine_dest(&self, original: &Path) -> PathBuf {
        let mut dest = self.files_dir.clone();
        let s = original.to_string_lossy();
        // Strip a leading drive specifier like `C:\`.
        let rel = if s.len() >= 2 && s.as_bytes()[1] == b':' {
            let drive = &s[0..1];
            dest.push(drive);
            s[2..].trim_start_matches(['\\', '/']).to_string()
        } else {
            s.trim_start_matches(['\\', '/']).to_string()
        };
        dest.push(rel);
        dest
    }
}

/// `%LOCALAPPDATA%\Oxidize\backups`, created if missing.
pub fn backups_base() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .context("LOCALAPPDATA is not set")?;
    Ok(local.join("Oxidize").join("backups"))
}

/// Run `reg.exe export <ROOT\subpath> <out_file> /y /reg:64` with a watchdog.
fn export_registry_key(hive: Hive, subpath: &str, out_file: &Path) -> Result<()> {
    let key_arg = format!("{}\\{}", hive.short_name(), subpath);
    let reg = {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        format!(r"{root}\System32\reg.exe")
    };

    let mut cmd = Command::new(reg);
    cmd.arg("export")
        .arg(&key_arg)
        .arg(out_file)
        .arg("/y")
        .arg("/reg:64");

    let status = run_with_timeout(cmd, Duration::from_secs(30))
        .with_context(|| format!("running reg export for {key_arg}"))?;

    if !status.success() {
        bail!(
            "reg export of {key_arg} failed ({}). The key may be missing or unreadable.",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "terminated".to_string())
        );
    }
    Ok(())
}

/// Spawn a command and wait, killing it if it exceeds `timeout`.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<std::process::ExitStatus> {
    let mut child = cmd.spawn().context("spawning child process")?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("process timed out after {:?}", timeout);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Validate that `path` is a real `.reg` v5 backup of the expected key: it must
/// have the UTF-16 LE BOM, the `Windows Registry Editor Version 5.00` header,
/// and contain the `[HKEY_...\subpath]` section for the key we exported (so a
/// truncated/empty/wrong-key file can never gate a deletion). The whole file is
/// read because these backups are small.
fn validate_reg_file(path: &Path, hive: Hive, subpath: &str) -> Result<()> {
    let bytes = fs::read(path).context("reading backup file")?;
    if bytes.len() < 2 || bytes[0] != 0xFF || bytes[1] != 0xFE {
        bail!("missing UTF-16 LE byte-order mark");
    }
    let units: Vec<u16> = bytes[2..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units).to_lowercase();

    if !text.contains("windows registry editor version 5.00") {
        bail!("missing 'Windows Registry Editor Version 5.00' header");
    }
    // reg.exe writes section headers with the full hive name, e.g.
    // `[HKEY_LOCAL_MACHINE\SOFTWARE\...]`.
    let section = format!("[{}\\{}]", hive.full_name(), subpath).to_lowercase();
    if !text.contains(&section) {
        bail!("backup does not contain the expected key section [{}\\{}]", hive.full_name(), subpath);
    }
    Ok(())
}

fn remove_path(p: &Path) -> std::io::Result<()> {
    if p.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

/// Recursively copy a file or directory tree.
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

/// Replace characters that are invalid in Windows filenames, and bound length.
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
    // Truncate by characters (not bytes) so we never split a multi-byte char.
    if out.chars().count() > 120 {
        out = out.chars().take(120).collect();
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
        // Build a genuine UTF-16 LE .reg byte stream (BOM + header + section).
        let content =
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\SOFTWARE\\OxidizeTest]\r\n\"x\"=\"y\"\r\n";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in content.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let path = std::env::temp_dir().join("oxidize_validate_test.reg");
        fs::write(&path, &bytes).unwrap();

        // Correct hive + subpath validates; a different section is rejected.
        assert!(validate_reg_file(&path, Hive::CurrentUser, r"SOFTWARE\OxidizeTest").is_ok());
        assert!(validate_reg_file(&path, Hive::CurrentUser, r"SOFTWARE\Other").is_err());

        let _ = fs::remove_file(&path);
    }
}
