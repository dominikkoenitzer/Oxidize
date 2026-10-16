//! Undo a removal from its backup manifest.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use winreg::RegValue;

use crate::backup::{self, BackupInfo, Undo};
use crate::model::{environment_key, Hive};
use crate::{registry, system};

/// Result for one manifest entry.
#[derive(Debug, Clone)]
pub struct RestoreItem {
    pub path: String,
    pub result: Result<(), String>,
}

/// Put back everything in the backup. Entries are restored in reverse order
/// of removal, so a folder comes back before the shortcut that pointed at it.
/// `dry_run` only lists what would happen.
pub fn restore(info: &BackupInfo, dry_run: bool) -> Result<Vec<RestoreItem>> {
    let manifest = backup::read_manifest(&info.path)?;
    let mut out = Vec::new();
    for entry in manifest.entries.iter().rev() {
        let result = if dry_run {
            check(&entry.undo)
        } else {
            undo(&entry.undo)
        };
        out.push(RestoreItem {
            path: entry.path.clone(),
            result: result.map_err(|e| format!("{e:#}")),
        });
    }
    // Listed as restored from now on, so its old item count does not read
    // as something still waiting in it. A partial restore stays unmarked.
    if !dry_run && out.iter().all(|i| i.result.is_ok()) {
        let _ = backup::mark_restored(&info.path);
    }
    Ok(out)
}

/// What a dry run can say without writing anything: the pieces the undo needs
/// are still there. A dry run that reports "would restore" for an entry whose
/// quarantined copy is gone is worse than no dry run at all.
fn check(action: &Undo) -> Result<()> {
    match action {
        Undo::RegImport { file } | Undo::TaskImport { file, .. } => {
            if file.exists() {
                Ok(())
            } else {
                anyhow::bail!("the backup file is missing: {}", file.display())
            }
        }
        Undo::MoveBack { from, to } => {
            if from.exists() || to.exists() {
                Ok(())
            } else {
                anyhow::bail!("the quarantined copy is missing: {}", from.display())
            }
        }
        Undo::PathAdd { .. } | Undo::ValueWrite { .. } => Ok(()),
        Undo::RawValueWrite { vtype, .. } => reg_type(*vtype)
            .map(|_| ())
            .with_context(|| format!("unknown registry value type {vtype}")),
    }
}

fn undo(action: &Undo) -> Result<()> {
    match action {
        Undo::RegImport { file } => backup::import_registry_file(file),
        Undo::MoveBack { from, to } => move_back(from, to),
        Undo::TaskImport { name, file } => system::import_task(name, file),
        Undo::PathAdd { hive, entry, index } => path_add(*hive, entry, *index),
        Undo::ValueWrite {
            hive,
            subpath,
            name,
            data,
            vtype,
        } => {
            let vtype =
                reg_type(*vtype).with_context(|| format!("unknown registry value type {vtype}"))?;
            let bytes: Vec<u8> = data
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            registry::write_raw(
                *hive,
                subpath,
                name,
                &RegValue {
                    bytes: bytes.into(),
                    vtype,
                },
            )
            .with_context(|| format!("writing {}\\{subpath} : {name}", hive.short_name()))
        }
        Undo::RawValueWrite {
            hive,
            subpath,
            name,
            vtype,
            bytes,
        } => {
            let vtype =
                reg_type(*vtype).with_context(|| format!("unknown registry value type {vtype}"))?;
            registry::write_raw(
                *hive,
                subpath,
                name,
                &RegValue {
                    bytes: bytes.clone().into(),
                    vtype,
                },
            )
            .with_context(|| format!("writing {}\\{subpath} : {name}", hive.short_name()))
        }
    }
}

/// The registry type discriminants, as stored in the manifest.
fn reg_type(vtype: u32) -> Option<winreg::enums::RegType> {
    use winreg::enums::RegType::*;
    Some(match vtype {
        0 => REG_NONE,
        1 => REG_SZ,
        2 => REG_EXPAND_SZ,
        3 => REG_BINARY,
        4 => REG_DWORD,
        5 => REG_DWORD_BIG_ENDIAN,
        6 => REG_LINK,
        7 => REG_MULTI_SZ,
        8 => REG_RESOURCE_LIST,
        9 => REG_FULL_RESOURCE_DESCRIPTOR,
        10 => REG_RESOURCE_REQUIREMENTS_LIST,
        11 => REG_QWORD,
        _ => return None,
    })
}
fn move_back(from: &Path, to: &Path) -> Result<()> {
    if !from.exists() {
        // Restoring the same backup twice: the first run already moved this
        // one home, which is the state the caller wanted either way.
        if to.exists() {
            return Ok(());
        }
        anyhow::bail!("quarantined copy is missing: {}", from.display());
    }
    if to.exists() {
        anyhow::bail!("already exists: {}", to.display());
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    backup::move_path(from, to)
        .with_context(|| format!("moving {} back to {}", from.display(), to.display()))
}

fn path_add(hive: Hive, entry: &str, index: Option<usize>) -> Result<()> {
    let key = environment_key(hive);
    // Exactly as it was recorded: the backup holds the strings the removal
    // actually took out, and two entries for one folder that differ only by a
    // trailing slash are two entries, both of which belong back.
    let entries = system::path_entries(hive);
    if entries.iter().any(|e| e.eq_ignore_ascii_case(entry)) {
        return Ok(());
    }
    // A Path that is gone entirely still gets its entry back, as the type the
    // entry itself calls for.
    let (current, vtype) = match registry::read_raw(hive, key, "Path") {
        Some(raw) => {
            let text = <String as winreg::types::FromRegValue>::from_reg_value(&raw)
                .context("decoding Path")?;
            let vtype = raw.vtype;
            (text, vtype)
        }
        None if entry.contains('%') => (String::new(), winreg::enums::RegType::REG_EXPAND_SZ),
        None => (String::new(), winreg::enums::RegType::REG_SZ),
    };
    // Back where it was, not at the end: the order of Path decides which of
    // two programs of the same name runs.
    let mut parts: Vec<&str> = current.split(';').filter(|e| !e.is_empty()).collect();
    put_back(&mut parts, entry, index);
    let joined = parts.join(";");
    let bytes: Vec<u8> = joined
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    registry::write_raw(
        hive,
        key,
        "Path",
        &RegValue {
            bytes: bytes.into(),
            vtype,
        },
    )
    .context("writing Path")?;
    // Without this, running shells keep the Path that is missing the entry.
    system::broadcast_environment_change();
    Ok(())
}

/// Insert a `Path` entry at its recorded position, or at the end.
pub(crate) fn put_back<'a>(parts: &mut Vec<&'a str>, entry: &'a str, index: Option<usize>) {
    let at = index.unwrap_or(parts.len()).min(parts.len());
    parts.insert(at, entry);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::BackupSession;
    use crate::model::LeftoverKind;

    fn fixture(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("oxidize_restore_{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn listed(session: &BackupSession) -> BackupInfo {
        backup::list_backups()
            .unwrap()
            .into_iter()
            .find(|b| b.path == session.root())
            .unwrap()
    }

    fn cleanup(session: &BackupSession, root: &Path) {
        let base = backup::backups_base().unwrap();
        let _ = fs::remove_dir_all(session.root());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir(&base);
        let _ = fs::remove_dir(base.parent().unwrap());
    }

    #[test]
    fn a_complete_restore_lists_the_backup_as_restored() {
        let root = fixture("complete");
        let file = root.join("settings.ini");
        fs::write(&file, "x=1").unwrap();
        let mut session = BackupSession::new("Oxidize Restored Test").unwrap();
        session.quarantine(LeftoverKind::File, &file).unwrap();
        assert!(listed(&session).restored.is_none());

        // A dry run checks, and marks nothing.
        restore(&listed(&session), true).unwrap();
        assert!(listed(&session).restored.is_none());

        let items = restore(&listed(&session), false).unwrap();
        assert!(items.iter().all(|i| i.result.is_ok()));
        assert_eq!(fs::read_to_string(&file).unwrap(), "x=1");
        let info = listed(&session);
        assert!(info.restored.is_some());
        assert_eq!(info.items, 1);
        let json = serde_json::to_value(&info).unwrap();
        assert!(json["restored"].is_string());
        cleanup(&session, &root);
    }

    #[test]
    fn a_partial_restore_stays_unmarked() {
        let root = fixture("partial");
        let (a, b) = (root.join("a.txt"), root.join("b.txt"));
        fs::write(&a, "a").unwrap();
        fs::write(&b, "b").unwrap();
        let mut session = BackupSession::new("Oxidize Partial Restore Test").unwrap();
        session.quarantine(LeftoverKind::File, &a).unwrap();
        session.quarantine(LeftoverKind::File, &b).unwrap();
        // Something new sits where b was, so b cannot go back.
        fs::write(&b, "new").unwrap();
        let items = restore(&listed(&session), false).unwrap();
        assert_eq!(items.iter().filter(|i| i.result.is_err()).count(), 1);
        assert!(listed(&session).restored.is_none());
        cleanup(&session, &root);
    }
}
