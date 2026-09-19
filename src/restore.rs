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
            Ok(())
        } else {
            undo(&entry.undo).map_err(|e| format!("{e:#}"))
        };
        out.push(RestoreItem {
            path: entry.path.clone(),
            result,
        });
    }
    Ok(out)
}

fn undo(action: &Undo) -> Result<()> {
    match action {
        Undo::RegImport { file } => backup::import_registry_file(file),
        Undo::MoveBack { from, to } => move_back(from, to),
        Undo::TaskImport { name, file } => system::import_task(name, file),
        Undo::PathAdd { hive, entry } => path_add(*hive, entry),
        Undo::ValueWrite {
            hive,
            subpath,
            name,
            data,
        } => {
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
                    vtype: winreg::enums::RegType::REG_SZ,
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
        anyhow::bail!("quarantined copy is missing: {}", from.display());
    }
    if to.exists() {
        anyhow::bail!("already exists: {}", to.display());
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::rename(from, to)
        .with_context(|| format!("moving {} back to {}", from.display(), to.display()))
}

fn path_add(hive: Hive, entry: &str) -> Result<()> {
    let key = environment_key(hive);
    if system::path_entries(hive)
        .iter()
        .any(|e| e.eq_ignore_ascii_case(entry))
    {
        return Ok(());
    }
    let raw = registry::read_raw(hive, key, "Path").context("reading Path")?;
    let current =
        <String as winreg::types::FromRegValue>::from_reg_value(&raw).context("decoding Path")?;
    let joined = if current.trim_end_matches(';').is_empty() {
        entry.to_string()
    } else {
        format!("{};{entry}", current.trim_end_matches(';'))
    };
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
            vtype: raw.vtype,
        },
    )
    .context("writing Path")
}
