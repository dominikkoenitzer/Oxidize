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
        let result = match stays_inside(&info.path, &entry.undo) {
            Err(e) => Err(e),
            Ok(()) if dry_run => check(&entry.undo),
            Ok(()) => undo(&entry.undo),
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
        // What went home leaves the folders it sat in behind, empty.
        prune_empty_dirs(&info.path.join("files"));
    }
    Ok(out)
}

/// Remove `dir` and the folders below it that hold nothing, deepest first.
/// A folder with anything in it stays, and links are never followed.
fn prune_empty_dirs(dir: &Path) {
    let Ok(meta) = fs::symlink_metadata(dir) else {
        return;
    };
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry
                .file_type()
                .is_ok_and(|t| t.is_dir() && !t.is_symlink())
            {
                prune_empty_dirs(&entry.path());
            }
        }
    }
    let _ = fs::remove_dir(dir);
}

/// An entry may only take its copy out of this backup and only put it back
/// where that copy came from. The manifest is a plain file in the user's
/// folder, and a restore can run as administrator: an entry pointing
/// anywhere else is refused, not followed.
fn stays_inside(root: &Path, action: &Undo) -> Result<()> {
    match action {
        Undo::RegImport { file } | Undo::TaskImport { file, .. } => {
            if !within(root, file) {
                anyhow::bail!("refused: {} is not part of this backup", file.display());
            }
        }
        Undo::MoveBack { from, to } => {
            if !within(&root.join("files"), from) {
                anyhow::bail!("refused: {} is not part of this backup", from.display());
            }
            let origin = origin_of(root, from);
            if origin.as_deref().map(norm) != Some(norm(to)) {
                anyhow::bail!(
                    "refused: the copy at {} did not come from {}",
                    from.display(),
                    to.display()
                );
            }
            if crate::scanner::is_protected_path(to) {
                anyhow::bail!("refused: {} is a protected folder", to.display());
            }
        }
        Undo::PathAdd { .. } | Undo::ValueWrite { .. } | Undo::RawValueWrite { .. } => {}
    }
    Ok(())
}

fn norm(p: &Path) -> String {
    p.to_string_lossy()
        .to_lowercase()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_string()
}

/// `p` lies below `dir`, written plainly, with no `..` that could climb out
/// and no folder on the way that leads somewhere else.
fn within(dir: &Path, p: &Path) -> bool {
    use std::path::Component;
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let (d, s) = (norm(dir), norm(p));
    if !(s.len() > d.len() && s.starts_with(&format!("{d}\\"))) {
        return false;
    }
    // The item itself may be a link (a junction was quarantined as one), but
    // the folders holding it are the backup's own.
    match (p.parent().map(fs::canonicalize), fs::canonicalize(dir)) {
        (Some(Ok(parent)), Ok(dir)) => parent.starts_with(&dir),
        _ => true,
    }
}

/// Where a quarantined copy came from: `<backup>\files\C\ProgramData\Foo`
/// was `C:\ProgramData\Foo`, and `<backup>\files\server\share\Foo` was
/// `\\server\share\Foo`. The reverse of the quarantine's own naming.
fn origin_of(root: &Path, from: &Path) -> Option<std::path::PathBuf> {
    let files = norm(&root.join("files"));
    let s = from.to_string_lossy().replace('/', "\\");
    if !s.to_lowercase().starts_with(&format!("{files}\\")) {
        return None;
    }
    let rest = s.get(files.len() + 1..)?;
    let (first, tail) = rest.split_once('\\').unwrap_or((rest, ""));
    if first.is_empty() {
        return None;
    }
    let first_is_drive = first.len() == 1 && first.as_bytes()[0].is_ascii_alphabetic();
    Some(if first_is_drive {
        format!("{first}:\\{tail}").into()
    } else {
        format!(r"\\{first}\{tail}").into()
    })
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
        // The same answers the real run gives: a copy with something new in
        // its place stays where it is, and one already home is fine.
        Undo::MoveBack { from, to } => match (from.exists(), to.exists()) {
            (true, true) => anyhow::bail!("already exists: {}", to.display()),
            (false, false) => {
                anyhow::bail!("the quarantined copy is missing: {}", from.display())
            }
            _ => Ok(()),
        },
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
        // The folders the copy sat in went with it; the manifest stays.
        assert!(!session.root().join("files").exists());
        assert!(session.root().join(backup::MANIFEST).exists());
        cleanup(&session, &root);
    }

    #[test]
    fn a_copy_goes_back_only_where_it_came_from() {
        let root = Path::new(r"C:\B\backups\2026-10-18 Example");
        let origin = |from: &str| origin_of(root, Path::new(from));
        assert_eq!(
            origin(r"C:\B\backups\2026-10-18 Example\files\C\ProgramData\Foo"),
            Some(r"C:\ProgramData\Foo".into())
        );
        assert_eq!(
            origin(r"c:\b\BACKUPS\2026-10-18 example\files\D\Games\Foo\a.ini"),
            Some(r"D:\Games\Foo\a.ini".into())
        );
        assert_eq!(
            origin(r"C:\B\backups\2026-10-18 Example\files\server\share\Foo"),
            Some(r"\\server\share\Foo".into())
        );
        for outside in [
            r"C:\B\backups\2026-10-18 Example\registry\x.reg",
            r"C:\B\backups\2026-10-18 Example\files",
            r"C:\B\backups\2026-10-18 Example\filesX\C\Foo",
            r"C:\Elsewhere\files\C\Foo",
        ] {
            assert_eq!(origin(outside), None, "{outside}");
        }
    }

    #[test]
    fn an_entry_that_points_outside_its_backup_is_refused() {
        let root = fixture("outside");
        let file = root.join("settings.ini");
        fs::write(&file, "x=1").unwrap();
        let mut session = BackupSession::new("Oxidize Outside Test").unwrap();
        session.quarantine(LeftoverKind::File, &file).unwrap();

        // Entries a hand-edited manifest could hold: a copy taken from
        // anywhere, put back anywhere, or a registry file from elsewhere.
        let stranger = root.join("stranger.txt");
        fs::write(&stranger, "not the backup's").unwrap();
        let elsewhere = root.join("moved here.txt");
        let own_copy = session.root().join("files").join("C").join("other.txt");
        fs::create_dir_all(own_copy.parent().unwrap()).unwrap();
        fs::write(&own_copy, "copy").unwrap();
        let climbing = session
            .root()
            .join("files")
            .join("..")
            .join("..")
            .join("stranger.txt");
        let forged = [
            Undo::MoveBack {
                from: stranger.clone(),
                to: elsewhere.clone(),
            },
            Undo::MoveBack {
                from: own_copy.clone(),
                to: elsewhere.clone(),
            },
            Undo::MoveBack {
                from: climbing,
                to: elsewhere.clone(),
            },
            Undo::RegImport {
                file: root.join("anything.reg"),
            },
            Undo::TaskImport {
                name: r"\Example".into(),
                file: root.join("anything.xml"),
            },
        ];
        let mut manifest = backup::read_manifest(session.root()).unwrap();
        for undo in forged {
            manifest.entries.insert(
                0,
                backup::ManifestEntry {
                    kind: LeftoverKind::File,
                    path: "forged".into(),
                    undo,
                },
            );
        }
        fs::write(
            session.root().join(backup::MANIFEST),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();

        for dry_run in [true, false] {
            let items = restore(&listed(&session), dry_run).unwrap();
            let refused: Vec<_> = items.iter().filter(|i| i.path == "forged").collect();
            assert_eq!(refused.len(), 5);
            for item in refused {
                let err = item.result.as_ref().unwrap_err();
                assert!(err.starts_with("refused:"), "{err}");
            }
        }
        // The real entry came home; nothing else moved.
        assert_eq!(fs::read_to_string(&file).unwrap(), "x=1");
        assert_eq!(fs::read_to_string(&stranger).unwrap(), "not the backup's");
        assert!(own_copy.exists());
        assert!(!elsewhere.exists());
        assert!(listed(&session).restored.is_none());
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
        // Something new sits where b was, so b cannot go back, and the dry
        // run says so before the real one finds out.
        fs::write(&b, "new").unwrap();
        let preview = restore(&listed(&session), true).unwrap();
        assert_eq!(preview.iter().filter(|i| i.result.is_err()).count(), 1);
        let items = restore(&listed(&session), false).unwrap();
        assert_eq!(items.iter().filter(|i| i.result.is_err()).count(), 1);
        assert!(listed(&session).restored.is_none());
        // The copy that could not go back is still there to try again.
        assert!(session.root().join("files").exists());
        cleanup(&session, &root);
    }
}
