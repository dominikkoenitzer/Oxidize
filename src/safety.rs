//! Administrator detection, self-elevation, and the one function every
//! destructive action goes through.
//!
//! Nothing in Oxidize deletes anything except via [`remove_leftovers`]. A dry
//! run changes nothing, registry keys are exported before deletion, files are
//! quarantined rather than destroyed, and everything removed is written to a
//! manifest that `oxidize restore` can replay.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::backup::BackupSession;
use crate::model::{Leftover, LeftoverKind};
use crate::scanner;
use crate::{registry, system};

#[derive(Debug, Clone, Copy)]
pub struct SafetyContext {
    pub dry_run: bool,
    /// True unless `--no-backup`.
    pub make_backups: bool,
}

#[derive(Debug, Clone)]
pub enum ItemStatus {
    Removed,
    AlreadyGone,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ItemOutcome {
    pub path: String,
    pub kind: LeftoverKind,
    pub status: ItemStatus,
}

#[derive(Debug, Default, Clone)]
pub struct DeletionOutcome {
    pub attempted: usize,
    pub deleted: usize,
    pub skipped: usize,
    pub failed: usize,
    pub backup_dir: Option<PathBuf>,
    pub backup_name: Option<String>,
    pub items: Vec<ItemOutcome>,
    /// Vendor folders that were left empty and removed too.
    pub emptied_parents: Vec<PathBuf>,
}

// Elevation
// ---------

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// Relaunch the current process through the shell "runas" verb (UAC prompt),
/// forwarding our arguments. Exit after this returns `Ok`.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{w, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_NORMAL;

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let exe_w: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let joined = std::env::args()
        .skip(1)
        .map(|a| quote_arg(&a))
        .collect::<Vec<_>>()
        .join(" ");
    let params_w: Vec<u16> = OsStr::new(&joined)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result = ShellExecuteW(
            None,
            w!("runas"),
            PCWSTR(exe_w.as_ptr()),
            if joined.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR(params_w.as_ptr())
            },
            PCWSTR::null(),
            SW_NORMAL,
        );
        if (result.0 as isize) <= 32 {
            bail!("could not relaunch elevated; the UAC prompt may have been declined");
        }
    }
    Ok(())
}

/// Quote one argument so `CommandLineToArgvW` parses it back unchanged.
#[cfg(windows)]
fn quote_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .bytes()
            .any(|b| b == b' ' || b == b'\t' || b == b'"' || b == b'\\');
    if !needs_quotes {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..backslashes * 2 + 1 {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('"');
    out
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<()> {
    bail!("elevation is only supported on Windows")
}

/// Does any of these items need administrator rights to remove?
pub fn needs_elevation(items: &[Leftover]) -> bool {
    items.iter().any(|l| match l.kind {
        LeftoverKind::RegistryKey | LeftoverKind::RegistryValue | LeftoverKind::PathEntry => {
            l.hive == Some(crate::model::Hive::LocalMachine)
        }
        LeftoverKind::Service | LeftoverKind::FirewallRule => true,
        LeftoverKind::ScheduledTask => true,
        LeftoverKind::File | LeftoverKind::Directory => {
            let p = Path::new(&l.path);
            ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"]
                .iter()
                .filter_map(|v| scanner::env_dir(v))
                .any(|root| system::path_under(p, &root))
        }
    })
}

// The one destructive choke point
// -------------------------------

/// Remove the given leftovers under the safety context.
pub fn remove_leftovers(
    items: &[Leftover],
    program_label: &str,
    ctx: &SafetyContext,
) -> Result<DeletionOutcome> {
    let mut outcome = DeletionOutcome::default();
    if items.is_empty() {
        return Ok(outcome);
    }

    if ctx.dry_run {
        outcome.attempted = items.len();
        outcome.skipped = items.len();
        return Ok(outcome);
    }

    // With backups on, failing to create the backup folder aborts. There is
    // no fall-through to an unbacked deletion; --no-backup is the opt out.
    let mut session = if ctx.make_backups {
        match BackupSession::new(program_label) {
            Ok(session) => Some(session),
            Err(e) => bail!(
                "could not create the backup folder ({e:#}); refusing to delete without a backup. \
                 Pass --no-backup to delete anyway."
            ),
        }
    } else {
        None
    };

    // Tasks are looked up once so their XML can be copied before deletion.
    let tasks = if items.iter().any(|l| l.kind == LeftoverKind::ScheduledTask) {
        system::scheduled_tasks()
    } else {
        Vec::new()
    };

    let mut removed_fs: Vec<PathBuf> = Vec::new();
    for item in items {
        outcome.attempted += 1;
        let status = match remove_one(item, session.as_mut(), &tasks) {
            Ok(true) => {
                outcome.deleted += 1;
                if matches!(item.kind, LeftoverKind::File | LeftoverKind::Directory) {
                    removed_fs.push(PathBuf::from(&item.path));
                }
                ItemStatus::Removed
            }
            Ok(false) => {
                outcome.skipped += 1;
                ItemStatus::AlreadyGone
            }
            Err(e) => {
                outcome.failed += 1;
                ItemStatus::Failed(format!("{e:#}"))
            }
        };
        outcome.items.push(ItemOutcome {
            path: item.path.clone(),
            kind: item.kind,
            status,
        });
    }

    // A vendor folder that only held this product is now empty. Removing an
    // empty folder needs no backup; it is recorded so restore recreates it.
    for p in removed_fs {
        if let Some(parent) = p.parent() {
            if !scanner::is_protected_path(parent)
                && !scanner::path_within_shared_dir(parent)
                && scanner::is_dir_empty(parent)
                && std::fs::remove_dir(parent).is_ok()
            {
                outcome.emptied_parents.push(parent.to_path_buf());
            }
        }
    }

    if let Some(s) = &session {
        outcome.backup_dir = Some(s.root().to_path_buf());
        outcome.backup_name = Some(s.name());
    }
    Ok(outcome)
}

/// `Ok(true)` removed, `Ok(false)` already gone.
fn remove_one(
    item: &Leftover,
    session: Option<&mut BackupSession>,
    tasks: &[system::TaskInfo],
) -> Result<bool> {
    match item.kind {
        LeftoverKind::RegistryKey => {
            let hive = item.hive.context("registry leftover missing hive")?;
            let subpath = item
                .subpath
                .as_deref()
                .context("registry leftover missing path")?;
            if !registry::key_exists(hive, subpath) {
                return Ok(false);
            }
            if let Some(s) = session {
                s.backup_registry_key(item.kind, &item.path, hive, subpath)
                    .context("backing up registry key")?;
            }
            registry::delete_key_tree(hive, subpath).context("deleting registry key")?;
            Ok(true)
        }
        LeftoverKind::RegistryValue | LeftoverKind::FirewallRule => {
            let hive = item.hive.context("registry leftover missing hive")?;
            let subpath = item
                .subpath
                .as_deref()
                .context("registry leftover missing path")?;
            let value = item
                .value_name
                .as_deref()
                .context("value leftover missing name")?;
            let Some(data) = registry::read_string(hive, subpath, value) else {
                if !registry::value_exists(hive, subpath, value) {
                    return Ok(false);
                }
                // Record the raw type and bytes. Exporting the containing key
                // instead would carry every other program in it, and a Run key
                // belongs to the whole machine.
                if let Some(s) = session {
                    let raw = registry::read_raw(hive, subpath, value)
                        .context("reading registry value")?;
                    s.backup_raw_value(item.kind, &item.path, hive, subpath, value, &raw)
                        .context("backing up registry value")?;
                }
                registry::delete_value(hive, subpath, value).context("deleting registry value")?;
                return Ok(true);
            };
            if let Some(s) = session {
                s.backup_value(item.kind, &item.path, hive, subpath, value, &data)
                    .context("recording registry value")?;
            }
            registry::delete_value(hive, subpath, value).context("deleting registry value")?;
            Ok(true)
        }
        LeftoverKind::File | LeftoverKind::Directory => {
            let path = PathBuf::from(&item.path);
            if !path.exists() {
                return Ok(false);
            }
            if scanner::is_protected_path(&path) {
                bail!("protected path");
            }
            match session {
                Some(s) => {
                    s.quarantine(item.kind, &path)
                        .context("moving to quarantine")?;
                }
                None => crate::backup::remove_path(&path).context("deleting")?,
            }
            Ok(true)
        }
        LeftoverKind::Service => {
            let name = item
                .name
                .as_deref()
                .context("service leftover missing name")?;
            let subpath = item
                .subpath
                .as_deref()
                .context("service leftover missing key")?;
            if !registry::key_exists(crate::model::Hive::LocalMachine, subpath) {
                return Ok(false);
            }
            if let Some(s) = session {
                s.backup_registry_key(
                    item.kind,
                    &item.path,
                    crate::model::Hive::LocalMachine,
                    subpath,
                )
                .context("backing up service key")?;
            }
            system::delete_service(name)?;
            Ok(true)
        }
        LeftoverKind::ScheduledTask => {
            let name = item.name.as_deref().context("task leftover missing name")?;
            let Some(task) = tasks.iter().find(|t| t.name.eq_ignore_ascii_case(name)) else {
                return Ok(false);
            };
            if let Some(s) = session {
                s.backup_task(&item.path, task).context("backing up task")?;
            }
            system::delete_task(name)?;
            Ok(true)
        }
        LeftoverKind::PathEntry => {
            let hive = item.hive.context("path leftover missing hive")?;
            let entry = item
                .name
                .as_deref()
                .context("path leftover missing entry")?;
            let present = system::path_entries(hive)
                .iter()
                .any(|e| e.eq_ignore_ascii_case(entry));
            if !present {
                return Ok(false);
            }
            if let Some(s) = session {
                s.backup_path_entry(&item.path, hive, entry)
                    .context("recording PATH entry")?;
            }
            system::remove_path_entry(hive, entry)?;
            Ok(true)
        }
    }
}
