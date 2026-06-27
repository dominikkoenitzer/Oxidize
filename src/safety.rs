//! The safety layer: administrator-privilege detection (and optional
//! self-elevation), plus the single choke point through which every destructive
//! action passes. Nothing in Oxidize deletes a registry key or a file except via
//! [`remove_leftovers`], which guarantees: dry-run shows-but-never-touches,
//! registry keys are exported to a `.reg` before deletion, and files are moved
//! to a reversible quarantine rather than destroyed.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::backup::BackupSession;
use crate::model::{Leftover, LeftoverKind};
use crate::registry;
use crate::term;

/// User-controlled safety switches, threaded through every destructive call.
#[derive(Debug, Clone, Copy)]
pub struct SafetyContext {
    /// Show what would happen, change nothing.
    pub dry_run: bool,
    /// Create backups before deleting (true unless `--no-backup`).
    pub make_backups: bool,
}

/// Tally of a removal pass.
#[derive(Debug, Default, Clone)]
pub struct DeletionOutcome {
    pub attempted: usize,
    pub deleted: usize,
    /// Already gone, or skipped in dry-run.
    pub skipped: usize,
    pub failed: usize,
    pub backup_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Elevation
// ---------------------------------------------------------------------------

/// Is this process running with an elevated (Administrator) token?
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

/// Relaunch the current process elevated via the shell "runas" verb (triggers a
/// UAC prompt), forwarding our command-line arguments. The caller should exit
/// after this returns `Ok`.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{w, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_NORMAL;

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // Forward our own arguments (everything after argv[0]), quoted with the same
    // rules the elevated instance will use to parse them (see util::split_command_line).
    let joined = std::env::args()
        .skip(1)
        .map(|a| quote_arg(&a))
        .collect::<Vec<_>>()
        .join(" ");
    let params_w: Vec<u16> = OsStr::new(&joined).encode_wide().chain(std::iter::once(0)).collect();

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
        // ShellExecuteW returns an HINSTANCE; a value <= 32 indicates failure.
        if (result.0 as isize) <= 32 {
            bail!("could not relaunch elevated (the UAC prompt may have been declined)");
        }
    }
    Ok(())
}

/// Quote a single argument for a Windows command line so that
/// `CommandLineToArgvW` (and our [`crate::util::split_command_line`]) parses it
/// back to the original string. This is the standard MSDN round-trip algorithm
/// (double backslashes that precede a quote, and any trailing backslashes).
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
                // Escape the run of backslashes (doubled) plus the quote.
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
    // Double any trailing backslashes so they don't escape the closing quote.
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

/// Warn (on stderr) when not elevated, since registry/system-folder writes need
/// Administrator rights.
pub fn warn_if_not_elevated() {
    if !is_elevated() {
        term::warn(
            "Oxidize is not running as Administrator. Reading is fine, but removing \
             HKLM keys or files under Program Files/ProgramData will fail. Re-run from \
             an elevated terminal, or use `oxidize ... --elevate` to trigger a UAC prompt.",
        );
    }
}

// ---------------------------------------------------------------------------
// The single destructive choke point
// ---------------------------------------------------------------------------

/// Remove the given leftovers, honouring the safety context. Prints per-item
/// progress and returns a tally.
pub fn remove_leftovers(
    items: &[Leftover],
    program_label: &str,
    ctx: &SafetyContext,
) -> Result<DeletionOutcome> {
    let mut outcome = DeletionOutcome::default();
    if items.is_empty() {
        return Ok(outcome);
    }

    // Dry-run: describe and stop.
    if ctx.dry_run {
        for item in items {
            println!(
                "  {} {} {}",
                term::dim("would remove"),
                kind_tag(item.kind),
                item.path
            );
        }
        outcome.attempted = items.len();
        outcome.skipped = items.len();
        return Ok(outcome);
    }

    // Set up the backup session (unless backups are disabled).
    // When backups are enabled (the default) the user is relying on them, so a
    // failure to create the backup directory must abort — we never silently fall
    // through to unbacked deletion, even with --yes. (Use --no-backup to opt out
    // explicitly.)
    let session = if ctx.make_backups {
        match BackupSession::new(program_label) {
            Ok(session) => {
                term::info(&format!("Backups in {}", session.root().display()));
                Some(session)
            }
            Err(e) => bail!(
                "could not create backup directory ({e:#}); refusing to delete without a backup. \
                 Pass --no-backup to delete without backups."
            ),
        }
    } else {
        None
    };

    for item in items {
        outcome.attempted += 1;
        match remove_one(item, session.as_ref(), ctx.make_backups) {
            Ok(true) => {
                outcome.deleted += 1;
                term::success(&format!("removed {} {}", kind_tag(item.kind), item.path));
            }
            Ok(false) => {
                outcome.skipped += 1;
                term::info(&format!("already gone: {}", item.path));
            }
            Err(e) => {
                outcome.failed += 1;
                term::error(&format!("failed to remove {}: {e:#}", item.path));
            }
        }
    }

    outcome.backup_dir = session.as_ref().map(|s| s.root().to_path_buf());
    Ok(outcome)
}

/// Remove a single leftover. Returns `Ok(true)` if removed, `Ok(false)` if it
/// was already gone.
fn remove_one(item: &Leftover, session: Option<&BackupSession>, make_backups: bool) -> Result<bool> {
    match item.kind {
        LeftoverKind::RegistryKey => {
            let hive = item.hive.context("registry leftover missing hive")?;
            let subpath = item.subpath.as_deref().context("registry leftover missing path")?;
            if !registry::key_exists(hive, subpath) {
                return Ok(false);
            }
            if make_backups {
                if let Some(session) = session {
                    session
                        .backup_registry_key(hive, subpath)
                        .context("backing up registry key before deletion")?;
                }
            }
            registry::delete_key_tree(hive, subpath).context("deleting registry key")?;
            Ok(true)
        }
        LeftoverKind::RegistryValue => {
            let hive = item.hive.context("registry leftover missing hive")?;
            let subpath = item.subpath.as_deref().context("registry leftover missing path")?;
            let value = item.value_name.as_deref().context("value leftover missing name")?;
            if !registry::value_exists(hive, subpath, value) {
                return Ok(false);
            }
            if make_backups {
                if let Some(session) = session {
                    // Exporting the containing key captures the value too.
                    session
                        .backup_registry_key(hive, subpath)
                        .context("backing up registry key before value deletion")?;
                }
            }
            registry::delete_value(hive, subpath, value).context("deleting registry value")?;
            Ok(true)
        }
        LeftoverKind::File | LeftoverKind::Directory => {
            let path = PathBuf::from(&item.path);
            if !path.exists() {
                return Ok(false);
            }
            if make_backups {
                if let Some(session) = session {
                    session
                        .quarantine(&path)
                        .context("moving to quarantine")?;
                    return Ok(true);
                }
            }
            delete_path_permanently(&path).context("deleting path")?;
            Ok(true)
        }
    }
}

fn delete_path_permanently(p: &Path) -> std::io::Result<()> {
    if p.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    }
}

fn kind_tag(kind: LeftoverKind) -> &'static str {
    match kind {
        LeftoverKind::RegistryKey => "[reg key]",
        LeftoverKind::RegistryValue => "[reg val]",
        LeftoverKind::File => "[file]   ",
        LeftoverKind::Directory => "[dir]    ",
    }
}
