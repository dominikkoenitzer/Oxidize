//! Administrator detection, self-elevation, and the one function every
//! destructive action goes through.
//!
//! Leftovers are only ever deleted through [`remove_leftovers`]; the one other
//! destructive call is the guarded Store-app removal in `packages.rs`. A dry
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
    /// A dry run: the item would be removed.
    WouldRemove,
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
    /// Vendor registry keys that were left empty and removed too.
    pub emptied_keys: Vec<String>,
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
/// forwarding our arguments, without waiting for it. Exit after this
/// returns `Ok`.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<()> {
    use windows::Win32::Foundation::CloseHandle;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let process = shell_runas(&elevated_params(None, &args))?;
    unsafe {
        let _ = CloseHandle(process);
    }
    Ok(())
}

/// Run this command line again as administrator (UAC prompt) and wait for
/// it. With `result_file` the elevated run writes its stdout there. Returns
/// the run's exit code.
#[cfg(windows)]
pub fn run_elevated(result_file: Option<&Path>) -> Result<i32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let process = shell_runas(&elevated_params(result_file, &args))?;
    let mut code = 1u32;
    let read = unsafe {
        WaitForSingleObject(process, INFINITE);
        let read = GetExitCodeProcess(process, &mut code);
        let _ = CloseHandle(process);
        read
    };
    read.context("reading the exit code of the elevated run")?;
    Ok(code as i32)
}

/// Start this program through the "runas" verb with `params` and return
/// its process handle. A declined UAC prompt is [`Failure::cancelled`].
#[cfg(windows)]
fn shell_runas(params: &str) -> Result<windows::Win32::Foundation::HANDLE> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::ERROR_CANCELLED;
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_NORMAL;

    let wide = |s: &OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    let exe = std::env::current_exe().context("resolving current executable path")?;
    let exe_w = wide(exe.as_os_str());
    let params_w = wide(OsStr::new(params));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: if params.is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(params_w.as_ptr())
        },
        nShow: SW_NORMAL.0,
        ..Default::default()
    };
    if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
        if e.code() == ERROR_CANCELLED.to_hresult() {
            return Err(
                crate::exit::Failure::cancelled("the UAC prompt was declined", false).into(),
            );
        }
        bail!("could not relaunch elevated: {e}");
    }
    if info.hProcess.is_invalid() {
        bail!("could not relaunch elevated: Windows returned no process");
    }
    Ok(info.hProcess)
}

/// The arguments of an elevated run: the result file first, so it comes
/// before the subcommand and any `--`, then ours unchanged.
#[cfg(windows)]
fn elevated_params(result_file: Option<&Path>, args: &[String]) -> String {
    let mut all = Vec::with_capacity(args.len() + 2);
    if let Some(path) = result_file {
        all.push(quote_arg("--result-file"));
        all.push(quote_arg(&path.to_string_lossy()));
    }
    all.extend(args.iter().map(|a| quote_arg(a)));
    all.join(" ")
}

/// Start of the name of every file an elevated run writes its output to.
const RESULT_FILE_PREFIX: &str = "oxidize-elevated-";

/// New empty files in `%TEMP%` for an elevated run's stdout and stderr.
/// Returns the stdout file; [`error_file`] names the other.
pub fn new_result_file() -> Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let name = format!("{RESULT_FILE_PREFIX}{}-{stamp}.out", std::process::id());
    let path = std::env::temp_dir().join(name);
    for file in [path.clone(), error_file(&path)] {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file)
            .with_context(|| format!("creating {}", file.display()))?;
    }
    Ok(path)
}

/// The stderr file next to a result file.
pub fn error_file(result_file: &Path) -> PathBuf {
    result_file.with_extension("err")
}

/// Whether `path` is named like a file [`new_result_file`] makes. An
/// elevated run writes to no other.
pub fn is_result_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(RESULT_FILE_PREFIX) && n.ends_with(".out"))
}

/// Send this process's stdout to `path`, an existing result file, and its
/// stderr to the [`error_file`] next to it. Call it before anything is
/// printed. Rust's stdout and stderr ask Windows for the handle on every
/// write, so `println!` and `eprintln!` follow.
#[cfg(windows)]
pub fn send_output_to(path: &Path) -> Result<()> {
    use windows::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};

    if !is_result_file(path) {
        bail!("{} is not a result file", path.display());
    }
    redirect(STD_OUTPUT_HANDLE, path)?;
    redirect(STD_ERROR_HANDLE, &error_file(path))
}

/// Point one standard handle at an existing file, which stays open until
/// the process ends.
#[cfg(windows)]
fn redirect(which: windows::Win32::System::Console::STD_HANDLE, path: &Path) -> Result<()> {
    use std::os::windows::io::IntoRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::SetStdHandle;

    let file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let handle = HANDLE(file.into_raw_handle());
    unsafe { SetStdHandle(which, handle) }
        .with_context(|| format!("redirecting output to {}", path.display()))
}

#[cfg(not(windows))]
pub fn run_elevated(_result_file: Option<&Path>) -> Result<i32> {
    bail!("elevation is only supported on Windows")
}

#[cfg(not(windows))]
pub fn send_output_to(_path: &Path) -> Result<()> {
    bail!("redirecting output is only supported on Windows")
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
            [
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramW6432",
                "ProgramData",
            ]
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
        outcome.items = items
            .iter()
            .map(|l| ItemOutcome {
                path: l.path.clone(),
                kind: l.kind,
                status: ItemStatus::WouldRemove,
            })
            .collect();
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
    let mut removed_keys: Vec<(crate::model::Hive, String)> = Vec::new();
    for item in items {
        outcome.attempted += 1;
        let status = match remove_one(item, session.as_mut(), &tasks) {
            Ok(true) => {
                outcome.deleted += 1;
                if matches!(item.kind, LeftoverKind::File | LeftoverKind::Directory) {
                    removed_fs.push(PathBuf::from(&item.path));
                }
                if item.kind == LeftoverKind::RegistryKey {
                    if let (Some(hive), Some(subpath)) = (item.hive, item.subpath.as_deref()) {
                        removed_keys.push((hive, subpath.to_string()));
                    }
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

    // The same for a vendor key that held nothing but this product. The
    // product's own .reg backup recreates the parent on restore.
    for (hive, subpath) in removed_keys {
        if let Some(parent) = empty_vendor_key(hive, &subpath) {
            if registry::delete_key_tree(hive, &parent).is_ok() {
                outcome
                    .emptied_keys
                    .push(format!("{}\\{}", hive.short_name(), parent));
            }
        }
    }

    if let Some(s) = &session {
        outcome.backup_dir = Some(s.root().to_path_buf());
        outcome.backup_name = Some(s.name());
    }
    Ok(outcome)
}

/// The vendor key a removed product key sat under, by name alone. Only
/// `SOFTWARE\<vendor>` in either view qualifies, never a root and never a
/// denied name.
fn vendor_key_above(subpath: &str) -> Option<&str> {
    let (parent, _) = subpath.rsplit_once('\\')?;
    let (root, vendor) = parent.rsplit_once('\\')?;
    let is_software_root =
        root.eq_ignore_ascii_case("SOFTWARE") || root.eq_ignore_ascii_case(r"SOFTWARE\WOW6432Node");
    (is_software_root && !scanner::reg_denied(vendor)).then_some(parent)
}

/// That same vendor key, if the product was all it held.
fn empty_vendor_key(hive: crate::model::Hive, subpath: &str) -> Option<String> {
    let parent = vendor_key_above(subpath)?;
    registry::key_is_empty(hive, parent).then(|| parent.to_string())
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
            if registry::key_absent(hive, subpath) {
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
            if registry::value_absent(hive, subpath, value) {
                return Ok(false);
            }
            // Only the value is recorded, never the key around it. Exporting
            // the containing key would carry every other program in it, and a
            // Run key belongs to the whole machine.
            if let Some(s) = session {
                let raw =
                    registry::read_raw(hive, subpath, value).context("reading registry value")?;
                s.backup_value(item.kind, &item.path, hive, subpath, value, &raw)
                    .context("backing up registry value")?;
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
            if registry::key_absent(crate::model::Hive::LocalMachine, subpath) {
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
            // The removal takes every entry for the same folder, so the backup
            // records each of them, not only the one that was flagged.
            let matches = system::matching_path_entries(hive, entry);
            if matches.is_empty() {
                return Ok(false);
            }
            if let Some(s) = session {
                record_path_entries(s, &item.path, hive, &matches)?;
            }
            system::remove_path_entry(hive, entry)?;
            Ok(true)
        }
    }
}

/// Record the `Path` entries one removal takes out, with their positions.
/// Restore replays the manifest backwards, so the last entry is recorded
/// first: put back front to back, each position is right again by the time
/// the next one goes in.
fn record_path_entries(
    session: &mut BackupSession,
    display: &str,
    hive: crate::model::Hive,
    matches: &[(usize, String)],
) -> Result<()> {
    for (index, text) in matches.iter().rev() {
        session
            .backup_path_entry(display, hive, text, *index)
            .context("recording PATH entry")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Hive};

    #[test]
    fn only_a_vendor_key_under_software_can_be_emptied() {
        // A product key two levels down names the vendor key above it.
        assert_eq!(
            vendor_key_above(r"SOFTWARE\Frobnic Labs\Frobnicator"),
            Some(r"SOFTWARE\Frobnic Labs")
        );
        assert_eq!(
            vendor_key_above(r"SOFTWARE\WOW6432Node\Frobnic Labs\Frobnicator"),
            Some(r"SOFTWARE\WOW6432Node\Frobnic Labs")
        );
        // Never a root, a top-level product key, or a denied vendor name.
        assert!(vendor_key_above(r"SOFTWARE\Frobnicator").is_none());
        assert!(vendor_key_above("SOFTWARE").is_none());
        assert!(vendor_key_above(r"SOFTWARE\Microsoft\Office").is_none());
        assert!(vendor_key_above(r"SOFTWARE\NVIDIA Corporation\Global").is_none());
        // A key that does not exist is not empty, so nothing is proposed.
        assert!(empty_vendor_key(Hive::CurrentUser, r"SOFTWARE\NoSuchVendor\NoSuchApp").is_none());
    }

    #[test]
    fn hklm_items_need_administrator_rights() {
        let hklm = Leftover::reg_key(
            Hive::LocalMachine,
            r"SOFTWARE\Vendor",
            Confidence::High,
            "test",
        );
        let hkcu = Leftover::reg_key(
            Hive::CurrentUser,
            r"SOFTWARE\Vendor",
            Confidence::High,
            "test",
        );
        assert!(needs_elevation(&[hklm]));
        assert!(!needs_elevation(&[hkcu]));
    }

    #[test]
    fn two_path_entries_come_back_where_they_were() {
        let before = [r"C:\A", r"C:\Tool", r"C:\B", r"C:\Tool\", r"C:\C"];
        let matches: Vec<(usize, String)> = before
            .iter()
            .enumerate()
            .filter(|(_, e)| system::same_path_entry(e, r"C:\Tool"))
            .map(|(i, e)| (i, e.to_string()))
            .collect();
        let base = crate::backup::backups_base().unwrap();
        let mut session = BackupSession::new("Oxidize Path Order Test").unwrap();
        record_path_entries(&mut session, "PATH entry", Hive::CurrentUser, &matches).unwrap();
        let manifest = crate::backup::read_manifest(session.root()).unwrap();
        let _ = std::fs::remove_dir_all(session.root());
        let _ = std::fs::remove_dir(&base);
        let _ = std::fs::remove_dir(base.parent().unwrap());

        // Restore replays the manifest newest first.
        let mut parts: Vec<&str> = before
            .iter()
            .copied()
            .filter(|e| !system::same_path_entry(e, r"C:\Tool"))
            .collect();
        for entry in manifest.entries.iter().rev() {
            match &entry.undo {
                crate::backup::Undo::PathAdd { entry, index, .. } => {
                    crate::restore::put_back(&mut parts, entry, *index)
                }
                other => panic!("unexpected undo: {other:?}"),
            }
        }
        assert_eq!(parts, before);
    }

    #[test]
    fn an_argument_survives_being_quoted_for_relaunch() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("two words"), "\"two words\"");
        assert_eq!(quote_arg(r"C:\Program Files\"), r#""C:\Program Files\\""#);
    }

    /// Split a command line the way the elevated run's Windows does.
    #[cfg(windows)]
    fn split_like_windows(line: &str) -> Vec<String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::UI::Shell::CommandLineToArgvW;

        let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
        let mut n = 0i32;
        unsafe {
            let argv = CommandLineToArgvW(PCWSTR(wide.as_ptr()), &mut n);
            assert!(!argv.is_null());
            let out = (0..n as usize)
                .map(|i| (*argv.add(i)).to_string().unwrap())
                .collect();
            let _ = LocalFree(Some(HLOCAL(argv as _)));
            out
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_result_file_survives_the_relaunch_command_line() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;

        let path = Path::new(r"C:\Users\Example User\AppData\Local\Temp\oxidize-elevated-7-9.out");
        let args: Vec<String> = [
            "uninstall",
            "Example Player",
            r#"Odd "quoted" name\"#,
            "--json",
            "--yes",
            "--elevate",
            "--",
            "--not-a-flag",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let params = elevated_params(Some(path), &args);
        let argv = split_like_windows(&format!("oxidize.exe {params}"));
        assert_eq!(
            argv[1..3],
            ["--result-file".to_string(), path.display().to_string()]
        );
        assert_eq!(argv[3..], args[..]);

        let cli = Cli::try_parse_from(&argv).unwrap();
        assert_eq!(cli.result_file.as_deref(), Some(path));
        assert!(cli.json && cli.yes && cli.elevate);
        let Commands::Uninstall(u) = cli.command else {
            panic!("not uninstall");
        };
        assert_eq!(
            u.targets,
            ["Example Player", r#"Odd "quoted" name\"#, "--not-a-flag"]
        );

        // Without a result file the arguments go through unchanged.
        let argv = split_like_windows(&format!("oxidize.exe {}", elevated_params(None, &args)));
        assert_eq!(argv[1..], args[..]);
    }

    #[test]
    fn only_a_result_file_takes_the_elevated_output() {
        assert!(is_result_file(Path::new(
            r"C:\Temp\oxidize-elevated-12-345.out"
        )));
        for path in [
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Temp\oxidize-elevated-12-345.txt",
            r"C:\Temp\other-12-345.out",
            r"C:\Temp\",
        ] {
            assert!(!is_result_file(Path::new(path)), "{path}");
            // Refused before anything is opened or redirected.
            assert!(send_output_to(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn a_result_file_is_new_and_empty() {
        let a = new_result_file().unwrap();
        let b = new_result_file().unwrap();
        assert_ne!(a, b);
        assert!(is_result_file(&a));
        assert!(!is_result_file(&error_file(&a)));
        for file in [&a, &error_file(&a)] {
            assert_eq!(std::fs::metadata(file).unwrap().len(), 0);
        }
        assert!(a.starts_with(std::env::temp_dir()));
        assert_eq!(error_file(&a).extension().unwrap(), "err");
        for file in [&a, &b] {
            let _ = std::fs::remove_file(file);
            let _ = std::fs::remove_file(error_file(file));
        }
    }
}
