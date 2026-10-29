//! Removing a program completely in one go. Close what runs from its folders,
//! let its own uninstaller run only when Oxidize cannot do the job alone,
//! remove every leftover with a backup, then scan again and say what is left.
//!
//! The decisions here are pure so they can be tested without a PC: which
//! folders belong to the program, which running processes live in them,
//! whether the vendor's uninstaller is needed and what the second scan means.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::model::{
    Confidence, Hive, Leftover, LeftoverKind, Package, Program, ScanReport, ScanTarget,
};
use crate::safety::{DeletionOutcome, SafetyContext};
use crate::uninstall::{Ran, UninstallPlan};
use crate::{scanner, system};

/// How long a program gets to close its windows before the flow stops.
pub const CLOSE_GRACE: Duration = Duration::from_secs(3);

/// The longest the one-shot flow waits for a vendor uninstaller that keeps
/// running after the process it started has exited.
pub const VENDOR_WAIT: Duration = Duration::from_secs(60);

/// One running process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Running {
    pub pid: u32,
    pub exe: PathBuf,
}

/// What happened to one process the flow closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CloseHow {
    /// It closed its windows and exited by itself.
    Closed,
    /// It was still running after the grace period, or had no window to be
    /// asked through. It is left running and the flow stops.
    Running,
    /// It could not be asked, usually for want of administrator rights.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Closed {
    pub pid: u32,
    pub exe: String,
    pub how: CloseHow,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// It had no window, so it could not be asked to close: a helper
    /// running in the background.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub windowless: bool,
}

/// The one error for processes that did not close, or None when all did.
/// Nothing is ended by force, so the flow stops on it.
pub fn still_running(closed: &[Closed]) -> Option<String> {
    let names: Vec<&str> = closed
        .iter()
        .filter(|c| c.how != CloseHow::Closed)
        .map(|c| {
            Path::new(&c.exe)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&c.exe)
        })
        .collect();
    match names.as_slice() {
        [] => None,
        [one] => Some(format!(
            "{one} is still running, so nothing was removed. Close it and try again."
        )),
        many => Some(format!(
            "{} are still running, so nothing was removed. Close them and try again.",
            many.join(", ")
        )),
    }
}

/// The folders a program's processes may run from: its install folder and
/// every folder the scan gives it at High confidence. Protected and shared
/// locations never count, so nothing outside the program is touched.
pub fn owned_dirs(target: &ScanTarget, footprint: &[Leftover]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(loc) = scanner::own_install_folder(target) {
        dirs.push(loc.to_path_buf());
    }
    dirs.extend(
        footprint
            .iter()
            .filter(|l| l.kind == LeftoverKind::Directory && l.confidence == Confidence::High)
            .map(|l| PathBuf::from(&l.path)),
    );
    dirs.retain(|d| {
        d.is_absolute() && !scanner::is_protected_path(d) && !scanner::path_within_shared_dir(d)
    });
    dirs.sort();
    dirs.dedup_by(|a, b| a.as_os_str().eq_ignore_ascii_case(b.as_os_str()));
    dirs
}

/// The processes whose image lives inside one of `dirs`. Anything in the
/// Windows folder and this process itself are never picked.
pub fn processes_in(running: &[Running], dirs: &[PathBuf], own_pid: u32) -> Vec<Running> {
    running
        .iter()
        .filter(|p| p.pid != own_pid && p.pid > 4)
        .filter(|p| !system::in_windows_dir(&p.exe))
        .filter(|p| dirs.iter().any(|d| system::path_under(&p.exe, d)))
        .cloned()
        .collect()
}

/// The processes running from a Store app's install folder. Only a folder
/// named after the package counts, so a sparse package pointing at a
/// program's folder, or a protected folder, never picks anything.
pub fn app_processes(running: &[Running], app: &Package, own_pid: u32) -> Vec<Running> {
    let dirs: Vec<PathBuf> = app
        .installed_path
        .iter()
        .map(PathBuf::from)
        .filter(|d| {
            d.is_absolute()
                && !scanner::is_protected_path(d)
                && d.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.to_lowercase().starts_with(&app.name.to_lowercase()))
        })
        .collect();
    processes_in(running, &dirs, own_pid)
}

/// Whether the vendor's uninstaller runs, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum VendorStep {
    /// Run it. `silent` says whether it runs without asking anything.
    Run { silent: bool, reason: String },
    /// Oxidize removes the footprint itself.
    Skip { reason: String },
}

impl VendorStep {
    pub fn runs(&self) -> bool {
        matches!(self, VendorStep::Run { .. })
    }
}

/// Decide whether the vendor's uninstaller is needed. Oxidize removes the
/// whole footprint itself when the program is registered for the current
/// user only, has a known folder of its own, and owns nothing machine-wide:
/// no service, firewall rule, machine key or file under Program Files or
/// ProgramData. An MSI product always goes through Windows Installer, which
/// keeps its own records of it. `machine_dirs` are the machine-wide roots.
pub fn vendor_step(
    program: &Program,
    plan: &UninstallPlan,
    target: &ScanTarget,
    footprint: &[Leftover],
    machine_dirs: &[PathBuf],
) -> VendorStep {
    let silent = runs_silently(program, plan);
    let run = |reason: &str| VendorStep::Run {
        silent,
        reason: reason.to_string(),
    };
    if plan.is_msi || program.is_windows_installer {
        return run("Windows Installer product");
    }
    if program.source.hive != Hive::CurrentUser {
        return run("installed for all users");
    }
    let has_folder = scanner::own_install_folder(target).is_some()
        || footprint
            .iter()
            .any(|l| l.kind == LeftoverKind::Directory && l.confidence == Confidence::High);
    if !has_folder {
        return run("no folder of its own is known");
    }
    let machine_wide = footprint.iter().any(|l| match l.kind {
        LeftoverKind::Service | LeftoverKind::FirewallRule => true,
        LeftoverKind::RegistryKey | LeftoverKind::RegistryValue | LeftoverKind::PathEntry => {
            l.hive == Some(Hive::LocalMachine)
        }
        // A task a per-user installer made is the user's to delete.
        LeftoverKind::ScheduledTask => false,
        LeftoverKind::File | LeftoverKind::Directory => machine_dirs
            .iter()
            .any(|root| system::path_under(Path::new(&l.path), root)),
    });
    if machine_wide {
        return run("owns something machine-wide");
    }
    VendorStep::Skip {
        reason: "installed for this user only; Oxidize removes all of it".to_string(),
    }
}

/// An uninstaller that runs without asking: the plan carries the unattended
/// switches, Windows Installer's, a recorded quiet command or the ones an
/// `unins000.exe` uninstaller documents.
/// A quiet command the plan does not use says nothing.
pub fn runs_silently(_program: &Program, plan: &UninstallPlan) -> bool {
    plan.unattended
}

/// The machine-wide folders: what is under them needs administrator rights.
pub fn machine_dirs() -> Vec<PathBuf> {
    [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramData",
        "PUBLIC",
    ]
    .iter()
    .filter_map(|v| scanner::env_dir(v))
    .collect()
}

/// What the second scan says.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Verdict {
    /// The program is gone and nothing at the chosen level is left.
    pub nothing_left: bool,
    pub still_installed: bool,
    /// Items at or above the chosen level that are still there.
    pub remaining: Vec<Leftover>,
    /// Items found below the chosen level, which were never meant to go.
    pub below_level: usize,
    /// Those items, with their reasons.
    pub kept: Vec<Leftover>,
}

/// Judge the scan made after the removal. `level` is the lowest confidence
/// the removal acted on.
pub fn verdict(still_installed: bool, rescan: &ScanReport, level: Confidence) -> Verdict {
    let (remaining, below): (Vec<Leftover>, Vec<Leftover>) = rescan
        .items
        .iter()
        .cloned()
        .partition(|l| l.confidence <= level);
    Verdict {
        nothing_left: !still_installed && remaining.is_empty(),
        still_installed,
        remaining,
        below_level: below.len(),
        kept: below,
    }
}

/// Close the processes that run from the program's folders: ask each to
/// close its windows and wait up to `grace`. What stays is left running.
pub fn close_processes(dirs: &[PathBuf], grace: Duration) -> Vec<Closed> {
    if dirs.is_empty() {
        return Vec::new();
    }
    let picked = processes_in(&system::running_processes(), dirs, std::process::id());
    system::close_processes(&picked, grace)
}

// The flow
// --------

/// What the flow needs from a PC. The command line, the window and the MCP
/// server each bring their own; tests bring a fake.
pub trait Pc {
    fn scan(&self, target: &ScanTarget, installed: bool) -> ScanReport;
    fn still_installed(&self, program: &Program) -> bool;
    /// Every running process with a known image.
    fn running(&self) -> Vec<Running>;
    /// Ask these processes to close through their windows; none is ended.
    fn close(&self, procs: &[Running]) -> Vec<Closed>;
    /// Run the vendor's uninstaller; returns how it went.
    fn run_uninstaller(&self, plan: &UninstallPlan) -> anyhow::Result<Ran>;
    /// Wait until the program is unregistered; true when it is.
    fn wait_until_gone(&self, program: &Program, plan: &UninstallPlan) -> bool;
    /// Remove the items, with a backup unless told otherwise.
    fn remove(&self, items: &[Leftover], label: &str) -> anyhow::Result<DeletionOutcome>;
    /// Remove items found only after `earlier`, into its backup when it
    /// made one.
    fn remove_more(
        &self,
        items: &[Leftover],
        label: &str,
        earlier: &DeletionOutcome,
    ) -> anyhow::Result<DeletionOutcome>;
    fn machine_dirs(&self) -> Vec<PathBuf>;
    /// Told whether the vendor's uninstaller runs, before anything changes.
    fn decided(&self, _vendor: &VendorStep) {}
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// The lowest confidence removed.
    pub level: Confidence,
    pub dry_run: bool,
    /// Run the vendor's uninstaller even when Oxidize could do without it.
    pub use_uninstaller: bool,
}

/// What one complete removal did.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub closed: Vec<Closed>,
    /// In a dry run, the processes that would be closed.
    pub would_close: Vec<Running>,
    pub vendor: VendorStep,
    /// How the vendor's uninstaller ended, when it ran.
    pub uninstaller: Option<String>,
    /// The leftovers scan the removal worked from.
    pub report: ScanReport,
    /// What was selected for removal, or would be in a dry run.
    pub selected: Vec<Leftover>,
    pub removal: Option<DeletionOutcome>,
    pub verdict: Verdict,
    /// Why the flow stopped early, when it did.
    pub error: Option<String>,
    pub seconds: f64,
}

impl Outcome {
    /// The program is gone, every item went and nothing is left.
    pub fn complete(&self) -> bool {
        self.error.is_none()
            && self.verdict.nothing_left
            && self.removal.as_ref().is_none_or(|o| o.failed == 0)
    }
}

/// Remove `program` completely: scan its footprint, close its processes,
/// run its uninstaller only when needed, remove everything at `opts.level`
/// and scan again. `target` is captured before anything changes.
pub fn remove_completely(
    pc: &dyn Pc,
    program: &Program,
    target: &ScanTarget,
    plan: &UninstallPlan,
    opts: &Options,
) -> Outcome {
    let start = std::time::Instant::now();
    // A dry run changes nothing between its two looks, so one scan of the
    // program as gone serves both: the footprint is the same without the
    // program's own uninstall entry.
    let full = opts.dry_run.then(|| pc.scan(target, false));
    let footprint = match &full {
        Some(report) => scanner::as_footprint(report, target),
        None => pc.scan(target, true),
    };
    let registered = opts.dry_run || pc.still_installed(program);
    let vendor = if !registered {
        VendorStep::Skip {
            reason: "no longer registered".to_string(),
        }
    } else if opts.use_uninstaller {
        VendorStep::Run {
            silent: runs_silently(program, plan),
            reason: "asked for".to_string(),
        }
    } else {
        vendor_step(program, plan, target, &footprint.items, &pc.machine_dirs())
    };
    pc.decided(&vendor);
    let mut out = Outcome {
        closed: Vec::new(),
        would_close: Vec::new(),
        vendor,
        uninstaller: None,
        report: ScanReport::default(),
        selected: Vec::new(),
        removal: None,
        verdict: Verdict {
            still_installed: true,
            ..Verdict::default()
        },
        error: None,
        seconds: 0.0,
    };

    let dirs = owned_dirs(target, &footprint.items);
    let picked = processes_in(&pc.running(), &dirs, std::process::id());

    if opts.dry_run {
        // Everything the removal would take: the footprint as leftovers.
        out.would_close = picked;
        out.report = full.unwrap_or_default();
        out.selected = at_level(&out.report, opts.level);
        out.removal = pc.remove(&out.selected, &program.display_name).ok();
        out.seconds = start.elapsed().as_secs_f64();
        return out;
    }

    if !picked.is_empty() {
        out.closed = pc.close(&picked);
        if let Some(e) = still_running(&out.closed) {
            // Its files are in use, and it is never ended by force: neither
            // the uninstaller nor the removal starts under it.
            out.error = Some(e);
            out.verdict.still_installed = true;
            out.seconds = start.elapsed().as_secs_f64();
            return out;
        }
    }

    let mut installed = true;
    if out.vendor.runs() {
        let ran = match pc.run_uninstaller(plan) {
            Ok(ran) => ran,
            Err(e) => {
                out.error = Some(format!("{e:#}"));
                out.verdict.still_installed = pc.still_installed(program);
                out.seconds = start.elapsed().as_secs_f64();
                return out;
            }
        };
        out.uninstaller = Some(ran.said.clone());
        installed = !ran.gone(|| pc.wait_until_gone(program, plan));
        if installed {
            // The scan would list the live install; leave it alone.
            out.verdict.still_installed = true;
            out.seconds = start.elapsed().as_secs_f64();
            return out;
        }
    }

    // Skipped, the footprint is what goes, its uninstall entry with it; run,
    // what the uninstaller left is scanned for.
    out.report = if out.vendor.runs() {
        pc.scan(target, false)
    } else if registered {
        with_own_entry(footprint, target)
    } else {
        ScanReport {
            installed: false,
            ..footprint
        }
    };
    out.selected = at_level(&out.report, opts.level);
    if !out.selected.is_empty() {
        match pc.remove(&out.selected, &program.display_name) {
            Ok(o) => out.removal = Some(o),
            Err(e) => out.error = Some(format!("{e:#}")),
        }
    }
    if installed {
        installed = pc.still_installed(program);
    }
    let mut rescan = pc.scan(target, installed);
    // Windows' records of a file the removal took, such as the history of a
    // shortcut that went, can only be told apart once the file is gone. They
    // go in one more pass, into the same backup; there is never a third.
    let removed_some = out.removal.as_ref().is_some_and(|o| o.deleted > 0);
    if !installed && removed_some && out.error.is_none() {
        let late = appeared(&out.report, &rescan);
        if let Some(first) = out.removal.as_mut().filter(|_| !late.is_empty()) {
            match pc.remove_more(&late, &program.display_name, first) {
                Ok(o) => first.absorb(o),
                Err(e) => out.error = Some(format!("{e:#}")),
            }
            out.report.items.extend(late.iter().cloned());
            out.selected.extend(late);
            rescan = pc.scan(target, installed);
        }
    }
    out.verdict = verdict(installed, &rescan, opts.level);
    out.seconds = start.elapsed().as_secs_f64();
    out
}

/// The High items of `rescan` that the scan the removal worked from did not
/// list.
fn appeared(report: &ScanReport, rescan: &ScanReport) -> Vec<Leftover> {
    let same =
        |a: &Leftover, b: &Leftover| a.kind == b.kind && a.path.eq_ignore_ascii_case(&b.path);
    rescan
        .items
        .iter()
        .filter(|l| l.confidence == Confidence::High)
        .filter(|l| !report.items.iter().any(|r| same(r, l)))
        .cloned()
        .collect()
}

/// The footprint plus the program's own uninstall entry, which a scan of an
/// installed program leaves out.
fn with_own_entry(mut footprint: ScanReport, target: &ScanTarget) -> ScanReport {
    if let Some((key, source)) = &target.registry {
        let subpath = format!("{}\\{}", source.view.uninstall_base(), key);
        let listed = footprint
            .items
            .iter()
            .any(|l| l.hive == Some(source.hive) && l.subpath.as_deref() == Some(subpath.as_str()));
        if !listed {
            footprint.items.insert(
                0,
                Leftover::reg_key(
                    source.hive,
                    subpath,
                    Confidence::High,
                    "the program's own uninstall entry",
                ),
            );
        }
    }
    footprint.installed = false;
    footprint
}

fn at_level(report: &ScanReport, level: Confidence) -> Vec<Leftover> {
    report
        .items
        .iter()
        .filter(|l| l.confidence <= level)
        .cloned()
        .collect()
}

/// This PC. `quiet` gives the vendor's uninstaller no console, for callers
/// whose own input and output are taken: the window and the MCP server.
pub struct ThisPc {
    pub safety: SafetyContext,
    pub quiet: bool,
}

impl Pc for ThisPc {
    fn scan(&self, target: &ScanTarget, installed: bool) -> ScanReport {
        scanner::scan(target, installed)
    }

    fn still_installed(&self, program: &Program) -> bool {
        crate::uninstall::still_installed(program)
    }

    fn running(&self) -> Vec<Running> {
        system::running_processes()
    }

    fn close(&self, procs: &[Running]) -> Vec<Closed> {
        system::close_processes(procs, CLOSE_GRACE)
    }

    fn run_uninstaller(&self, plan: &UninstallPlan) -> anyhow::Result<Ran> {
        use std::process::Stdio;
        let status = if self.quiet {
            crate::uninstall::run_for(plan, Stdio::null(), Stdio::null(), VENDOR_WAIT)?
        } else {
            crate::uninstall::run_for(plan, Stdio::inherit(), Stdio::inherit(), VENDOR_WAIT)?
        };
        Ok(Ran::of(status, plan.is_msi, || {
            format!("was still running after {} s", VENDOR_WAIT.as_secs())
        }))
    }

    fn wait_until_gone(&self, program: &Program, plan: &UninstallPlan) -> bool {
        crate::uninstall::wait_for_completion(program, plan, VENDOR_WAIT)
    }

    fn remove(&self, items: &[Leftover], label: &str) -> anyhow::Result<DeletionOutcome> {
        crate::safety::remove_leftovers(items, label, &self.safety)
    }

    fn remove_more(
        &self,
        items: &[Leftover],
        label: &str,
        earlier: &DeletionOutcome,
    ) -> anyhow::Result<DeletionOutcome> {
        crate::safety::remove_leftovers_into(
            items,
            label,
            &self.safety,
            earlier.backup_dir.as_deref(),
        )
    }

    fn machine_dirs(&self) -> Vec<PathBuf> {
        machine_dirs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RegistrySource, RegistryView};
    use std::cell::RefCell;

    #[test]
    fn only_what_runs_from_the_apps_own_folder_is_picked() {
        let apps = r"C:\Program Files\WindowsApps";
        let mut app = crate::packages::fake::package("Vendor.Notes", "Notes");
        app.installed_path = Some(format!(r"{apps}\Vendor.Notes_1.2.3.0_x64__8wekyb3d8bbwe"));
        let running: Vec<Running> = [
            (100, r"Vendor.Notes_1.2.3.0_x64__8wekyb3d8bbwe\Notes.exe"),
            (
                101,
                r"Vendor.Notes_1.2.3.0_x64__8wekyb3d8bbwe\sync\Sync.exe",
            ),
            (102, r"Vendor.NotesPro_2.0.0.0_x64__8wekyb3d8bbwe\Notes.exe"),
            (
                103,
                r"Vendor.Notes_1.2.3.0_x64__8wekyb3d8bbwe.old\Notes.exe",
            ),
            (104, r"Vendor.Notes_1.2.3.0_x64__8wekyb3d8bbwe\Notes.exe"),
        ]
        .into_iter()
        .map(|(pid, exe)| Running {
            pid,
            exe: PathBuf::from(format!(r"{apps}\{exe}")),
        })
        .collect();
        let pids = |app: &Package| -> Vec<u32> {
            app_processes(&running, app, 104)
                .iter()
                .map(|p| p.pid)
                .collect()
        };
        // Its own processes, not a sibling package's, a look-alike folder's
        // or this process itself.
        assert_eq!(pids(&app), [100, 101]);

        let mut elsewhere = app.clone();
        for path in [
            None,
            Some(r"Vendor.Notes_1.2.3.0_x64__8wekyb3d8bbwe".to_string()),
            // A sparse package points at its program's folder.
            Some(r"C:\Program Files\Notes Editor".to_string()),
            Some(apps.to_string()),
        ] {
            elsewhere.installed_path = path.clone();
            assert!(pids(&elsewhere).is_empty(), "{path:?}");
        }
    }

    /// A PC in memory: the footprint shrinks by what was removed.
    struct FakePc {
        items: RefCell<Vec<Leftover>>,
        installed: RefCell<bool>,
        /// What the removal refuses.
        stuck: Vec<String>,
        /// What the vendor's uninstaller takes with it.
        vendor_takes: Vec<String>,
        /// The vendor's uninstaller is still running when the wait ends.
        never_ends: bool,
        /// Processes that stay when they are asked to close.
        stays: Vec<u32>,
        /// Items a scan finds only once the item at the path is gone.
        shows_once_gone: RefCell<Vec<(String, Leftover)>>,
        /// Backups made so far.
        backups: RefCell<usize>,
        calls: RefCell<Vec<String>>,
    }

    impl FakePc {
        fn new(items: Vec<Leftover>) -> Self {
            FakePc {
                items: RefCell::new(items),
                installed: RefCell::new(true),
                stuck: Vec::new(),
                vendor_takes: Vec::new(),
                never_ends: false,
                stays: Vec::new(),
                shows_once_gone: RefCell::new(Vec::new()),
                backups: RefCell::new(0),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        /// Take the items off the PC, all but the stuck ones, and let what
        /// only shows once they are gone appear.
        fn take(&self, items: &[Leftover]) -> DeletionOutcome {
            let mut o = DeletionOutcome {
                attempted: items.len(),
                ..DeletionOutcome::default()
            };
            for l in items {
                if self.stuck.contains(&l.path) {
                    o.failed += 1;
                } else {
                    o.deleted += 1;
                    self.items.borrow_mut().retain(|i| i.path != l.path);
                    if l.path.ends_with(r"Uninstall\example-player") {
                        *self.installed.borrow_mut() = false;
                    }
                    let shown: Vec<Leftover> = self
                        .shows_once_gone
                        .borrow_mut()
                        .extract_if(.., |(after, _)| *after == l.path)
                        .map(|(_, item)| item)
                        .collect();
                    self.items.borrow_mut().extend(shown);
                }
            }
            o
        }
    }

    impl Pc for FakePc {
        fn scan(&self, target: &ScanTarget, installed: bool) -> ScanReport {
            self.calls.borrow_mut().push(format!("scan {installed}"));
            // A scan of an installed program leaves its own entry out.
            let mut items = self.items.borrow().clone();
            if installed && *self.installed.borrow() {
                items.retain(|l| !l.path.ends_with(r"Uninstall\example-player"));
            }
            ScanReport {
                program_name: target.display_name.clone(),
                installed,
                items,
            }
        }

        fn still_installed(&self, _program: &Program) -> bool {
            *self.installed.borrow()
        }

        fn running(&self) -> Vec<Running> {
            vec![
                Running {
                    pid: 100,
                    exe: PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer\player.exe"),
                },
                Running {
                    pid: 200,
                    exe: PathBuf::from(r"C:\Users\me\AppData\Local\Other\player.exe"),
                },
            ]
        }

        fn close(&self, procs: &[Running]) -> Vec<Closed> {
            let pids: Vec<String> = procs.iter().map(|p| p.pid.to_string()).collect();
            self.calls
                .borrow_mut()
                .push(format!("close {}", pids.join(",")));
            procs
                .iter()
                .map(|p| Closed {
                    pid: p.pid,
                    exe: p.exe.display().to_string(),
                    how: if self.stays.contains(&p.pid) {
                        CloseHow::Running
                    } else {
                        CloseHow::Closed
                    },
                    error: None,
                    windowless: false,
                })
                .collect()
        }

        fn run_uninstaller(&self, _plan: &UninstallPlan) -> anyhow::Result<Ran> {
            self.calls.borrow_mut().push("uninstall".to_string());
            self.items
                .borrow_mut()
                .retain(|l| !self.vendor_takes.contains(&l.path));
            if self.never_ends {
                return Ok(Ran {
                    said: "was still running after 60 s".to_string(),
                    ended: false,
                });
            }
            Ok(Ran {
                said: "finished".to_string(),
                ended: true,
            })
        }

        fn wait_until_gone(&self, _program: &Program, _plan: &UninstallPlan) -> bool {
            *self.installed.borrow_mut() = false;
            true
        }

        fn remove(&self, items: &[Leftover], _label: &str) -> anyhow::Result<DeletionOutcome> {
            self.calls
                .borrow_mut()
                .push(format!("remove {}", items.len()));
            let n = self.backups.replace_with(|n| *n + 1) + 1;
            Ok(DeletionOutcome {
                backup_name: Some(format!("backup {n}")),
                ..self.take(items)
            })
        }

        fn remove_more(
            &self,
            items: &[Leftover],
            _label: &str,
            earlier: &DeletionOutcome,
        ) -> anyhow::Result<DeletionOutcome> {
            self.calls.borrow_mut().push(format!(
                "remove {} more into {}",
                items.len(),
                earlier.backup_name.as_deref().unwrap_or("nothing")
            ));
            Ok(DeletionOutcome {
                backup_name: earlier.backup_name.clone(),
                ..self.take(items)
            })
        }

        fn machine_dirs(&self) -> Vec<PathBuf> {
            machine()
        }
    }

    fn entry() -> Leftover {
        Leftover::reg_key(
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\example-player",
            Confidence::High,
            "orphaned uninstall entry",
        )
    }

    fn per_user_footprint() -> Vec<Leftover> {
        vec![
            entry(),
            dir(r"C:\Users\me\AppData\Local\ExamplePlayer", Confidence::High),
            dir(
                r"C:\Users\me\AppData\Local\Temp\ExamplePlayer",
                Confidence::Medium,
            ),
        ]
    }

    fn opts(level: Confidence) -> Options {
        Options {
            level,
            dry_run: false,
            use_uninstaller: false,
        }
    }

    #[test]
    fn a_per_user_program_goes_in_one_pass_without_its_uninstaller() {
        let pc = FakePc::new(per_user_footprint());
        let p = program(Hive::CurrentUser);
        let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::High));
        assert!(!out.vendor.runs());
        assert_eq!(
            pc.calls(),
            ["scan true", "close 100", "remove 2", "scan false"]
        );
        assert!(out.complete(), "{out:?}");
        // The medium item was found but never meant to go.
        assert_eq!(out.verdict.below_level, 1);
    }

    #[test]
    fn a_process_that_stays_stops_the_flow_before_anything_runs_or_goes() {
        // Skipped uninstaller and one that would run alike.
        for p in [program(Hive::CurrentUser), program(Hive::LocalMachine)] {
            let mut pc = FakePc::new(per_user_footprint());
            pc.stays = vec![100];
            let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::High));
            assert_eq!(pc.calls(), ["scan true", "close 100"]);
            assert_eq!(out.closed[0].how, CloseHow::Running);
            assert_eq!(
                out.error.as_deref(),
                Some(
                    "player.exe is still running, so nothing was removed. Close it and try again."
                )
            );
            assert!(out.verdict.still_installed, "{out:?}");
            assert!(out.removal.is_none(), "{out:?}");
            assert!(!out.complete(), "{out:?}");
        }
    }

    #[test]
    fn processes_that_stay_are_named_in_one_sentence() {
        let closed = |how: CloseHow, exe: &str| Closed {
            pid: 1,
            exe: exe.to_string(),
            how,
            error: None,
            windowless: false,
        };
        assert_eq!(
            still_running(&[closed(CloseHow::Closed, r"C:\a\a.exe")]),
            None
        );
        assert_eq!(
            still_running(&[
                closed(CloseHow::Running, r"C:\a\tray.exe"),
                closed(CloseHow::Closed, r"C:\a\a.exe"),
                closed(CloseHow::Failed, r"C:\a\svc.exe"),
            ])
            .as_deref(),
            Some("tray.exe, svc.exe are still running, so nothing was removed. Close them and try again.")
        );
    }

    const SHORTCUT: &str =
        r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Example Player.lnk";

    /// A record of Windows' that the scan finds only once the file it names
    /// is gone.
    fn record(name: &str) -> Leftover {
        Leftover::reg_value(
            Hive::CurrentUser,
            r"Software\Microsoft\Windows\CurrentVersion\UFH\SHC",
            name,
            Confidence::High,
            "shortcut history of the program",
        )
    }

    fn with_shortcut() -> Vec<Leftover> {
        let mut items = per_user_footprint();
        items.push(Leftover::fs(
            LeftoverKind::File,
            PathBuf::from(SHORTCUT),
            Confidence::High,
            "shortcut to the program",
            None,
            false,
        ));
        items
    }

    #[test]
    fn what_shows_only_once_its_file_is_gone_goes_in_one_more_pass() {
        let pc = FakePc::new(with_shortcut());
        pc.shows_once_gone
            .borrow_mut()
            .push((SHORTCUT.to_string(), record("35")));
        let p = program(Hive::CurrentUser);
        let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::High));
        assert_eq!(
            pc.calls(),
            [
                "scan true",
                "close 100",
                "remove 3",
                "scan false",
                "remove 1 more into backup 1",
                "scan false"
            ]
        );
        assert!(out.complete(), "{out:?}");
        // One removal, one backup, counted together.
        let removal = out.removal.as_ref().unwrap();
        assert_eq!((removal.attempted, removal.deleted), (4, 4));
        assert_eq!(removal.backup_name.as_deref(), Some("backup 1"));
        assert_eq!(out.selected.len(), 4);
        assert!(out.report.items.iter().any(|l| l.path == record("35").path));
    }

    #[test]
    fn there_is_never_a_third_pass() {
        let pc = FakePc::new(with_shortcut());
        let (first, second) = (record("35"), record("36"));
        pc.shows_once_gone.borrow_mut().extend([
            (SHORTCUT.to_string(), first.clone()),
            (first.path.clone(), second.clone()),
        ]);
        let p = program(Hive::CurrentUser);
        let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::High));
        let more = pc.calls().iter().filter(|c| c.contains("more")).count();
        assert_eq!(more, 1);
        // What shows after the extra pass is named, not taken.
        assert!(!out.complete());
        let left: Vec<&str> = out
            .verdict
            .remaining
            .iter()
            .map(|l| l.path.as_str())
            .collect();
        assert_eq!(left, [second.path.as_str()]);
    }

    #[test]
    fn nothing_more_goes_when_the_removal_took_nothing() {
        let mut pc = FakePc::new(with_shortcut());
        pc.stuck = with_shortcut().into_iter().map(|l| l.path).collect();
        pc.shows_once_gone
            .borrow_mut()
            .push((SHORTCUT.to_string(), record("35")));
        let p = program(Hive::CurrentUser);
        let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::High));
        assert!(pc.calls().iter().all(|c| !c.contains("more")));
        assert!(!out.complete());
    }

    #[test]
    fn a_program_already_gone_goes_straight_to_its_leftovers() {
        let mut items = per_user_footprint();
        items.remove(0);
        let pc = FakePc::new(items);
        *pc.installed.borrow_mut() = false;
        let p = program(Hive::CurrentUser);
        let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::High));
        assert_eq!(
            out.vendor,
            VendorStep::Skip {
                reason: "no longer registered".to_string()
            }
        );
        // Only the folder: the entry that is gone is not listed again.
        assert_eq!(out.selected.len(), 1);
        assert!(out.complete(), "{out:?}");
    }

    #[test]
    fn medium_takes_the_medium_items_too() {
        let pc = FakePc::new(per_user_footprint());
        let p = program(Hive::CurrentUser);
        let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::Medium));
        assert!(out.complete());
        assert_eq!(out.verdict.below_level, 0);
        assert_eq!(out.selected.len(), 3);
    }

    #[test]
    fn a_machine_wide_program_runs_its_uninstaller_first() {
        let mut items = per_user_footprint();
        items.push(Leftover::service(
            "ExampleSvc",
            r"C:\Users\me\AppData\Local\ExamplePlayer\svc.exe",
            Confidence::High,
            "inside the install folder",
        ));
        let mut pc = FakePc::new(items);
        pc.vendor_takes = vec![
            "service ExampleSvc  (C:\\Users\\me\\AppData\\Local\\ExamplePlayer\\svc.exe)"
                .to_string(),
            entry().path,
        ];
        let p = program(Hive::CurrentUser);
        let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::High));
        assert!(out.vendor.runs());
        assert_eq!(
            pc.calls(),
            [
                "scan true",
                "close 100",
                "uninstall",
                "scan false",
                "remove 1",
                "scan false"
            ]
        );
        assert!(out.complete(), "{out:?}");
    }

    #[test]
    fn an_uninstaller_still_running_keeps_its_leftovers() {
        let mut pc = FakePc::new(per_user_footprint());
        pc.never_ends = true;
        let p = program(Hive::CurrentUser);
        let mut o = opts(Confidence::High);
        o.use_uninstaller = true;
        let out = remove_completely(&pc, &p, &target(), &plan(false), &o);
        assert_eq!(pc.calls(), ["scan true", "close 100", "uninstall"]);
        assert!(out.removal.is_none(), "{out:?}");
        assert!(out.verdict.still_installed);
        assert_eq!(
            out.uninstaller.as_deref(),
            Some("was still running after 60 s")
        );
    }

    #[test]
    fn an_item_that_stays_is_named_and_the_run_is_not_complete() {
        let mut pc = FakePc::new(per_user_footprint());
        pc.stuck = vec![r"C:\Users\me\AppData\Local\ExamplePlayer".to_string()];
        let p = program(Hive::CurrentUser);
        let out = remove_completely(&pc, &p, &target(), &plan(false), &opts(Confidence::High));
        assert!(!out.complete());
        assert!(!out.verdict.nothing_left);
        let left: Vec<&str> = out
            .verdict
            .remaining
            .iter()
            .map(|l| l.path.as_str())
            .collect();
        assert_eq!(left, [r"C:\Users\me\AppData\Local\ExamplePlayer"]);
    }

    #[test]
    fn a_dry_run_lists_every_item_and_changes_nothing() {
        let pc = FakePc::new(per_user_footprint());
        let p = program(Hive::CurrentUser);
        let mut o = opts(Confidence::Medium);
        o.dry_run = true;
        let out = remove_completely(&pc, &p, &target(), &plan(false), &o);
        assert_eq!(out.selected.len(), 3);
        // The fake's remove is the dry-run path of the real one; nothing
        // was closed and no uninstaller ran.
        assert_eq!(pc.calls(), ["scan false", "remove 3"]);
        let pids: Vec<u32> = out.would_close.iter().map(|p| p.pid).collect();
        assert_eq!(pids, [100]);
        assert!(!out.complete());
    }

    #[test]
    fn a_footprint_is_the_scan_without_the_own_uninstall_entry() {
        let report = ScanReport {
            program_name: "Example Player".into(),
            installed: false,
            items: per_user_footprint(),
        };
        let f = scanner::as_footprint(&report, &target());
        assert!(f.installed);
        assert_eq!(f.items.len(), 2);
        assert!(f.items.iter().all(|l| !l.path.ends_with("example-player")));
    }

    fn program(hive: Hive) -> Program {
        Program {
            registry_key: "example-player".to_string(),
            source: RegistrySource::new(hive, RegistryView::Native64),
            display_name: "Example Player".to_string(),
            display_version: None,
            publisher: Some("Example Studio".to_string()),
            install_date: None,
            install_location: Some(r"C:\Users\me\AppData\Local\ExamplePlayer".to_string()),
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: Some(
                r"C:\Users\me\AppData\Local\ExamplePlayer\uninstall.exe".to_string(),
            ),
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    fn plan(is_msi: bool) -> UninstallPlan {
        UninstallPlan {
            argv: vec![r"C:\Users\me\AppData\Local\ExamplePlayer\uninstall.exe".to_string()],
            is_msi,
            source: "UninstallString".to_string(),
            unattended: is_msi,
        }
    }

    fn target() -> ScanTarget {
        let mut t = scanner::name_only_target("Example Player", Some("Example Studio"));
        t.install_location = Some(PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer"));
        t.registry = Some((
            "example-player".to_string(),
            RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
        ));
        t
    }

    fn dir(path: &str, conf: Confidence) -> Leftover {
        Leftover::fs(
            LeftoverKind::Directory,
            PathBuf::from(path),
            conf,
            "named after the program",
            None,
            false,
        )
    }

    fn machine() -> Vec<PathBuf> {
        vec![
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\ProgramData"),
        ]
    }

    #[test]
    fn a_per_user_program_with_nothing_machine_wide_skips_its_uninstaller() {
        let footprint = vec![
            dir(r"C:\Users\me\AppData\Local\ExamplePlayer", Confidence::High),
            Leftover::reg_key(
                Hive::CurrentUser,
                r"Software\Example Studio",
                Confidence::High,
                "the vendor's key",
            ),
        ];
        let step = vendor_step(
            &program(Hive::CurrentUser),
            &plan(false),
            &target(),
            &footprint,
            &machine(),
        );
        assert!(!step.runs(), "{step:?}");
    }

    #[test]
    fn anything_machine_wide_keeps_the_vendors_uninstaller() {
        let p = program(Hive::CurrentUser);
        let cases = vec![
            Leftover::service("ExampleSvc", r"C:\x\svc.exe", Confidence::High, "own"),
            Leftover::reg_key(
                Hive::LocalMachine,
                r"SOFTWARE\Example Studio",
                Confidence::High,
                "own",
            ),
            dir(r"C:\ProgramData\ExamplePlayer", Confidence::High),
            Leftover::firewall_rule(
                "{id}",
                "Example",
                "",
                r"C:\x\a.exe",
                Confidence::High,
                "own",
            ),
        ];
        for item in cases {
            let step = vendor_step(
                &p,
                &plan(false),
                &target(),
                std::slice::from_ref(&item),
                &machine(),
            );
            assert!(step.runs(), "{} should keep the uninstaller", item.path);
        }
        // Registered for every user, or an MSI product: always.
        let step = vendor_step(
            &program(Hive::LocalMachine),
            &plan(false),
            &target(),
            &[],
            &machine(),
        );
        assert!(step.runs());
        let step = vendor_step(&p, &plan(true), &target(), &[], &machine());
        assert_eq!(
            step,
            VendorStep::Run {
                silent: true,
                reason: "Windows Installer product".to_string()
            }
        );
    }

    #[test]
    fn a_program_without_a_known_folder_keeps_its_uninstaller() {
        let mut t = target();
        t.install_location = None;
        let step = vendor_step(
            &program(Hive::CurrentUser),
            &plan(false),
            &t,
            &[dir(
                r"C:\Users\me\AppData\Roaming\Other",
                Confidence::Medium,
            )],
            &machine(),
        );
        assert!(step.runs());
    }

    #[test]
    fn only_processes_inside_the_programs_folders_are_picked() {
        let dirs = vec![
            PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer"),
            PathBuf::from(r"C:\Users\me\AppData\Local\Temp\ExamplePlayer"),
        ];
        let running = vec![
            Running {
                pid: 100,
                exe: PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer\v2\player.exe"),
            },
            Running {
                pid: 101,
                exe: PathBuf::from(r"c:\users\ME\appdata\local\temp\exampleplayer\helper.exe"),
            },
            // Same name, other folder.
            Running {
                pid: 102,
                exe: PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayerBeta\player.exe"),
            },
            Running {
                pid: 103,
                exe: PathBuf::from(r"C:\Program Files\Other\player.exe"),
            },
            Running {
                pid: 104,
                exe: PathBuf::from(r"C:\Windows\System32\svchost.exe"),
            },
            // This process, even when it runs from there.
            Running {
                pid: 7,
                exe: PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer\oxidize.exe"),
            },
        ];
        let picked: Vec<u32> = processes_in(&running, &dirs, 7)
            .iter()
            .map(|p| p.pid)
            .collect();
        assert_eq!(picked, [100, 101]);
        // No folders, nothing picked.
        assert!(processes_in(&running, &[], 7).is_empty());
    }

    #[test]
    fn a_recorded_folder_named_otherwise_is_not_the_programs_to_close() {
        let mut t = target();
        // Recorded, but its name says nothing about the program: whatever
        // else runs from there stays untouched.
        t.install_location = Some(PathBuf::from(r"D:\Apps"));
        assert!(owned_dirs(&t, &[]).is_empty());
        // The vendor's folder is not the program's either.
        t.install_location = Some(PathBuf::from(r"C:\Users\me\AppData\Local\Example Studio"));
        assert!(owned_dirs(&t, &[]).is_empty());
        // Its own folder is.
        t.install_location = Some(PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer"));
        assert_eq!(owned_dirs(&t, &[]).len(), 1);
    }

    #[test]
    fn owned_folders_never_include_a_protected_or_shared_location() {
        let mut t = target();
        t.install_location = Some(PathBuf::from(r"C:\"));
        let footprint = vec![
            dir(r"C:\Users\me\AppData\Local\ExamplePlayer", Confidence::High),
            dir(
                r"C:\Users\me\AppData\Roaming\ExamplePlayer",
                Confidence::Medium,
            ),
            dir(
                r"C:\Program Files\Common Files\ExamplePlayer",
                Confidence::High,
            ),
            dir(r"C:\Windows", Confidence::High),
        ];
        let dirs = owned_dirs(&t, &footprint);
        assert_eq!(
            dirs,
            [PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer")]
        );
    }

    #[test]
    fn the_second_scan_says_nothing_left_only_when_nothing_at_the_level_remains() {
        let rescan = ScanReport {
            program_name: "Example Player".to_string(),
            installed: false,
            items: vec![dir(r"C:\x\Example", Confidence::Low)],
        };
        let v = verdict(false, &rescan, Confidence::High);
        assert!(v.nothing_left);
        assert_eq!(v.below_level, 1);
        // What was kept is named, not only counted.
        assert_eq!(v.kept.len(), 1);
        assert_eq!(v.kept[0].path, r"C:\x\Example");

        let v = verdict(false, &rescan, Confidence::Low);
        assert!(!v.nothing_left);
        assert_eq!(v.remaining.len(), 1);

        let empty = ScanReport::default();
        let v = verdict(true, &empty, Confidence::High);
        assert!(!v.nothing_left, "still installed is never nothing left");
    }
}
