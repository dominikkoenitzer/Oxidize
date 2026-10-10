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

use crate::model::{Confidence, Hive, Leftover, LeftoverKind, Program, ScanReport, ScanTarget};
use crate::uninstall::UninstallPlan;
use crate::{scanner, system};

/// How long a program gets to close its windows before it is ended.
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
    /// It was still running after the grace period and was ended.
    Ended,
    /// It could not be ended, usually for want of administrator rights.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Closed {
    pub pid: u32,
    pub exe: String,
    pub how: CloseHow,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The folders a program's processes may run from: its install folder and
/// every folder the scan gives it at High confidence. Protected and shared
/// locations never count, so nothing outside the program is touched.
pub fn owned_dirs(target: &ScanTarget, footprint: &[Leftover]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(loc) = &target.install_location {
        dirs.push(loc.clone());
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
    let has_folder = target.install_location.is_some()
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

/// An uninstaller that runs without asking: Windows Installer, a recorded
/// quiet command, or a plan that already carries the unattended switches.
pub fn runs_silently(program: &Program, plan: &UninstallPlan) -> bool {
    plan.is_msi || program.quiet_uninstall_string.is_some() || plan.unattended
}

/// The machine-wide folders: what is under them needs administrator rights.
pub fn machine_dirs() -> Vec<PathBuf> {
    [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramData",
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
    }
}

/// Close the processes that run from the program's folders: ask each to
/// close its windows, wait up to `grace`, then end what is still running.
pub fn close_processes(dirs: &[PathBuf], grace: Duration) -> Vec<Closed> {
    if dirs.is_empty() {
        return Vec::new();
    }
    let picked = processes_in(&system::running_processes(), dirs, std::process::id());
    system::close_processes(&picked, grace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RegistrySource, RegistryView};

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
            unattended: false,
        }
    }

    fn target() -> ScanTarget {
        let mut t = scanner::name_only_target("Example Player", Some("Example Studio"));
        t.install_location = Some(PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer"));
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
            let step = vendor_step(&p, &plan(false), &target(), &[item.clone()], &machine());
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

        let v = verdict(false, &rescan, Confidence::Low);
        assert!(!v.nothing_left);
        assert_eq!(v.remaining.len(), 1);

        let empty = ScanReport::default();
        let v = verdict(true, &empty, Confidence::High);
        assert!(!v.nothing_left, "still installed is never nothing left");
    }
}
