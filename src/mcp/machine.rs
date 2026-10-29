//! What `oxidize mcp` works on: this PC, read through the engine, and the
//! engine's removal path for a plan the user approved.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;

use super::{Inspect, Remove};
use crate::backup::{self, BackupInfo};
use crate::commands;
use crate::complete::{self, Closed, Running};
use crate::hunter::{self, HunterMatch};
use crate::model::{Leftover, Package, Program, ScanReport, ScanTarget};
use crate::orphans::{self, OrphanReport};
use crate::packages::{PackageStore, RemovalOutcome, WindowsPackageStore};
use crate::safety::{self, DeletionOutcome, SafetyContext};
use crate::uninstall::{self, Ran, UninstallPlan};
use crate::{registry, scanner, system};

/// This PC, read only.
pub struct ThisPc;

impl Inspect for ThisPc {
    fn programs(&self, system: bool) -> Vec<Program> {
        registry::enumerate_installed_programs(system)
    }

    fn store_apps(&self) -> Result<Vec<Package>> {
        WindowsPackageStore.list()
    }

    fn target(&self, program: &Program) -> ScanTarget {
        scanner::build_target(program)
    }

    fn target_by_name(&self, name: &str, publisher: Option<&str>) -> ScanTarget {
        scanner::removed_program_target(name, publisher)
    }

    fn scan(&self, target: &ScanTarget, installed: bool) -> ScanReport {
        scanner::scan(target, installed)
    }

    fn orphans(&self, programs: &[Program]) -> OrphanReport {
        orphans::sweep(programs)
    }

    fn trace(&self, query: &str, programs: &[Program]) -> Vec<HunterMatch> {
        hunter::hunt(query, programs)
    }

    fn backups(&self) -> Result<Vec<BackupInfo>> {
        backup::list_backups()
    }

    fn backups_folder(&self) -> Option<PathBuf> {
        backup::backups_base().ok()
    }

    fn local_appdata(&self) -> Option<PathBuf> {
        scanner::env_dir("LOCALAPPDATA")
    }

    fn is_elevated(&self) -> bool {
        safety::is_elevated()
    }

    fn running(&self) -> Vec<Running> {
        system::running_processes()
    }

    fn machine_dirs(&self) -> Vec<PathBuf> {
        complete::machine_dirs()
    }
}

/// The steps `oxidize uninstall` takes, always with a backup. The
/// uninstaller gets no console input or output: those carry the protocol.
pub struct Remover;

/// How long an uninstaller is waited for. Someone may be clicking through
/// it, so the wait is long; one that is still running after it is reported
/// as running, and its leftovers stay.
pub const UNINSTALLER_RUN: Duration = Duration::from_secs(30 * 60);

/// How long the uninstall entry then has to go away.
pub const ENTRY_WAIT: Duration = Duration::from_secs(120);

impl Remove for Remover {
    fn uninstall(&self, plan: &UninstallPlan) -> Result<Ran> {
        let status = uninstall::run_for(plan, Stdio::null(), Stdio::null(), UNINSTALLER_RUN)?;
        Ok(Ran::of(status, plan.is_msi, || {
            format!(
                "is still running after {} minutes; its leftovers stay until it has finished",
                UNINSTALLER_RUN.as_secs() / 60
            )
        }))
    }

    fn wait_until_gone(&self, program: &Program, plan: &UninstallPlan) -> bool {
        uninstall::wait_for_completion(program, plan, ENTRY_WAIT)
    }

    fn remove_app(&self, app: &Package, before: &mut dyn FnMut() -> Result<()>) -> Result<bool> {
        Ok(commands::remove_package(&WindowsPackageStore, app, before)? == RemovalOutcome::Removed)
    }

    fn close(&self, procs: &[Running]) -> Vec<Closed> {
        system::close_processes(procs, complete::CLOSE_GRACE)
    }

    fn remove_items(&self, items: &[Leftover], label: &str) -> Result<DeletionOutcome> {
        let ctx = SafetyContext {
            dry_run: false,
            make_backups: true,
        };
        safety::remove_leftovers(items, label, &ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_uninstaller_is_waited_for_as_long_as_the_plan_says() {
        let plan = UninstallPlan {
            argv: vec![system::system32("cmd.exe"), "/c".into(), "exit 0".into()],
            is_msi: false,
            source: "test".into(),
            unattended: true,
        };
        let ran = Remover.uninstall(&plan).unwrap();
        assert!(ran.ended, "{ran:?}");
        assert!(!ran.said.contains("still running"), "{ran:?}");
        // `plan_removal` tells the user how long each wait is.
        let how = crate::mcp::HOW_IT_RUNS;
        assert!(how.contains("up to 30 minutes"), "{how}");
        assert!(how.contains("two minutes"), "{how}");
        assert_eq!(UNINSTALLER_RUN, Duration::from_secs(30 * 60));
        assert_eq!(ENTRY_WAIT, Duration::from_secs(120));
    }
}
