//! Running a program's *own* registered uninstaller.
//!
//! We build an explicit argument vector (never shelling through `cmd.exe`, which
//! would lose the child's exit code and re-interpret metacharacters), prefer the
//! synchronous, reliable MSI path when the product is a Windows Installer
//! package, and verify completion by re-checking the registry afterwards (EXE
//! uninstallers often relaunch a copy of themselves from `%TEMP%` and the first
//! process exits before the real work is done).

use std::process::{Command, ExitStatus};

use anyhow::{bail, Context, Result};

use crate::model::Program;
use crate::registry;
use crate::util;

/// A concrete, ready-to-run uninstall command.
#[derive(Debug, Clone)]
pub struct UninstallPlan {
    /// `argv[0]` = executable, the rest = arguments.
    pub argv: Vec<String>,
    /// True if this is an `msiexec` invocation (synchronous, reliable code).
    pub is_msi: bool,
    /// Human description of where the command came from.
    pub source: String,
}

impl UninstallPlan {
    /// The command rendered as a readable string (for dry-run / logging).
    pub fn display(&self) -> String {
        self.argv
            .iter()
            .map(|a| {
                if a.contains(' ') {
                    format!("\"{a}\"")
                } else {
                    a.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Does `s` look like an MSI ProductCode GUID, e.g. `{0F1B...-...}`?
fn looks_like_guid(s: &str) -> bool {
    let s = s.trim();
    s.len() == 38
        && s.starts_with('{')
        && s.ends_with('}')
        && s[1..s.len() - 1]
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Absolute path to a System32 executable, avoiding PATH hijacking.
fn system32(exe: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\{exe}")
}

/// Decide how to uninstall `program`. `silent` requests an unattended run.
pub fn plan(program: &Program, silent: bool) -> Result<UninstallPlan> {
    // MSI products: build the command from the ProductCode rather than trusting
    // the stored string's UI level. `msiexec /x` is synchronous and returns a
    // meaningful exit code.
    if program.is_windows_installer && looks_like_guid(&program.registry_key) {
        let mut argv = vec![system32("msiexec.exe"), "/x".to_string(), program.registry_key.clone()];
        if silent {
            argv.push("/qn".to_string());
            argv.push("/norestart".to_string());
        }
        return Ok(UninstallPlan {
            argv,
            is_msi: true,
            source: "MSI ProductCode".to_string(),
        });
    }

    // EXE uninstallers: prefer the publisher-provided silent command when asked.
    let (raw, source) = if silent {
        match (&program.quiet_uninstall_string, &program.uninstall_string) {
            (Some(q), _) => (q.clone(), "QuietUninstallString".to_string()),
            (None, Some(u)) => (u.clone(), "UninstallString (no quiet variant)".to_string()),
            (None, None) => bail!("no uninstall command recorded for this program"),
        }
    } else {
        let u = program
            .uninstall_string
            .clone()
            .context("no UninstallString recorded for this program")?;
        (u, "UninstallString".to_string())
    };

    let argv = util::split_command_line(&util::expand_env_vars(&raw));
    if argv.is_empty() {
        bail!("uninstall command parsed to nothing: {raw:?}");
    }

    Ok(UninstallPlan {
        argv,
        is_msi: false,
        source,
    })
}

/// Launch the plan and wait for the spawned process to exit.
///
/// Note: for non-MSI uninstallers this is necessary but not always sufficient —
/// see [`still_installed`] for the post-run verification.
pub fn run(plan: &UninstallPlan) -> Result<ExitStatus> {
    let (exe, args) = plan
        .argv
        .split_first()
        .expect("plan argv is never empty (checked in plan())");

    let status = Command::new(exe).args(args).status().map_err(|e| {
        // CreateProcess returns 740 when the target needs elevation.
        if e.raw_os_error() == Some(740) {
            anyhow::anyhow!(
                "the uninstaller requires Administrator rights (error 740). \
                 Re-run Oxidize from an elevated prompt."
            )
        } else {
            anyhow::Error::new(e).context(format!("failed to launch uninstaller: {exe}"))
        }
    })?;

    Ok(status)
}

/// Re-check whether the program's Uninstall key still exists. After a genuine
/// uninstall it disappears; if it is still there the uninstall may have been
/// cancelled, failed, or detached into a background process.
pub fn still_installed(program: &Program) -> bool {
    registry::key_exists(program.source.hive, &program.uninstall_subpath())
}

/// Interpret an MSI/EXE uninstaller exit code for display.
pub fn describe_exit(status: ExitStatus, is_msi: bool) -> String {
    match status.code() {
        Some(0) => "completed successfully".to_string(),
        Some(3010) => "completed; a reboot is required".to_string(),
        Some(1641) => "completed; a reboot has been initiated".to_string(),
        Some(1605) if is_msi => "product was not installed (1605)".to_string(),
        Some(1602) if is_msi => "cancelled by the user (1602)".to_string(),
        Some(1618) if is_msi => "another installation is already in progress (1618)".to_string(),
        Some(code) => format!("exited with code {code}"),
        None => "terminated without an exit code".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_product_guids() {
        assert!(looks_like_guid("{2D7E0D49-1A2B-3C4D-5E6F-708192A3B4C5}"));
        assert!(!looks_like_guid("Google Chrome"));
        assert!(!looks_like_guid("{too-short}"));
    }
}
