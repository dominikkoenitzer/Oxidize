//! Running a program's own registered uninstaller.
//!
//! The command is built as an explicit argument vector, never through
//! `cmd.exe`. MSI products go through a synchronous `msiexec /x`, which has a
//! reliable exit code. EXE uninstallers often copy themselves to `%TEMP%` and
//! exit early, so completion is confirmed by watching the registry and the
//! process list afterwards.

use std::path::Path;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::model::Program;
use crate::{registry, system, util};

#[derive(Debug, Clone)]
pub struct UninstallPlan {
    /// `argv[0]` is the executable.
    pub argv: Vec<String>,
    pub is_msi: bool,
    /// Where the command came from.
    pub source: String,
}

impl UninstallPlan {
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

fn looks_like_guid(s: &str) -> bool {
    let s = s.trim();
    s.len() == 38
        && s.starts_with('{')
        && s.ends_with('}')
        && s[1..s.len() - 1]
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Decide how to uninstall `program`.
pub fn plan(program: &Program, silent: bool) -> Result<UninstallPlan> {
    if program.is_windows_installer && looks_like_guid(&program.registry_key) {
        let mut argv = vec![
            system::system32("msiexec.exe"),
            "/x".to_string(),
            program.registry_key.clone(),
        ];
        if silent {
            argv.push("/qn".to_string());
            argv.push("/norestart".to_string());
        }
        return Ok(UninstallPlan {
            argv,
            is_msi: true,
            source: "MSI product code".to_string(),
        });
    }

    let (raw, source) = if silent {
        match (&program.quiet_uninstall_string, &program.uninstall_string) {
            (Some(q), _) => (q.clone(), "QuietUninstallString".to_string()),
            (None, Some(u)) => (u.clone(), "UninstallString, no quiet variant".to_string()),
            (None, None) => bail!("no uninstall command recorded for this program"),
        }
    } else {
        let u = program
            .uninstall_string
            .clone()
            .context("no uninstall command recorded for this program")?;
        (u, "UninstallString".to_string())
    };

    let argv = util::split_uninstall_command(&util::expand_env_vars(&raw));
    if argv.first().is_none_or(|exe| exe.trim().is_empty()) {
        bail!("uninstall command parsed to nothing: {raw:?}");
    }
    Ok(UninstallPlan {
        argv,
        is_msi: false,
        source,
    })
}

/// Launch the plan and wait for the spawned process to exit.
pub fn run(plan: &UninstallPlan) -> Result<ExitStatus> {
    let (exe, args) = plan.argv.split_first().expect("plan argv is never empty");

    Command::new(exe).args(args).status().map_err(|e| {
        if e.raw_os_error() == Some(740) {
            anyhow::anyhow!("the uninstaller needs administrator rights. Add --elevate or use an elevated terminal.")
        } else {
            anyhow::Error::new(e).context(format!("failed to launch {exe}"))
        }
    })
}

/// Is the program's Uninstall key still there?
pub fn still_installed(program: &Program) -> bool {
    registry::key_exists(program.source.hive, &program.uninstall_subpath())
}

/// After the launched process exits, an EXE uninstaller may still be running
/// as a detached copy. Wait while the registry entry exists and a process
/// that looks like the uninstaller is alive, up to `max`. Returns true if the
/// entry is gone.
pub fn wait_for_completion(program: &Program, plan: &UninstallPlan, max: Duration) -> bool {
    if plan.is_msi || !still_installed(program) {
        return !still_installed(program);
    }
    let install_dir = program
        .install_location
        .as_deref()
        .map(util::expand_env_vars)
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());

    let start = Instant::now();
    while start.elapsed() < max {
        // A running process is only ours if it runs from the program's own
        // folder or is the uninstaller's copy of itself in %TEMP%. Matching on
        // the file name alone waits for any unrelated program that happens to
        // share it: a Steam game uninstalls through `steam.exe`, which runs the
        // whole time, and every Squirrel app uninstalls through `Update.exe`.
        let alive = system::running_exes().into_iter().any(|exe| {
            install_dir
                .as_deref()
                .map(|d| system::path_under(&exe, d))
                .unwrap_or(false)
                || is_temp_uninstaller(&exe)
        });
        if !alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    !still_installed(program)
}

/// Inno Setup and friends run from `%TEMP%\<random>\_iu14D2N.tmp` or similar.
fn is_temp_uninstaller(exe: &Path) -> bool {
    let Some(temp) = std::env::var_os("TEMP").map(std::path::PathBuf::from) else {
        return false;
    };
    if !system::path_under(exe, &temp) {
        return false;
    }
    let name = exe
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    name.contains("unins")
        || name.ends_with(".tmp")
        || name.contains("setup")
        || name.contains("install")
}

pub fn describe_exit(status: ExitStatus, is_msi: bool) -> String {
    match status.code() {
        Some(0) => "finished".to_string(),
        Some(3010) => "finished, a reboot is required".to_string(),
        Some(1641) => "finished, a reboot has been started".to_string(),
        Some(1605) if is_msi => "reported the product as not installed (1605)".to_string(),
        Some(1602) if is_msi => "was cancelled (1602)".to_string(),
        Some(1618) if is_msi => "found another installation in progress (1618)".to_string(),
        Some(code) => format!("exited with code {code}"),
        None => "ended without an exit code".to_string(),
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
