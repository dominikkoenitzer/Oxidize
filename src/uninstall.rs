//! Running a program's own registered uninstaller.
//!
//! The command is built as an explicit argument vector, never through
//! `cmd.exe`. MSI products go through a synchronous `msiexec /x`, which has a
//! reliable exit code. EXE uninstallers often copy themselves to `%TEMP%` and
//! exit early, so completion is confirmed by watching the registry and the
//! process list afterwards.

use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::model::Program;
use crate::{registry, system, util};

/// Why an uninstaller did not start when Windows asked for administrator rights.
pub const NEEDS_ADMIN: &str =
    "the uninstaller needs administrator rights. Add --elevate or use an elevated terminal.";
pub const UNINSTALLER_MISSING: &str = "the uninstaller file is missing";

#[derive(Debug, Clone)]
pub struct UninstallPlan {
    /// `argv[0]` is the executable.
    pub argv: Vec<String>,
    pub is_msi: bool,
    /// Where the command came from.
    pub source: String,
    /// The command runs without asking anything.
    pub unattended: bool,
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
            unattended: silent,
        });
    }

    let (raw, source) = if silent {
        match (&program.quiet_uninstall_string, &program.uninstall_string) {
            (Some(q), _) => (q.clone(), "QuietUninstallString".to_string()),
            (None, Some(u)) if unins_uninstaller(u) => (
                format!("{u} {UNINS_SILENT}"),
                "UninstallString with the unins000.exe silent switches".to_string(),
            ),
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
    let unattended =
        silent && (program.quiet_uninstall_string.is_some() || unins_uninstaller(&raw));
    Ok(UninstallPlan {
        argv,
        is_msi: false,
        source,
        unattended,
    })
}

/// What an `unins000.exe` uninstaller takes to run without a window or a
/// question.
const UNINS_SILENT: &str = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART";

/// One widely used installer names its uninstaller `unins000.exe` (the digits count up when
/// several installs share a folder) and documents the silent switches, so it
/// runs unattended even when no quiet command was recorded.
fn unins_uninstaller(command: &str) -> bool {
    let argv = util::split_uninstall_command(&util::expand_env_vars(command));
    let Some(base) = argv.first().and_then(|exe| util::file_basename_lower(exe)) else {
        return false;
    };
    let stem = base.strip_suffix(".exe").unwrap_or(&base);
    stem.len() == 8 && stem.starts_with("unins") && stem[5..].bytes().all(|b| b.is_ascii_digit())
}

/// Launch the plan and wait for the spawned process to exit.
pub fn run(plan: &UninstallPlan) -> Result<ExitStatus> {
    run_with(plan, Stdio::inherit(), Stdio::inherit())
}

/// `run` with the uninstaller's input and output given. The MCP server
/// passes `Stdio::null()` for both: its own are the protocol stream.
pub fn run_with(plan: &UninstallPlan, stdin: Stdio, stdout: Stdio) -> Result<ExitStatus> {
    let (exe, args) = plan.argv.split_first().expect("plan argv is never empty");

    Command::new(exe)
        .args(args)
        .stdin(stdin)
        .stdout(stdout)
        .status()
        .map_err(|e| launch_error(e, exe))
}

fn launch_error(e: std::io::Error, exe: &str) -> anyhow::Error {
    if e.raw_os_error() == Some(740) {
        anyhow::anyhow!(NEEDS_ADMIN)
    } else if e.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!("{UNINSTALLER_MISSING}: {exe}")
    } else {
        anyhow::Error::new(e).context(format!("failed to launch {exe}"))
    }
}

/// `run_with`, but give up waiting after `max`: `Ok(None)` means it is still
/// running. For unattended uninstallers, which nobody is clicking through.
pub fn run_for(
    plan: &UninstallPlan,
    stdin: Stdio,
    stdout: Stdio,
    max: Duration,
) -> Result<Option<ExitStatus>> {
    let (exe, args) = plan.argv.split_first().expect("plan argv is never empty");
    let mut child = Command::new(exe)
        .args(args)
        .stdin(stdin)
        .stdout(stdout)
        .spawn()
        .map_err(|e| launch_error(e, exe))?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if start.elapsed() >= max {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// How a run of the vendor's uninstaller went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// How it ended, or that it was still running, in words.
    pub said: String,
    /// False when it was still running at the end of the wait.
    pub ended: bool,
}

impl Ran {
    /// What `run_for` found; `running` says it was still running.
    pub fn of(status: Option<ExitStatus>, is_msi: bool, running: impl FnOnce() -> String) -> Ran {
        match status {
            Some(status) => Ran {
                said: describe_exit(status, is_msi),
                ended: true,
            },
            None => Ran {
                said: running(),
                ended: false,
            },
        }
    }

    /// Whether the program is gone, asking `gone` only once the uninstaller
    /// has ended: one still running is not done, whatever the registry says.
    pub fn gone(&self, gone: impl FnOnce() -> bool) -> bool {
        self.ended && gone()
    }
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

/// Some uninstallers run from `%TEMP%\<random>\_iu14D2N.tmp` or similar.
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

    fn program(uninstall: &str, quiet: Option<&str>) -> Program {
        use crate::model::{Hive, RegistrySource, RegistryView};
        Program {
            registry_key: "app_is1".to_string(),
            source: RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
            display_name: "App".to_string(),
            display_version: None,
            publisher: None,
            install_date: None,
            install_location: None,
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: Some(uninstall.to_string()),
            quiet_uninstall_string: quiet.map(str::to_string),
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    #[test]
    fn a_program_is_gone_only_once_its_uninstaller_has_ended() {
        use std::os::windows::process::ExitStatusExt;
        let running = Ran::of(None, false, || "was still running after 60 s".into());
        assert_eq!(running.said, "was still running after 60 s");
        assert!(!running.ended);
        assert!(!running.gone(|| panic!("the entry is not looked at")));

        let ended = Ran::of(Some(ExitStatus::from_raw(0)), false, String::new);
        assert_eq!(ended.said, "finished");
        assert!(ended.gone(|| true));
        assert!(!ended.gone(|| false));
    }

    #[test]
    fn an_unins000_uninstaller_gets_its_silent_switches() {
        let p = program(r#""C:\Apps\App\unins000.exe""#, None);
        let silent = plan(&p, true).unwrap();
        assert!(silent.unattended);
        assert_eq!(
            silent.argv,
            [
                r"C:\Apps\App\unins000.exe",
                "/VERYSILENT",
                "/SUPPRESSMSGBOXES",
                "/NORESTART"
            ]
        );
        // Not asked for silence: the command as recorded.
        let asked = plan(&p, false).unwrap();
        assert!(!asked.unattended);
        assert_eq!(asked.argv, [r"C:\Apps\App\unins000.exe"]);
    }

    #[test]
    fn only_a_known_quiet_command_counts_as_unattended() {
        let other = program(r"C:\Apps\App\uninstall.exe", None);
        assert!(!plan(&other, true).unwrap().unattended);
        let quiet = program(
            r"C:\Apps\App\uninstall.exe",
            Some(r"C:\Apps\App\uninstall.exe /S"),
        );
        assert!(plan(&quiet, true).unwrap().unattended);
        assert!(!unins_uninstaller(r"C:\Apps\unins.exe"));
        assert!(!unins_uninstaller(r"C:\Apps\uninstaller.exe"));
        assert!(unins_uninstaller(r"C:\Apps\unins001.exe /LOG"));
    }

    #[test]
    fn recognises_product_guids() {
        assert!(looks_like_guid("{2D7E0D49-1A2B-3C4D-5E6F-708192A3B4C5}"));
        assert!(!looks_like_guid("Google Chrome"));
        assert!(!looks_like_guid("{too-short}"));
    }
}
