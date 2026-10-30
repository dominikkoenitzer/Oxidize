//! Stores Windows owns, cleaned only through the tools Windows provides for
//! them: DISM for the component store, the Delivery Optimization cmdlets for
//! their cache, Disk Cleanup for a previous Windows installation. Oxidize
//! never deletes a file in any of them itself.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::system;

/// DISM's analysis of the component store. Read-only.
pub const DISM_ANALYZE: &[&str] = &[
    "/Online",
    "/English",
    "/Cleanup-Image",
    "/AnalyzeComponentStore",
];

/// The component store cleanup Windows runs on its own schedule. Superseded
/// components go; installed updates can still be uninstalled afterwards,
/// which `/ResetBase` would end, so it is never passed.
pub const DISM_CLEANUP: &[&str] = &[
    "/Online",
    "/English",
    "/Cleanup-Image",
    "/StartComponentCleanup",
];

/// How many files the Delivery Optimization cache holds and their size, as
/// the service lists them.
const DO_STATUS: &str = "$s = @(Get-DeliveryOptimizationStatus); \
     $b = ($s | Measure-Object -Property FileSizeInCache -Sum).Sum; \
     if ($null -eq $b) { $b = 0 }; \
     Write-Output (\"{0} {1}\" -f $s.Count, [UInt64]$b)";

const DO_DELETE: &str = "Delete-DeliveryOptimizationCache -Force";

/// The Disk Cleanup handler for previous Windows installations.
const PREVIOUS_INSTALLATIONS: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations";
/// The Disk Cleanup preset Oxidize sets on that handler alone for one run.
const SAGESET: u32 = 6500;

/// What DISM says about the component store.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct StoreReport {
    pub actual_size: Option<String>,
    pub backups_and_disabled_features: Option<String>,
    pub cache_and_temporary_data: Option<String>,
    pub reclaimable_packages: Option<u32>,
    pub cleanup_recommended: Option<bool>,
}

/// The Windows tools the cleaner calls, and git, behind a trait so tests
/// never run them.
pub trait Tools: Send + Sync {
    fn component_store(&self) -> Result<StoreReport>;
    fn component_cleanup(&self) -> Result<()>;
    /// Files in the Delivery Optimization cache, and their bytes.
    fn delivery_cache(&self) -> Result<(usize, u64)>;
    fn delete_delivery_cache(&self) -> Result<()>;
    fn remove_windows_old(&self) -> Result<()>;
    /// Free bytes on the drive `path` is on.
    fn free_bytes(&self, path: &Path) -> Option<u64>;
    /// The executables running now.
    fn running_exes(&self) -> Vec<std::path::PathBuf>;
    /// Whether the git checkout at `dir` holds uncommitted work: changed,
    /// staged or untracked files. None when git cannot tell.
    fn uncommitted(&self, dir: &Path) -> Option<bool>;
}

/// `git status` in its short form, for scripts. Its file system monitor,
/// a program a checkout's settings can name, is never started, and no
/// lock is taken that a running git would trip over.
pub const GIT_STATUS: &[&str] = &[
    "-c",
    "core.fsmonitor=false",
    "--no-optional-locks",
    "status",
    "--porcelain",
];

/// The real tools.
pub struct WindowsTools;

impl Tools for WindowsTools {
    fn component_store(&self) -> Result<StoreReport> {
        let out = run(dism(), DISM_ANALYZE)?;
        Ok(parse_store_report(&out))
    }

    fn component_cleanup(&self) -> Result<()> {
        run(dism(), DISM_CLEANUP).map(|_| ())
    }

    fn delivery_cache(&self) -> Result<(usize, u64)> {
        let out = run(powershell(), &powershell_args(DO_STATUS))?;
        parse_delivery_status(&out).context("reading the Delivery Optimization cache")
    }

    fn delete_delivery_cache(&self) -> Result<()> {
        run(powershell(), &powershell_args(DO_DELETE)).map(|_| ())
    }

    fn remove_windows_old(&self) -> Result<()> {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
        let name = format!("StateFlags{SAGESET:04}");
        let key = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(PREVIOUS_INSTALLATIONS, KEY_SET_VALUE)
            .context("opening the Disk Cleanup handler for previous installations")?;
        key.set_value(&name, &2u32)
            .context("choosing previous installations in Disk Cleanup")?;
        let result = run(
            system::system32("cleanmgr.exe"),
            &[&format!("/sagerun:{SAGESET}")],
        );
        let _ = key.delete_value(&name);
        result.map(|_| ())
    }

    fn free_bytes(&self, path: &Path) -> Option<u64> {
        free_bytes(path)
    }

    fn running_exes(&self) -> Vec<std::path::PathBuf> {
        system::running_exes()
    }

    fn uncommitted(&self, dir: &Path) -> Option<bool> {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(dir).args(GIT_STATUS);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let out = cmd.stdin(std::process::Stdio::null()).output().ok()?;
        out.status
            .success()
            .then(|| out.stdout.iter().any(|b| !b.is_ascii_whitespace()))
    }
}

fn dism() -> String {
    system::system32("dism.exe")
}

fn powershell() -> String {
    system::system32(r"WindowsPowerShell\v1.0\powershell.exe")
}

fn powershell_args(script: &str) -> Vec<&str> {
    vec!["-NoProfile", "-NonInteractive", "-Command", script]
}

/// Run a tool without a window and return what it printed.
fn run(exe: String, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new(&exe);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("starting {exe}"))?;
    let text = tool_text(&out.stdout);
    // 3010: done, a restart finishes it.
    match out.status.code() {
        Some(0) | Some(3010) => Ok(text),
        code => {
            let err = tool_text(&out.stderr);
            let detail = last_line(&err)
                .or_else(|| last_line(&text))
                .unwrap_or_default();
            let name = Path::new(&exe)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or(exe.clone());
            match code {
                Some(c) => bail!("{name} ended with exit code {c} {detail}"),
                None => bail!("{name} was stopped {detail}"),
            }
        }
    }
}

/// What a tool started by `run` printed to a pipe.
fn tool_text(bytes: &[u8]) -> String {
    // DISM writes the OEM code page; PowerShell writes its new console's page, which starts there.
    system::code_page_text(bytes, windows::Win32::Globalization::CP_OEMCP)
}

fn last_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .map(|l| format!("({l})"))
}

/// Read `/AnalyzeComponentStore` output, which `/English` keeps in English.
pub fn parse_store_report(text: &str) -> StoreReport {
    let mut r = StoreReport::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(" : ") else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim().to_string();
        match key.as_str() {
            "actual size of component store" => r.actual_size = Some(value),
            "backups and disabled features" => r.backups_and_disabled_features = Some(value),
            "cache and temporary data" => r.cache_and_temporary_data = Some(value),
            "number of reclaimable packages" => r.reclaimable_packages = value.parse().ok(),
            "component store cleanup recommended" => {
                r.cleanup_recommended = Some(value.eq_ignore_ascii_case("yes"))
            }
            _ => {}
        }
    }
    r
}

/// Read the `<files> <bytes>` line the status script prints.
fn parse_delivery_status(text: &str) -> Option<(usize, u64)> {
    let line = text.lines().map(str::trim).rfind(|l| !l.is_empty())?;
    let (files, bytes) = line.split_once(' ')?;
    Some((files.parse().ok()?, bytes.parse().ok()?))
}

/// Free bytes on the drive `path` is on.
#[cfg(windows)]
pub fn free_bytes(path: &Path) -> Option<u64> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut free = 0u64;
    unsafe { GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut free), None, None) }.ok()?;
    Some(free)
}

#[cfg(not(windows))]
pub fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

/// `C:\Windows.old` on the system drive.
pub fn windows_old() -> Option<PathBuf> {
    let root = system::windows_dir();
    let drive = root.ancestors().last()?.to_path_buf();
    Some(drive.join("Windows.old"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_component_store_cleanup_never_resets_the_base() {
        for args in [DISM_ANALYZE, DISM_CLEANUP] {
            assert!(args.contains(&"/Online"));
            assert!(
                args.iter().all(|a| !a.to_lowercase().contains("resetbase")),
                "{args:?}"
            );
        }
        assert!(DISM_CLEANUP.contains(&"/StartComponentCleanup"));
    }

    #[test]
    fn the_analysis_reads_what_dism_reports() {
        let text = "\
Deployment Image Servicing and Management tool
Version: 10.0.26100.1

Image Version: 10.0.26300.1

[==========================100.0%==========================]

Component Store (WinSxS) information:

Windows Explorer Reported Size of Component Store : 8.42 GB

Actual Size of Component Store : 8.18 GB

    Shared with Windows : 5.71 GB
    Backups and Disabled Features : 2.30 GB
    Cache and Temporary Data :  166.42 MB

Date of Last Cleanup : 2026-09-30 10:12:04

Number of Reclaimable Packages : 2
Component Store Cleanup Recommended : Yes

The operation completed successfully.
";
        let r = parse_store_report(text);
        assert_eq!(r.actual_size.as_deref(), Some("8.18 GB"));
        assert_eq!(r.backups_and_disabled_features.as_deref(), Some("2.30 GB"));
        assert_eq!(r.cache_and_temporary_data.as_deref(), Some("166.42 MB"));
        assert_eq!(r.reclaimable_packages, Some(2));
        assert_eq!(r.cleanup_recommended, Some(true));
        assert_eq!(parse_store_report("nothing"), StoreReport::default());
    }

    #[test]
    fn the_delivery_status_line_reads() {
        assert_eq!(
            parse_delivery_status("14 2254147166\r\n"),
            Some((14, 2254147166))
        );
        assert_eq!(parse_delivery_status("0 0"), Some((0, 0)));
        assert_eq!(parse_delivery_status("error"), None);
    }

    #[test]
    fn tool_output_is_read_in_the_oem_code_page() {
        let oem = unsafe { windows::Win32::Globalization::GetOEMCP() };
        let text = tool_text(b"Error: 5\r\n\r\nAcc\x8as refus\x82.\r\n");
        assert_eq!(
            text,
            system::code_page_text(b"Error: 5\r\n\r\nAcc\x8as refus\x82.\r\n", oem)
        );
        assert!(!text.contains(char::REPLACEMENT_CHARACTER), "{text}");
        assert_eq!(tool_text(b"14 2254147166\r\n"), "14 2254147166\r\n");
    }

    #[test]
    fn free_space_reads_for_the_system_drive() {
        assert!(free_bytes(&system::windows_dir()).unwrap() > 0);
        assert_eq!(
            windows_old().unwrap().file_name().unwrap(),
            std::ffi::OsStr::new("Windows.old")
        );
    }
}
