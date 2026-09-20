//! Services, scheduled tasks, PATH entries, firewall rules and running
//! processes: the parts of a program's footprint that live outside its own
//! folders and keys. Read here, removed through `safety`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use winreg::RegValue;

use crate::model::{environment_key, Hive, FIREWALL_RULES_KEY};
use crate::registry;
use crate::util;

pub const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";

/// Absolute path of a System32 executable, so PATH cannot redirect us.
pub fn system32(exe: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\{exe}")
}

fn windir() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// Case-insensitive "is `p` inside `dir`" on string paths.
pub fn path_under(p: &Path, dir: &Path) -> bool {
    let norm = |x: &Path| {
        x.to_string_lossy()
            .to_lowercase()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_string()
    };
    let (p, d) = (norm(p), norm(dir));
    !d.is_empty() && (p == d || p.starts_with(&format!("{d}\\")))
}

pub fn in_windows_dir(p: &Path) -> bool {
    path_under(p, &windir())
}

/// Is the drive or share this path sits on mounted? A path on an unplugged
/// drive is missing for now, not gone, and the setting works again once the
/// drive is back.
pub fn volume_available(p: &Path) -> bool {
    match p.ancestors().last() {
        Some(root) if !root.as_os_str().is_empty() => root.exists(),
        _ => false,
    }
}

/// Turn the first token of a command line into an executable path, resolving
/// the kernel-style prefixes service ImagePaths use.
pub fn command_exe(command: &str) -> Option<PathBuf> {
    let expanded = util::expand_env_vars(command.trim());
    let mut s = if expanded.starts_with('"') {
        util::split_command_line(&expanded).into_iter().next()?
    } else {
        // Unquoted: Windows tries ever longer prefixes, so a path with
        // spaces runs up to and including the first `.exe`.
        let lower = expanded.to_lowercase();
        match lower.find(".exe") {
            Some(i) => expanded[..i + 4].to_string(),
            None => util::split_command_line(&expanded).into_iter().next()?,
        }
    };
    s = s.trim_matches('"').to_string();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix(r"\??\") {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_prefix(r"\SystemRoot\") {
        s = windir().join(rest).to_string_lossy().to_string();
    } else if let Some(rest) = s
        .strip_prefix("system32\\")
        .or_else(|| s.strip_prefix("System32\\"))
    {
        s = windir()
            .join("System32")
            .join(rest)
            .to_string_lossy()
            .to_string();
    }
    // Unquoted paths with spaces and no extension: take the token as given.
    Some(PathBuf::from(s))
}

// Services
// --------

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: Option<String>,
    /// The raw `ImagePath` value.
    pub image_path: String,
    /// The executable from `image_path`, expanded.
    pub exe: Option<PathBuf>,
}

/// User-mode services (drivers are skipped) with a non-empty ImagePath.
pub fn services() -> Vec<ServiceInfo> {
    let mut out = Vec::new();
    for name in registry::enum_subkeys(Hive::LocalMachine, SERVICES_KEY) {
        let sub = format!("{SERVICES_KEY}\\{name}");
        // Type 0x10 own process, 0x20 shared process, 0x50/0x60 user services.
        let ty = registry::read_u32(Hive::LocalMachine, &sub, "Type").unwrap_or(0);
        if ty & 0x30 == 0 {
            continue;
        }
        let Some(image_path) = registry::read_string(Hive::LocalMachine, &sub, "ImagePath") else {
            continue;
        };
        let exe = command_exe(&image_path);
        out.push(ServiceInfo {
            display_name: registry::read_string(Hive::LocalMachine, &sub, "DisplayName"),
            name,
            image_path,
            exe,
        });
    }
    out
}

/// Stop and delete a service. Needs elevation.
pub fn delete_service(name: &str) -> Result<()> {
    let sc = system32("sc.exe");
    // Stopping may fail because it is already stopped; that is fine.
    let _ = Command::new(&sc).args(["stop", name]).output();
    let out = Command::new(&sc)
        .args(["delete", name])
        .output()
        .context("running sc delete")?;
    match out.status.code() {
        // 1060: does not exist. 1072: already marked for deletion.
        Some(0) | Some(1060) | Some(1072) => Ok(()),
        Some(code) => bail!(
            "sc delete failed with code {code}: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ),
        None => bail!("sc delete was terminated"),
    }
}

// Scheduled tasks
// ---------------

#[derive(Debug, Clone)]
pub struct TaskInfo {
    /// Full task path, e.g. `\Vendor\Updater`.
    pub name: String,
    /// The task's XML file under `System32\Tasks`.
    pub file: PathBuf,
    /// `<Command>` of the first Exec action, expanded.
    pub command: Option<String>,
    pub exe: Option<PathBuf>,
}

fn tasks_root() -> PathBuf {
    windir().join("System32").join("Tasks")
}

/// Every task except Microsoft's own, read from the Task Scheduler folder.
pub fn scheduled_tasks() -> Vec<TaskInfo> {
    let root = tasks_root();
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                // Windows' own tasks live under \Microsoft.
                if dir == root && entry.file_name().eq_ignore_ascii_case("Microsoft") {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                let rel = path.strip_prefix(&root).unwrap_or(&path);
                let name = format!("\\{}", rel.to_string_lossy().replace('/', "\\"));
                let command = read_task_command(&path);
                // `<Command>` holds only the program, arguments live elsewhere.
                let exe = command
                    .as_deref()
                    .map(|c| util::expand_env_vars(c.trim().trim_matches('"')))
                    .filter(|c| !c.is_empty())
                    .map(PathBuf::from);
                out.push(TaskInfo {
                    name,
                    file: path,
                    command,
                    exe,
                });
            }
        }
    }
    out.sort_by_key(|t| t.name.to_lowercase());
    out
}

/// Pull `<Command>` out of a task XML file (UTF-16 LE with BOM).
fn read_task_command(file: &Path) -> Option<String> {
    let bytes = fs::read(file).ok()?;
    let text = decode_utf16_or_utf8(&bytes);
    let start = text.find("<Command>")? + "<Command>".len();
    let end = text[start..].find("</Command>")? + start;
    let raw = text[start..end].trim();
    if raw.is_empty() {
        return None;
    }
    Some(unescape_xml(raw))
}

fn unescape_xml(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub fn decode_utf16_or_utf8(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let (pairs, _) = bytes[2..].as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

/// Copy a task's XML definition to `out`. The file is already the format
/// `schtasks /create /xml` accepts.
pub fn export_task(task: &TaskInfo, out: &Path) -> Result<()> {
    fs::copy(&task.file, out)
        .with_context(|| format!("copying task definition {}", task.file.display()))?;
    Ok(())
}

pub fn delete_task(name: &str) -> Result<()> {
    let out = Command::new(system32("schtasks.exe"))
        .args(["/delete", "/tn", name, "/f"])
        .output()
        .context("running schtasks /delete")?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "schtasks /delete failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

/// Re-create a task from an exported XML file.
pub fn import_task(name: &str, xml: &Path) -> Result<()> {
    let out = Command::new(system32("schtasks.exe"))
        .args(["/create", "/tn", name, "/xml"])
        .arg(xml)
        .arg("/f")
        .output()
        .context("running schtasks /create")?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "schtasks /create failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

// PATH
// ----

/// The entries of the user or machine `Path` variable, unexpanded, in order.
pub fn path_entries(hive: Hive) -> Vec<String> {
    registry::read_string(hive, environment_key(hive), "Path")
        .map(|s| {
            s.split(';')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Drop one entry (case-insensitive, trailing slashes ignored) from the
/// `Path` variable, keeping the value's registry type.
pub fn remove_path_entry(hive: Hive, entry: &str) -> Result<()> {
    let key = environment_key(hive);
    let raw = registry::read_raw(hive, key, "Path").context("reading Path")?;
    let current =
        <String as winreg::types::FromRegValue>::from_reg_value(&raw).context("decoding Path")?;
    let same = |a: &str, b: &str| {
        a.trim()
            .trim_end_matches('\\')
            .eq_ignore_ascii_case(b.trim().trim_end_matches('\\'))
    };
    let kept: Vec<&str> = current
        .split(';')
        .filter(|e| !e.trim().is_empty() && !same(e, entry))
        .collect();
    let joined = kept.join(";");
    let bytes: Vec<u8> = joined
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    registry::write_raw(
        hive,
        key,
        "Path",
        &RegValue {
            bytes: bytes.into(),
            vtype: raw.vtype,
        },
    )
    .context("writing Path")?;
    broadcast_environment_change();
    Ok(())
}

/// Tell open windows the environment changed, so new shells pick up PATH.
#[cfg(windows)]
fn broadcast_environment_change() {
    use windows::core::w;
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };
    unsafe {
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(w!("Environment").as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            1000,
            None,
        );
    }
}

#[cfg(not(windows))]
fn broadcast_environment_change() {}

// Firewall
// --------

#[derive(Debug, Clone)]
pub struct FirewallRule {
    /// The value name under `FirewallRules` (a GUID).
    pub id: String,
    pub name: String,
    /// The program the rule applies to.
    pub app: PathBuf,
    /// `in` or `out`, plus the protocol when it is TCP or UDP.
    pub kind: String,
}

/// Firewall rules bound to a program path (rules for services, ports only or
/// Store apps are skipped).
pub fn firewall_rules() -> Vec<FirewallRule> {
    let mut out = Vec::new();
    for (id, data) in registry::enum_string_values(Hive::LocalMachine, FIREWALL_RULES_KEY) {
        let mut app = None;
        let mut name = None;
        let mut dir = String::new();
        let mut proto = String::new();
        for part in data.split('|') {
            if let Some(v) = part.strip_prefix("App=") {
                app = Some(v.to_string());
            } else if let Some(v) = part.strip_prefix("Name=") {
                name = Some(v.to_string());
            } else if let Some(v) = part.strip_prefix("Dir=") {
                dir = v.to_lowercase();
            } else if let Some(v) = part.strip_prefix("Protocol=") {
                proto = match v {
                    "6" => "tcp".to_string(),
                    "17" => "udp".to_string(),
                    _ => String::new(),
                };
            }
        }
        let kind = [dir, proto]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let Some(app) = app else { continue };
        if app.eq_ignore_ascii_case("System") || !app.contains('\\') {
            continue;
        }
        let app = PathBuf::from(util::expand_env_vars(&app));
        if in_windows_dir(&app) {
            continue;
        }
        let name = name.unwrap_or_else(|| id.clone());
        // Localised names arrive as resource references; show the file instead.
        let name = if name.starts_with('@') {
            app.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or(name)
        } else {
            name
        };
        out.push(FirewallRule {
            id,
            name,
            app,
            kind,
        });
    }
    out
}

// Processes
// ---------

/// Executable paths of all running processes.
pub fn running_exes() -> Vec<PathBuf> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let mut out: Vec<PathBuf> = sys
        .processes()
        .values()
        .filter_map(|p| p.exe().map(Path::to_path_buf))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_exe_handles_service_prefixes() {
        assert_eq!(
            command_exe(r#""C:\Program Files\Vendor\svc.exe" /run"#),
            Some(PathBuf::from(r"C:\Program Files\Vendor\svc.exe"))
        );
        let sys = command_exe(r"\SystemRoot\System32\svchost.exe -k netsvcs").unwrap();
        assert!(in_windows_dir(&sys));
        assert!(volume_available(&sys));
        assert!(!volume_available(Path::new(r"relative\path")));
        assert_eq!(command_exe(""), None);
        assert_eq!(
            command_exe(r"C:\Program Files\Vendor\svc.exe -k run"),
            Some(PathBuf::from(r"C:\Program Files\Vendor\svc.exe"))
        );
    }

    #[test]
    fn xml_unescape() {
        assert_eq!(unescape_xml("a &amp; b &quot;c&quot;"), "a & b \"c\"");
    }

    #[test]
    fn utf16_decoding() {
        let mut bytes = vec![0xFF, 0xFE];
        for u in "hi".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_utf16_or_utf8(&bytes), "hi");
        assert_eq!(decode_utf16_or_utf8(b"plain"), "plain");
    }
}
