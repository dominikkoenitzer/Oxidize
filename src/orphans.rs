//! The sweep for things no installed program owns: folders under the usual
//! roots that no registered program claims, and PATH entries, autostart
//! values, services and tasks whose executable no longer exists.
//!
//! Folder ownership is judged from the registry (install folders, uninstall
//! and icon paths), from name and publisher words of installed programs, and
//! from running processes. The result is a list to look at, not a verdict;
//! portable tools and caches of programs without an uninstall entry show up
//! here too.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::model::{Confidence, Hive, Leftover, LeftoverKind, Program};
use crate::scanner;
use crate::system;
use crate::util::{self, normalize, significant_tokens};

/// A folder nobody claims.
#[derive(Debug, Clone, Serialize)]
pub struct OrphanFolder {
    pub path: PathBuf,
    pub size_bytes: u64,
    /// Last modification as `YYYY-MM-DD`.
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OrphanReport {
    pub folders: Vec<OrphanFolder>,
    /// References to files that no longer exist. Safe to remove.
    pub dangling: Vec<Leftover>,
}

/// Everything installed programs are known to own.
struct Claims {
    dirs: Vec<PathBuf>,
    words: HashSet<String>,
    names: HashSet<String>,
}

impl Claims {
    fn build(programs: &[Program]) -> Self {
        let mut dirs = Vec::new();
        let mut words = HashSet::new();
        let mut names = HashSet::new();
        // A program that records `AppData\Local` itself as its folder must
        // not claim everything under it.
        let mut push_dir = |s: &str| {
            let p = PathBuf::from(util::expand_env_vars(s.trim().trim_matches('"')));
            if !p.as_os_str().is_empty() && !scanner::is_protected_path(&p) {
                dirs.push(p);
            }
        };
        for p in programs {
            if let Some(loc) = &p.install_location {
                push_dir(loc);
            }
            for cmd in [&p.uninstall_string, &p.quiet_uninstall_string]
                .into_iter()
                .flatten()
            {
                if let Some(exe) = system::command_exe(cmd) {
                    if let Some(dir) = exe.parent() {
                        push_dir(&dir.to_string_lossy());
                    }
                }
            }
            if let Some(icon) = &p.display_icon {
                let without_index = icon.split(',').next().unwrap_or(icon);
                if let Some(dir) =
                    Path::new(util::expand_env_vars(without_index).trim_matches('"')).parent()
                {
                    push_dir(&dir.to_string_lossy());
                }
            }
            names.insert(normalize(&p.display_name));
            words.extend(
                significant_tokens(&p.display_name)
                    .into_iter()
                    .filter(|t| t.len() >= 4),
            );
            if let Some(pubr) = &p.publisher {
                names.insert(normalize(pubr));
                words.extend(
                    significant_tokens(pubr)
                        .into_iter()
                        .filter(|t| t.len() >= 4),
                );
            }
        }
        // Running processes own their folders too.
        for exe in system::running_exes() {
            if let Some(dir) = exe.parent() {
                if !scanner::is_protected_path(dir) {
                    dirs.push(dir.to_path_buf());
                }
            }
        }
        Claims { dirs, words, names }
    }

    /// Is `folder` owned: does a claimed path sit inside it or contain it, or
    /// does its name belong to an installed program?
    fn owns(&self, folder: &Path) -> bool {
        if self
            .dirs
            .iter()
            .any(|d| system::path_under(d, folder) || system::path_under(folder, d))
        {
            return true;
        }
        let name = folder
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let norm = normalize(&name);
        // "BraveSoftware" against publisher "Brave Software Inc", "Google"
        // against "Google Chrome": one is a prefix of the other.
        if norm.len() >= 4
            && self
                .names
                .iter()
                .any(|n| n.len() >= 4 && (n.starts_with(&norm) || norm.starts_with(n.as_str())))
        {
            return true;
        }
        significant_tokens(&name)
            .iter()
            .any(|t| self.words.contains(t))
    }
}

fn orphan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut push = |p: Option<PathBuf>| {
        if let Some(p) = p {
            if p.is_dir() && !roots.contains(&p) {
                roots.push(p);
            }
        }
    };
    push(scanner::env_dir("ProgramFiles"));
    push(scanner::env_dir("ProgramFiles(x86)"));
    push(scanner::env_dir("ProgramData"));
    push(scanner::env_dir("LOCALAPPDATA"));
    push(scanner::env_dir("LOCALAPPDATA").map(|p| p.join("Programs")));
    push(scanner::env_dir("APPDATA"));
    roots
}

fn modified_date(p: &Path) -> Option<String> {
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    let dt: chrono::DateTime<chrono::Local> = t.into();
    Some(dt.format("%Y-%m-%d").to_string())
}

/// Folders under the usual roots that no installed program claims.
pub fn unclaimed_folders(programs: &[Program]) -> Vec<OrphanFolder> {
    let claims = Claims::build(programs);
    let mut out = Vec::new();
    for root in orphan_roots() {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if scanner::fs_denied(&name) || name.starts_with('.') {
                continue;
            }
            let Ok(ft) = entry.file_type() else { continue };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if scanner::is_protected_path(&path)
                || scanner::path_within_shared_dir(&path)
                || claims.owns(&path)
            {
                continue;
            }
            out.push(OrphanFolder {
                size_bytes: scanner::dir_size(&path),
                modified: modified_date(&path),
                path,
            });
        }
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.size_bytes));
    out
}

/// PATH entries, autostart values, services and tasks pointing at files that
/// are gone.
pub fn dangling_references() -> Vec<Leftover> {
    let mut out = Vec::new();

    for hive in [Hive::CurrentUser, Hive::LocalMachine] {
        for entry in system::path_entries(hive) {
            let dir = PathBuf::from(util::expand_env_vars(&entry));
            if !dir.is_absolute() || dir.exists() {
                continue;
            }
            out.push(Leftover::path_entry(
                hive,
                entry,
                Confidence::High,
                "folder does not exist",
            ));
        }
    }

    const RUN_KEYS: &[(Hive, &str)] = &[
        (
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
    ];
    for (hive, base) in RUN_KEYS {
        for (name, data) in crate::registry::enum_string_values(*hive, base) {
            let Some(exe) = system::command_exe(&data) else {
                continue;
            };
            if exe.is_absolute() && !exe.exists() {
                out.push(Leftover::reg_value(
                    *hive,
                    *base,
                    name,
                    Confidence::High,
                    "autostart, file does not exist",
                ));
            }
        }
    }

    for svc in system::services() {
        let Some(exe) = &svc.exe else { continue };
        if exe.is_absolute() && !exe.exists() && !system::in_windows_dir(exe) {
            out.push(Leftover::service(
                svc.name,
                &exe.to_string_lossy(),
                Confidence::High,
                "file does not exist",
            ));
        }
    }

    for task in system::scheduled_tasks() {
        let Some(exe) = &task.exe else { continue };
        if exe.is_absolute() && !exe.exists() && !system::in_windows_dir(exe) {
            out.push(Leftover::task(
                task.name,
                &exe.to_string_lossy(),
                Confidence::High,
                "file does not exist",
            ));
        }
    }

    out
}

pub fn sweep(programs: &[Program]) -> OrphanReport {
    OrphanReport {
        folders: unclaimed_folders(programs),
        dangling: dangling_references(),
    }
}

/// Folders as leftovers, for callers that want one list type.
pub fn folder_leftovers(report: &OrphanReport) -> Vec<Leftover> {
    report
        .folders
        .iter()
        .map(|f| {
            Leftover::fs(
                LeftoverKind::Directory,
                f.path.clone(),
                Confidence::Low,
                "no installed program claims it",
                Some(f.size_bytes),
                f.size_bytes == 0,
            )
        })
        .collect()
}
