//! Hunter mode: point it at a binary or process to find its program. Given a path
//! to an executable/folder, or the name of a running process, trace it back to
//! the installed-program entry it belongs to so the user can uninstall it.
//!
//! Matching is path-first (the strongest signal is "this exe lives inside that
//! program's install folder"), with DisplayIcon and name fallbacks.

use std::path::{Path, PathBuf};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::model::Program;
use crate::util::{self, normalize, significant_tokens};

/// A program matched to the hunter query, with a score and explanation.
#[derive(Debug, Clone)]
pub struct HunterMatch {
    pub program: Program,
    pub score: u32,
    pub reason: String,
}

/// Heuristic: does this query look like a filesystem path (rather than a bare
/// process/exe name)? Used to still seed from a path that isn't on disk now.
fn looks_like_path(q: &str) -> bool {
    q.contains('\\') || q.contains('/') || (q.len() >= 2 && q.as_bytes()[1] == b':')
}

/// Make a path absolute (joining the current dir if relative) without
/// canonicalising — canonicalisation yields `\\?\` verbatim paths on Windows,
/// which break simple prefix comparisons against registry `InstallLocation`s.
fn absolutize(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

/// Is `child` equal to, or nested under, `parent` (case-insensitive)?
fn path_under(child: &Path, parent: &Path) -> bool {
    let normalize = |p: &Path| {
        p.to_string_lossy()
            .to_lowercase()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_string()
    };
    let c = normalize(child);
    let p = normalize(parent);
    if p.is_empty() {
        return false;
    }
    c == p || c.starts_with(&format!("{p}\\"))
}

/// Find the executable paths of running processes whose name matches `query`
/// (with or without a `.exe` suffix).
fn find_process_exes(query: &str) -> Vec<PathBuf> {
    let q = query.to_lowercase();
    let q_exe = if q.ends_with(".exe") {
        q.clone()
    } else {
        format!("{q}.exe")
    };

    let mut sys = System::new();
    // Refresh only the executable paths (the only thing we need).
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );

    let mut out = Vec::new();
    for process in sys.processes().values() {
        let name = process.name().to_string_lossy().to_lowercase();
        let exe = process.exe().map(Path::to_path_buf);
        let exe_base = exe
            .as_deref()
            .and_then(|p| util::file_basename_lower(&p.to_string_lossy()));

        let hit = name == q
            || name == q_exe
            || exe_base.as_deref() == Some(q.as_str())
            || exe_base.as_deref() == Some(q_exe.as_str());

        if hit {
            if let Some(exe) = exe {
                if !out.contains(&exe) {
                    out.push(exe);
                }
            }
        }
    }
    out
}

fn dedup(paths: &mut Vec<PathBuf>) {
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.to_string_lossy().to_lowercase()));
}

/// Trace `query` (an exe/folder path, or a process name) back to installed
/// programs. Returns matches sorted best-first.
pub fn hunt(query: &str, programs: &[Program]) -> Vec<HunterMatch> {
    let mut exe_paths: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();

    let raw = Path::new(query);
    if raw.exists() {
        let abs = absolutize(raw);
        if abs.is_dir() {
            dirs.push(abs);
        } else {
            if let Some(parent) = abs.parent() {
                dirs.push(parent.to_path_buf());
            }
            exe_paths.push(abs);
        }
    } else if looks_like_path(query) {
        // Path-shaped but not present right now (partial removal, disconnected
        // drive, typo). Still seed from it so a registry InstallLocation can match.
        let abs = absolutize(raw);
        if abs.extension().is_some() {
            if let Some(parent) = abs.parent() {
                dirs.push(parent.to_path_buf());
            }
            exe_paths.push(abs);
        } else {
            dirs.push(abs);
        }
    } else {
        // Treat as a process / executable name and look it up among running
        // processes.
        for exe in find_process_exes(query) {
            if let Some(parent) = exe.parent() {
                dirs.push(parent.to_path_buf());
            }
            exe_paths.push(exe);
        }
    }

    dedup(&mut exe_paths);
    dedup(&mut dirs);

    let exe_basenames: Vec<String> = exe_paths
        .iter()
        .filter_map(|p| util::file_basename_lower(&p.to_string_lossy()))
        .collect();
    let query_basename = util::file_basename_lower(query);

    let mut matches: Vec<HunterMatch> = Vec::new();

    for program in programs {
        let mut score = 0u32;
        let mut reasons: Vec<String> = Vec::new();

        let install = program
            .install_location
            .as_deref()
            .map(util::expand_env_vars)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty());

        // Path signals are weighted an order of magnitude above the name/icon
        // bonuses below, so a genuine "exe lives in this install folder" match
        // can never be outranked by coincidental DisplayIcon + folder hits.
        if let Some(install) = &install {
            if exe_paths.iter().any(|exe| path_under(exe, install)) {
                score += 1000;
                reasons.push("executable runs from this program's install folder".to_string());
            } else if dirs
                .iter()
                .any(|d| path_under(d, install) || install.parent() == Some(d.as_path()))
            {
                score += 500;
                reasons.push("located inside this program's install folder".to_string());
            }
        }

        // DisplayIcon usually points at the program's main exe.
        if let Some(icon) = &program.display_icon {
            // Strip only a trailing ",<index>" icon selector (keep commas in paths).
            let without_index = match icon.rsplit_once(',') {
                Some((left, right)) if right.trim().parse::<i32>().is_ok() => left,
                _ => icon.as_str(),
            };
            if let Some(icon_base) =
                util::file_basename_lower(&util::expand_env_vars(without_index))
            {
                if exe_basenames.contains(&icon_base)
                    || query_basename.as_deref() == Some(icon_base.as_str())
                {
                    score += 80;
                    reasons.push(format!("matches DisplayIcon ({icon_base})"));
                }
            }
        }

        // Folder-name keyword overlap (weak signal).
        let prog_tokens = significant_tokens(&program.display_name);
        if !prog_tokens.is_empty() {
            let folder_hit = dirs.iter().any(|d| {
                d.file_name()
                    .and_then(|s| s.to_str())
                    .map(|name| {
                        let nt = significant_tokens(name);
                        prog_tokens.iter().any(|t| nt.iter().any(|n| n == t))
                            || normalize(name) == normalize(&program.display_name)
                    })
                    .unwrap_or(false)
            });
            if folder_hit {
                score += 30;
                reasons.push("folder name matches the program".to_string());
            }
        }

        if score > 0 {
            matches.push(HunterMatch {
                program: program.clone(),
                score,
                reason: reasons.join("; "),
            });
        }
    }

    matches.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.program.display_name.cmp(&b.program.display_name))
    });
    matches
}
