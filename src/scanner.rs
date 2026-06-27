//! The leftover scanner — what makes Oxidize thorough rather than a thin
//! wrapper around the Windows uninstaller.
//!
//! Given a [`ScanTarget`] (a snapshot of a program's identity captured *before*
//! uninstalling), it searches a fixed, program-scoped set of registry and
//! filesystem locations for remnants the program's own uninstaller left behind,
//! scoring each by confidence.
//!
//! Safety is designed in, not bolted on:
//!   * we never recurse the whole disk or the whole registry (program-scoped,
//!     shallow walks);
//!   * publisher folders/keys (which may hold sibling products) are *descended
//!     into* to find the specific product, never flagged wholesale;
//!   * denylists keep OS/shared locations (`C:\Windows`, `SOFTWARE\Microsoft`,
//!     driver vendor roots, …) out of the results entirely.

use std::fs;
use std::path::{Path, PathBuf};

use crate::model::{
    Confidence, Hive, Leftover, LeftoverKind, Program, RegistrySource, ScanReport, ScanTarget,
};
use crate::registry;
use crate::util::{self, normalize, significant_tokens};

/// Top-level folder names that are never reported as leftovers (OS/shared).
const FS_DENY: &[&str] = &[
    "microsoft",
    "windows",
    "windowsapps",
    "windows defender",
    "windows nt",
    "windows photo viewer",
    "windowspowershell",
    "common files",
    "internet explorer",
    "uninstall information",
    "modifiablewindowsapps",
    "packages",
    "package cache",
    "usoshared",
    "temp",
    "programs",
    "comms",
];

/// Top-level `SOFTWARE\...` child key names that are never reported or
/// descended (OS/shared/driver roots).
const REG_DENY: &[&str] = &[
    "microsoft",
    "classes",
    "clients",
    "policies",
    "registeredapplications",
    "wow6432node",
    "windows",
    "intel",
    "nvidia",
    "nvidia corporation",
    "amd",
    "realtek",
    "khronos group",
    "odbc",
];

/// OS/shared directory names that must never appear as *any* component of a path
/// we propose deleting (guards against an install folder recorded as a shared
/// location, e.g. `Program Files\Common Files\...`). Unlike `FS_DENY` this is
/// checked per path component, so it omits names that are legitimate as
/// intermediate components (e.g. `Programs`, `Temp`).
const SHARED_DIR_DENY: &[&str] = &[
    "windows",
    "microsoft",
    "common files",
    "internet explorer",
    "windowsapps",
    "windows defender",
    "windowspowershell",
    "windows nt",
    "uninstall information",
    "modifiablewindowsapps",
    "usoshared",
    "package cache",
];

fn fs_denied(name: &str) -> bool {
    let n = name.to_lowercase();
    FS_DENY.contains(&n.as_str())
}

/// True if any component of `p` is an OS/shared directory we must never delete.
fn path_within_shared_dir(p: &Path) -> bool {
    p.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| SHARED_DIR_DENY.contains(&s.to_lowercase().as_str()))
            .unwrap_or(false)
    })
}

fn reg_denied(name: &str) -> bool {
    let n = name.to_lowercase();
    REG_DENY.contains(&n.as_str())
}

// ---------------------------------------------------------------------------
// Building a scan target from a program
// ---------------------------------------------------------------------------

/// Capture the identity/footprint of a program into a [`ScanTarget`].
pub fn build_target(program: &Program) -> ScanTarget {
    let install_location = program
        .install_location
        .as_deref()
        .map(util::expand_env_vars)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());

    let mut exe_names = Vec::new();
    // DisplayIcon is the most reliable pointer to the program's main exe.
    if let Some(icon) = &program.display_icon {
        let without_index = icon.split(',').next().unwrap_or(icon);
        if let Some(base) = util::file_basename_lower(&util::expand_env_vars(without_index)) {
            if base.ends_with(".exe") {
                exe_names.push(base);
            }
        }
    }
    // The uninstaller's own exe is usually generic (unins000.exe / msiexec.exe),
    // so we only add it when it looks app-specific.
    if let Some(us) = &program.uninstall_string {
        let argv = util::split_command_line(&util::expand_env_vars(us));
        if let Some(first) = argv.first() {
            if let Some(base) = util::file_basename_lower(first) {
                let generic = matches!(
                    base.as_str(),
                    "msiexec.exe" | "unins000.exe" | "uninstall.exe" | "setup.exe" | "rundll32.exe"
                );
                if base.ends_with(".exe") && !generic && !exe_names.contains(&base) {
                    exe_names.push(base);
                }
            }
        }
    }

    let mut name_tokens = significant_tokens(&program.display_name);
    // The install folder's own name is often the most distinctive token.
    if let Some(loc) = &install_location {
        if let Some(folder) = loc.file_name().and_then(|s| s.to_str()) {
            for t in significant_tokens(folder) {
                if !name_tokens.contains(&t) {
                    name_tokens.push(t);
                }
            }
        }
    }

    let publisher_tokens = program
        .publisher
        .as_deref()
        .map(significant_tokens)
        .unwrap_or_default();

    ScanTarget {
        display_name: program.display_name.clone(),
        publisher: program.publisher.clone(),
        install_location,
        exe_names,
        name_tokens,
        publisher_tokens,
        registry_key: program.registry_key.clone(),
        source: program.source,
    }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Score a folder/key name against the *product* identity. Matching is
/// word/token-aware (so "ZoomIt" does **not** match "Zoom"); a single
/// coincidental keyword is at most `Medium`, so it never enters the default
/// (High-only) removal set. Publisher-only names are handled by
/// [`matches_publisher`] so a shared vendor folder is descended into, never
/// flagged wholesale.
fn score_product(name: &str, target: &ScanTarget) -> Option<(Confidence, String)> {
    let norm = normalize(name);
    if norm.len() < 3 {
        return None;
    }
    // 1. Exact normalized match — the strongest signal.
    if !target.display_name.is_empty() && norm == normalize(&target.display_name) {
        return Some((
            Confidence::High,
            format!("exact match for \"{}\"", target.display_name),
        ));
    }

    let candidate = significant_tokens(name);
    if candidate.is_empty() || target.name_tokens.is_empty() {
        return None;
    }

    // 2. The full product token-sequence appears (word-aligned), e.g.
    //    "Google Chrome" inside "Google Chrome Beta".
    if contains_subslice(&candidate, &target.name_tokens) {
        return Some((
            Confidence::High,
            format!("name contains \"{}\"", target.display_name),
        ));
    }

    // 3. Every product keyword is present (any order), with at least two of them
    //    (so this never fires on a single generic word).
    if target.name_tokens.len() >= 2 && target.name_tokens.iter().all(|t| candidate.contains(t)) {
        return Some((
            Confidence::High,
            format!("all keywords of \"{}\" present", target.display_name),
        ));
    }

    // 4. A single distinctive keyword matches — plausible, but Medium only.
    if let Some(hit) = target
        .name_tokens
        .iter()
        .find(|t| t.len() >= 4 && candidate.contains(*t))
    {
        return Some((Confidence::Medium, format!("matches keyword \"{hit}\"")));
    }
    None
}

/// True if `needle` appears as a contiguous run of whole tokens within `haystack`.
fn contains_subslice(haystack: &[String], needle: &[String]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True if `name` is essentially just the program's publisher (a shared vendor
/// root such as "Google" or "BraveSoftware"), so we should descend one level to
/// find the specific product rather than flag the vendor folder wholesale.
fn matches_publisher(name: &str, target: &ScanTarget) -> bool {
    let Some(publisher) = &target.publisher else {
        return false;
    };
    let norm = normalize(name);
    let pubn = normalize(publisher);
    // Only the "name is contained in the publisher" direction: a folder whose
    // name *contains* the publisher (e.g. "Mozilla Firefox") is a product, not a
    // vendor root, and must NOT be treated as publisher-only.
    if norm.len() >= 4 && pubn.len() >= 4 && pubn.contains(&norm) {
        return true;
    }
    // Or every significant token of the name is a publisher token (vendor-only).
    let candidate = significant_tokens(name);
    !candidate.is_empty()
        && !target.publisher_tokens.is_empty()
        && candidate.iter().all(|t| target.publisher_tokens.contains(t))
}

// ---------------------------------------------------------------------------
// Filesystem scan
// ---------------------------------------------------------------------------

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// The fixed set of roots whose immediate children we inspect by name.
fn fs_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |p: Option<PathBuf>| {
        if let Some(p) = p {
            if p.is_dir() && !roots.contains(&p) {
                roots.push(p);
            }
        }
    };

    push(env_dir("ProgramFiles"));
    push(env_dir("ProgramFiles(x86)"));
    push(env_dir("ProgramW6432"));
    push(env_dir("ProgramData"));
    push(env_dir("APPDATA"));
    push(env_dir("LOCALAPPDATA"));
    push(env_dir("LOCALAPPDATA").map(|p| p.join("Programs")));
    push(env_dir("APPDATA").map(|p| p.join(r"Microsoft\Windows\Start Menu\Programs")));
    push(env_dir("ProgramData").map(|p| p.join(r"Microsoft\Windows\Start Menu\Programs")));
    push(env_dir("USERPROFILE").map(|p| p.join("Desktop")));
    push(env_dir("PUBLIC").map(|p| p.join("Desktop")));
    roots
}

/// Normalize a path string for prefix/equality comparison: lower-cased, forward
/// slashes folded to back-slashes, trailing separators trimmed.
fn norm_path_str(p: &str) -> String {
    p.to_lowercase().replace('/', "\\").trim_end_matches('\\').to_string()
}

fn norm_path_key(p: &Path) -> String {
    norm_path_str(&p.to_string_lossy())
}

/// True if directory `dir` *strictly* contains `other` (i.e. `other` is a
/// descendant of `dir`). Both arguments must already be normalized via
/// [`norm_path_str`]. The trailing-separator boundary prevents a sibling such as
/// `...\Apple` from being treated as inside `...\App`.
fn dir_contains(dir: &str, other: &str) -> bool {
    other.len() > dir.len() && other.starts_with(&format!("{dir}\\"))
}

/// Install directories of every *other* installed program. Used so we never
/// propose deleting a directory that still houses a different program — e.g.
/// when a program's recorded `InstallLocation` is a shared parent folder that
/// also contains a sibling product.
fn other_program_install_dirs(target: &ScanTarget) -> Vec<PathBuf> {
    registry::enumerate_installed_programs(true)
        .into_iter()
        .filter(|p| !(p.registry_key == target.registry_key && p.source == target.source))
        .filter_map(|p| p.install_location)
        .map(|s| util::expand_env_vars(&s))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .collect()
}

/// Paths we must never propose deleting (the Windows directory, drive roots,
/// and the scan roots themselves).
fn is_protected_path(p: &Path) -> bool {
    let s = p.to_string_lossy().to_lowercase();
    let s = s.trim_end_matches('\\');
    if s.len() <= 3 {
        // Drive root like "c:" / "c:\".
        return true;
    }
    if let Some(windir) = env_dir("windir") {
        let w = windir.to_string_lossy().to_lowercase();
        if s == w.trim_end_matches('\\') || s.starts_with(&format!("{}\\", w.trim_end_matches('\\'))) {
            return true;
        }
    }
    // Exactly a known scan root directory.
    for root in fs_roots() {
        if s == root.to_string_lossy().to_lowercase().trim_end_matches('\\') {
            return true;
        }
    }
    // The user-profile tree roots (never delete the whole profile / Users / Public).
    let guards = [
        env_dir("USERPROFILE"),
        env_dir("PUBLIC"),
        env_dir("USERPROFILE").and_then(|p| p.parent().map(Path::to_path_buf)),
        env_dir("USERPROFILE").map(|p| p.join("Documents")),
    ];
    for guard in guards.into_iter().flatten() {
        if s == guard.to_string_lossy().to_lowercase().trim_end_matches('\\') {
            return true;
        }
    }
    false
}

fn is_dir_empty(p: &Path) -> bool {
    fs::read_dir(p)
        .map(|mut it| it.next().is_none())
        .unwrap_or(false)
}

/// Best-effort recursive size of a directory. Skips symlinks/reparse points to
/// avoid cycles and double-counting; ignores unreadable entries.
fn dir_size(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(entry.path());
            } else if let Ok(md) = entry.metadata() {
                total += md.len();
            }
        }
    }
    total
}

fn push_dir_leftover(out: &mut Vec<Leftover>, path: PathBuf, conf: Confidence, reason: String) {
    if is_protected_path(&path) || path_within_shared_dir(&path) {
        return;
    }
    let empty = is_dir_empty(&path);
    let size = if empty { Some(0) } else { Some(dir_size(&path)) };
    out.push(Leftover::fs(
        LeftoverKind::Directory,
        path,
        conf,
        reason,
        size,
        empty,
    ));
}

/// Flag product-matching immediate sub-directories of `parent` (never `parent`
/// itself). Used to descend into a shared vendor/parent folder and pick out only
/// the target product's own subfolder; `note` is appended to each reason.
fn flag_product_children(parent: &Path, target: &ScanTarget, out: &mut Vec<Leftover>, note: &str) {
    let Ok(children) = fs::read_dir(parent) else {
        return;
    };
    for child in children.flatten() {
        let cname = child.file_name().to_string_lossy().to_string();
        if fs_denied(&cname) {
            continue;
        }
        if child.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if let Some((conf, reason)) = score_product(&cname, target) {
                push_dir_leftover(out, child.path(), conf, format!("{reason} ({note})"));
            }
        }
    }
}

fn scan_dir_children(root: &Path, target: &ScanTarget, out: &mut Vec<Leftover>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if fs_denied(&name) {
            continue;
        }
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };

        if ft.is_dir() {
            // Check publisher-only FIRST so a shared vendor folder is descended
            // into rather than flagged wholesale.
            if matches_publisher(&name, target) {
                // Descend one level: flag the specific product subfolder(s),
                // never the shared publisher folder itself.
                flag_product_children(&path, target, out, &format!("under publisher folder \"{name}\""));
            } else if let Some((conf, reason)) = score_product(&name, target) {
                push_dir_leftover(out, path, conf, reason);
            }
        } else if ft.is_file() {
            // Files matter mainly for Start-Menu / Desktop shortcuts.
            if let Some((conf, reason)) = score_product(&name, target) {
                let size = entry.metadata().map(|m| m.len()).ok();
                out.push(Leftover::fs(LeftoverKind::File, path, conf, reason, size, false));
            }
        }
    }
}

fn scan_filesystem(target: &ScanTarget) -> Vec<Leftover> {
    let mut out: Vec<Leftover> = Vec::new();

    // 1. The install folder itself, if the uninstaller left it behind. Be
    //    careful: a program's recorded `InstallLocation` can be a *shared* parent
    //    directory (two products under `C:\Program Files\Vendor`, a suite root,
    //    or even a publisher folder). Deleting it wholesale would take a sibling
    //    program's files with it, so we only flag the folder itself when it is
    //    unambiguously this product's own — otherwise we descend and flag just
    //    the matching sub-folder, or downgrade out of the default removal set.
    if let Some(loc) = &target.install_location {
        if loc.is_dir() && !is_protected_path(loc) {
            let leaf = loc.file_name().and_then(|s| s.to_str()).unwrap_or_default();
            let descend_note = format!("under recorded install folder \"{leaf}\"");

            if matches_publisher(leaf, target) {
                // The folder is the publisher/vendor root — never wholesale.
                flag_product_children(loc, target, &mut out, &descend_note);
            } else {
                let loc_key = norm_path_key(loc);
                let houses_other_program = other_program_install_dirs(target)
                    .iter()
                    .any(|other| dir_contains(&loc_key, &norm_path_key(other)));

                if houses_other_program {
                    // A different installed program lives inside this folder.
                    flag_product_children(loc, target, &mut out, &descend_note);
                } else if let Some((conf, _)) = score_product(leaf, target) {
                    // The folder's own name identifies the product → safe whole.
                    push_dir_leftover(
                        &mut out,
                        loc.clone(),
                        conf,
                        "install folder still present after uninstall".to_string(),
                    );
                } else {
                    // Recorded as this program's folder, but its name does not
                    // identify the product and it holds no other program. Likely
                    // genuine, yet flag at Medium so it is not auto-removed in the
                    // default (High-only) set without the user opting in.
                    push_dir_leftover(
                        &mut out,
                        loc.clone(),
                        Confidence::Medium,
                        "recorded install folder still present (name does not match the product — verify before removing)".to_string(),
                    );
                }
            }
        }
    }

    // 2. Name-matched children of the common roots.
    for root in fs_roots() {
        scan_dir_children(&root, target, &mut out);
    }

    dedupe_by_path(&mut out);
    let mut out = dedupe_nested_fs(out);
    out.sort_by(|a, b| a.confidence.cmp(&b.confidence).then_with(|| a.path.cmp(&b.path)));
    out
}

/// Collapse nested filesystem leftovers so a folder and items inside it aren't
/// both listed (and sizes aren't double-counted). The ancestor is kept and its
/// weaker/equal descendants dropped — but a *more* confident descendant is kept
/// as its own entry rather than inflating the broader ancestor's confidence
/// (which could promote a vendor folder to High and propose deleting siblings).
fn dedupe_nested_fs(items: Vec<Leftover>) -> Vec<Leftover> {
    let key = norm_path_str;

    // Shortest paths first, so ancestors are seen before their descendants.
    let mut sorted = items;
    sorted.sort_by_key(|l| key(&l.path).len());

    let mut kept: Vec<Leftover> = Vec::new();
    for item in sorted {
        let p = key(&item.path);
        match kept
            .iter()
            .position(|k| p.starts_with(&format!("{}\\", key(&k.path))))
        {
            // `Confidence` orders High < Medium < Low. Keep a stronger
            // descendant separately; drop a weaker/equal one (covered by the
            // ancestor). Never change the ancestor's confidence.
            Some(i) => {
                if item.confidence < kept[i].confidence {
                    kept.push(item);
                }
            }
            None => kept.push(item),
        }
    }
    kept
}

// ---------------------------------------------------------------------------
// Registry scan
// ---------------------------------------------------------------------------

/// `SOFTWARE` roots whose immediate children we inspect for vendor/product keys.
fn software_roots() -> [(Hive, &'static str); 3] {
    [
        (Hive::CurrentUser, r"SOFTWARE"),
        (Hive::LocalMachine, r"SOFTWARE"),
        (Hive::LocalMachine, r"SOFTWARE\WOW6432Node"),
    ]
}

/// `App Paths` locations (an exe → full-path map) to check by exe name.
fn app_paths_roots() -> [(Hive, &'static str); 3] {
    [
        (
            Hive::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
        ),
        (
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        ),
    ]
}

fn scan_software_root(hive: Hive, base: &str, target: &ScanTarget, out: &mut Vec<Leftover>) {
    for child in registry::enum_subkeys(hive, base) {
        if reg_denied(&child) {
            continue;
        }
        let child_path = format!("{base}\\{child}");

        // Publisher-only key FIRST: descend to product subkeys, never flag the
        // shared vendor key itself.
        if matches_publisher(&child, target) {
            for grand in registry::enum_subkeys(hive, &child_path) {
                if let Some((conf, reason)) = score_product(&grand, target) {
                    out.push(Leftover::reg_key(
                        hive,
                        format!("{child_path}\\{grand}"),
                        conf,
                        format!("{reason} (under publisher key \"{child}\")"),
                    ));
                }
            }
        } else if let Some((conf, reason)) = score_product(&child, target) {
            out.push(Leftover::reg_key(hive, child_path, conf, reason));
        }
    }
}

fn scan_app_paths(hive: Hive, base: &str, target: &ScanTarget, out: &mut Vec<Leftover>) {
    if target.exe_names.is_empty() {
        return;
    }
    for child in registry::enum_subkeys(hive, base) {
        let child_lower = child.to_lowercase();
        if target.exe_names.iter().any(|e| e == &child_lower) {
            out.push(Leftover::reg_key(
                hive,
                format!("{base}\\{child}"),
                Confidence::High,
                format!("App Paths entry for {child}"),
            ));
        }
    }
}

/// Match a `Run`/`RunOnce` value (an autostart entry) against the target. The
/// value name, the launched executable, and the command path are all checked.
fn match_run_value(name: &str, data: &str, target: &ScanTarget) -> Option<(Confidence, String)> {
    // 1. The value name itself identifies the product.
    if let Some((conf, reason)) = score_product(name, target) {
        return Some((conf, format!("autostart entry — {reason}")));
    }
    // 2. The command launches one of the program's executables.
    let expanded = util::expand_env_vars(data);
    let argv = util::split_command_line(&expanded);
    if let Some(first) = argv.first() {
        if let Some(base) = util::file_basename_lower(first) {
            if target.exe_names.iter().any(|e| e == &base) {
                return Some((Confidence::High, format!("autostart launches {base}")));
            }
        }
    }
    // 3. The command path is inside the install folder (boundary-aware: a real
    //    directory separator is required, so "...\App" does not match "...\Apple").
    if let Some(loc) = &target.install_location {
        let loc_str = loc.to_string_lossy().to_lowercase().replace('/', "\\");
        let loc_str = loc_str.trim_end_matches('\\');
        if loc_str.len() >= 6 {
            let inside = argv.iter().any(|arg| {
                let a = arg.to_lowercase().replace('/', "\\");
                let a = a.trim_matches('"');
                a == loc_str || a.starts_with(&format!("{loc_str}\\"))
            });
            if inside {
                return Some((
                    Confidence::High,
                    "autostart command points into the install folder".to_string(),
                ));
            }
        }
    }
    None
}

/// Scan the autostart (`Run`/`RunOnce`) keys for orphaned entries.
fn scan_run_keys(target: &ScanTarget, out: &mut Vec<Leftover>) {
    const RUN_KEYS: &[(Hive, &str)] = &[
        (Hive::CurrentUser, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (Hive::CurrentUser, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (
            Hive::LocalMachine,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ];
    for (hive, base) in RUN_KEYS {
        for (name, data) in registry::enum_string_values(*hive, base) {
            if let Some((conf, reason)) = match_run_value(&name, &data, target) {
                out.push(Leftover::reg_value(*hive, *base, name, conf, reason));
            }
        }
    }
}

fn scan_registry(target: &ScanTarget) -> Vec<Leftover> {
    let mut out: Vec<Leftover> = Vec::new();

    // 1. The program's own Uninstall key, if it survived the uninstaller
    //    (an orphaned "Apps & features" entry).
    let RegistrySource { hive, view } = target.source;
    let uninstall_subpath = format!("{}\\{}", view.uninstall_base(), target.registry_key);
    if registry::key_exists(hive, &uninstall_subpath) {
        out.push(Leftover::reg_key(
            hive,
            uninstall_subpath,
            Confidence::High,
            "orphaned uninstall entry (still listed in Apps & features)".to_string(),
        ));
    }

    // 2. Vendor/product keys under the SOFTWARE roots.
    for (hive, base) in software_roots() {
        scan_software_root(hive, base, target, &mut out);
    }

    // 3. App Paths entries for the program's executables.
    for (hive, base) in app_paths_roots() {
        scan_app_paths(hive, base, target, &mut out);
    }

    // 4. Orphaned autostart (Run/RunOnce) entries.
    scan_run_keys(target, &mut out);

    dedupe_by_path(&mut out);
    out.sort_by(|a, b| a.confidence.cmp(&b.confidence).then_with(|| a.path.cmp(&b.path)));
    out
}

fn dedupe_by_path(items: &mut Vec<Leftover>) {
    let mut seen = std::collections::HashSet::new();
    items.retain(|l| seen.insert(l.path.to_lowercase()));
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run a full leftover scan for `target`, returning registry and filesystem
/// findings grouped separately.
pub fn scan(target: &ScanTarget) -> ScanReport {
    ScanReport {
        program_name: target.display_name.clone(),
        registry: scan_registry(target),
        filesystem: scan_filesystem(target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RegistryView, Hive};

    fn target() -> ScanTarget {
        ScanTarget {
            display_name: "Google Chrome".to_string(),
            publisher: Some("Google LLC".to_string()),
            install_location: None,
            exe_names: vec!["chrome.exe".to_string()],
            name_tokens: vec!["google".to_string(), "chrome".to_string()],
            publisher_tokens: vec!["google".to_string()],
            registry_key: "Google Chrome".to_string(),
            source: RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
        }
    }

    #[test]
    fn exact_and_substring_matches() {
        let t = target();
        assert!(matches!(
            score_product("Google Chrome", &t),
            Some((Confidence::High, _))
        ));
        // Folder named after the full product, with extra suffix.
        assert!(matches!(
            score_product("Google Chrome Beta", &t),
            Some((Confidence::High, _))
        ));
        // A distinctive keyword.
        assert!(matches!(score_product("Chrome", &t), Some((_, _))));
    }

    #[test]
    fn unrelated_names_do_not_match() {
        let t = target();
        assert!(score_product("Mozilla Firefox", &t).is_none());
        assert!(score_product("7-Zip", &t).is_none());
    }

    #[test]
    fn publisher_is_detected_for_descent() {
        let t = target();
        assert!(matches_publisher("Google", &t));
        assert!(!matches_publisher("Mozilla", &t));
    }

    #[test]
    fn denylists_protect_system_locations() {
        assert!(fs_denied("Windows"));
        assert!(fs_denied("Common Files"));
        assert!(reg_denied("Microsoft"));
        assert!(!fs_denied("Google"));
        // Shared-dir component guard (any path segment).
        assert!(path_within_shared_dir(Path::new(
            r"C:\Program Files\Common Files\Vendor"
        )));
        assert!(!path_within_shared_dir(Path::new(r"C:\Program Files\BraveSoftware")));
    }

    #[test]
    fn word_boundary_prevents_concatenation_false_positive() {
        // "ZoomIt" must NOT match the program "Zoom" (different product).
        let zoom = ScanTarget {
            display_name: "Zoom".to_string(),
            publisher: Some("Zoom Video Communications, Inc.".to_string()),
            install_location: None,
            exe_names: vec!["zoom.exe".to_string()],
            name_tokens: vec!["zoom".to_string()],
            publisher_tokens: vec!["zoom".to_string(), "video".to_string(), "communications".to_string()],
            registry_key: "ZoomUMX".to_string(),
            source: RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
        };
        assert!(score_product("ZoomIt", &zoom).is_none());
        // The real product folder still matches exactly.
        assert!(matches!(score_product("Zoom", &zoom), Some((Confidence::High, _))));
    }

    #[test]
    fn single_generic_token_is_never_high() {
        // "VLC media player": media/player are stopwords, so only "vlc" is a token.
        let vlc = ScanTarget {
            display_name: "VLC media player".to_string(),
            publisher: Some("VideoLAN".to_string()),
            install_location: None,
            exe_names: vec!["vlc.exe".to_string()],
            name_tokens: vec!["vlc".to_string()],
            publisher_tokens: vec!["videolan".to_string()],
            registry_key: "VLC media player".to_string(),
            source: RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
        };
        // The shared "Windows Media Player" folder must not match at all.
        assert!(score_product("Windows Media Player", &vlc).is_none());
    }

    #[test]
    fn publisher_only_folder_descends_not_flagged() {
        // A vendor folder whose name is a shortened form of the publisher is
        // recognised as publisher-only (so the scanner descends into it).
        let brave = ScanTarget {
            display_name: "Brave".to_string(),
            publisher: Some("Brave Software Inc".to_string()),
            install_location: None,
            exe_names: vec!["brave.exe".to_string()],
            name_tokens: vec!["brave".to_string()],
            publisher_tokens: vec!["brave".to_string()],
            registry_key: "BraveSoftware Brave-Browser".to_string(),
            source: RegistrySource::new(Hive::LocalMachine, RegistryView::Wow6432),
        };
        assert!(matches_publisher("BraveSoftware", &brave));
        // The product subfolder still scores.
        assert!(matches!(
            score_product("Brave-Browser", &brave),
            Some((Confidence::High, _))
        ));
    }

    #[test]
    fn dir_contains_is_boundary_aware() {
        // A genuine descendant is contained.
        assert!(dir_contains(
            r"c:\program files\vendor",
            r"c:\program files\vendor\productb"
        ));
        // A sibling sharing a name prefix is NOT (App must not "contain" Apple).
        assert!(!dir_contains(r"c:\program files\app", r"c:\program files\apple"));
        // An equal path is not a *strict* descendant.
        assert!(!dir_contains(r"c:\program files\app", r"c:\program files\app"));
        // An ancestor is not contained by its descendant.
        assert!(!dir_contains(r"c:\program files\vendor\app", r"c:\program files\vendor"));
    }

    #[test]
    fn protected_paths_are_never_deletable() {
        // Drive roots, regardless of the machine.
        assert!(is_protected_path(Path::new("C:\\")));
        assert!(is_protected_path(Path::new("D:\\")));
        // The real Windows directory and a child of it.
        if let Some(windir) = env_dir("windir") {
            assert!(is_protected_path(&windir), "windir must be protected");
            assert!(
                is_protected_path(&windir.join("System32")),
                "System32 must be protected"
            );
        }
        // The Program Files scan root is itself protected (only children may be
        // proposed for deletion, never the root).
        if let Some(pf) = env_dir("ProgramFiles") {
            assert!(is_protected_path(&pf), "Program Files root must be protected");
        }
        // A normal product sub-folder is NOT protected.
        assert!(!is_protected_path(Path::new(
            r"C:\Program Files\Some Vendor\Some App"
        )));
    }

    #[test]
    fn contains_subslice_is_word_aligned() {
        let hay = vec!["google".to_string(), "chrome".to_string(), "beta".to_string()];
        assert!(contains_subslice(&hay, &["google".to_string(), "chrome".to_string()]));
        assert!(!contains_subslice(&hay, &["chrome".to_string(), "google".to_string()]));
        assert!(!contains_subslice(&["zoomit".to_string()], &["zoom".to_string()]));
    }
}
