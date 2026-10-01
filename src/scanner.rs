//! Finds what a program left behind: registry keys and values, files and
//! folders, services, scheduled tasks, PATH entries and firewall rules.
//!
//! Every walk is program-scoped and shallow. A vendor folder or key can hold
//! sibling products, so the scanner descends into it and never flags it
//! wholesale. Denylists keep the OS and shared locations out entirely.

use std::fs;
use std::path::{Path, PathBuf};

use crate::model::{Confidence, Hive, Leftover, LeftoverKind, Program, ScanReport, ScanTarget};
use crate::registry;
use crate::system;
use crate::util::{self, normalize, significant_tokens};

/// Top-level folder names that are never reported (OS and shared).
const FS_DENY: &[&str] = &[
    "microsoft",
    "windows",
    "windowsapps",
    "windows defender",
    "windows mail",
    "windows media player",
    "windows nt",
    "windows photo viewer",
    "windows sidebar",
    "windowspowershell",
    "common files",
    "internet explorer",
    "uninstall information",
    "modifiablewindowsapps",
    "packages",
    "package cache",
    "softwaredistribution",
    "usoprivate",
    "usoshared",
    "virtualstore",
    "temp",
    "programs",
    "comms",
    "connecteddevicesplatform",
    "d3dscache",
    "peerdistrepub",
    "publishers",
    "crashdumps",
    "placeholdertilelogofolder",
    "desktop",
    "startup",
];

/// Top-level `SOFTWARE` child keys that are never reported or descended.
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
    "khronos",
    "odbc",
];

/// Directory names that must never appear anywhere in a path we propose
/// deleting, so an install folder recorded inside a shared location stays.
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

pub fn fs_denied(name: &str) -> bool {
    FS_DENY.contains(&name.to_lowercase().as_str())
}

pub fn path_within_shared_dir(p: &Path) -> bool {
    p.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| SHARED_DIR_DENY.contains(&s.to_lowercase().as_str()))
            .unwrap_or(false)
    })
}

pub fn reg_denied(name: &str) -> bool {
    REG_DENY.contains(&name.to_lowercase().as_str())
}

// Targets
// -------

/// Capture a registered program's identity.
pub fn build_target(program: &Program) -> ScanTarget {
    let install_location = program
        .install_location
        .as_deref()
        .map(util::expand_env_vars)
        // Installers write this with quotes around it, with a trailing
        // separator, or neither. Keep one form, or the folder is missed or
        // reported twice.
        .map(|s| {
            s.trim()
                .trim_matches('"')
                .trim_end_matches(['\\', '/'])
                .to_string()
        })
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        // A program writes its own install location, so a protected one is
        // either a broken installer or a hostile one. Either way nothing may
        // be claimed through it: everything under the folder would count as
        // the program's, down to Windows' own autostart entries.
        .filter(|p| !is_protected_path(p));

    let mut target = name_target(&program.display_name, program.publisher.as_deref());
    // The install folder's own name is often the most distinctive token.
    if let Some(loc) = &install_location {
        if let Some(folder) = loc.file_name().and_then(|s| s.to_str()) {
            for t in folder_tokens(loc, folder) {
                if !target.name_tokens.contains(&t) && !target.publisher_tokens.contains(&t) {
                    target.name_tokens.push(t);
                }
            }
        }
    }
    target.registry = Some((program.registry_key.clone(), program.source));
    // Another program's folder only decides anything when this one has no
    // folder of its own on record.
    let other_installs: Vec<PathBuf> = if install_location.is_none() {
        other_program_install_dirs(&target)
            .into_iter()
            .filter(|p| !is_protected_path(p))
            .collect()
    } else {
        Vec::new()
    };
    target.exe_names = own_exe_names(program, install_location.as_deref(), &other_installs);
    target.install_location = install_location;
    target.vendor_is_shared = vendor_is_shared(&target);
    target
}

/// A name that says nothing about which product this is. Every Squirrel app
/// uninstalls through `Update.exe`, and `App Paths\setup.exe` belongs to
/// nobody, so those names would claim each other's entries.
fn generic_exe(base: &str) -> bool {
    matches!(
        base,
        "msiexec.exe"
            | "unins000.exe"
            | "uninstall.exe"
            | "setup.exe"
            | "install.exe"
            | "rundll32.exe"
            | "update.exe"
            | "updater.exe"
    )
}

/// Shells and script hosts an uninstall command runs through. They run
/// whatever they are given, so they are nobody's own executable.
fn host_exe(base: &str) -> bool {
    matches!(
        base,
        "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "regsvr32.exe"
    )
}

/// Is this argument a link such as `steam://uninstall/431960`? A command
/// that passes one hands the job to the client that owns the scheme.
fn is_link(arg: &str) -> bool {
    arg.split_once("://").is_some_and(|(scheme, _)| {
        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    })
}

/// The executables the program owns, by file name: its icon's and its
/// uninstaller's, as long as they sit in its own folder. Ownership comes from
/// where a file is, not from being named in the uninstall entry. A Steam game
/// uninstalls through `steam.exe steam://uninstall/431960`, and taking that
/// name for the game's would hand Steam's autostart and firewall rules to
/// every game. The folder is the recorded install folder; without one, the
/// folder the program's own uninstaller runs from. Whatever runs the
/// uninstall on the program's behalf is never its own: a bare name Windows
/// looks up (`MsiExec.exe`, `powershell.exe`), anything in the Windows
/// folder, a shell or script host, a client handed a link, or a file inside
/// another program's install folder.
fn own_exe_names(
    program: &Program,
    install_location: Option<&Path>,
    other_installs: &[PathBuf],
) -> Vec<String> {
    let as_path = |s: &str| PathBuf::from(s.trim().trim_matches('"'));
    let icon = program.display_icon.as_deref().map(|icon| {
        let without_index = icon.split(',').next().unwrap_or(icon);
        as_path(&util::expand_env_vars(without_index))
    });
    let argv = program
        .uninstall_string
        .as_deref()
        .map(|us| util::split_command_line(&util::expand_env_vars(us)))
        .unwrap_or_default();
    let hands_over = argv.iter().skip(1).any(|a| is_link(a));
    let uninstaller = argv.first().map(|s| as_path(s)).filter(|_| !hands_over);

    let base_of = |p: &Path| util::file_basename_lower(&p.to_string_lossy());
    let foreign = |p: &Path| {
        !p.is_absolute()
            || system::in_windows_dir(p)
            || base_of(p).is_some_and(|b| host_exe(&b))
            || other_installs.iter().any(|o| system::path_under(p, o))
    };
    let home: Option<PathBuf> = match install_location {
        Some(loc) => Some(loc.to_path_buf()),
        None => uninstaller
            .as_deref()
            .filter(|u| !foreign(u))
            .and_then(Path::parent)
            .map(Path::to_path_buf),
    };

    let mut names = Vec::new();
    for path in [icon, uninstaller].into_iter().flatten() {
        let Some(base) = base_of(&path) else { continue };
        if !base.ends_with(".exe") || generic_exe(&base) || names.contains(&base) {
            continue;
        }
        let own = match &home {
            Some(home) => path.is_absolute() && system::path_under(&path, home),
            None => !foreign(&path),
        };
        if own {
            names.push(base);
        }
    }
    names
}

/// Match tokens from the install folder's own name. A word the folder shares
/// with the path above it belongs to the container, not to the product. A
/// winget package sits under `Microsoft\WinGet\Packages` and repeats both
/// words in its own folder name, and "microsoft" as a token matches every
/// folder Microsoft ever installed.
fn folder_tokens(location: &Path, folder: &str) -> Vec<String> {
    let container: Vec<String> = location
        .parent()
        .map(|p| {
            p.components()
                .filter_map(|c| c.as_os_str().to_str())
                .flat_map(significant_tokens)
                .collect()
        })
        .unwrap_or_default();
    significant_tokens(folder)
        .into_iter()
        .filter(|t| !container.contains(t) && !fs_denied(t) && !reg_denied(t))
        .collect()
}

/// A target for a program that is no longer registered: all we have is what
/// the user typed. Without a publisher, a two-word name such as "Google
/// Chrome" is read as vendor plus product, so the vendor folder is descended
/// into rather than flagged.
pub fn name_only_target(name: &str, publisher: Option<&str>) -> ScanTarget {
    if publisher.is_some() {
        let mut target = name_target(name, publisher);
        target.vendor_is_shared = vendor_is_shared(&target);
        return target;
    }
    let tokens = significant_tokens(name);
    if tokens.len() >= 2 {
        let vendor = name
            .split(|c: char| !c.is_alphanumeric())
            .find(|w| w.to_lowercase() == tokens[0])
            .unwrap_or(&tokens[0]);
        return name_target(name, Some(vendor));
    }
    name_target(name, None)
}

/// Identity from a display name and publisher.
pub fn name_target(name: &str, publisher: Option<&str>) -> ScanTarget {
    let publisher_tokens = publisher.map(significant_tokens).unwrap_or_default();
    let name_tokens = product_tokens(name, &publisher_tokens);
    let mut target = ScanTarget {
        vendor_is_shared: false,
        display_name: name.to_string(),
        publisher: publisher.map(str::to_string),
        install_location: None,
        exe_names: Vec::new(),
        name_tokens,
        publisher_tokens,
        registry: None,
        exact_names: Vec::new(),
        lone_words_match: true,
    };
    // "Python Launcher" by the Python Software Foundation boils down to
    // "python", the vendor's word, which every product of theirs carries; the
    // word that says which one it is, "launcher", is too common to match on.
    // Like a Store app's description, such a name matches only whole.
    if let [only] = target.name_tokens.as_slice() {
        if target.publisher_tokens.contains(only) && !name_is_one_word(&target) {
            target.lone_words_match = false;
        }
    }
    target
}

/// The words of a product's name that say which product it is. "Mozilla
/// Thunderbird" by Mozilla: the vendor word is not the product, so it is
/// dropped as long as something else remains.
fn product_tokens(name: &str, publisher_tokens: &[String]) -> Vec<String> {
    let tokens = significant_tokens(name);
    let without_vendor: Vec<String> = tokens
        .iter()
        .filter(|t| !publisher_tokens.contains(t))
        .cloned()
        .collect();
    if without_vendor.is_empty() {
        tokens
    } else {
        without_vendor
    }
}

/// Does the product's name boil down to the vendor's own word, with other
/// programs from that vendor installed? "NVIDIA App" keeps only "nvidia", and
/// `ProgramData\NVIDIA` holds the data of five NVIDIA products. A vendor with
/// nothing else installed is a different matter: `AppData\Roaming\discord` is
/// Discord's, whatever else the word may mean.
fn vendor_is_shared(target: &ScanTarget) -> bool {
    if target.publisher_tokens.is_empty() || target.name_tokens != target.publisher_tokens {
        return false;
    }
    registry::enumerate_installed_programs(true)
        .into_iter()
        .filter(|p| {
            target
                .registry
                .as_ref()
                .map(|(key, source)| !(p.registry_key == *key && p.source == *source))
                .unwrap_or(true)
        })
        .any(|p| {
            p.publisher
                .as_deref()
                .map(|pubr| significant_tokens(pubr) == target.publisher_tokens)
                .unwrap_or(false)
        })
}

// Matching
// --------

/// Is the product's name really just its one token? "Brave" is, and so is
/// "Malwarebytes version 5.6.5.306", where everything else is version noise.
/// "Python Launcher" is not: "launcher" says something, even though it is too
/// common to match on.
fn name_is_one_word(target: &ScanTarget) -> bool {
    let [token] = target.name_tokens.as_slice() else {
        return false;
    };
    target
        .display_name
        .split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|w| w.len() >= 3 && !w.chars().all(|c| c.is_ascii_digit()))
        .all(|w| w == *token || target.publisher_tokens.contains(&w) || util::is_noise_word(&w))
}

/// Is this name the product itself: the display name, one of the target's
/// exact names, or its product words joined ("GoogleChrome" for "Google
/// Chrome")? One product word is the product only where lone words match.
fn is_exact_product(name: &str, target: &ScanTarget) -> bool {
    let norm = normalize(name);
    if norm.len() < 3 {
        return false;
    }
    if !target.display_name.is_empty() && norm == normalize(&target.display_name) {
        return true;
    }
    if target.exact_names.contains(&norm) {
        return true;
    }
    let product_joined: String = target.name_tokens.concat();
    (target.lone_words_match || target.name_tokens.len() >= 2)
        && product_joined.len() >= 4
        && norm == product_joined
}

/// Score a folder or key name against the product. Word-aware, so "ZoomIt"
/// does not match "Zoom"; a single coincidental keyword is capped at Medium,
/// and counts for nothing where lone words do not match.
fn score_product(name: &str, target: &ScanTarget) -> Option<(Confidence, String)> {
    let norm = normalize(name);
    if norm.len() < 3 {
        return None;
    }
    if is_exact_product(name, target) && !target.vendor_is_shared {
        return Some((Confidence::High, "exact name".to_string()));
    }

    let candidate = significant_tokens(name);
    if candidate.is_empty() || target.name_tokens.is_empty() {
        return None;
    }

    // The same words on both sides, give or take the noise: "CLI" for "GitHub
    // CLI".
    let same_words = candidate.len() == target.name_tokens.len();
    // A single word carries the name only when the name really is that one
    // word, and only if it is long enough to mean anything. "Microsoft Visual
    // C++ 2010 Redistributable" boils down to "visual", which would claim
    // Visual Studio's services, and ".NET SDK" to "sdk".
    let one_word = target.name_tokens.len() == 1
        && target.name_tokens[0].len() >= 4
        && name_is_one_word(target);
    let enough_words =
        target.name_tokens.len() >= 2 || (target.lone_words_match && (same_words || one_word));
    if contains_subslice(&candidate, &target.name_tokens)
        && !target.vendor_is_shared
        && enough_words
    {
        return Some((
            Confidence::High,
            format!("contains \"{}\"", target.display_name),
        ));
    }

    if target.name_tokens.len() >= 2 && target.name_tokens.iter().all(|t| candidate.contains(t)) {
        return Some((Confidence::High, "all name words present".to_string()));
    }

    if !target.lone_words_match {
        return None;
    }
    // One word of a two-word name is half of it, so it claims only a name
    // made of the product's and the vendor's words: "Wallpaper" for
    // "Wallpaper Engine", never `docker-secrets-engine`. The name's own words
    // decide, not the install folder's: "NVIDIA App" installed in
    // `Installer2\Display.NvApp.{GUID}` is still a one-word name.
    let own_word =
        |w: &String| target.name_tokens.contains(w) || target.publisher_tokens.contains(w);
    if product_tokens(&target.display_name, &target.publisher_tokens).len() >= 2
        && !candidate.iter().all(own_word)
    {
        return None;
    }
    if let Some(hit) = target
        .name_tokens
        .iter()
        .find(|t| t.len() >= 4 && candidate.contains(*t))
    {
        return Some((Confidence::Medium, format!("matches \"{hit}\"")));
    }
    None
}

fn contains_subslice(haystack: &[String], needle: &[String]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True if `name` is essentially the publisher (a shared vendor root such as
/// "Google" or "BraveSoftware"). Those are descended into, never flagged.
fn matches_publisher(name: &str, target: &ScanTarget) -> bool {
    let Some(publisher) = &target.publisher else {
        return false;
    };
    let norm = normalize(name);
    let pubn = normalize(publisher);
    if norm.len() >= 4 && pubn.len() >= 4 && pubn.contains(&norm) {
        return true;
    }
    let candidate = significant_tokens(name);
    !candidate.is_empty()
        && !target.publisher_tokens.is_empty()
        && candidate
            .iter()
            .all(|t| target.publisher_tokens.contains(t))
}

/// Is `p` inside the install folder, or does its exe name belong to the
/// product?
fn owned_exe(p: &Path, target: &ScanTarget) -> Option<&'static str> {
    if let Some(loc) = &target.install_location {
        if system::path_under(p, loc) {
            return Some("inside the install folder");
        }
    }
    let base = util::file_basename_lower(&p.to_string_lossy())?;
    if target.exe_names.contains(&base) {
        return Some("runs the program's executable");
    }
    None
}

/// The executable a command runs, with a bare file name such as
/// `powershell.exe` found where Windows would find it. A name Windows cannot
/// find stays as it is.
fn locate_exe(exe: &Path) -> PathBuf {
    system::locate_bare_exe(exe).unwrap_or_else(|| exe.to_path_buf())
}

/// Is the file a reference points to gone? Only a full path can say so. A
/// bare name that nothing answers to, or a path relative to a folder nobody
/// knows, is unknown, and resolving it against our own current folder would
/// call nearly every one of them missing.
fn exe_missing(exe: &Path) -> bool {
    exe.is_absolute() && !exe.exists()
}

/// A path whose components name the product, for dangling references.
fn path_names_product(p: &Path, target: &ScanTarget) -> bool {
    p.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| matches!(score_product(s, target), Some((Confidence::High, _))))
            .unwrap_or(false)
    })
}

// Filesystem
// ----------

pub fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Roots whose immediate children are inspected by name.
pub fn fs_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |p: Option<PathBuf>| {
        if let Some(p) = p {
            if p.is_dir() && !roots.contains(&p) {
                roots.push(p);
            }
        }
    };
    const START_MENU: &str = r"Microsoft\Windows\Start Menu\Programs";

    push(env_dir("ProgramFiles"));
    push(env_dir("ProgramFiles(x86)"));
    push(env_dir("ProgramW6432"));
    push(env_dir("ProgramData"));
    push(env_dir("APPDATA"));
    push(env_dir("LOCALAPPDATA"));
    push(env_dir("LOCALAPPDATA").map(|p| p.join("Programs")));
    push(env_dir("APPDATA").map(|p| p.join(START_MENU)));
    push(env_dir("ProgramData").map(|p| p.join(START_MENU)));
    push(env_dir("APPDATA").map(|p| p.join(START_MENU).join("Startup")));
    push(env_dir("ProgramData").map(|p| p.join(START_MENU).join("Startup")));
    push(env_dir("USERPROFILE").map(|p| p.join("Desktop")));
    push(env_dir("PUBLIC").map(|p| p.join("Desktop")));
    roots
}

fn norm_path_str(p: &str) -> String {
    p.to_lowercase()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_string()
}

fn norm_path_key(p: &Path) -> String {
    norm_path_str(&p.to_string_lossy())
}

/// Strict containment on normalised path strings, separator-aware.
fn dir_contains(dir: &str, other: &str) -> bool {
    other.len() > dir.len() && other.starts_with(&format!("{dir}\\"))
}

/// Install folders of every other program, so a shared parent folder is never
/// proposed for deletion.
fn other_program_install_dirs(target: &ScanTarget) -> Vec<PathBuf> {
    registry::enumerate_installed_programs(true)
        .into_iter()
        .filter(|p| {
            target
                .registry
                .as_ref()
                .map(|(key, source)| !(p.registry_key == *key && p.source == *source))
                .unwrap_or(true)
        })
        .filter_map(|p| p.install_location)
        .map(|s| util::expand_env_vars(&s))
        .map(|s| s.trim().trim_matches('"').to_string())
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .collect()
}

/// A path as Windows will read it when the time comes to delete it: real name
/// resolved where the path exists, extended-length prefix and forward slashes
/// gone, and the trailing dots and spaces Windows itself ignores taken off
/// every part. `C:/Windows`, `C:\PROGRA~1` and `C:\Windows.` all name a
/// protected directory, and a guard that compares raw strings misses all
/// three.
fn resolve_for_guard(p: &Path) -> String {
    let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = real.to_string_lossy().to_lowercase().replace('/', "\\");
    let s = s
        .strip_prefix("\\\\?\\unc\\")
        .map(|rest| format!("\\\\{rest}"))
        .unwrap_or_else(|| s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string());
    s.split('\\')
        .map(|part| part.trim_end_matches(['.', ' ']))
        .collect::<Vec<_>>()
        .join("\\")
        .trim_end_matches('\\')
        .to_string()
}

/// Paths that are never deletable: drive roots, the Windows folder, the scan
/// roots themselves and the user-profile tree roots.
pub fn is_protected_path(p: &Path) -> bool {
    let s = resolve_for_guard(p);
    let s = s.as_str();
    if s.len() <= 3 {
        return true;
    }
    {
        let windir = env_dir("windir").unwrap_or_else(system::windows_dir);
        let w = windir.to_string_lossy().to_lowercase();
        let w = w.trim_end_matches('\\');
        if s == w || s.starts_with(&format!("{w}\\")) {
            return true;
        }
    }
    for root in fs_roots() {
        if s == root.to_string_lossy().to_lowercase().trim_end_matches('\\') {
            return true;
        }
    }
    let guards = [
        env_dir("USERPROFILE"),
        env_dir("PUBLIC"),
        env_dir("USERPROFILE").and_then(|p| p.parent().map(Path::to_path_buf)),
        env_dir("USERPROFILE").map(|p| p.join("Documents")),
        // Every Store app keeps its data one level below this folder; the
        // empty-parent cleanup after a data-folder leftover must stop here.
        env_dir("LOCALAPPDATA").map(|p| p.join("Packages")),
    ];
    for guard in guards.into_iter().flatten() {
        if s == guard
            .to_string_lossy()
            .to_lowercase()
            .trim_end_matches('\\')
        {
            return true;
        }
    }
    false
}

pub fn is_dir_empty(p: &Path) -> bool {
    fs::read_dir(p)
        .map(|mut it| it.next().is_none())
        .unwrap_or(false)
}

/// Recursive size, skipping reparse points.
pub fn dir_size(root: &Path) -> u64 {
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
    let size = if empty {
        Some(0)
    } else {
        Some(dir_size(&path))
    };
    out.push(Leftover::fs(
        LeftoverKind::Directory,
        path,
        conf,
        reason,
        size,
        empty,
    ));
}

/// Does the folder hold a longer namesake, the way `Programs\Python` holds
/// `Python313`? Then it is a family folder. It can hold versions another
/// program still uses, so only its matching children count.
fn holds_namesake_child(dir: &Path, target: &ScanTarget) -> bool {
    let joined: String = target.name_tokens.concat();
    let product = if joined.len() >= 4 {
        joined
    } else {
        normalize(&target.display_name)
    };
    if product.len() < 4 {
        return false;
    }
    let Ok(children) = fs::read_dir(dir) else {
        return false;
    };
    children.flatten().any(|child| {
        if !child.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            return false;
        }
        let name = normalize(&child.file_name().to_string_lossy());
        name.len() > product.len() && name.starts_with(&product)
    })
}

/// Flag product-matching children of `parent`, never `parent` itself.
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
                push_dir_leftover(out, child.path(), conf, format!("{reason}, {note}"));
            }
        }
    }
}

fn scan_dir_children(
    root: &Path,
    target: &ScanTarget,
    other_installs: &[PathBuf],
    out: &mut Vec<Leftover>,
) {
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
            // A folder named exactly like the product is the product's own,
            // even where the publisher name carries the product word ("Git"
            // by "The Git Development Community"). Two exceptions: another
            // program installs inside it, or our own install folder is
            // further down, which makes it a container.
            let key = norm_path_key(&path);
            let contains_install = target
                .install_location
                .as_deref()
                .map(|loc| dir_contains(&key, &norm_path_key(loc)))
                .unwrap_or(false);
            let houses_other = other_installs
                .iter()
                .any(|o| dir_contains(&key, &norm_path_key(o)));
            let family = holds_namesake_child(&path, target);
            if is_exact_product(&name, target)
                && !target.vendor_is_shared
                && !houses_other
                && !contains_install
                && !family
            {
                push_dir_leftover(out, path, Confidence::High, "exact name".to_string());
            } else if matches_publisher(&name, target) {
                flag_product_children(&path, target, out, &format!("in vendor folder {name}"));
            } else if houses_other || contains_install || family {
                // Another program is installed inside, and the folder is not
                // the vendor's, so it is shared whatever its name says:
                // Visual Studio's folder holds the Build Tools, Steam's holds
                // the games. The one folder in there we know is ours, the
                // recorded install folder, is listed on its own.
                continue;
            } else if let Some((conf, reason)) = score_product(&name, target) {
                push_dir_leftover(out, path, conf, reason);
            }
        } else if ft.is_file() {
            // Mostly Start Menu, Startup and Desktop shortcuts.
            let stem = Path::new(&name)
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or(name.clone());
            if let Some((conf, reason)) = score_product(&stem, target) {
                let size = entry.metadata().map(|m| m.len()).ok();
                out.push(Leftover::fs(
                    LeftoverKind::File,
                    path,
                    conf,
                    reason,
                    size,
                    false,
                ));
            }
        }
    }
}

fn scan_filesystem(target: &ScanTarget) -> Vec<Leftover> {
    let mut out: Vec<Leftover> = Vec::new();
    let other_installs = other_program_install_dirs(target);

    // The install folder itself. Its recorded path can be a shared parent
    // (two products under one vendor folder), so it is only flagged whole
    // when its name identifies this product and nothing else lives inside.
    if let Some(loc) = &target.install_location {
        if loc.is_dir() && !is_protected_path(loc) {
            let leaf = loc.file_name().and_then(|s| s.to_str()).unwrap_or_default();
            let note = format!("in install folder {leaf}");
            let loc_key = norm_path_key(loc);
            let houses_other = other_installs
                .iter()
                .any(|other| dir_contains(&loc_key, &norm_path_key(other)));
            // A folder named exactly like the product is the product's own,
            // even if the publisher name contains that word.
            let vendor_root = matches_publisher(leaf, target) && !is_exact_product(leaf, target);

            {
                if houses_other || vendor_root {
                    flag_product_children(loc, target, &mut out, &note);
                } else {
                    let (conf, reason) = install_folder_score(leaf, target);
                    push_dir_leftover(&mut out, loc.clone(), conf, reason);
                }
            }
        }
    }

    for root in fs_roots() {
        scan_dir_children(&root, target, &other_installs, &mut out);
    }

    dedupe_by_path(&mut out);
    let mut out = dedupe_nested_fs(out);
    out.sort_by(|a, b| {
        a.confidence
            .cmp(&b.confidence)
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

/// How sure the recorded install folder is the product's own, by its name.
/// The target's words include the folder's own, which would match any folder
/// at all, so the name is checked against the program's name alone.
fn install_folder_score(leaf: &str, target: &ScanTarget) -> (Confidence, String) {
    let mut own_name = name_target(&target.display_name, target.publisher.as_deref());
    own_name.vendor_is_shared = target.vendor_is_shared;
    if score_product(leaf, &own_name).is_some() {
        (Confidence::High, "install folder".to_string())
    } else {
        (
            Confidence::Medium,
            "recorded install folder, name does not match".to_string(),
        )
    }
}

/// Collapse nested filesystem leftovers so a folder and items inside it are
/// not both listed. A more confident descendant stays as its own entry.
fn dedupe_nested_fs(items: Vec<Leftover>) -> Vec<Leftover> {
    let mut sorted = items;
    sorted.sort_by_key(|l| norm_path_str(&l.path).len());

    let mut kept: Vec<Leftover> = Vec::new();
    for item in sorted {
        let p = norm_path_str(&item.path);
        match kept
            .iter()
            .position(|k| p.starts_with(&format!("{}\\", norm_path_str(&k.path))))
        {
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

// Registry
// --------

fn software_roots() -> [(Hive, &'static str); 3] {
    [
        (Hive::CurrentUser, r"SOFTWARE"),
        (Hive::LocalMachine, r"SOFTWARE"),
        (Hive::LocalMachine, r"SOFTWARE\WOW6432Node"),
    ]
}

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
        if matches_publisher(&child, target) {
            for grand in registry::enum_subkeys(hive, &child_path) {
                if let Some((conf, reason)) = score_product(&grand, target) {
                    out.push(Leftover::reg_key(
                        hive,
                        format!("{child_path}\\{grand}"),
                        conf,
                        format!("{reason}, in vendor key {child}"),
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
        if target
            .exe_names
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&child))
        {
            out.push(Leftover::reg_key(
                hive,
                format!("{base}\\{child}"),
                Confidence::High,
                format!("App Paths entry for {child}"),
            ));
        }
    }
}

/// Match an autostart (`Run`) value by its name, its executable or its path.
fn match_run_value(name: &str, data: &str, target: &ScanTarget) -> Option<(Confidence, String)> {
    if let Some((conf, reason)) = score_product(name, target) {
        return Some((conf, format!("autostart, {reason}")));
    }
    let exe = locate_exe(&system::command_exe(data)?);
    if let Some(why) = owned_exe(&exe, target) {
        return Some((Confidence::High, format!("autostart, {why}")));
    }
    if exe_missing(&exe) && path_names_product(&exe, target) {
        return Some((
            Confidence::High,
            "autostart, points to a missing file".to_string(),
        ));
    }
    None
}

fn scan_run_keys(target: &ScanTarget, out: &mut Vec<Leftover>) {
    const RUN_KEYS: &[(Hive, &str)] = &[
        (
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
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

fn scan_registry(target: &ScanTarget, installed: bool) -> Vec<Leftover> {
    let mut out: Vec<Leftover> = Vec::new();

    // The program's own Uninstall key, if the uninstaller left it behind.
    if !installed {
        if let Some((key, source)) = &target.registry {
            let subpath = format!("{}\\{}", source.view.uninstall_base(), key);
            if registry::key_exists(source.hive, &subpath) {
                out.push(Leftover::reg_key(
                    source.hive,
                    subpath,
                    Confidence::High,
                    "orphaned uninstall entry",
                ));
            }
        }
    }

    for (hive, base) in software_roots() {
        scan_software_root(hive, base, target, &mut out);
    }
    for (hive, base) in app_paths_roots() {
        scan_app_paths(hive, base, target, &mut out);
    }
    scan_run_keys(target, &mut out);

    dedupe_by_path(&mut out);
    out.sort_by(|a, b| {
        a.confidence
            .cmp(&b.confidence)
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

// Services, tasks, PATH, firewall
// -------------------------------

/// Match something that runs an executable: a service, a task, a rule.
fn match_exe_item(
    name: &str,
    exe: Option<&Path>,
    target: &ScanTarget,
) -> Option<(Confidence, String)> {
    if let Some(exe) = exe {
        if system::in_windows_dir(exe) {
            return None;
        }
        let exe = locate_exe(exe);
        if let Some(why) = owned_exe(&exe, target) {
            return Some((Confidence::High, why.to_string()));
        }
        if exe_missing(&exe) && path_names_product(&exe, target) {
            return Some((Confidence::High, "points to a missing file".to_string()));
        }
    }
    score_product(name, target)
}

/// Is this service Windows' own host process, or a driver Windows installed?
/// Both take their name from whoever asked for them, so Logitech's LampArray
/// service in the driver store reads as Logitech's, and every per-user service
/// reads as whatever shares a word with it. Neither is a program's leftover.
/// A program that puts its own service binary in `System32` still counts.
fn windows_hosted_service(exe: &Path) -> bool {
    let base = util::file_basename_lower(&exe.to_string_lossy()).unwrap_or_default();
    matches!(
        base.as_str(),
        "svchost.exe" | "rundll32.exe" | "dllhost.exe" | "services.exe"
    ) || exe
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .any(|c| {
            // Defender runs out of `ProgramData\Microsoft\Windows Defender` and
            // Edge's updater out of `Program Files (x86)\Microsoft`: Microsoft's
            // own, under a folder that says so, never a third party's leftover.
            c.eq_ignore_ascii_case("DriverStore") || c.eq_ignore_ascii_case("Microsoft")
        })
}

fn scan_system(target: &ScanTarget) -> Vec<Leftover> {
    let mut out = Vec::new();

    for svc in system::services() {
        if svc
            .exe
            .as_deref()
            .map(windows_hosted_service)
            .unwrap_or(false)
        {
            continue;
        }
        let label = svc.display_name.as_deref().unwrap_or(&svc.name);
        let hit = match_exe_item(&svc.name, svc.exe.as_deref(), target)
            .or_else(|| match_exe_item(label, None, target));
        if let Some((conf, reason)) = hit {
            let image = svc
                .exe
                .as_deref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            out.push(Leftover::service(svc.name, &image, conf, reason));
        }
    }

    for task in system::scheduled_tasks() {
        let leaf = task.name.rsplit('\\').next().unwrap_or(&task.name);
        // Strip a trailing GUID so "UpdaterTask{GUID}" scores by its words.
        let leaf = leaf.split('{').next().unwrap_or(leaf);
        if let Some((conf, reason)) = match_exe_item(leaf, task.exe.as_deref(), target) {
            let command = task
                .exe
                .as_deref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            out.push(Leftover::task(task.name, &command, conf, reason));
        }
    }

    for hive in [Hive::CurrentUser, Hive::LocalMachine] {
        for entry in system::path_entries(hive) {
            let dir = PathBuf::from(util::expand_env_vars(&entry));
            if system::in_windows_dir(&dir) {
                continue;
            }
            let inside = target
                .install_location
                .as_deref()
                .map(|loc| system::path_under(&dir, loc))
                .unwrap_or(false);
            if inside {
                out.push(Leftover::path_entry(
                    hive,
                    entry,
                    Confidence::High,
                    "inside the install folder",
                ));
            } else if !dir.exists() && path_names_product(&dir, target) {
                out.push(Leftover::path_entry(
                    hive,
                    entry,
                    Confidence::High,
                    "points to a missing folder",
                ));
            }
        }
    }

    for rule in system::firewall_rules() {
        if let Some((conf, reason)) = match_exe_item(&rule.name, Some(&rule.app), target) {
            let app = rule.app.to_string_lossy().to_string();
            out.push(Leftover::firewall_rule(
                rule.id, &rule.name, &rule.kind, &app, conf, reason,
            ));
        }
    }

    out.sort_by(|a, b| {
        a.confidence
            .cmp(&b.confidence)
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

/// Drop repeats. Paths compare normalised, so an install folder recorded with
/// a trailing separator is the entry the walk already found, and of two
/// findings for one path the more confident one stays whichever came first.
fn dedupe_by_path(items: &mut Vec<Leftover>) {
    let mut best: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut drop = vec![false; items.len()];
    for i in 0..items.len() {
        let key = norm_path_str(&items[i].path);
        match best.get(&key) {
            Some(&j) if items[j].confidence <= items[i].confidence => drop[i] = true,
            Some(&j) => {
                drop[j] = true;
                best.insert(key, i);
            }
            None => {
                best.insert(key, i);
            }
        }
    }
    let mut keep = drop.iter().map(|d| !d);
    items.retain(|_| keep.next().unwrap_or(true));
}

// Entry point
// -----------

/// Run a full scan. `installed` says whether the program is still registered,
/// in which case its own uninstall entry is not a leftover.
pub fn scan(target: &ScanTarget, installed: bool) -> ScanReport {
    let mut items = scan_registry(target, installed);
    items.extend(scan_filesystem(target));
    items.extend(scan_system(target));
    ScanReport {
        program_name: target.display_name.clone(),
        installed,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RegistrySource, RegistryView};

    fn target() -> ScanTarget {
        let mut t = name_target("Google Chrome", Some("Google LLC"));
        t.exe_names = vec!["chrome.exe".to_string()];
        t.registry = Some((
            "Google Chrome".to_string(),
            RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
        ));
        t
    }

    #[test]
    fn vendor_word_is_dropped_from_product_tokens() {
        let t = name_target("Mozilla Thunderbird (x64 en-US)", Some("Mozilla"));
        assert_eq!(t.name_tokens, vec!["thunderbird".to_string()]);
        // The program's own folder is a strong match now.
        assert!(matches!(
            score_product("Thunderbird", &t),
            Some((Confidence::High, _))
        ));
        // A shared vendor folder is not.
        assert!(score_product("Mozilla-1de4eec8", &t).is_none());
    }

    #[test]
    fn install_folder_tokens_leave_out_the_container() {
        // A winget package: the folder repeats the words of the path above it.
        let loc = Path::new(
            r"C:\Users\x\AppData\Local\Microsoft\WinGet\Packages\Fastfetch-cli.Fastfetch_Microsoft.Winget.Source_8wekyb3d8bbwe",
        );
        let tokens = folder_tokens(loc, loc.file_name().unwrap().to_str().unwrap());
        assert!(tokens.contains(&"fastfetch".to_string()));
        assert!(!tokens.contains(&"microsoft".to_string()));
        assert!(!tokens.contains(&"winget".to_string()));

        // A plain install folder still gives up its name.
        let loc = Path::new(r"C:\Program Files\Obsidian");
        assert_eq!(
            folder_tokens(loc, loc.file_name().unwrap().to_str().unwrap()),
            vec!["obsidian".to_string()]
        );
    }

    #[test]
    fn a_product_named_folder_wins_over_the_vendor_reading() {
        // "Git" by "The Git Development Community": the publisher carries
        // the product word, and the folder is still Git's own.
        let git = name_target("Git", Some("The Git Development Community"));
        assert!(matches_publisher("Git", &git));
        assert!(is_exact_product("Git", &git));
        // A real vendor folder still is one.
        let brave = name_target("Brave", Some("Brave Software Inc"));
        assert!(matches_publisher("BraveSoftware", &brave));
        assert!(!is_exact_product("BraveSoftware", &brave));
    }

    #[test]
    fn a_folder_holding_a_longer_namesake_is_a_family_folder() {
        let root = std::env::temp_dir().join("oxidize_namesake_test");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("Python").join("Python313")).unwrap();
        fs::create_dir_all(root.join("Git").join("bin")).unwrap();

        let python = name_target("Python 3.13.7 (64-bit)", Some("Python Software Foundation"));
        assert!(holds_namesake_child(&root.join("Python"), &python));
        let git = name_target("Git", Some("The Git Development Community"));
        assert!(!holds_namesake_child(&root.join("Git"), &git));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn name_only_target_guesses_the_vendor() {
        let t = name_only_target("Google Chrome", None);
        assert_eq!(t.name_tokens, vec!["chrome".to_string()]);
        assert!(matches_publisher("Google", &t));
        assert!(matches!(
            score_product("Chrome", &t),
            Some((Confidence::High, _))
        ));
        let t = name_only_target("Steam", None);
        assert_eq!(t.name_tokens, vec!["steam".to_string()]);
        assert!(t.publisher.is_none());
    }

    #[test]
    fn vendor_only_name_keeps_its_token() {
        let t = name_target("Steam", Some("Valve Corporation"));
        assert_eq!(t.name_tokens, vec!["steam".to_string()]);
        let t = name_target("Brave", Some("Brave Software Inc"));
        assert_eq!(t.name_tokens, vec!["brave".to_string()]);
    }

    #[test]
    fn exact_and_substring_matches() {
        let t = target();
        assert!(matches!(
            score_product("Google Chrome", &t),
            Some((Confidence::High, _))
        ));
        assert!(matches!(
            score_product("Google Chrome Beta", &t),
            Some((Confidence::High, _))
        ));
        // The vendor word is dropped, so the product word alone is the name.
        assert_eq!(t.name_tokens, vec!["chrome".to_string()]);
        assert!(matches!(
            score_product("Chrome", &t),
            Some((Confidence::High, _))
        ));
        // Two-word product: one word alone is only plausible.
        let two = name_target("Wallpaper Engine", None);
        assert!(matches!(
            score_product("Wallpaper Engine", &two),
            Some((Confidence::High, _))
        ));
        assert!(matches!(
            score_product("Wallpaper", &two),
            Some((Confidence::Medium, _))
        ));
    }

    #[test]
    fn one_word_matches_only_when_the_name_is_that_word() {
        // "Brave Update Service" is Brave's: the name really is one word.
        let brave = name_target("Brave", Some("Brave Software Inc"));
        assert!(matches!(
            score_product("Brave Update Service", &brave),
            Some((Confidence::High, _))
        ));

        // "Microsoft Visual C++ 2010 x64 Redistributable" boils down to
        // "visual", which is not what the product is called, so Visual
        // Studio's service is plausible at most.
        let vcredist = name_target(
            "Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219",
            Some("Microsoft Corporation"),
        );
        assert_eq!(vcredist.name_tokens, vec!["visual".to_string()]);
        assert!(matches!(
            score_product("Visual Studio Installer Elevation Service", &vcredist),
            Some((Confidence::Medium, _))
        ));

        // Version noise does not stop a name from being one word.
        let mbam = name_target("Malwarebytes version 5.6.5.306", Some("Malwarebytes"));
        assert!(matches!(
            score_product("Malwarebytes Anti-Malware", &mbam),
            Some((Confidence::High, _))
        ));
    }

    #[test]
    fn a_short_word_carries_no_name_on_its_own() {
        let sdk = name_target(
            "Microsoft .NET SDK 9.0.318 (x64)",
            Some("Microsoft Corporation"),
        );
        assert_eq!(sdk.name_tokens, vec!["sdk".to_string()]);
        assert!(score_product("NVIDIA FrameView SDK", &sdk).is_none());

        // The same words on both sides still match, inside the vendor key
        // "GitHub" the child "CLI" is the product.
        let cli = name_target("GitHub CLI", Some("GitHub, Inc."));
        assert_eq!(cli.name_tokens, vec!["cli".to_string()]);
        assert!(matches!(
            score_product("CLI", &cli),
            Some((Confidence::High, _))
        ));
        assert!(score_product("claude-cli-nodejs", &cli).is_none());
    }

    #[test]
    fn windows_own_service_hosts_are_left_alone() {
        assert!(windows_hosted_service(Path::new(
            r"C:\WINDOWS\system32\svchost.exe"
        )));
        assert!(windows_hosted_service(Path::new(
            r"C:\WINDOWS\System32\DriverStore\FileRepository\logi.inf_amd64_1\logi_service.exe"
        )));
        // A program that drops its own service binary in System32 still counts.
        assert!(!windows_hosted_service(Path::new(
            r"C:\WINDOWS\SysWOW64\wallpaperservice32.exe"
        )));
    }

    #[test]
    fn a_folder_that_holds_another_install_is_left_alone() {
        let root = std::env::temp_dir().join("oxidize_shared_test");
        let _ = fs::remove_dir_all(&root);
        let game = root
            .join("Steam")
            .join("library")
            .join("common")
            .join("game");
        fs::create_dir_all(&game).unwrap();

        let steam = name_target("Steam", Some("Valve Corporation"));

        // On its own the folder is Steam's, by name.
        let mut out = Vec::new();
        scan_dir_children(&root, &steam, &[], &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, Confidence::High);

        // With another program installed inside it, it is shared and stays.
        let mut out = Vec::new();
        scan_dir_children(&root, &steam, std::slice::from_ref(&game), &mut out);
        assert!(out.is_empty(), "{out:?}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_install_folder_is_not_matched_by_its_own_name() {
        let program = |install: &str| Program {
            registry_key: "Foo Editor".to_string(),
            source: RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
            display_name: "Foo Editor".to_string(),
            display_version: None,
            publisher: None,
            install_date: None,
            install_location: Some(install.to_string()),
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        };
        // A general folder recorded as the install location stays Medium.
        let t = build_target(&program(r"D:\Games"));
        assert_eq!(install_folder_score("Games", &t).0, Confidence::Medium);
        // A folder that names the product is still the product's.
        let t = build_target(&program(r"D:\Apps\Foo Editor"));
        assert_eq!(install_folder_score("Foo Editor", &t).0, Confidence::High);
    }

    fn registered(
        name: &str,
        install: Option<&str>,
        icon: Option<&str>,
        uninstall: Option<&str>,
    ) -> Program {
        Program {
            registry_key: format!("{name} test entry"),
            source: RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
            display_name: name.to_string(),
            display_version: None,
            publisher: None,
            install_date: None,
            install_location: install.map(str::to_string),
            display_icon: icon.map(str::to_string),
            estimated_size_kb: None,
            uninstall_string: uninstall.map(str::to_string),
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    #[test]
    fn what_runs_the_uninstall_is_not_the_programs_own() {
        // A Steam game uninstalls through Steam. Steam's autostart value and
        // its firewall rules stay Steam's.
        let steam = r"C:\Program Files (x86)\Steam\steam.exe";
        let game_dir = r"C:\Program Files (x86)\Steam\steamapps\common\wallpaper_engine";
        let game = build_target(&registered(
            "Wallpaper Engine",
            Some(game_dir),
            Some(r"C:\Program Files (x86)\Steam\steam\games\5b3bd0d9e5800b93.ico"),
            Some(&format!("\"{steam}\" steam://uninstall/431960")),
        ));
        assert!(game.exe_names.is_empty(), "{:?}", game.exe_names);
        assert!(match_run_value("Steam", &format!("\"{steam}\" -silent"), &game).is_none());
        for rule in ["Steam", "Steam Web Helper"] {
            assert!(
                match_exe_item(rule, Some(Path::new(steam)), &game).is_none(),
                "{rule}"
            );
        }
        // The game's own rule is still the game's.
        let launcher = PathBuf::from(game_dir).join("launcher.exe");
        assert!(matches!(
            match_exe_item("Wallpaper Engine", Some(launcher.as_path()), &game),
            Some((Confidence::High, _))
        ));

        // Without a recorded folder: a client handed a link, a bare name
        // Windows looks up, the Windows folder, a shell.
        for uninstall in [
            r#""C:\Games\Client\client.exe" client://uninstall/7"#,
            r#"powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\Foo Editor\remove.ps1""#,
            r#""C:\Windows\System32\cmd.exe" /c "C:\Program Files\Foo Editor\remove.cmd""#,
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -File "C:\ProgramData\Foo\remove.ps1""#,
        ] {
            let t = build_target(&registered("Foo Editor", None, None, Some(uninstall)));
            assert!(t.exe_names.is_empty(), "{uninstall}: {:?}", t.exe_names);
        }
        // With one, nothing outside it.
        let t = build_target(&registered(
            "Foo Editor",
            Some(r"C:\Program Files\Foo Editor"),
            Some(r"C:\Program Files\Foo Editor\foo.exe,0"),
            Some(
                r#""C:\Program Files\PowerShell\7\pwsh.exe" -File "C:\Program Files\Foo Editor\remove.ps1""#,
            ),
        ));
        assert_eq!(t.exe_names, ["foo.exe"]);
    }

    #[test]
    fn a_programs_own_executables_are_still_its_own() {
        let icon = Some(r"C:\Program Files\Foo Editor\foo.exe,0");
        let uninstall = Some(r#""C:\Program Files\Foo Editor\uninst.exe" /S"#);
        // In the recorded install folder.
        let t = build_target(&registered(
            "Foo Editor",
            Some(r"C:\Program Files\Foo Editor"),
            icon,
            uninstall,
        ));
        assert_eq!(t.exe_names, ["foo.exe", "uninst.exe"]);
        // Without one, next to the program's own uninstaller.
        let t = build_target(&registered("Foo Editor", None, icon, uninstall));
        assert_eq!(t.exe_names, ["foo.exe", "uninst.exe"]);
        // An MSI product uninstalls through msiexec; its icon still counts.
        let t = build_target(&registered(
            "Foo Editor",
            None,
            icon,
            Some("MsiExec.exe /X{2D7E0D49-0001-0000-0000-000000000000}"),
        ));
        assert_eq!(t.exe_names, ["foo.exe"]);
    }

    #[test]
    fn a_bare_program_name_is_never_a_missing_file() {
        let pwsh = build_target(&registered(
            "PowerShell 7-x64",
            Some(r"C:\Program Files\PowerShell\7"),
            Some(r"C:\Program Files\PowerShell\7\pwsh.exe"),
            Some("MsiExec.exe /X{2D7E0D49-0001-0000-0000-000000000000}"),
        ));
        // Autostart values that run Windows PowerShell by its bare name.
        let runs = [
            (
                "DiscordVencord",
                r#"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\x\start-discord.ps1""#,
            ),
            (
                "Mochi",
                r#"powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath 'C:\Users\x\AppData\Local\Programs\Mochi\bin\mochic.exe' -ArgumentList 'start' -WindowStyle Hidden""#,
            ),
        ];
        for (name, data) in runs {
            assert!(match_run_value(name, data, &pwsh).is_none(), "{name}");
        }
        // A scheduled task's command holds the bare name alone.
        assert!(match_exe_item("Mochi", Some(Path::new("powershell.exe")), &pwsh).is_none());

        // A bare name nothing answers to is unknown, not missing.
        let foo = name_target("Fooberry", None);
        assert!(match_run_value("Helper", "fooberry.exe --tray", &foo).is_none());
        assert!(match_exe_item("Helper", Some(Path::new("fooberry.exe")), &foo).is_none());
        // A full path that is gone still is.
        assert!(matches!(
            match_run_value(
                "Helper",
                r#""C:\Program Files\Fooberry\fooberry.exe" --tray"#,
                &foo
            ),
            Some((Confidence::High, _))
        ));
    }

    #[test]
    fn one_word_of_a_longer_name_claims_nothing_on_its_own() {
        // `AppData\Local\docker-secrets-engine` is Docker's.
        let engine = name_target("Wallpaper Engine", Some("Wallpaper Engine Team"));
        assert_eq!(engine.name_tokens, ["wallpaper", "engine"]);
        assert!(score_product("docker-secrets-engine", &engine).is_none());
        // Its own leftovers are named after it.
        for name in ["Wallpaper Engine", "wallpaper_engine", "WallpaperEngine"] {
            assert!(
                matches!(score_product(name, &engine), Some((Confidence::High, _))),
                "{name}"
            );
        }
        assert!(matches!(
            score_product("Wallpaper", &engine),
            Some((Confidence::Medium, _))
        ));

        // A one-word name stays one, whatever words its install folder adds:
        // NVIDIA App's own self-update task still is its.
        let mut nvapp = registered(
            "NVIDIA App 11.0.9.251",
            Some(
                r"C:\Program Files\NVIDIA Corporation\Installer2\Display.NvApp.{EAB5A4EC-3E37-4254-9510-236A9B8FF631}",
            ),
            None,
            None,
        );
        nvapp.publisher = Some("NVIDIA Corporation".to_string());
        let nvapp = build_target(&nvapp);
        assert!(nvapp.name_tokens.len() > 1, "{:?}", nvapp.name_tokens);
        assert!(score_product("NVIDIA App SelfUpdate_", &nvapp).is_some());

        // The firewall rules for Python 3.13's `python.exe` are not the
        // launcher's, by their name or by their path.
        let python = r"C:\Users\x\AppData\Local\Programs\Python\Python313\python.exe";
        let launcher = name_target("Python Launcher", Some("Python Software Foundation"));
        assert!(score_product("python.exe", &launcher).is_none());
        assert!(match_exe_item("python.exe", Some(Path::new(python)), &launcher).is_none());
        assert!(matches!(
            score_product("Python Launcher", &launcher),
            Some((Confidence::High, _))
        ));
        // Python itself keeps them.
        let interpreter = name_target("Python 3.13.7 (64-bit)", Some("Python Software Foundation"));
        assert!(matches!(
            score_product("python.exe", &interpreter),
            Some((Confidence::High, _))
        ));
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
        assert!(path_within_shared_dir(Path::new(
            r"C:\Program Files\Common Files\Vendor"
        )));
        assert!(!path_within_shared_dir(Path::new(
            r"C:\Program Files\BraveSoftware"
        )));
    }

    #[test]
    fn word_boundary_prevents_concatenation_false_positive() {
        let zoom = name_target("Zoom", Some("Zoom Video Communications, Inc."));
        assert!(score_product("ZoomIt", &zoom).is_none());
        assert!(matches!(
            score_product("Zoom", &zoom),
            Some((Confidence::High, _))
        ));
    }

    #[test]
    fn single_generic_token_is_never_high() {
        let vlc = name_target("VLC media player", Some("VideoLAN"));
        assert_eq!(vlc.name_tokens, vec!["vlc".to_string()]);
        assert!(score_product("Windows Media Player", &vlc).is_none());
    }

    #[test]
    fn publisher_only_folder_descends_not_flagged() {
        let brave = name_target("Brave", Some("Brave Software Inc"));
        assert!(matches_publisher("BraveSoftware", &brave));
        assert!(matches!(
            score_product("Brave-Browser", &brave),
            Some((Confidence::High, _))
        ));
    }

    #[test]
    fn dir_contains_is_boundary_aware() {
        assert!(dir_contains(
            r"c:\program files\vendor",
            r"c:\program files\vendor\productb"
        ));
        assert!(!dir_contains(
            r"c:\program files\app",
            r"c:\program files\apple"
        ));
        assert!(!dir_contains(
            r"c:\program files\app",
            r"c:\program files\app"
        ));
        assert!(!dir_contains(
            r"c:\program files\vendor\app",
            r"c:\program files\vendor"
        ));
    }

    #[test]
    fn protected_paths_are_never_deletable() {
        assert!(is_protected_path(Path::new("C:\\")));
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            assert!(is_protected_path(&Path::new(&local).join("Packages")));
        }
        assert!(is_protected_path(Path::new("D:\\")));
        if let Some(windir) = env_dir("windir") {
            assert!(is_protected_path(&windir));
            assert!(is_protected_path(&windir.join("System32")));
        }
        if let Some(pf) = env_dir("ProgramFiles") {
            assert!(is_protected_path(&pf));
        }
        assert!(!is_protected_path(Path::new(
            r"C:\Program Files\Some Vendor\Some App"
        )));
    }

    #[test]
    fn contains_subslice_is_word_aligned() {
        let hay = vec![
            "google".to_string(),
            "chrome".to_string(),
            "beta".to_string(),
        ];
        assert!(contains_subslice(
            &hay,
            &["google".to_string(), "chrome".to_string()]
        ));
        assert!(!contains_subslice(
            &hay,
            &["chrome".to_string(), "google".to_string()]
        ));
        assert!(!contains_subslice(
            &["zoomit".to_string()],
            &["zoom".to_string()]
        ));
    }

    #[test]
    fn dangling_paths_that_name_the_product_match() {
        let t = target();
        let gone = Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe");
        assert!(path_names_product(gone, &t));
        assert!(!path_names_product(
            Path::new(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
            &t
        ));
    }

    /// The Store app Windows lists as "Game Speech Window", package
    /// `Microsoft.XboxSpeechToTextOverlay`.
    fn game_speech_window() -> ScanTarget {
        let mut app = crate::packages::fake::package(
            "Microsoft.XboxSpeechToTextOverlay",
            "Game Speech Window",
        );
        app.publisher = Some("Microsoft Corporation".to_string());
        crate::packages::scan_target(&app)
    }

    #[test]
    fn one_word_of_a_store_apps_name_matches_nothing() {
        let t = game_speech_window();
        assert_eq!(t.name_tokens, ["game", "speech", "window"]);

        // `AppData\Local\speech` holds Windows' speech data.
        assert!(score_product("speech", &t).is_none());
        assert!(!is_exact_product("speech", &t));
        // Warframe's firewall rules, by their name and by their program.
        for rule in [
            "Warframe Epic Game 64-bit (TCP-In)",
            "Warframe Epic Game 64-bit (TCP-Out)",
        ] {
            assert!(match_exe_item(rule, None, &t).is_none(), "{rule}");
        }
        assert!(!path_names_product(
            Path::new(r"C:\Program Files\Epic Games\Warframe\Downloaded\Warframe.x64.exe"),
            &t
        ));
        for other in ["Game", "Games", "Window", "Speech Recognition", "Game Bar"] {
            assert!(score_product(other, &t).is_none(), "{other}");
        }

        // A program of that name keeps its rule: one word is plausible.
        let program = name_target("Game Speech Window", Some("Microsoft Corporation"));
        assert!(matches!(
            score_product("speech", &program),
            Some((Confidence::Medium, _))
        ));
    }

    #[test]
    fn a_store_app_is_found_by_its_package_identity_or_whole_name() {
        let t = game_speech_window();
        for name in [
            "XboxSpeechToTextOverlay",
            "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe",
            "Game Speech Window",
            "GameSpeechWindow",
            "Game Speech Window Cache",
        ] {
            assert!(
                matches!(score_product(name, &t), Some((Confidence::High, _))),
                "{name}"
            );
        }

        // One word of the identity is no name either: `ohmyposh.cli` does not
        // claim a folder "cli", but its shown name still claims `oh-my-posh`.
        let mut posh = crate::packages::fake::package("ohmyposh.cli", "Oh My Posh");
        posh.publisher = Some("Jan Joris De Dobbeleer".to_string());
        let posh = crate::packages::scan_target(&posh);
        assert!(score_product("cli", &posh).is_none());
        assert!(matches!(
            score_product("oh-my-posh", &posh),
            Some((Confidence::High, _))
        ));

        // A one-word shown name claims the folder of that name, not every
        // folder that has the word in it.
        let terminal = crate::packages::scan_target(&crate::packages::fake::package(
            "Microsoft.WindowsTerminal",
            "Windows Terminal",
        ));
        assert_eq!(terminal.name_tokens, ["terminal"]);
        for name in ["Windows Terminal", "WindowsTerminal"] {
            assert!(
                matches!(score_product(name, &terminal), Some((Confidence::High, _))),
                "{name}"
            );
        }
        for name in ["Terminal", "Terminal Icons"] {
            assert!(score_product(name, &terminal).is_none(), "{name}");
        }
    }

    #[test]
    fn a_store_apps_folders_are_found_by_identity_not_by_one_word() {
        let root =
            std::env::temp_dir().join(format!("oxidize_store_scan_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for folder in [
            "speech",
            "Games",
            "XboxSpeechToTextOverlay",
            "Game Speech Window",
        ] {
            fs::create_dir_all(root.join(folder)).unwrap();
        }

        let mut out = Vec::new();
        scan_dir_children(&root, &game_speech_window(), &[], &mut out);
        let mut found: Vec<String> = out
            .iter()
            .map(|l| {
                Path::new(&l.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        found.sort();
        assert_eq!(found, ["Game Speech Window", "XboxSpeechToTextOverlay"]);
        assert!(out.iter().all(|l| l.confidence == Confidence::High));

        let _ = fs::remove_dir_all(&root);
    }
}
