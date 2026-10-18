//! Finds what a program left behind: registry keys and values, files and
//! folders, services, scheduled tasks, PATH entries and firewall rules.
//!
//! Every walk is program-scoped and shallow. A vendor folder or key can hold
//! sibling products, so the scanner descends into it and never flags it
//! wholesale. Denylists keep the OS and shared locations out entirely.

use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::thread;

use crate::model::{
    Confidence, Hive, Leftover, LeftoverKind, Program, RegistrySource, ScanReport, ScanTarget,
};
use crate::registry;
use crate::system;
use crate::util::{self, normalize, significant_tokens};

mod links;
mod records;

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

/// Windows' own folders in the Start menu.
const START_MENU_DENY: &[&str] = &[
    "accessibility",
    "accessories",
    "administrative tools",
    "maintenance",
    "startup",
    "system tools",
    "windows tools",
];

fn start_menu_roots() -> Vec<PathBuf> {
    const START_MENU: &str = r"Microsoft\Windows\Start Menu\Programs";
    [env_dir("APPDATA"), env_dir("ProgramData")]
        .into_iter()
        .flatten()
        .map(|p| p.join(START_MENU))
        .collect()
}

/// `path_within_shared_dir`, except that in the Start menu, which lives in
/// `Microsoft\Windows`, only the part below it counts: a vendor's folder in
/// there is the vendor's. Windows' own folders in it, and every folder that
/// names Windows or Microsoft, are not.
fn shared_dir(p: &Path) -> bool {
    match below_root(p, &start_menu_roots()) {
        Some((_, segments)) => segments.iter().any(|s| {
            let lower = s.to_lowercase();
            SHARED_DIR_DENY.contains(&lower.as_str())
                || START_MENU_DENY.contains(&lower.as_str())
                || words(s).iter().any(|w| w == "windows" || w == "microsoft")
        }),
        None => path_within_shared_dir(p),
    }
}

pub fn reg_denied(name: &str) -> bool {
    REG_DENY.contains(&name.to_lowercase().as_str())
}

// Targets
// -------

/// What one run reads from the system, read once and shared by its steps.
/// Make a new one per run: the GUI and the MCP server live long and must see
/// the machine as it is now.
#[derive(Default)]
pub struct Snapshot {
    programs: OnceLock<Vec<Program>>,
    services: OnceLock<Vec<system::ServiceInfo>>,
    tasks: OnceLock<Vec<system::TaskInfo>>,
    roots: OnceLock<Vec<PathBuf>>,
}

impl Snapshot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from a list of programs already read, system components
    /// included.
    pub fn with_programs(programs: Vec<Program>) -> Self {
        let snap = Self::default();
        let _ = snap.programs.set(programs);
        snap
    }

    /// Every registered program, system components included.
    pub fn programs(&self) -> &[Program] {
        self.programs
            .get_or_init(|| registry::enumerate_installed_programs(true))
    }

    pub fn services(&self) -> &[system::ServiceInfo] {
        self.services.get_or_init(system::services)
    }

    pub fn tasks(&self) -> &[system::TaskInfo] {
        self.tasks.get_or_init(system::scheduled_tasks)
    }

    /// The folders whose children are inspected by name.
    pub fn roots(&self) -> &[PathBuf] {
        self.roots.get_or_init(fs_roots)
    }

    /// Read the programs, and the services and tasks if asked, at the same
    /// time.
    fn prefetch(&self, services_and_tasks: bool) {
        thread::scope(|s| {
            if self.programs.get().is_none() {
                s.spawn(|| {
                    self.programs();
                });
            }
            if services_and_tasks {
                s.spawn(|| {
                    self.services();
                });
                s.spawn(|| {
                    self.tasks();
                });
            }
        });
    }
}

/// Capture a registered program's identity.
pub fn build_target(program: &Program) -> ScanTarget {
    build_target_with(program, &Snapshot::new())
}

/// `build_target` reading the system through `snap`.
pub fn build_target_with(program: &Program, snap: &Snapshot) -> ScanTarget {
    let roots = snap.roots();
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
        // A drive and a root, or a share. `C:\` loses its separator above and
        // reads as "the current folder on C:", and a bare `Quillmark` names a
        // folder of whatever the current one is; neither says where the
        // program is.
        .filter(|p| p.is_absolute())
        // A program writes its own install location, so a protected one is
        // either a broken installer or a hostile one. Either way nothing may
        // be claimed through it: everything under the folder would count as
        // the program's, down to Windows' own autostart entries.
        .filter(|p| !is_protected_path_in(p, roots));

    snap.prefetch(install_location.is_some());
    let own = (program.registry_key.clone(), program.source);
    let other_installs: Vec<PathBuf> = other_program_install_dirs(Some(&own), snap.programs())
        .into_iter()
        .filter(|p| !is_protected_path_in(p, roots))
        .collect();
    // What services and scheduled tasks run, by name, to tell a folder of the
    // program's own from a vendor folder recorded in its place.
    let runs: Vec<(Vec<String>, PathBuf)> = if install_location.is_some() {
        let services = snap.services().iter().filter_map(|s| {
            let mut names = vec![s.name.clone()];
            names.extend(s.display_name.clone());
            Some((names, s.exe.clone()?))
        });
        let tasks = snap.tasks().iter().filter_map(|t| {
            let leaf = t.name.rsplit('\\').next().unwrap_or(&t.name);
            let leaf = leaf.split('{').next().unwrap_or(leaf).to_string();
            Some((vec![leaf], t.exe.clone()?))
        });
        services.chain(tasks).collect()
    } else {
        Vec::new()
    };
    build_target_from(program, install_location, &other_installs, &runs, snap)
}

/// `build_target` with what it reads from the system passed in: the install
/// folder as recorded, the other programs' install folders, and the names and
/// executables of the services and scheduled tasks.
fn build_target_from(
    program: &Program,
    install_location: Option<PathBuf>,
    other_installs: &[PathBuf],
    runs: &[(Vec<String>, PathBuf)],
    snap: &Snapshot,
) -> ScanTarget {
    let mut target = name_target(&program.display_name, program.publisher.as_deref());
    // A vendor folder recorded as the install folder is no evidence: what is
    // inside belongs to whichever product put it there. Ownership falls back
    // to the uninstaller's folder and the program's names.
    let install_location =
        install_location.filter(|loc| !shared_install_folder(loc, &target, other_installs, runs));
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
    let own = (program.registry_key.clone(), program.source);
    target.registry = Some(own.clone());
    target.exe_names = own_exe_names(program, install_location.as_deref(), other_installs);
    target.install_location = install_location;
    target.vendor_is_shared = vendor_is_shared(&target, snap);

    let roots = install_roots();
    target.brand = derive_brand(program, target.install_location.as_deref(), &roots);
    if let Some(brand) = target.brand.clone() {
        target.brand_alone = !others_carry(&brand, Some(&own), snap.programs());
        if let Some(loc) = target.install_location.clone() {
            let mut others = other_program_paths(Some(&own), snap.programs());
            others.extend(other_installs.iter().cloned());
            target.install_vouched = install_vouched(&loc, &target, &others, &roots);
            target.vendor_dir = vendor_dir_of(&loc, &target, &others, runs, &roots, snap.roots());
        }
    }
    target
}

// Brand
// -----

/// Words that are never a vendor's own, however often an entry repeats
/// them: what a product is, how it ships and where it goes.
const BRAND_STOP: &[&str] = &[
    "player",
    "launcher",
    "update",
    "updater",
    "setup",
    "studio",
    "studios",
    "client",
    "microsoft",
    "windows",
    "corporation",
    "games",
    "digital",
    "online",
    "mobile",
    "cloud",
    "desktop",
    "versions",
    "version",
    "current",
    "latest",
    "stable",
    "shared",
    "local",
    "roaming",
    "users",
    "admin",
    "machine",
    "uninstall",
    "uninstaller",
    "unins",
    "installer",
    "appdata",
    "browser",
    "entertainment",
    "interactive",
    "system",
    "device",
    "devices",
    "network",
    "security",
    "office",
    "portable",
];

/// The words of a name, split at punctuation and where lower case turns to
/// upper case: `ExampleViewerSetup` is three words.
fn words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.split(|c: char| !c.is_alphanumeric()) {
        let mut word = String::new();
        let mut after_lower = false;
        for c in part.chars() {
            if c.is_uppercase() && after_lower {
                out.push(word.to_lowercase());
                word.clear();
            }
            after_lower = c.is_lowercase() || c.is_ascii_digit();
            word.push(c);
        }
        if !word.is_empty() {
            out.push(word.to_lowercase());
        }
    }
    out
}

/// Can this word be a vendor's? Long enough, letters only (a version or a
/// hash is not a name), and not one of the words every vendor uses.
fn brand_word(w: &str) -> bool {
    w.len() >= 5
        && w.chars().all(char::is_alphabetic)
        && !util::is_stopword(w)
        && !BRAND_STOP.contains(&w)
        && !fs_denied(w)
        && !reg_denied(w)
}

/// Does this name or path carry the brand: one of its words is it, or
/// starts with it (`ExampleSoft`)?
fn carries_brand(s: &str, brand: &str) -> bool {
    words(s).iter().any(|w| w.starts_with(brand))
}

/// The folders programs install into and keep their data in. Where a folder
/// sits below one of them says whose it is.
fn install_roots() -> Vec<PathBuf> {
    let local = env_dir("LOCALAPPDATA");
    [
        env_dir("ProgramFiles"),
        env_dir("ProgramFiles(x86)"),
        env_dir("ProgramW6432"),
        env_dir("ProgramData"),
        env_dir("APPDATA"),
        local.clone(),
        local.map(|p| p.join("Programs")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The deepest of `roots` that `p` is inside, and the folder names from
/// there down to `p`. `None` when `p` is in none of them, or is one, or
/// climbs with `..`, which would put it somewhere else than it reads.
fn below_root(p: &Path, roots: &[PathBuf]) -> Option<(PathBuf, Vec<String>)> {
    if p.components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return None;
    }
    let key = norm_path_key(p);
    let root = roots
        .iter()
        .filter(|r| dir_contains(&norm_path_key(r), &key))
        .max_by_key(|r| norm_path_key(r).len())?;
    let segments = p
        .components()
        .skip(root.components().count())
        .filter_map(|c| c.as_os_str().to_str())
        .map(str::to_string)
        .collect();
    Some((root.clone(), segments))
}

/// The vendor's word, from what the program says about itself: its name,
/// its publisher, the folders of its install path, uninstaller and icon below
/// the install root, its uninstall key and the names of its executables. A
/// word counts when at least two of those carry it; of several, the
/// publisher's wins, then the one most of them carry.
fn derive_brand(
    program: &Program,
    install_location: Option<&Path>,
    roots: &[PathBuf],
) -> Option<String> {
    let as_path = |s: &str| PathBuf::from(util::expand_env_vars(s).trim().trim_matches('"'));
    let uninstaller = program
        .uninstall_string
        .as_deref()
        .and_then(system::command_exe)
        .filter(|p| p.is_absolute() && !system::in_windows_dir(p));
    let icon = program
        .display_icon
        .as_deref()
        .map(|i| as_path(i.split(',').next().unwrap_or(i)))
        .filter(|p| p.is_absolute() && !system::in_windows_dir(p));

    let mut paths = Vec::new();
    let mut exes = Vec::new();
    if let Some((_, segments)) = install_location.and_then(|loc| below_root(loc, roots)) {
        paths.extend(segments.iter().flat_map(|s| words(s)));
    }
    for file in [uninstaller, icon].into_iter().flatten() {
        if let Some((_, segments)) = file.parent().and_then(|dir| below_root(dir, roots)) {
            paths.extend(segments.iter().flat_map(|s| words(s)));
        }
        if let Some(stem) = file.file_stem().and_then(|s| s.to_str()) {
            exes.extend(words(stem));
        }
    }
    let sources = [
        words(&program.display_name),
        program.publisher.as_deref().map(words).unwrap_or_default(),
        paths,
        words(&program.registry_key),
        exes,
    ];

    let mut best: Option<(bool, usize, &String)> = None;
    for word in sources.iter().flatten() {
        if !brand_word(word) {
            continue;
        }
        // The word has to be in the program's own name or its publisher's:
        // a game that uninstalls through its launcher's folder is not the
        // launcher's vendor.
        let count = sources.iter().filter(|s| s.contains(word)).count();
        if count < 2 || !(sources[0].contains(word) || sources[1].contains(word)) {
            continue;
        }
        let rank = (sources[1].contains(word), count);
        if best.is_none_or(|(p, c, _)| rank > (p, c)) {
            best = Some((rank.0, rank.1, word));
        }
    }
    best.map(|(_, _, w)| w.clone())
}

/// Does any other registered program carry the brand: in its name,
/// publisher, uninstall key, install folder, uninstaller or icon?
fn others_carry(brand: &str, own: Option<&(String, RegistrySource)>, programs: &[Program]) -> bool {
    programs
        .iter()
        .filter(|p| {
            own.is_none_or(|(key, source)| !(p.registry_key == *key && p.source == *source))
        })
        .any(|p| {
            [
                Some(&p.display_name),
                p.publisher.as_ref(),
                Some(&p.registry_key),
                p.install_location.as_ref(),
                p.uninstall_string.as_ref(),
                p.quiet_uninstall_string.as_ref(),
                p.display_icon.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|s| carries_brand(s, brand))
        })
}

/// The install folders, uninstallers and icons of every other program.
fn other_program_paths(
    own: Option<&(String, RegistrySource)>,
    programs: &[Program],
) -> Vec<PathBuf> {
    let as_path = |s: &str| PathBuf::from(util::expand_env_vars(s).trim().trim_matches('"'));
    programs
        .iter()
        .filter(|p| {
            own.is_none_or(|(key, source)| !(p.registry_key == *key && p.source == *source))
        })
        .flat_map(|p| {
            [
                p.install_location.as_deref().map(as_path),
                p.uninstall_string.as_deref().and_then(system::command_exe),
                p.display_icon
                    .as_deref()
                    .map(|i| as_path(i.split(',').next().unwrap_or(i))),
            ]
        })
        .flatten()
        .filter(|p| p.is_absolute() && !system::in_windows_dir(p))
        .collect()
}

/// Is a folder or key named after the vendor, with nothing else of the
/// vendor's installed? Only the brand itself counts, with or without its
/// company form, or the publisher's whole name when that carries the brand.
fn is_brand_name(name: &str, target: &ScanTarget) -> bool {
    let Some(brand) = target.brand.as_deref().filter(|_| target.brand_alone) else {
        return false;
    };
    normalize(name) == brand
        || without_company_form(name) == brand
        || (target
            .publisher
            .as_deref()
            .is_some_and(|p| carries_brand(p, brand))
            && is_publisher_exactly(name, target))
}

/// Is the recorded install folder the program's own? Its path has to be
/// below an install root, nothing another program records may be in it, and
/// it or a folder on the way down has to carry the brand: `Vendor\Versions\
/// version-3f2a` is the vendor's version folder. Only while nothing else of
/// the vendor's is installed: another product of theirs can share the folder
/// without saying so, an MSI product with no folder recorded for one.
fn install_vouched(loc: &Path, target: &ScanTarget, others: &[PathBuf], roots: &[PathBuf]) -> bool {
    let Some(brand) = target.brand.as_deref().filter(|_| target.brand_alone) else {
        return false;
    };
    if others.iter().any(|o| system::path_under(o, loc)) {
        return false;
    }
    below_root(loc, roots)
        .is_some_and(|(_, segments)| segments.iter().any(|s| carries_brand(s, brand)))
}

/// The vendor's folder right below the install root that the install folder
/// sits in, when it is this program's to remove: nothing else of the
/// vendor's is installed, nothing another program records is inside, and
/// nothing runs from it that carries neither the brand nor the product.
fn vendor_dir_of(
    loc: &Path,
    target: &ScanTarget,
    others: &[PathBuf],
    runs: &[(Vec<String>, PathBuf)],
    roots: &[PathBuf],
    protected: &[PathBuf],
) -> Option<PathBuf> {
    let brand = target
        .brand
        .as_deref()
        .filter(|_| target.brand_alone && target.install_vouched)?;
    let (root, segments) = below_root(loc, roots)?;
    let [first, _, ..] = segments.as_slice() else {
        return None;
    };
    if !carries_brand(first, brand) || fs_denied(first) || path_within_shared_dir(Path::new(first))
    {
        return None;
    }
    let dir = root.join(first);
    if is_protected_path_in(&dir, protected) || others.iter().any(|o| system::path_under(o, &dir)) {
        return None;
    }
    let foreign = runs.iter().any(|(names, exe)| {
        system::path_under(exe, &dir)
            && !system::path_under(exe, loc)
            && !names
                .iter()
                .any(|n| carries_brand(n, brand) || score_product(n, target).is_some())
    });
    (!foreign).then_some(dir)
}

/// Does another registered program carry the product's name? Then a folder
/// that holds a longer namesake can hold that program's version too.
fn name_in_use(target: &ScanTarget, programs: &[Program]) -> bool {
    let joined: String = target.name_tokens.concat();
    programs
        .iter()
        .filter(|p| {
            target
                .registry
                .as_ref()
                .is_none_or(|(key, source)| !(p.registry_key == *key && p.source == *source))
        })
        .any(|p| {
            let mut tokens = significant_tokens(&p.display_name);
            tokens.extend(
                p.publisher
                    .as_deref()
                    .map(significant_tokens)
                    .unwrap_or_default(),
            );
            (!target.name_tokens.is_empty()
                && target.name_tokens.iter().all(|t| tokens.contains(t)))
                || (joined.len() >= 4 && normalize(&p.display_name).contains(&joined))
        })
}

/// Is the recorded install folder shared rather than the program's own?
/// Intel's Bluetooth driver records `Program Files (x86)\Intel`, which holds
/// the Driver & Support Assistant and its two services. A folder is shared
/// when another program is installed inside it, or when a service or
/// scheduled task runs from a subfolder of it that names neither this
/// program nor anything the service or task is called.
fn shared_install_folder(
    loc: &Path,
    target: &ScanTarget,
    other_installs: &[PathBuf],
    runs: &[(Vec<String>, PathBuf)],
) -> bool {
    let key = norm_path_key(loc);
    if other_installs
        .iter()
        .any(|o| dir_contains(&key, &norm_path_key(o)))
    {
        return true;
    }
    runs.iter().any(|(names, exe)| {
        let exe_key = norm_path_key(exe);
        if !dir_contains(&key, &exe_key) {
            return false;
        }
        let rest = &exe_key[key.len() + 1..];
        let Some((subfolder, _file)) = rest.split_once('\\') else {
            // Right in the install folder: the program's own.
            return false;
        };
        score_product(subfolder, target).is_none()
            && names.iter().all(|n| score_product(n, target).is_none())
    })
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
        .filter(|t| !container.contains(t) && !fs_denied(t) && !reg_denied(t) && !is_hash(t))
        .collect()
}

/// A build id such as `3f2a9c0d7b1e4a65`: hex digits only, some of them
/// numbers, and long. It names one build, never the product.
fn is_hash(token: &str) -> bool {
    token.len() >= 8
        && token.chars().all(|c| c.is_ascii_hexdigit())
        && token.chars().any(|c| c.is_ascii_digit())
}

/// A target for a program that is no longer registered: all we have is what
/// the user typed. Without a publisher, a two-word name such as "Google
/// Chrome" is read as vendor plus product, so the vendor folder is descended
/// into rather than flagged.
pub fn name_only_target(name: &str, publisher: Option<&str>) -> ScanTarget {
    name_only_target_with(name, publisher, &Snapshot::new())
}

/// Where the publisher of a program that is gone came from, when the user
/// named none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherSource {
    /// The uninstall entry an earlier removal backed up.
    Backup,
    /// The company Windows cached for the program's files.
    CachedName,
}

/// The publisher of a program that is gone: from the uninstall entry a
/// backup of its removal holds, or from the company Windows cached for the
/// files it shows under that name.
pub fn publisher_hint(name: &str) -> Option<(String, PublisherSource)> {
    crate::backup::recorded_publisher(name)
        .map(|p| (p, PublisherSource::Backup))
        .or_else(|| records::cached_company(name).map(|p| (p, PublisherSource::CachedName)))
}

/// `name_only_target` for a program that is gone, with the publisher from
/// `publisher_hint` when none is given.
pub fn removed_program_target(name: &str, publisher: Option<&str>) -> ScanTarget {
    match publisher {
        Some(p) => name_only_target(name, Some(p)),
        None => match publisher_hint(name) {
            Some((p, _)) => name_only_target(name, Some(&p)),
            None => name_only_target(name, None),
        },
    }
}

/// `name_only_target` reading the installed programs through `snap`.
pub fn name_only_target_with(name: &str, publisher: Option<&str>, snap: &Snapshot) -> ScanTarget {
    if publisher.is_some() {
        let mut target = name_target(name, publisher);
        target.vendor_is_shared = vendor_is_shared(&target, snap);
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
        brand: None,
        brand_alone: false,
        install_vouched: false,
        vendor_dir: None,
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
    product_tokens_for(name, publisher_tokens, util::account_tokens())
}

/// `product_tokens` with the account's words given. The account's name in a
/// display name is dropped like the vendor word, as long as something remains.
fn product_tokens_for(name: &str, publisher_tokens: &[String], account: &[String]) -> Vec<String> {
    let all = significant_tokens(name);
    let not_account: Vec<String> = all
        .iter()
        .filter(|t| !account.contains(t))
        .cloned()
        .collect();
    let tokens = if not_account.is_empty() {
        all
    } else {
        not_account
    };
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
fn vendor_is_shared(target: &ScanTarget, snap: &Snapshot) -> bool {
    if target.publisher_tokens.is_empty() || target.name_tokens != target.publisher_tokens {
        return false;
    }
    snap.programs()
        .iter()
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

/// Does `name` carry every word of the product's name, the common ones
/// included? "Driver and Support Assistant" does for Intel's "Driver & Support
/// Assistant"; HP's "Support Solutions Framework Updater" does not.
fn carries_whole_name(name: &str, target: &ScanTarget) -> bool {
    let words = |s: &str| -> Vec<String> {
        s.split(|c: char| !c.is_alphanumeric())
            .map(str::to_lowercase)
            .filter(|w| w.len() >= 3 && !w.chars().all(|c| c.is_ascii_digit()))
            .collect()
    };
    let have = words(name);
    let need: Vec<String> = words(&target.display_name)
        .into_iter()
        .filter(|w| !util::is_noise_word(w) && !target.publisher_tokens.contains(w))
        .collect();
    !need.is_empty() && need.iter().all(|w| have.contains(w))
}

/// Is this name the product itself: the display name, one of the target's
/// exact names, or its product words joined ("GoogleChrome" for "Google
/// Chrome")? One product word is the product only where lone words match
/// and the name is that word: `desktop.ini` is not "Windows Desktop Runtime".
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
    (target.name_tokens.len() >= 2 || (target.lone_words_match && name_is_one_word(target)))
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
    // CLI". Where the one word left is only part of the name, the rest of the
    // name has to be there too: Intel's "Driver & Support Assistant" keeps
    // "support", and so does HP's "Support Solutions Framework Updater" task.
    let same_words = candidate.len() == target.name_tokens.len()
        && (target.name_tokens.len() >= 2
            || name_is_one_word(target)
            || carries_whole_name(name, target));
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

/// How sure a folder named `name` is the program's, by the rules every
/// leftover folder is scored with.
pub fn folder_score(name: &str, target: &ScanTarget) -> Option<(Confidence, String)> {
    score_product(name, target)
}

fn contains_subslice(haystack: &[String], needle: &[String]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True if `name` is essentially the publisher (a shared vendor root such as
/// "Google" or "BraveSoftware"). Those are descended into, never flagged.
/// Is `name` the publisher's whole name, not just part of it? Only the
/// company form (Inc., Ltd., GmbH ...) may differ.
fn is_publisher_exactly(name: &str, target: &ScanTarget) -> bool {
    let Some(publisher) = &target.publisher else {
        return false;
    };
    let bare = without_company_form(name);
    bare.len() >= 4 && bare == without_company_form(publisher)
}

/// A name in lower case without spaces or punctuation and without its
/// company form.
fn without_company_form(name: &str) -> String {
    const FORMS: &[&str] = &[
        "inc",
        "llc",
        "ltd",
        "corp",
        "corporation",
        "company",
        "co",
        "limited",
        "gmbh",
        "ag",
        "srl",
        "sas",
        "sa",
        "bv",
        "incorporated",
        "plc",
        "pty",
    ];
    name.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|w| !w.is_empty() && !FORMS.contains(&w.as_str()))
        .collect()
}

/// Does no other installed program come from this program's publisher?
/// Programs without a publisher say nothing either way.
fn vendor_alone(target: &ScanTarget, programs: &[Program]) -> bool {
    let Some(publisher) = target.publisher.as_deref() else {
        return false;
    };
    if target.publisher_tokens.is_empty() {
        return false;
    }
    !programs
        .iter()
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
                .is_some_and(|pubr| same_vendor(pubr, publisher))
        })
}

/// Two publisher names for one vendor: the same words, or one the start of
/// the other once the company form is gone ("Example Studio" and "Example
/// Studio Games Pty Ltd").
fn same_vendor(a: &str, b: &str) -> bool {
    let (a, b) = (without_company_form(a), without_company_form(b));
    !a.is_empty() && !b.is_empty() && (a.starts_with(&b) || b.starts_with(&a))
}

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
fn owned_exe(p: &Path, target: &ScanTarget) -> Option<(Confidence, &'static str)> {
    if let Some(own) = own_install_folder(target) {
        if system::path_under(p, own) {
            return Some((Confidence::High, "inside the install folder"));
        }
    }
    if let Some(dir) = &target.vendor_dir {
        if system::path_under(p, dir) {
            return Some((Confidence::High, "inside the vendor's folder"));
        }
    }
    // A recorded folder whose name says nothing about the program, such as
    // a games folder it was put in, is only as sure as the folder itself.
    if let Some(loc) = &target.install_location {
        if system::path_under(p, loc) {
            return Some((Confidence::Medium, "inside the recorded install folder"));
        }
    }
    let base = util::file_basename_lower(&p.to_string_lossy())?;
    if target.exe_names.contains(&base) {
        // The program's own copy is gone once it is uninstalled. A file of
        // that name that is still there sits somewhere else and can be
        // another program's: every runtime ships its own `node.exe`.
        return Some(if exe_missing(p) {
            (Confidence::High, "runs the program's executable")
        } else {
            (
                Confidence::Medium,
                "runs a file named like the program's executable",
            )
        });
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

/// A path whose components name the product, for dangling references. Below
/// an install root, one that carries the brand does too when nothing else of
/// the vendor's is installed.
fn path_names_product(p: &Path, target: &ScanTarget) -> bool {
    let named = p.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| matches!(score_product(s, target), Some((Confidence::High, _))))
            .unwrap_or(false)
    });
    named || path_names_brand(p, target)
}

fn path_names_brand(p: &Path, target: &ScanTarget) -> bool {
    let Some(brand) = target.brand.as_deref().filter(|_| target.brand_alone) else {
        return false;
    };
    below_root(p, &install_roots())
        .is_some_and(|(_, segments)| segments.iter().any(|s| carries_brand(s, brand)))
}

/// The folders that are wholly the program's: its own install folder and
/// the vendor's folder around it.
pub fn owned_folders(target: &ScanTarget) -> Vec<&Path> {
    own_install_folder(target)
        .into_iter()
        .chain(target.vendor_dir.as_deref())
        .collect()
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
fn other_program_install_dirs(
    own: Option<&(String, RegistrySource)>,
    programs: &[Program],
) -> Vec<PathBuf> {
    programs
        .iter()
        .filter(|p| {
            own.map(|(key, source)| !(p.registry_key == *key && p.source == *source))
                .unwrap_or(true)
        })
        .filter_map(|p| p.install_location.as_deref())
        .map(util::expand_env_vars)
        .map(|s| s.trim().trim_matches('"').to_string())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
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
    is_protected_path_in(p, &fs_roots())
}

/// `is_protected_path` with the scan roots already read.
fn is_protected_path_in(p: &Path, roots: &[PathBuf]) -> bool {
    let s = resolve_for_guard(p);
    let s = s.as_str();
    if s.len() <= 3 {
        return true;
    }
    let guards = guard_paths();
    let inside = |g: &str| s == g || s.starts_with(&format!("{g}\\"));
    if guards.trees.iter().any(|g| inside(g)) {
        return true;
    }
    if guards.exact.iter().any(|g| s == g) {
        return true;
    }
    roots
        .iter()
        .any(|root| root_forms(root).iter().any(|g| s == g))
}

/// Is `p` inside Downloads or a desktop, where the folders are the user's
/// own? A removal that empties one of them leaves it standing.
pub fn in_user_files(p: &Path) -> bool {
    let s = resolve_for_guard(p);
    system::user_file_folders()
        .iter()
        .flat_map(|f| root_forms(f))
        .any(|g| g.len() > 3 && (s == g || s.starts_with(&format!("{g}\\"))))
}

/// [`guard_forms`] of a scan root, worked out once per root: a scan asks
/// about hundreds of folders against the same dozen roots.
fn root_forms(root: &Path) -> Vec<String> {
    static SEEN: OnceLock<std::sync::Mutex<HashMap<PathBuf, Vec<String>>>> = OnceLock::new();
    let seen = SEEN.get_or_init(Default::default);
    if let Some(forms) = seen.lock().ok().and_then(|m| m.get(root).cloned()) {
        return forms;
    }
    let forms = guard_forms(root);
    if let Ok(mut m) = seen.lock() {
        m.insert(root.to_path_buf(), forms.clone());
    }
    forms
}

/// What [`is_protected_path`] compares against, in both the written and the
/// resolved form. A guard read only as written misses a profile or AppData
/// that a junction moved to another drive, since the path checked is
/// resolved.
struct Guards {
    /// Nothing in or below these: the Windows folder and Oxidize's own.
    trees: Vec<String>,
    /// These folders themselves: the profile, the folders Windows keeps for
    /// the user and the machine, and the one holding every Store app's data.
    exact: Vec<String>,
}

fn guard_paths() -> &'static Guards {
    static GUARDS: OnceLock<Guards> = OnceLock::new();
    GUARDS.get_or_init(|| {
        let forms = |paths: Vec<Option<PathBuf>>| -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for g in paths.into_iter().flatten().flat_map(|p| guard_forms(&p)) {
                if g.len() > 3 && !out.contains(&g) {
                    out.push(g);
                }
            }
            out
        };
        // Oxidize's own folder holds the backups every undo depends on and
        // the protected list; no product's name, however close, may reach
        // into it.
        let trees = forms(vec![
            Some(env_dir("windir").unwrap_or_else(system::windows_dir)),
            Some(system::windows_dir()),
            env_dir("LOCALAPPDATA").map(|p| p.join("Oxidize")),
        ]);
        let mut exact = vec![
            env_dir("USERPROFILE"),
            env_dir("PUBLIC"),
            env_dir("USERPROFILE").and_then(|p| p.parent().map(Path::to_path_buf)),
            env_dir("USERPROFILE").map(|p| p.join("Documents")),
            env_dir("USERPROFILE").map(|p| p.join("Downloads")),
            env_dir("APPDATA").and_then(|p| p.parent().map(Path::to_path_buf)),
            env_dir("LOCALAPPDATA").and_then(|p| p.parent().map(|a| a.join("LocalLow"))),
            env_dir("TEMP"),
            env_dir("TMP"),
            // Every Store app keeps its data one level below this folder;
            // the empty-parent cleanup after a data-folder leftover must
            // stop here.
            env_dir("LOCALAPPDATA").map(|p| p.join("Packages")),
        ];
        exact.extend(system::known_folders().iter().cloned().map(Some));
        Guards {
            trees,
            exact: forms(exact),
        }
    })
}

/// A guard as written and as resolved, each normalised like the path it is
/// compared with.
fn guard_forms(p: &Path) -> Vec<String> {
    let written = norm_path_key(p);
    let resolved = resolve_for_guard(p);
    if written == resolved {
        vec![written]
    } else {
        vec![written, resolved]
    }
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

fn push_dir_leftover(
    out: &mut Vec<Leftover>,
    path: PathBuf,
    conf: Confidence,
    reason: String,
    roots: &[PathBuf],
) {
    if is_protected_path_in(&path, roots) || shared_dir(&path) {
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
fn flag_product_children(
    parent: &Path,
    target: &ScanTarget,
    out: &mut Vec<Leftover>,
    note: &str,
    roots: &[PathBuf],
) {
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
                push_dir_leftover(out, child.path(), conf, format!("{reason}, {note}"), roots);
            }
        }
    }
}

/// Why a folder named after the vendor is a leftover.
const VENDOR_FOLDER: &str = "the vendor's folder, nothing else of theirs is installed";

/// A vendor's folder that a service or scheduled task still runs from is not
/// sure to go: it can be a driver or a helper nothing registers. It is
/// listed, at Medium.
fn demote_vendor_folders_in_use(items: &mut [Leftover], snap: &Snapshot) {
    if !items.iter().any(|l| l.reason == VENDOR_FOLDER) {
        return;
    }
    let runs: Vec<&Path> = snap
        .services()
        .iter()
        .filter_map(|s| s.exe.as_deref())
        .chain(snap.tasks().iter().filter_map(|t| t.exe.as_deref()))
        .collect();
    demote_where_run(items, &runs);
}

fn demote_where_run(items: &mut [Leftover], runs: &[&Path]) {
    for item in items.iter_mut().filter(|l| l.reason == VENDOR_FOLDER) {
        let dir = Path::new(&item.path);
        if runs.iter().any(|exe| system::path_under(exe, dir)) {
            item.confidence = Confidence::Medium;
            item.reason = "the vendor's folder, a service or task runs from it".to_string();
        }
    }
}

/// `name_shared`: another registered program carries the product's name, so
/// a folder holding a longer namesake may hold its version too.
fn scan_dir_children(
    root: &Path,
    target: &ScanTarget,
    other_installs: &[PathBuf],
    name_shared: bool,
    roots: &[PathBuf],
    out: &mut Vec<Leftover>,
) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let desktop = ["USERPROFILE", "PUBLIC"]
        .iter()
        .filter_map(|v| env_dir(v))
        .any(|home| norm_path_key(&home.join("Desktop")) == norm_path_key(root));
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
            // Reading the folder is only worth it where its name counts.
            let family = std::cell::OnceCell::new();
            let family =
                |p: &Path| *family.get_or_init(|| name_shared && holds_namesake_child(p, target));
            if is_brand_name(&name, target) && !houses_other && !desktop {
                // The vendor's own folder, with nothing else of theirs
                // installed and no other program inside: all of it goes,
                // whatever the vendor's other products left in it. On the
                // desktop a folder is the user's.
                push_dir_leftover(
                    out,
                    path,
                    Confidence::High,
                    VENDOR_FOLDER.to_string(),
                    roots,
                );
            } else if is_exact_product(&name, target)
                && !target.vendor_is_shared
                && !houses_other
                && !contains_install
                && !family(&path)
            {
                push_dir_leftover(out, path, Confidence::High, "exact name".to_string(), roots);
            } else if matches_publisher(&name, target) {
                let note = format!("in vendor folder {name}");
                flag_product_children(&path, target, out, &note, roots);
            } else if houses_other || contains_install {
                // Another program is installed inside, and the folder is not
                // the vendor's, so it is shared whatever its name says:
                // Visual Studio's folder holds the Build Tools, Steam's holds
                // the games. The one folder in there we know is ours, the
                // recorded install folder, is listed on its own. A family
                // folder is shared the same way.
                continue;
            } else if let Some((conf, reason)) = score_product(&name, target) {
                if !family(&path) {
                    push_dir_leftover(out, path, conf, reason, roots);
                }
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

fn scan_filesystem(target: &ScanTarget, snap: &Snapshot) -> Vec<Leftover> {
    let other_installs = other_program_install_dirs(target.registry.as_ref(), snap.programs());
    let other_installs = other_installs.as_slice();
    let roots = snap.roots();
    let name_shared = name_in_use(target, snap.programs());

    // The install folder itself. Its recorded path can be a shared parent
    // (two products under one vendor folder), so it is only flagged whole
    // when its name or its path identifies this product and nothing else
    // lives inside.
    let install_folder = move || {
        let mut out = Vec::new();
        let Some(loc) = &target.install_location else {
            return out;
        };
        if let Some(dir) = target.vendor_dir.as_ref().filter(|d| d.is_dir()) {
            push_dir_leftover(
                &mut out,
                dir.clone(),
                Confidence::High,
                "the vendor's folder around the install folder, nothing else of theirs is installed"
                    .to_string(),
                roots,
            );
        }
        if loc.is_dir() && !is_protected_path_in(loc, roots) {
            let leaf = loc.file_name().and_then(|s| s.to_str()).unwrap_or_default();
            let note = format!("in install folder {leaf}");
            let loc_key = norm_path_key(loc);
            let houses_other = other_installs
                .iter()
                .any(|other| dir_contains(&loc_key, &norm_path_key(other)));
            // A folder named exactly like the product is the product's own,
            // even if the publisher name contains that word.
            let vendor_root = matches_publisher(leaf, target) && !is_exact_product(leaf, target);

            if houses_other {
                flag_product_children(loc, target, &mut out, &note, roots);
            } else if target.install_vouched {
                push_dir_leftover(
                    &mut out,
                    loc.clone(),
                    Confidence::High,
                    "install folder, in the vendor's folder".to_string(),
                    roots,
                );
            } else if vendor_root {
                flag_product_children(loc, target, &mut out, &note, roots);
            } else {
                let (conf, reason) = install_folder_score(leaf, target);
                push_dir_leftover(&mut out, loc.clone(), conf, reason, roots);
            }
        }
        out
    };

    // The install folder and each root are walked at the same time, and
    // their findings joined in this order.
    let mut jobs: Vec<Job<Vec<Leftover>>> = vec![Box::new(install_folder)];
    for root in roots {
        jobs.push(Box::new(move || {
            let mut out = Vec::new();
            scan_dir_children(root, target, other_installs, name_shared, roots, &mut out);
            out
        }));
    }
    let mut out: Vec<Leftover> = run_all(jobs).into_iter().flatten().collect();
    demote_vendor_folders_in_use(&mut out, snap);

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
/// The install folder when it is the program's own: its name says so and it
/// is not the vendor's folder. A folder recorded under another name may hold
/// more than this program, so being inside it proves nothing.
pub fn own_install_folder(target: &ScanTarget) -> Option<&Path> {
    let loc = target.install_location.as_deref()?;
    if target.install_vouched {
        return Some(loc);
    }
    let leaf = loc.file_name()?.to_str()?;
    let vendors = matches_publisher(leaf, target) && !is_exact_product(leaf, target);
    (!vendors && install_folder_score(leaf, target).0 == Confidence::High).then_some(loc)
}

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

/// The phases find files on their own, so a shortcut can be listed beside
/// the folder it sits in. The folder takes it with it: listing both made the
/// shortcut count as "already gone" once the folder was removed. Same rule as
/// `dedupe_nested_fs`, across every phase, order kept.
fn drop_files_inside_removed_folders(items: &mut Vec<Leftover>) {
    let is_fs = |l: &Leftover| matches!(l.kind, LeftoverKind::File | LeftoverKind::Directory);
    let kept: std::collections::HashSet<String> =
        dedupe_nested_fs(items.iter().filter(|l| is_fs(l)).cloned().collect())
            .into_iter()
            .map(|l| l.path)
            .collect();
    items.retain(|l| !is_fs(l) || kept.contains(&l.path));
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

fn scan_software_root(
    hive: Hive,
    base: &str,
    target: &ScanTarget,
    vendor_alone: bool,
    out: &mut Vec<Leftover>,
) {
    for child in registry::enum_subkeys(hive, base) {
        if reg_denied(&child) {
            continue;
        }
        let child_path = format!("{base}\\{child}");
        // The user's own settings from a vendor with nothing else installed
        // belong to this program, whatever the subkeys are called. So does
        // the machine's key named after the brand when no other program
        // carries it.
        if (hive == Hive::CurrentUser && vendor_alone && is_publisher_exactly(&child, target))
            || is_brand_name(&child, target)
        {
            out.push(Leftover::reg_key(
                hive,
                child_path,
                Confidence::High,
                "the vendor's key, nothing else of theirs is installed",
            ));
            continue;
        }
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
            let key = format!("{base}\\{child}");
            // The entry names the file it starts. One that starts a file of
            // the same name in someone else's folder is theirs, not ours.
            let conf = registry::read_string(hive, &key, "")
                .and_then(|data| system::command_exe(&data))
                .filter(|exe| exe.is_absolute())
                .map(|exe| owned_exe(&exe, target).map_or(Confidence::Medium, |(c, _)| c))
                .unwrap_or(Confidence::High);
            out.push(Leftover::reg_key(
                hive,
                key,
                conf,
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
    if let Some((conf, why)) = owned_exe(&exe, target) {
        return Some((conf, format!("autostart, {why}")));
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

/// `vendor_alone`: no other installed program comes from the same publisher,
/// so the publisher's own key under `HKCU\Software` is this program's.
fn scan_registry(target: &ScanTarget, installed: bool, vendor_alone: bool) -> Vec<Leftover> {
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
        scan_software_root(hive, base, target, vendor_alone, &mut out);
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
        if let Some((conf, why)) = owned_exe(&exe, target) {
            return Some((conf, why.to_string()));
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

fn scan_system(target: &ScanTarget, snap: &Snapshot) -> Vec<Leftover> {
    let mut out = Vec::new();

    // The four lists are independent, so they are read at the same time.
    let mut paths = Vec::new();
    let mut rules = Vec::new();
    run_all::<()>(vec![
        Box::new(|| {
            snap.services();
        }),
        Box::new(|| {
            snap.tasks();
        }),
        Box::new(|| {
            paths = [Hive::CurrentUser, Hive::LocalMachine]
                .map(|hive| (hive, system::path_entries(hive)))
                .to_vec();
        }),
        Box::new(|| rules = system::firewall_rules()),
    ]);

    for svc in snap.services() {
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
            out.push(Leftover::service(svc.name.clone(), &image, conf, reason));
        }
    }

    for task in snap.tasks() {
        let leaf = task.name.rsplit('\\').next().unwrap_or(&task.name);
        // Strip a trailing GUID so "UpdaterTask{GUID}" scores by its words.
        let leaf = leaf.split('{').next().unwrap_or(leaf);
        if let Some((conf, reason)) = match_exe_item(leaf, task.exe.as_deref(), target) {
            let command = task
                .exe
                .as_deref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            out.push(Leftover::task(task.name.clone(), &command, conf, reason));
        }
    }

    for (hive, entries) in paths {
        for entry in entries {
            let dir = PathBuf::from(util::expand_env_vars(&entry));
            if system::in_windows_dir(&dir) {
                continue;
            }
            let inside = |loc: Option<&Path>| loc.is_some_and(|loc| system::path_under(&dir, loc));
            if inside(own_install_folder(target)) {
                out.push(Leftover::path_entry(
                    hive,
                    entry,
                    Confidence::High,
                    "inside the install folder",
                ));
            } else if inside(target.install_location.as_deref()) {
                out.push(Leftover::path_entry(
                    hive,
                    entry,
                    Confidence::Medium,
                    "inside the recorded install folder",
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

    for rule in rules {
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

/// Work for one thread of `run_all`.
type Job<'a, T> = Box<dyn FnOnce() -> T + Send + 'a>;

/// Run each job on its own thread and return the results in the jobs' order.
/// A job that panics panics the caller, as if it had run there.
fn run_all<'a, T: Send + 'a>(jobs: Vec<Job<'a, T>>) -> Vec<T> {
    thread::scope(|s| {
        let handles: Vec<_> = jobs.into_iter().map(|job| s.spawn(job)).collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

/// The footprint of an installed program, from a scan of it as if it were
/// gone: the same items without its own uninstall entry, which is the only
/// thing `installed` changes.
pub fn as_footprint(report: &ScanReport, target: &ScanTarget) -> ScanReport {
    let own = target.registry.as_ref().map(|(key, source)| {
        (
            source.hive,
            format!("{}\\{}", source.view.uninstall_base(), key),
        )
    });
    let is_own = |l: &Leftover| {
        own.as_ref().is_some_and(|(hive, subpath)| {
            l.kind == LeftoverKind::RegistryKey
                && l.hive == Some(*hive)
                && l.subpath.as_deref() == Some(subpath.as_str())
        })
    };
    ScanReport {
        program_name: report.program_name.clone(),
        installed: true,
        items: report
            .items
            .iter()
            .filter(|l| !is_own(l))
            .cloned()
            .collect(),
    }
}

/// Run a full scan. `installed` says whether the program is still registered,
/// in which case its own uninstall entry is not a leftover.
pub fn scan(target: &ScanTarget, installed: bool) -> ScanReport {
    scan_with(target, installed, &Snapshot::new())
}

/// `scan` reading the system through `snap`.
pub fn scan_with(target: &ScanTarget, installed: bool, snap: &Snapshot) -> ScanReport {
    // The phases only read, so they run at the same time. Their findings are
    // joined in this order, whichever finishes first.
    let mut handlers = Vec::new();
    let mut shortcuts = Vec::new();
    let (handlers_out, shortcuts_out) = (&mut handlers, &mut shortcuts);
    let phases: Vec<Job<Vec<Leftover>>> = vec![
        Box::new(move || scan_registry(target, installed, vendor_alone(target, snap.programs()))),
        Box::new(move || scan_filesystem(target, snap)),
        Box::new(move || scan_system(target, snap)),
        Box::new(move || {
            let (found, rest) = links::scan_link_handlers(target);
            *handlers_out = rest;
            found
        }),
        Box::new(move || links::scan_file_types(target)),
        Box::new(move || {
            let (found, rest) = links::scan_shortcuts(target);
            *shortcuts_out = rest;
            found
        }),
        Box::new(move || links::scan_temp_folders(target, snap)),
        Box::new(move || links::scan_stale_uninstall_entries(target, snap)),
    ];
    let mut items: Vec<Leftover> = run_all(phases).into_iter().flatten().collect();

    // Link types and shortcuts that lead into a folder this scan removes
    // lead nowhere once it is gone, whatever product they were made for.
    let removed: Vec<PathBuf> = items
        .iter()
        .filter(|l| l.kind == LeftoverKind::Directory && l.confidence == Confidence::High)
        .map(|l| PathBuf::from(&l.path))
        .chain(owned_folders(target).into_iter().map(Path::to_path_buf))
        .collect();
    let others = other_program_install_dirs(target.registry.as_ref(), snap.programs());
    if !removed.is_empty() {
        handlers.append(&mut shortcuts);
        items.extend(links::into_removed(handlers, &removed, &others));
    }
    // Windows' own records of a file in those folders or of a single file
    // that goes, such as a shortcut, of a missing file that names the
    // product, or of the vendor's files when nothing else of theirs is
    // installed.
    let removed_files: Vec<PathBuf> = items
        .iter()
        .filter(|l| l.kind == LeftoverKind::File && l.confidence == Confidence::High)
        .map(|l| PathBuf::from(&l.path))
        .collect();
    let alone = vendor_alone(target, snap.programs());
    items.extend(records::scan_windows_records(
        target,
        &removed,
        &removed_files,
        &others,
        alone,
    ));
    dedupe_by_path(&mut items);
    drop_files_inside_removed_folders(&mut items);
    // A link type that goes takes its permission to open without asking with
    // it, and one that is already gone leaves only that permission behind.
    let allowed = links::scan_allowed_link_types(&items, target);
    items.extend(allowed);
    ScanReport {
        program_name: target.display_name.clone(),
        installed,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RegistryView;

    fn target() -> ScanTarget {
        let mut t = name_target("Google Chrome", Some("Google LLC"));
        t.exe_names = vec!["chrome.exe".to_string()];
        t.registry = Some((
            "Google Chrome".to_string(),
            RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
        ));
        t
    }

    fn listed(name: &str, key: &str, publisher: Option<&str>) -> Program {
        Program {
            registry_key: key.to_string(),
            source: RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
            display_name: name.to_string(),
            display_version: None,
            publisher: publisher.map(str::to_string),
            install_date: None,
            install_location: None,
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    #[test]
    fn the_vendors_key_is_the_programs_only_when_nothing_else_of_theirs_is_installed() {
        let mut t = name_target("Example Player", Some("Example Studio Inc."));
        t.registry = Some((
            "example-player".to_string(),
            RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
        ));
        let own = listed(
            "Example Player",
            "example-player",
            Some("Example Studio Inc."),
        );
        let other = listed("Other Tool", "other-tool", Some("Other Vendor"));
        assert!(vendor_alone(&t, &[own.clone(), other.clone()]));

        let sibling = listed(
            "Example Editor",
            "example-editor",
            Some("Example Studio Inc"),
        );
        assert!(!vendor_alone(&t, &[own.clone(), other.clone(), sibling]));
        // Written another way, still the same vendor.
        for publisher in [
            "ExampleStudio",
            "Example Studio Games Pty Ltd",
            "Example Studio GmbH",
        ] {
            let sibling = listed("Example Editor", "example-editor", Some(publisher));
            assert!(
                !vendor_alone(&t, &[own.clone(), other.clone(), sibling]),
                "{publisher}"
            );
        }

        // No publisher, no claim.
        let bare = name_target("Example Player", None);
        assert!(!vendor_alone(&bare, &[]));
    }

    #[test]
    fn only_the_publishers_whole_name_is_its_key() {
        let t = name_target("Example Player", Some("Example Studio Inc."));
        assert!(is_publisher_exactly("Example Studio", &t));
        assert!(is_publisher_exactly("Example Studio Inc.", &t));
        // Part of the name is not the vendor's key.
        assert!(!is_publisher_exactly("Example", &t));
        assert!(!is_publisher_exactly("Studio", &t));
        assert!(!is_publisher_exactly("Example Studio Tools", &t));
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
    fn the_account_name_in_a_display_name_is_not_the_product() {
        let account = vec!["jdoe".to_string()];
        let vendor = vec!["example".to_string()];
        // "for jdoe" says whose copy it is: only the vendor word is left, and
        // the user's own folders named after the account are no match.
        assert_eq!(
            product_tokens_for("Example Player for jdoe", &vendor, &account),
            vec!["example".to_string()]
        );
        assert_eq!(
            product_tokens_for("Quillmark Studio for jdoe", &[], &account),
            vec!["quillmark".to_string(), "studio".to_string()]
        );
        // A program named only like the account keeps its name.
        assert_eq!(
            product_tokens_for("Jdoe", &[], &account),
            vec!["jdoe".to_string()]
        );
    }

    #[test]
    fn a_shortcut_inside_a_removed_folder_goes_with_it() {
        let fs = |kind, p: &str| {
            Leftover::fs(kind, PathBuf::from(p), Confidence::High, "x", None, false)
        };
        let mut items = vec![
            fs(LeftoverKind::File, r"C:\Menu\Quillmark\Quillmark.lnk"),
            fs(LeftoverKind::Directory, r"C:\Menu\Quillmark"),
            fs(LeftoverKind::File, r"C:\Desktop\Quillmark.lnk"),
            Leftover::reg_key(
                Hive::CurrentUser,
                r"Software\Quillmark",
                Confidence::High,
                "x",
            ),
        ];
        drop_files_inside_removed_folders(&mut items);
        let paths: Vec<&str> = items.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                r"C:\Menu\Quillmark",
                r"C:\Desktop\Quillmark.lnk",
                r"HKCU\Software\Quillmark"
            ]
        );
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
        scan_dir_children(&root, &steam, &[], false, &fs_roots(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].confidence, Confidence::High);

        // With another program installed inside it, it is shared and stays.
        let mut out = Vec::new();
        scan_dir_children(
            &root,
            &steam,
            std::slice::from_ref(&game),
            false,
            &fs_roots(),
            &mut out,
        );
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
    fn a_vendor_folder_recorded_as_the_install_folder_owns_nothing() {
        // Intel's Bluetooth driver records `Program Files (x86)\Intel`, where
        // the Driver & Support Assistant keeps its two services.
        let intel = PathBuf::from(r"C:\Program Files (x86)\Intel");
        let dsa = intel.join(r"Driver and Support Assistant\x86");
        let mut bluetooth = registered(
            "Intel(R) Wireless Bluetooth(R)",
            Some(r"C:\Program Files (x86)\Intel\"),
            None,
            Some("MsiExec.exe /I{00000020-0240-1033-84C8-B8D95FA3C8C3}"),
        );
        bluetooth.publisher = Some("Intel Corporation".to_string());
        let runs = vec![
            (
                vec![
                    "DSAService".to_string(),
                    "Intel(R) Driver & Support Assistant".to_string(),
                ],
                dsa.join("DSAService.exe"),
            ),
            (
                vec![
                    "DSAUpdateService".to_string(),
                    "Intel(R) Driver & Support Assistant Updater".to_string(),
                ],
                dsa.join("DSAUpdateService.exe"),
            ),
        ];
        let snap = Snapshot::new();
        let t = build_target_from(&bluetooth, Some(intel.clone()), &[], &runs, &snap);
        assert!(t.install_location.is_none(), "{:?}", t.install_location);
        for (names, exe) in &runs {
            for name in names {
                assert!(
                    match_exe_item(name, Some(exe.as_path()), &t).is_none(),
                    "{name}"
                );
            }
        }
        // Another program installed inside makes a folder shared too.
        let t = build_target_from(
            &bluetooth,
            Some(intel.clone()),
            &[intel.join("Some Other Product")],
            &[],
            &snap,
        );
        assert!(t.install_location.is_none());
    }

    #[test]
    fn a_programs_own_install_folder_keeps_what_runs_from_it() {
        let dir = PathBuf::from(r"C:\Program Files\Foo Editor");
        let foo = registered(
            "Foo Editor",
            Some(r"C:\Program Files\Foo Editor"),
            Some(r"C:\Program Files\Foo Editor\foo.exe,0"),
            None,
        );
        // Its own service in a subfolder, another right inside.
        let runs = vec![
            (
                vec![
                    "FooEditorUpdate".to_string(),
                    "Foo Editor Update Service".to_string(),
                ],
                dir.join(r"updater\fooupdate.exe"),
            ),
            (vec!["FooSvc".to_string()], dir.join("foosvc.exe")),
        ];
        let t = build_target_from(&foo, Some(dir.clone()), &[], &runs, &Snapshot::new());
        assert_eq!(t.install_location.as_deref(), Some(dir.as_path()));
        assert_eq!(t.exe_names, ["foo.exe"]);
        for (names, exe) in &runs {
            assert!(
                matches!(
                    match_exe_item(&names[0], Some(exe.as_path()), &t),
                    Some((Confidence::High, _))
                ),
                "{}",
                names[0]
            );
        }
    }

    #[test]
    fn a_file_named_like_the_programs_elsewhere_is_not_the_programs() {
        let base = std::env::temp_dir().join("oxidize_exe_name_test");
        let _ = fs::remove_dir_all(&base);
        let own = base.join("Example Runtime");
        let other = base.join("Other App").join("bin");
        fs::create_dir_all(&own).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("node.exe"), "MZ").unwrap();
        let mut t = name_target("Example Runtime", Some("Example Foundation"));
        t.exe_names = vec!["node.exe".to_string()];
        t.install_location = Some(own.clone());
        t.install_vouched = true;

        // Another program's copy that is still there: a guess at most.
        let theirs = other.join("node.exe");
        assert!(matches!(
            match_exe_item("Other App", Some(&theirs), &t),
            Some((Confidence::Medium, _))
        ));
        // The program's own copy, or one that is gone with it, is its own.
        assert!(matches!(
            match_exe_item("x", Some(&own.join("node.exe")), &t),
            Some((Confidence::High, _))
        ));
        assert!(matches!(
            match_exe_item("x", Some(&base.join("Gone").join("node.exe")), &t),
            Some((Confidence::High, _))
        ));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn what_runs_from_an_untrusted_install_folder_is_only_as_sure_as_the_folder() {
        // A tool that recorded a folder whose name says nothing about it.
        let mut t = name_target("Quillmark", Some("Example Studio"));
        t.install_location = Some(PathBuf::from(r"C:\Users\x\Tools"));
        assert!(own_install_folder(&t).is_none());
        let hit = match_exe_item(
            "Other Game",
            Some(Path::new(r"C:\Users\x\Tools\OtherGame\game.exe")),
            &t,
        );
        assert!(matches!(hit, Some((Confidence::Medium, _))), "{hit:?}");
        // Once the folder is the program's own, so is what runs from it.
        t.install_vouched = true;
        let hit = match_exe_item(
            "Other Game",
            Some(Path::new(r"C:\Users\x\Tools\OtherGame\game.exe")),
            &t,
        );
        assert!(matches!(hit, Some((Confidence::High, _))), "{hit:?}");
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
    fn the_one_word_left_of_a_longer_name_is_not_the_whole_name() {
        // Every .NET Desktop Runtime boils down to "desktop"; the
        // `desktop.ini` files in Program Files, the Start Menu and on the
        // desktop are Windows'.
        let runtime = name_target(
            "Microsoft Windows Desktop Runtime - 8.0.23 (x64)",
            Some("Microsoft Corporation"),
        );
        assert_eq!(runtime.name_tokens, ["desktop"]);
        assert!(!is_exact_product("desktop", &runtime));
        assert!(!matches!(
            score_product("desktop", &runtime),
            Some((Confidence::High, _))
        ));
        // Intel's "Driver & Support Assistant" and HP's updater task.
        let dsa = name_target("Intel\u{ae} Driver & Support Assistant", Some("Intel"));
        assert_eq!(dsa.name_tokens, ["support"]);
        assert!(!matches!(
            score_product("HP Support Solutions Framework Updater", &dsa),
            Some((Confidence::High, _))
        ));
        // Their own names still match, the whole name with more around it
        // too: Intel's folder, HP's own updater task.
        for name in [
            "Intel Driver & Support Assistant",
            "Driver and Support Assistant",
        ] {
            assert!(
                matches!(score_product(name, &dsa), Some((Confidence::High, _))),
                "{name}"
            );
        }
        let hp = name_target("HP Support Solutions Framework", Some("HP Inc."));
        assert!(matches!(
            score_product("HP Support Solutions Framework Updater", &hp),
            Some((Confidence::High, _))
        ));
        assert!(matches!(
            score_product("Microsoft Windows Desktop Runtime - 8.0.23 (x64)", &runtime),
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
            let local = Path::new(&local);
            assert!(is_protected_path(&local.join("Packages")));
            // Oxidize's own folder and everything in it, the backups first.
            assert!(is_protected_path(&local.join("Oxidize")));
            assert!(is_protected_path(&local.join("OXIDIZE")));
            assert!(is_protected_path(
                &local
                    .join("Oxidize")
                    .join("backups")
                    .join("2026-10-17 Example")
            ));
            // A folder that only starts with the name is not it.
            assert!(!is_protected_path(&local.join("Oxidize Tools")));
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
    fn the_folders_windows_keeps_for_the_user_are_never_deletable() {
        let known = system::known_folders();
        // Windows answers for these on every machine.
        assert!(known.len() >= 20, "{known:?}");
        for folder in known {
            assert!(is_protected_path(folder), "{}", folder.display());
            // A folder inside one is not the folder itself, except in the
            // Windows folder, where nothing is.
            assert_eq!(
                is_protected_path(&folder.join("Example Vendor Leftover")),
                system::in_windows_dir(folder),
                "{}",
                folder.display()
            );
        }
        let profile = env_dir("USERPROFILE").unwrap();
        for name in ["Downloads", "Saved Games", "Music", "Pictures", "Videos"] {
            assert!(is_protected_path(&profile.join(name)), "{name}");
        }
        let local = env_dir("LOCALAPPDATA").unwrap();
        assert!(is_protected_path(&local.parent().unwrap().join("LocalLow")));
        assert!(is_protected_path(local.parent().unwrap()));
        assert!(is_protected_path(&std::env::temp_dir()));
    }

    #[test]
    fn downloads_and_the_desktop_hold_the_users_own_folders() {
        for folder in system::user_file_folders() {
            assert!(in_user_files(folder), "{}", folder.display());
            assert!(in_user_files(&folder.join("Installers")));
        }
        let profile = env_dir("USERPROFILE").unwrap();
        assert!(in_user_files(&profile.join("Downloads").join("Setups")));
        assert!(!in_user_files(&profile.join("Documents").join("Vendor")));
        assert!(!in_user_files(Path::new(
            r"C:\Program Files\Example Vendor"
        )));
    }

    #[test]
    fn a_root_behind_a_junction_is_protected_where_it_really_is() {
        let base = std::env::temp_dir().join("oxidize_guard_junction_test");
        let _ = fs::remove_dir_all(&base);
        let real = base.join("real root");
        fs::create_dir_all(real.join("Vendor")).unwrap();
        let link = base.join("linked root");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .unwrap();
        assert!(made.status.success());
        // The root is known by its junction, and asked about by its real
        // name, by the junction, and written with forward slashes.
        let roots = [link.clone()];
        assert!(is_protected_path_in(&real, &roots));
        assert!(is_protected_path_in(&link, &roots));
        let slashed = PathBuf::from(link.to_string_lossy().replace('\\', "/"));
        assert!(is_protected_path_in(&slashed, &roots));
        assert!(is_protected_path_in(&real, &[slashed]));
        // What is inside it is still only a folder.
        assert!(!is_protected_path_in(&real.join("Vendor"), &roots));
        assert!(!is_protected_path_in(&link.join("Vendor"), &roots));
        let _ = fs::remove_dir(&link);
        let _ = fs::remove_dir_all(&base);
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
        scan_dir_children(
            &root,
            &game_speech_window(),
            &[],
            false,
            &fs_roots(),
            &mut out,
        );
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

    /// A machine-wide install that keeps each build in its own folder below
    /// the vendor's: `Program Files\Brightway\Versions\version-<hash>`, with
    /// the uninstaller in there and no folder named after the product.
    const BUILD: &str = "version-cec3ad5889b447cf";

    fn program_files() -> PathBuf {
        env_dir("ProgramFiles").expect("ProgramFiles")
    }

    fn vendor_program(name: &str, key: &str, loc: &Path, exe: &str) -> Program {
        Program {
            registry_key: key.to_string(),
            source: RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
            display_name: name.to_string(),
            display_version: None,
            publisher: Some("Brightway Corporation".to_string()),
            install_date: None,
            install_location: Some(loc.display().to_string()),
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: Some(format!("\"{}\" -uninstall", loc.join(exe).display())),
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    fn player_loc() -> PathBuf {
        program_files()
            .join("Brightway")
            .join("Versions")
            .join(BUILD)
    }

    fn player() -> Program {
        vendor_program(
            "Brightway Player",
            "brightway-player-admin",
            &player_loc(),
            "BrightwayPlayerInstaller.exe",
        )
    }

    /// The target the uninstall builds, with `others` registered next to it.
    fn player_target(others: Vec<Program>) -> ScanTarget {
        let mut programs = vec![player()];
        programs.extend(others);
        let snap = Snapshot::with_programs(programs);
        build_target_from(&player(), Some(player_loc()), &[], &[], &snap)
    }

    #[test]
    fn the_brand_comes_from_what_the_entry_agrees_on() {
        let t = player_target(vec![listed(
            "Other Tool",
            "other-tool",
            Some("Other Vendor"),
        )]);
        assert_eq!(t.brand.as_deref(), Some("brightway"));
        assert!(t.brand_alone);
        // The build id is no word of the product's.
        assert!(
            !t.name_tokens.iter().any(|w| w.contains("cec3")),
            "{:?}",
            t.name_tokens
        );
        assert!(folder_tokens(&player_loc(), BUILD).is_empty());

        // One source alone is no brand, and neither are the common words.
        let mut bare = player();
        bare.publisher = None;
        bare.install_location = None;
        bare.uninstall_string = None;
        bare.registry_key = "{6A1F0E52-0000-0000-0000-000000000000}".to_string();
        assert_eq!(derive_brand(&bare, None, &install_roots()), None);
        let generic = vendor_program(
            "Media Player",
            "media-player",
            &program_files().join("Player").join("app-1.0"),
            "Update.exe",
        );
        let mut generic = generic;
        generic.publisher = Some("Studio Launcher Inc.".to_string());
        assert_eq!(
            derive_brand(
                &generic,
                generic.install_location.as_deref().map(Path::new),
                &install_roots()
            ),
            None
        );
    }

    #[test]
    fn a_build_folder_below_the_vendors_folder_is_the_programs_with_the_vendors_folder() {
        let t = player_target(Vec::new());
        assert!(t.install_vouched);
        assert_eq!(own_install_folder(&t), Some(player_loc().as_path()));
        assert_eq!(t.vendor_dir, Some(program_files().join("Brightway")));
        assert_eq!(owned_folders(&t).len(), 2);

        // The vendor's folders and keys, by the brand or the publisher's name.
        for name in [
            "Brightway",
            "brightway",
            "Brightway Corporation",
            "Brightway Corp.",
        ] {
            assert!(is_brand_name(name, &t), "{name}");
        }
        // A sibling product's folder is not the vendor's own.
        for name in ["Brightway Studio", "Brightwayish", "Other Vendor"] {
            assert!(!is_brand_name(name, &t), "{name}");
        }
        // Something of the vendor's that runs from its folder is the program's.
        let helper = program_files().join(r"Brightway\Helper\helper.exe");
        assert!(matches!(
            match_exe_item("Brightway Helper", Some(helper.as_path()), &t),
            Some((Confidence::High, _))
        ));
        // Once the folder is gone, a path into it names the program.
        let gone = program_files().join(r"Brightway\Versions\version-0000\StudioBeta.exe");
        assert!(path_names_product(&gone, &t));
    }

    #[test]
    fn the_vendors_folders_go_whole_and_the_start_menu_folder_is_not_windows() {
        let t = player_target(Vec::new());
        let root = std::env::temp_dir().join(format!("oxidize_brand_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        // `AppData\Local\Brightway` holds a longer namesake; that does not
        // make it a family folder when nothing else carries the name.
        for dir in [
            r"Brightway\Downloads\brightway-player",
            r"Brightway\logs",
            r"Brightway\BrightwayPlayerInstaller",
            r"Other Vendor\Brightway",
        ] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        let mut out = Vec::new();
        scan_dir_children(&root, &t, &[], false, &fs_roots(), &mut out);
        let found: Vec<(String, Confidence)> =
            out.iter().map(|l| (l.path.clone(), l.confidence)).collect();
        assert_eq!(
            found,
            [(
                root.join("Brightway").display().to_string(),
                Confidence::High
            )]
        );

        // The same for a scan by the word alone.
        let word = name_only_target("brightway", None);
        let mut out = Vec::new();
        scan_dir_children(&root, &word, &[], false, &fs_roots(), &mut out);
        assert!(out
            .iter()
            .any(|l| Path::new(&l.path) == root.join("Brightway")));
        let _ = fs::remove_dir_all(&root);

        // The Start menu sits in `Microsoft\Windows`; a vendor's folder in it
        // is still the vendor's, and Windows' own folders still are not.
        if let Some(data) = env_dir("ProgramData") {
            let menu = data.join(r"Microsoft\Windows\Start Menu\Programs");
            assert!(!shared_dir(&menu.join("Brightway")));
            for windows in [
                "Windows PowerShell",
                "WindowsPowerShell",
                "Administrative Tools",
                "Accessibility",
                r"Brightway\Microsoft Tools",
            ] {
                assert!(shared_dir(&menu.join(windows)), "{windows}");
            }
            assert!(shared_dir(&data.join(r"Microsoft\Brightway")));
            assert!(shared_dir(&program_files().join(r"Common Files\Brightway")));
        }
        // Outside the Start menu nothing changes.
        assert!(!shared_dir(&program_files().join("WindowsTerminalTools")));
    }

    #[test]
    fn a_vendor_folder_something_runs_from_is_only_medium() {
        let dir = program_files().join("Brightway");
        let folder = || {
            vec![Leftover::fs(
                LeftoverKind::Directory,
                dir.clone(),
                Confidence::High,
                VENDOR_FOLDER,
                None,
                false,
            )]
        };
        let driver = dir.join(r"Driver\brightwaysvc.exe");
        let mut items = folder();
        demote_where_run(&mut items, &[driver.as_path()]);
        assert_eq!(items[0].confidence, Confidence::Medium);

        let elsewhere = program_files().join(r"Other Tool\svc.exe");
        let mut items = folder();
        demote_where_run(&mut items, &[elsewhere.as_path()]);
        assert_eq!(items[0].confidence, Confidence::High);
    }

    #[test]
    fn a_path_that_climbs_out_is_below_nothing() {
        let climbing = program_files().join(r"Brightway\..\Example\App");
        assert!(below_root(&climbing, &install_roots()).is_none());
        let snap = Snapshot::with_programs(vec![player()]);
        let t = build_target_from(&player(), Some(climbing), &[], &[], &snap);
        assert!(!t.install_vouched);
        assert_eq!(t.vendor_dir, None);
    }

    #[test]
    fn a_launchers_folder_is_not_the_brand_of_what_it_uninstalls() {
        // A game registered under the launcher's key, uninstalled by the
        // launcher from the launcher's folder, by another publisher.
        let launcher = program_files().join("Brightway");
        let mut game = vendor_program(
            "Tidewater Quest",
            "Brightway App 4417",
            &launcher,
            "BrightwayLauncher.exe",
        );
        game.install_location = None;
        game.publisher = Some("Harbor Games Ltd".to_string());
        assert_eq!(derive_brand(&game, None, &install_roots()), None);
        // With its own vendor's word in its name and publisher, that is its
        // brand, never the launcher's.
        game.publisher = Some("Tidewater Games Ltd".to_string());
        assert_eq!(
            derive_brand(&game, None, &install_roots()).as_deref(),
            Some("tidewater")
        );
    }

    #[test]
    fn another_installed_product_of_the_vendor_keeps_the_vendors_folders() {
        // Its own build folder next to ours: ours is still ours, the vendor's
        // folder and everything named after the vendor stay.
        let studio_loc = program_files().join(r"Brightway\Versions\version-0aa1bb2cc3dd4ee5");
        let studio = vendor_program(
            "Brightway Studio",
            "brightway-studio",
            &studio_loc,
            "BrightwayStudioInstaller.exe",
        );
        let t = player_target(vec![studio.clone()]);
        assert_eq!(t.brand.as_deref(), Some("brightway"));
        assert!(!t.brand_alone);
        // The build folder may hold the other product's files without its
        // entry saying so: it is not vouched for either.
        assert!(!t.install_vouched);
        assert_eq!(own_install_folder(&t), None);
        assert_eq!(t.vendor_dir, None);
        for name in ["Brightway", "Brightway Corporation"] {
            assert!(!is_brand_name(name, &t), "{name}");
        }
        let studio_exe = studio_loc.join("BrightwayStudio.exe");
        assert!(match_exe_item("Brightway Studio", Some(studio_exe.as_path()), &t).is_none());
        assert!(!path_names_product(&studio_exe, &t));

        // Both in one build folder: that folder is not ours alone.
        let shared = vendor_program(
            "Brightway Studio",
            "brightway-studio",
            &player_loc(),
            "BrightwayStudioInstaller.exe",
        );
        let t = player_target(vec![shared]);
        assert!(!t.install_vouched);
        assert_eq!(own_install_folder(&t), None);
        assert_eq!(t.vendor_dir, None);

        // A folder with a longer namesake stays when another program carries
        // the name.
        let word = name_only_target("brightway", None);
        assert!(name_in_use(&word, &[studio]));
    }

    #[test]
    fn a_shared_root_or_a_generic_name_vouches_for_nothing() {
        // Recorded as Program Files itself: protected, so not recorded at all.
        let mut at_root = player();
        at_root.install_location = Some(program_files().display().to_string());
        let t = build_target_with(&at_root, &Snapshot::with_programs(vec![at_root.clone()]));
        assert!(t.install_location.is_none());
        assert!(!t.install_vouched);
        assert_eq!(t.vendor_dir, None);

        // A general folder outside the install roots, named otherwise.
        let games = PathBuf::from(r"D:\Games");
        let mut general = player();
        general.install_location = Some(games.display().to_string());
        let snap = Snapshot::with_programs(vec![general.clone()]);
        let t = build_target_from(&general, Some(games), &[], &[], &snap);
        assert!(!t.install_vouched);
        assert_eq!(own_install_folder(&t), None);

        // A generic display name with a generic folder: no brand, no claim.
        let loc = program_files().join(r"Player\Versions").join(BUILD);
        let mut generic = vendor_program("Player", "player", &loc, "Setup.exe");
        generic.publisher = None;
        let snap = Snapshot::with_programs(vec![generic.clone()]);
        let t = build_target_from(&generic, Some(loc), &[], &[], &snap);
        assert_eq!(t.brand, None);
        assert!(!t.install_vouched);
        assert_eq!(t.vendor_dir, None);
        assert!(!is_brand_name("Player", &t));
    }

    /// A root like `Program Files`: a few hundred unrelated folders, the
    /// product's own folder, its vendor folder and a family folder.
    fn many_folders(name: &str, unrelated: usize) -> PathBuf {
        let root = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for i in 0..unrelated {
            fs::create_dir_all(root.join(format!("Unrelated Tool {i}")).join("bin")).unwrap();
        }
        fs::create_dir_all(root.join("Tindral Notes")).unwrap();
        fs::create_dir_all(root.join("Quillhaven").join("Tindral Notes")).unwrap();
        fs::create_dir_all(root.join("Quillhaven").join("Other Product")).unwrap();
        fs::create_dir_all(root.join("Tindral Notes Kit").join("TindralNotes2")).unwrap();
        root
    }

    #[test]
    fn a_root_of_many_folders_yields_only_the_products_own() {
        let root = many_folders("oxidize_many_folders_test", 300);
        let target = name_target("Tindral Notes", Some("Quillhaven"));
        let mut out = Vec::new();
        scan_dir_children(&root, &target, &[], true, &fs_roots(), &mut out);
        let mut found: Vec<String> = out
            .iter()
            .map(|l| {
                Path::new(&l.path)
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        found.sort();
        assert_eq!(found, [r"Quillhaven\Tindral Notes", "Tindral Notes"]);
        let _ = fs::remove_dir_all(&root);
    }

    /// Times the walk of one large root. Run with
    /// `cargo test --lib many_folders_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn many_folders_timing() {
        let root = many_folders("oxidize_many_folders_timing", 2000);
        let target = name_target("Tindral Notes", Some("Quillhaven"));
        let roots = fs_roots();
        let start = std::time::Instant::now();
        for _ in 0..20 {
            let mut out = Vec::new();
            scan_dir_children(&root, &target, &[], true, &roots, &mut out);
            assert_eq!(out.len(), 2);
        }
        eprintln!("20 walks of 2000 folders: {:?}", start.elapsed());
        let _ = fs::remove_dir_all(&root);
    }
}
