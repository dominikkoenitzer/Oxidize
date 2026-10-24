//! `oxidize clean`: temporary files, crash dumps, the Recycle Bin, browser
//! caches, the stores Windows cleans with its own tools, and folders of
//! programs that are gone.
//!
//! An analysis comes first and changes nothing. It counts every category
//! from the files themselves and says for each what would stay and why. The
//! cleaning then works from that analysis, for the categories the user
//! chose, and checks every file again right before it goes. Folders the user
//! protected are never entered. Folders of removed programs go into a backup
//! like any other leftover, so they can be put back.

pub mod browsers;
pub mod files;
pub mod jumplist;
pub mod protect;
pub mod recycle;
pub mod temp_root;
pub mod traces;
pub mod windows;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::ser::SerializeStruct;
use serde::Serialize;

use crate::model::{Confidence, Leftover, LeftoverKind, Program};
use crate::orphans::OrphanFolder;
use crate::safety::{self, ItemStatus, SafetyContext};
use crate::{scanner, util};

use files::{Candidate, Rule};
use protect::Protected;
use recycle::BinItem;
use temp_root::TempCheck;
use windows::Tools;

/// Temporary files have to be this old, in days, before they go.
pub const TEMP_DAYS: u64 = 7;
/// Recycle Bin items deleted at least this many days ago go, unless the
/// user picks another age.
pub const RECYCLE_DAYS: u64 = 30;
/// The name backups of a cleanup carry.
pub const BACKUP_LABEL: &str = "Clean up";

const DAY: u64 = 86_400;

/// `days` as an age. A number of days too large to count in seconds is
/// forever, never a wrapped-around few seconds that would take everything.
fn days_ago(days: u64) -> Duration {
    Duration::from_secs(days.saturating_mul(DAY))
}

/// What the cleaner can clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Temp,
    CrashDumps,
    RecycleBin,
    BrowserCache,
    ComponentStore,
    DeliveryOptimization,
    WindowsOld,
    Orphans,
}

impl Category {
    pub const ALL: [Category; 8] = [
        Category::Temp,
        Category::CrashDumps,
        Category::RecycleBin,
        Category::BrowserCache,
        Category::ComponentStore,
        Category::DeliveryOptimization,
        Category::WindowsOld,
        Category::Orphans,
    ];

    /// The id in JSON, also the command-line flag without its dashes.
    pub fn id(self) -> &'static str {
        match self {
            Category::Temp => "temp",
            Category::CrashDumps => "crash-dumps",
            Category::RecycleBin => "recycle-bin",
            Category::BrowserCache => "browser-cache",
            Category::ComponentStore => "component-store",
            Category::DeliveryOptimization => "delivery-optimization",
            Category::WindowsOld => "windows-old",
            Category::Orphans => "orphans",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Category::Temp => "Temporary files",
            Category::CrashDumps => "Crash dumps and error reports",
            Category::RecycleBin => "Recycle Bin",
            Category::BrowserCache => "Browser caches",
            Category::ComponentStore => "Windows component store",
            Category::DeliveryOptimization => "Delivery Optimization cache",
            Category::WindowsOld => "Previous Windows installation",
            Category::Orphans => "Folders of removed programs",
        }
    }

    /// One line on what goes.
    pub fn about(self) -> &'static str {
        match self {
            Category::Temp => "files in your temp folder and Windows' own not changed for 7 days",
            Category::CrashDumps => "memory dumps of programs that crashed, and queued error reports",
            Category::RecycleBin => "items you deleted, on every drive",
            Category::BrowserCache => {
                "cached pages, scripts and shaders; never cookies, history, sessions or logins"
            }
            Category::ComponentStore => {
                "superseded Windows components, removed by DISM the way Windows does it on a schedule"
            }
            Category::DeliveryOptimization => {
                "update files kept to share with other PCs, removed by Windows' own cmdlet"
            }
            Category::WindowsOld => {
                "the Windows from before the last upgrade; once it is gone there is no going back to it"
            }
            Category::Orphans => "folders no installed program claims, moved into a backup",
        }
    }

    /// Whether what it removes can be put back from a backup.
    pub fn backed_up(self) -> bool {
        self == Category::Orphans
    }
}

/// Why something stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeptReason {
    /// Changed within the last this many days.
    Recent(u64),
    /// Deleted within the last this many days.
    RecentlyDeleted(u64),
    InUse,
    Protected,
    AccessDenied,
    Unreadable,
    NeedsAdmin,
    /// The browser of that name is running.
    Running(String),
    /// A jump list with pinned items; only its other items go.
    Pinned,
    Failed(String),
}

impl KeptReason {
    /// A stable name for scripts.
    pub fn code(&self) -> &'static str {
        match self {
            KeptReason::Recent(_) => "recent",
            KeptReason::RecentlyDeleted(_) => "recently_deleted",
            KeptReason::InUse => "in_use",
            KeptReason::Protected => "protected",
            KeptReason::AccessDenied => "access_denied",
            KeptReason::Unreadable => "unreadable",
            KeptReason::NeedsAdmin => "needs_admin",
            KeptReason::Running(_) => "running",
            KeptReason::Pinned => "pinned",
            KeptReason::Failed(_) => "failed",
        }
    }

    pub fn text(&self) -> String {
        match self {
            KeptReason::Recent(days) => format!("changed in the last {days} days"),
            KeptReason::RecentlyDeleted(days) => format!("deleted in the last {days} days"),
            KeptReason::InUse => "in use by a running program".to_string(),
            KeptReason::Protected => "protected".to_string(),
            KeptReason::AccessDenied => "access denied".to_string(),
            KeptReason::Unreadable => "could not be read".to_string(),
            KeptReason::NeedsAdmin => "needs administrator rights".to_string(),
            KeptReason::Running(name) => format!("{name} is running"),
            KeptReason::Pinned => "with pinned items".to_string(),
            KeptReason::Failed(e) => e.clone(),
        }
    }
}

/// Things that stay, with their reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub reason: KeptReason,
    pub count: usize,
    pub bytes: u64,
}

impl Serialize for Kept {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Kept", 4)?;
        st.serialize_field("code", self.reason.code())?;
        st.serialize_field("reason", &self.reason.text())?;
        st.serialize_field("count", &self.count)?;
        st.serialize_field("bytes", &self.bytes)?;
        st.end()
    }
}

/// What stays and why, as one line: "stays: 812 changed in the last 7 days
/// (1.2 GB), 14 in use by a running program (2.1 MB)".
pub fn stays_text(kept: &[Kept]) -> Option<String> {
    if kept.is_empty() {
        return None;
    }
    let parts: Vec<String> = kept
        .iter()
        .map(|k| {
            let mut s = if k.reason == KeptReason::Unreadable && k.count > 0 {
                // Folders and files both: say how many, not which kind.
                let noun = if k.count == 1 { "item" } else { "items" };
                format!("{} {noun} {}", k.count, k.reason.text())
            } else if k.count > 0 {
                format!("{} {}", k.count, k.reason.text())
            } else {
                k.reason.text()
            };
            if k.bytes > 0 {
                s.push_str(&format!(" ({})", util::human_size(k.bytes)));
            }
            s
        })
        .collect();
    Some(format!("stays: {}", parts.join(", ")))
}

/// A folder no installed program claims.
#[derive(Debug, Clone, Serialize)]
pub struct OrphanItem {
    pub path: PathBuf,
    pub bytes: u64,
    pub modified: Option<String>,
    pub confidence: Confidence,
    pub reason: String,
    pub needs_admin: bool,
}

/// What the analysis found in one category.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: Category,
    /// Bytes the cleaning would free, counted from the files.
    pub bytes: u64,
    /// Files, items or folders that would go.
    pub count: usize,
    /// False when only the tool can say what goes; the space freed is then
    /// measured afterwards.
    pub size_known: bool,
    /// What stays, and why.
    pub kept: Vec<Kept>,
    /// Facts worth knowing before choosing.
    pub notes: Vec<String>,
    /// Nothing, or not all of it, can be done without administrator rights.
    pub needs_admin: bool,
    /// Part of the safe set that is chosen unless the user says otherwise.
    pub preselected: bool,
    /// Orphans only: each folder with how sure the match is.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<OrphanItem>,
    #[serde(skip)]
    work: Work,
    /// Browser caches only: the browsers whose caches it holds, asked again
    /// whether they run right before anything goes.
    #[serde(skip)]
    browsers: Vec<browsers::Browser>,
}

impl Finding {
    fn new(category: Category) -> Self {
        Finding {
            category,
            bytes: 0,
            count: 0,
            size_known: true,
            kept: Vec::new(),
            notes: Vec::new(),
            needs_admin: false,
            preselected: false,
            folders: Vec::new(),
            work: Work::None,
            browsers: Vec::new(),
        }
    }

    /// Whether choosing it would do anything.
    pub fn actionable(&self) -> bool {
        match &self.work {
            Work::None => false,
            Work::Tool => true,
            _ => self.count > 0,
        }
    }

    fn keep(&mut self, reason: KeptReason, count: usize, bytes: u64) {
        files::add(&mut self.kept, reason, count, bytes);
    }

    fn take_walk(&mut self, walk: files::Walk, rule: Rule) {
        self.bytes += walk.bytes();
        self.count += walk.files();
        for k in walk.kept {
            self.keep(k.reason, k.count, k.bytes);
        }
        match &mut self.work {
            Work::Files(groups) => groups.push((walk.candidates, rule)),
            other => *other = Work::Files(vec![(walk.candidates, rule)]),
        }
    }
}

/// What the cleaning works from, kept out of the JSON.
#[derive(Debug, Clone, Default)]
enum Work {
    #[default]
    None,
    Files(Vec<(Vec<Candidate>, Rule)>),
    Bin(Vec<BinItem>),
    /// A Windows tool does the work.
    Tool,
    /// The chosen folders of `Finding::folders`.
    Folders,
}

/// The whole analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    pub elevated: bool,
    pub recycle_bin_days: u64,
    /// The protected folders as the user wrote them.
    pub protected: Vec<String>,
}

impl Analysis {
    pub fn finding(&self, c: Category) -> Option<&Finding> {
        self.findings.iter().find(|f| f.category == c)
    }

    /// The safe set: what is chosen when the user picks nothing.
    pub fn default_choice(&self) -> Choice {
        self.choice(
            &self
                .findings
                .iter()
                .filter(|f| f.preselected)
                .map(|f| f.category)
                .collect::<Vec<_>>(),
            Confidence::High,
        )
    }

    /// The given categories, with the orphan folders at `level` or surer.
    pub fn choice(&self, categories: &[Category], level: Confidence) -> Choice {
        let folders = if categories.contains(&Category::Orphans) {
            self.finding(Category::Orphans)
                .map(|f| {
                    f.folders
                        .iter()
                        .filter(|o| o.confidence <= level)
                        .map(|o| o.path.clone())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Choice {
            categories: categories
                .iter()
                .copied()
                .filter(|c| self.finding(*c).is_some_and(Finding::actionable))
                .collect(),
            folders,
        }
    }

    /// The bytes a choice would free, where they are known.
    pub fn chosen_bytes(&self, choice: &Choice) -> u64 {
        choice
            .categories
            .iter()
            .filter_map(|c| self.finding(*c))
            .map(|f| match f.category {
                Category::Orphans => f
                    .folders
                    .iter()
                    .filter(|o| choice.folders.contains(&o.path))
                    .map(|o| o.bytes)
                    .sum(),
                _ => f.bytes,
            })
            .sum()
    }
}

/// What the user chose to clean.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Choice {
    pub categories: Vec<Category>,
    /// The orphan folders, when `Orphans` is among the categories.
    pub folders: Vec<PathBuf>,
}

/// Where everything is. `this_pc` reads it from the environment; tests point
/// it into their own folders.
#[derive(Debug, Clone, Default)]
pub struct Places {
    pub user_temp: Option<PathBuf>,
    pub windows_temp: Option<PathBuf>,
    /// What both temp folders are checked against before anything in them
    /// is looked at, on top of this PC's own check.
    pub temp_check: TempCheck,
    /// Dump and report folders of this user.
    pub user_dumps: Vec<Spot>,
    /// Machine-wide dump and report folders, which need administrator
    /// rights.
    pub machine_dumps: Vec<Spot>,
    /// This user's `$Recycle.Bin\<SID>` folder on each drive.
    pub recycle_bins: Vec<PathBuf>,
    /// `%LOCALAPPDATA%` and `%APPDATA%`, where browsers keep their data.
    pub local_appdata: Option<PathBuf>,
    pub roaming_appdata: Option<PathBuf>,
    pub windows_old: Option<PathBuf>,
    /// The drive Windows is on, for measuring what a Windows tool freed.
    pub system_drive: Option<PathBuf>,
}

/// A folder or file of dumps, and which of its files count.
#[derive(Debug, Clone)]
pub struct Spot {
    pub path: PathBuf,
    pub extensions: Option<&'static [&'static str]>,
}

const DUMPS: &[&str] = &["dmp", "mdmp", "hdmp"];

impl Places {
    pub fn this_pc() -> Places {
        let env = scanner::env_dir;
        let windir = crate::system::windows_dir();
        let local = env("LOCALAPPDATA");
        let program_data = env("ProgramData");
        let wer = |base: &Path| -> Vec<Spot> {
            ["ReportArchive", "ReportQueue"]
                .iter()
                .map(|n| Spot {
                    path: base.join(r"Microsoft\Windows\WER").join(n),
                    extensions: None,
                })
                .collect()
        };
        let mut user_dumps = Vec::new();
        if let Some(local) = &local {
            user_dumps.push(Spot {
                path: local.join("CrashDumps"),
                extensions: Some(DUMPS),
            });
            user_dumps.extend(wer(local));
        }
        let mut machine_dumps = Vec::new();
        if let Some(pd) = &program_data {
            machine_dumps.extend(wer(pd));
        }
        for (folder, ext) in [
            ("Minidump", Some(DUMPS)),
            ("LiveKernelReports", Some(DUMPS)),
        ] {
            machine_dumps.push(Spot {
                path: windir.join(folder),
                extensions: ext,
            });
        }
        machine_dumps.push(Spot {
            path: windir.join("MEMORY.DMP"),
            extensions: None,
        });
        Places {
            user_temp: Some(std::env::temp_dir()),
            windows_temp: Some(windir.join("Temp")),
            temp_check: TempCheck::this_pc().clone(),
            user_dumps,
            machine_dumps,
            recycle_bins: recycle::current_sid()
                .map(|sid| recycle::bins(&sid))
                .unwrap_or_default(),
            local_appdata: local,
            roaming_appdata: env("APPDATA"),
            windows_old: windows::windows_old(),
            system_drive: windir.ancestors().last().map(Path::to_path_buf),
        }
    }
}

/// What an analysis is told besides the places.
pub struct Options<'a> {
    pub protected: &'a Protected,
    pub elevated: bool,
    pub now: SystemTime,
    /// Executables of the running processes.
    pub running: &'a [PathBuf],
    pub recycle_bin_days: u64,
    pub tools: &'a dyn Tools,
    /// The unclaimed folders, already scored.
    pub orphans: &'a (dyn Fn() -> Vec<OrphanItem> + Sync),
}

/// Look at every category. Changes nothing.
pub fn analyse(places: &Places, opts: &Options) -> Analysis {
    let mut findings = std::thread::scope(|s| {
        let jobs: Vec<std::thread::ScopedJoinHandle<'_, Finding>> = vec![
            s.spawn(|| temp(places, opts)),
            s.spawn(|| crash_dumps(places, opts)),
            s.spawn(|| recycle_bin(places, opts)),
            s.spawn(|| browser_cache(places, opts)),
            s.spawn(|| component_store(opts)),
            s.spawn(|| delivery_optimization(opts)),
            s.spawn(|| windows_old(places, opts)),
            s.spawn(|| orphans(opts)),
        ];
        jobs.into_iter()
            .zip(Category::ALL)
            .map(|(j, c)| {
                j.join().unwrap_or_else(|_| {
                    let mut f = Finding::new(c);
                    f.notes
                        .push("the analysis of this category stopped unexpectedly".into());
                    f
                })
            })
            .collect::<Vec<_>>()
    });
    findings.sort_by_key(|f| f.category);
    Analysis {
        findings,
        elevated: opts.elevated,
        recycle_bin_days: opts.recycle_bin_days,
        protected: opts.protected.entries().to_vec(),
    }
}

fn temp(places: &Places, opts: &Options) -> Finding {
    let mut f = Finding::new(Category::Temp);
    f.preselected = true;
    let rule = Rule {
        min_age: Some(Duration::from_secs(TEMP_DAYS * DAY)),
        extensions: None,
        probe_in_use: true,
    };
    // Without TMP and TEMP the temp folder Windows names is the profile,
    // and a variable can name any folder; only a real temp folder is
    // walked.
    let fit = |root: &PathBuf, f: &mut Finding, hint: &str| match temp_root::refusal(
        root,
        &places.temp_check,
    ) {
        None => true,
        Some(why) => {
            f.notes.push(format!(
                "{why}, not a temp folder; nothing in it was looked at{hint}"
            ));
            false
        }
    };
    let user_temp = places
        .user_temp
        .as_ref()
        .filter(|root| fit(root, &mut f, " (TMP and TEMP name the temp folder)"));
    if let Some(root) = user_temp {
        let walk = files::walk(root, &rule, opts.protected, opts.now);
        f.take_walk(walk, rule);
    }
    if let Some(root) = &places.windows_temp {
        // The user's own temp folder can sit inside Windows' one on some
        // setups; it was counted already.
        let same = user_temp.is_some_and(|u| protect::key_of(u) == protect::key_of(root));
        if !same && root.is_dir() && fit(root, &mut f, "") {
            admin_walk(&mut f, root, rule, opts);
        }
    }
    f
}

/// Walk a machine-wide folder. Without administrator rights it is only
/// counted, as what would need them.
fn admin_walk(f: &mut Finding, root: &Path, rule: Rule, opts: &Options) {
    if opts.elevated {
        let walk = files::walk(root, &rule, opts.protected, opts.now);
        f.take_walk(walk, rule);
        return;
    }
    let looked = Rule {
        probe_in_use: false,
        ..rule
    };
    let walk = files::walk(root, &looked, opts.protected, opts.now);
    let (count, bytes) = (walk.files(), walk.bytes());
    for k in walk.kept {
        f.keep(k.reason, k.count, k.bytes);
    }
    if count > 0 {
        f.keep(KeptReason::NeedsAdmin, count, bytes);
        f.needs_admin = true;
    }
}

fn crash_dumps(places: &Places, opts: &Options) -> Finding {
    let mut f = Finding::new(Category::CrashDumps);
    f.preselected = true;
    for spot in &places.user_dumps {
        let rule = Rule {
            min_age: None,
            extensions: spot.extensions,
            probe_in_use: true,
        };
        let walk = files::walk(&spot.path, &rule, opts.protected, opts.now);
        f.take_walk(walk, rule);
    }
    for spot in &places.machine_dumps {
        let rule = Rule {
            min_age: None,
            extensions: spot.extensions,
            probe_in_use: true,
        };
        if spot.path.exists() {
            admin_walk(&mut f, &spot.path, rule, opts);
        }
    }
    f
}

fn recycle_bin(places: &Places, opts: &Options) -> Finding {
    let mut f = Finding::new(Category::RecycleBin);
    let days = opts.recycle_bin_days;
    let mut chosen = Vec::new();
    for bin in &places.recycle_bins {
        let items = recycle::items(bin);
        chosen.extend(recycle::select(
            items,
            days_ago(days),
            opts.protected,
            opts.now,
            &mut f.kept,
        ));
    }
    f.bytes = chosen.iter().map(|i| i.bytes).sum();
    f.count = chosen.len();
    f.notes
        .push(format!("only items deleted at least {days} days ago"));
    f.work = Work::Bin(chosen);
    f
}

fn browser_cache(places: &Places, opts: &Options) -> Finding {
    let mut f = Finding::new(Category::BrowserCache);
    f.preselected = true;
    let Some(local) = &places.local_appdata else {
        return f;
    };
    let rule = Rule {
        min_age: None,
        extensions: None,
        probe_in_use: true,
    };
    let mut names = Vec::new();
    for b in browsers::installed(local, places.roaming_appdata.as_deref()) {
        let dirs = browsers::cache_dirs(&b);
        if dirs.is_empty() {
            continue;
        }
        if browsers::is_running(&b, opts.running) {
            let mut walk = files::Walk::default();
            for d in &dirs {
                let w = files::walk(
                    d,
                    &Rule {
                        probe_in_use: false,
                        ..rule
                    },
                    opts.protected,
                    opts.now,
                );
                walk.candidates.extend(w.candidates);
            }
            f.keep(
                KeptReason::Running(b.name.to_string()),
                walk.files(),
                walk.bytes(),
            );
            continue;
        }
        names.push(b.name);
        for d in &dirs {
            f.take_walk(files::walk(d, &rule, opts.protected, opts.now), rule);
        }
        f.browsers.push(b);
    }
    if !names.is_empty() {
        f.notes.push(names.join(", "));
    }
    f
}

fn component_store(opts: &Options) -> Finding {
    let mut f = Finding::new(Category::ComponentStore);
    f.size_known = false;
    if !opts.elevated {
        f.needs_admin = true;
        f.keep(KeptReason::NeedsAdmin, 0, 0);
        return f;
    }
    match opts.tools.component_store() {
        Ok(r) => {
            if let Some(n) = r.reclaimable_packages {
                f.notes.push(format!("{n} reclaimable packages"));
                f.count = n as usize;
            }
            if let Some(size) = &r.backups_and_disabled_features {
                f.notes.push(format!(
                    "Windows reports {size} in backups and disabled features"
                ));
            }
            if let Some(yes) = r.cleanup_recommended {
                f.notes.push(if yes {
                    "Windows recommends a cleanup".to_string()
                } else {
                    "Windows does not recommend a cleanup now".to_string()
                });
            }
            f.notes
                .push("the space freed is measured on the drive afterwards".into());
            f.work = Work::Tool;
        }
        Err(e) => f.keep(KeptReason::Failed(format!("{e:#}")), 0, 0),
    }
    f
}

fn delivery_optimization(opts: &Options) -> Finding {
    let mut f = Finding::new(Category::DeliveryOptimization);
    match opts.tools.delivery_cache() {
        Ok((count, bytes)) => {
            if opts.elevated {
                f.count = count;
                f.bytes = bytes;
                if count > 0 {
                    f.work = Work::Tool;
                }
            } else if count > 0 {
                f.needs_admin = true;
                f.keep(KeptReason::NeedsAdmin, count, bytes);
            }
        }
        Err(e) => f.keep(KeptReason::Failed(format!("{e:#}")), 0, 0),
    }
    f
}

fn windows_old(places: &Places, opts: &Options) -> Finding {
    let mut f = Finding::new(Category::WindowsOld);
    let Some(dir) = places.windows_old.as_ref().filter(|d| d.is_dir()) else {
        return f;
    };
    if opts.protected.touches(dir) {
        f.keep(KeptReason::Protected, 1, 0);
        return f;
    }
    let bytes = scanner::dir_size(dir);
    f.notes.push(
        "removing it ends the way back to the Windows you upgraded from; choose it only on purpose"
            .into(),
    );
    if opts.elevated {
        f.bytes = bytes;
        f.count = 1;
        f.work = Work::Tool;
    } else {
        f.needs_admin = true;
        f.keep(KeptReason::NeedsAdmin, 1, bytes);
    }
    f
}

fn orphans(opts: &Options) -> Finding {
    let mut f = Finding::new(Category::Orphans);
    for item in (opts.orphans)() {
        if opts.protected.touches(&item.path) {
            f.keep(KeptReason::Protected, 1, item.bytes);
            continue;
        }
        f.folders.push(item);
    }
    f.count = f.folders.len();
    f.bytes = f.folders.iter().map(|o| o.bytes).sum();
    let at = |c: Confidence| f.folders.iter().filter(|o| o.confidence == c).count();
    let (high, medium, low) = (
        at(Confidence::High),
        at(Confidence::Medium),
        at(Confidence::Low),
    );
    if f.count > 0 {
        f.notes.push(format!(
            "{high} high, {medium} medium, {low} low confidence"
        ));
    }
    f.preselected = high > 0;
    f.needs_admin = !opts.elevated && f.folders.iter().any(|o| o.needs_admin);
    f.work = Work::Folders;
    f
}

/// Score unclaimed folders against programs that were removed. A folder
/// named the way the scanner's rules call a program's own is High; a
/// plausible match is Medium; every other one is Low, as `oxidize orphans`
/// lists it.
pub fn score_orphans(
    folders: &[OrphanFolder],
    removed: &[(String, Option<String>)],
    snap: &scanner::Snapshot,
) -> Vec<OrphanItem> {
    let targets: Vec<_> = removed
        .iter()
        .map(|(name, publisher)| scanner::name_only_target_with(name, publisher.as_deref(), snap))
        .collect();
    folders
        .iter()
        .map(|f| {
            let name = f
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let best = targets
                .iter()
                .filter_map(|t| {
                    scanner::folder_score(&name, t)
                        .map(|(c, why)| (c, format!("{why}, a program that was removed")))
                })
                .min_by_key(|(c, _)| *c);
            let (confidence, reason) = best.unwrap_or((
                Confidence::Low,
                "no installed program claims it".to_string(),
            ));
            OrphanItem {
                needs_admin: safety::needs_elevation(&[folder_leftover(&f.path, f.size_bytes)]),
                path: f.path.clone(),
                bytes: f.size_bytes,
                modified: f.modified.clone(),
                confidence,
                reason,
            }
        })
        .collect()
}

fn folder_leftover(path: &Path, bytes: u64) -> Leftover {
    Leftover::fs(
        LeftoverKind::Directory,
        path.to_path_buf(),
        Confidence::Low,
        "folder of a removed program",
        Some(bytes),
        bytes == 0,
    )
}

/// Programs known to have been removed: those Oxidize removed, from its
/// backups, and those Windows Installer removed, from its events. Names
/// still installed are left out.
pub fn removed_programs(installed: &[Program]) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    if let Ok(backups) = crate::backup::list_backups() {
        for b in backups {
            if !b.program.is_empty() && b.program != BACKUP_LABEL {
                out.push((b.program, None));
            }
        }
    }
    out.extend(installer_removals());
    let installed: Vec<Vec<String>> = installed
        .iter()
        .map(|p| util::significant_tokens(&p.display_name))
        .collect();
    let mut seen = Vec::new();
    out.retain(|(name, _)| {
        let tokens = util::significant_tokens(name);
        let keep = !tokens.is_empty() && !installed.contains(&tokens) && !seen.contains(&tokens);
        seen.push(tokens);
        keep
    });
    out
}

/// The wevtutil query for the last 300 removals Windows Installer logged.
const INSTALLER_EVENTS: &[&str] = &[
    "qe",
    "Application",
    "/q:*[System[Provider[@Name='MsiInstaller'] and (EventID=1034)]]",
    "/f:xml",
    "/c:300",
    "/rd:true",
    "/uni:true",
];

/// Products Windows Installer reports as removed, newest first.
fn installer_removals() -> Vec<(String, Option<String>)> {
    let mut cmd = std::process::Command::new(crate::system::system32("wevtutil.exe"));
    cmd.args(INSTALLER_EVENTS);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let Ok(out) = cmd.stdin(std::process::Stdio::null()).output() else {
        return Vec::new();
    };
    parse_installer_removals(&installer_events_text(&out.stdout))
}

/// What the `INSTALLER_EVENTS` query printed to a pipe.
fn installer_events_text(bytes: &[u8]) -> String {
    // UTF-16 with a byte order mark; the ANSI code page is what wevtutil writes without /uni.
    crate::system::code_page_text(bytes, ::windows::Win32::Globalization::CP_ACP)
}

/// Product name and manufacturer from each 1034 event that reports
/// success.
fn parse_installer_removals(xml: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for event in xml.split("<EventData>").skip(1) {
        let event = event.split("</EventData>").next().unwrap_or("");
        let data: Vec<String> = event
            .split("<Data>")
            .skip(1)
            .map(|d| unescape(d.split("</Data>").next().unwrap_or("")))
            .collect();
        let (Some(name), Some(status)) = (data.first(), data.get(3)) else {
            continue;
        };
        if status != "0" || name.is_empty() {
            continue;
        }
        let maker = data
            .get(4)
            .filter(|m| !m.is_empty() && *m != "(NULL)")
            .cloned();
        out.push((name.clone(), maker));
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// What cleaning one category did.
#[derive(Debug, Clone, Serialize)]
pub struct Cleaned {
    pub category: Category,
    /// Bytes freed. For folders moved into a backup, the bytes moved.
    pub freed: u64,
    /// Files, items or folders that went.
    pub removed: usize,
    pub kept: Vec<Kept>,
    /// The backup the removed folders went into.
    pub backup: Option<String>,
    pub notes: Vec<String>,
}

impl Cleaned {
    fn new(category: Category) -> Self {
        Cleaned {
            category,
            freed: 0,
            removed: 0,
            kept: Vec::new(),
            backup: None,
            notes: Vec::new(),
        }
    }

    fn keep(&mut self, reason: KeptReason, count: usize, bytes: u64) {
        files::add(&mut self.kept, reason, count, bytes);
    }

    /// Something chosen could not be done for another reason than the rules.
    pub fn failed(&self) -> bool {
        self.kept
            .iter()
            .any(|k| matches!(k.reason, KeptReason::Failed(_)))
    }
}

/// How a cleaning runs.
pub struct CleanOptions<'a> {
    pub protected: &'a Protected,
    pub now: SystemTime,
    pub elevated: bool,
    /// False with `--no-backup`: removed folders are deleted for good.
    pub make_backups: bool,
    pub tools: &'a dyn Tools,
    pub system_drive: Option<PathBuf>,
}

/// Clean what was chosen, from the analysis. Every file is checked again
/// right before it goes.
pub fn clean(analysis: &Analysis, choice: &Choice, opts: &CleanOptions) -> Vec<Cleaned> {
    let mut out = Vec::new();
    for f in &analysis.findings {
        if !choice.categories.contains(&f.category) {
            continue;
        }
        let mut c = Cleaned::new(f.category);
        match &f.work {
            Work::None => {}
            Work::Files(groups) => {
                // A browser started since the analysis has its cache open;
                // what is in it stays, the way it would have at the analysis.
                let started: Vec<&browsers::Browser> = if f.browsers.is_empty() {
                    Vec::new()
                } else {
                    let running = opts.tools.running_exes();
                    f.browsers
                        .iter()
                        .filter(|b| browsers::is_running(b, &running))
                        .collect()
                };
                for (candidates, rule) in groups {
                    let mut left = Vec::new();
                    for cand in candidates {
                        match started
                            .iter()
                            .find(|b| crate::system::path_under(&cand.path, &b.data))
                        {
                            // Its folders stay with it, and are no files.
                            Some(_) if cand.dir => {}
                            Some(b) => {
                                c.keep(KeptReason::Running(b.name.to_string()), 1, cand.bytes)
                            }
                            None => left.push(cand.clone()),
                        }
                    }
                    let done = files::delete(&left, rule, opts.protected, opts.now);
                    c.freed += done.freed;
                    c.removed += done.files;
                    for k in done.kept {
                        c.keep(k.reason, k.count, k.bytes);
                    }
                }
            }
            Work::Bin(items) => {
                let (freed, gone) = recycle::delete(items, opts.protected, &mut c.kept);
                c.freed = freed;
                c.removed = gone;
            }
            Work::Tool => run_tool(f, &mut c, opts),
            Work::Folders => clean_folders(f, choice, &mut c, opts),
        }
        // What the analysis left out stays too, and is reported with what
        // the cleaning itself had to leave.
        for k in &f.kept {
            c.keep(k.reason.clone(), k.count, k.bytes);
        }
        out.push(c);
    }
    out
}

fn run_tool(f: &Finding, c: &mut Cleaned, opts: &CleanOptions) {
    if !opts.elevated {
        c.keep(KeptReason::NeedsAdmin, f.count, f.bytes);
        return;
    }
    let free = || {
        opts.system_drive
            .as_deref()
            .and_then(|d| opts.tools.free_bytes(d))
    };
    let before = free();
    let result = match f.category {
        Category::ComponentStore => opts.tools.component_cleanup(),
        Category::DeliveryOptimization => opts.tools.delete_delivery_cache(),
        Category::WindowsOld => opts.tools.remove_windows_old(),
        _ => Ok(()),
    };
    if let Err(e) = result {
        c.keep(KeptReason::Failed(format!("{e:#}")), f.count, f.bytes);
        return;
    }
    match f.category {
        Category::DeliveryOptimization => {
            let left = opts.tools.delivery_cache().map(|(_, b)| b).unwrap_or(0);
            c.freed = f.bytes.saturating_sub(left);
            c.removed = f.count;
        }
        _ => {
            if let (Some(b), Some(a)) = (before, free()) {
                c.freed = a.saturating_sub(b);
            }
            c.removed = f.count;
            c.notes
                .push("measured as the change in free space on the drive".to_string());
        }
    }
}

fn clean_folders(f: &Finding, choice: &Choice, c: &mut Cleaned, opts: &CleanOptions) {
    let mut items = Vec::new();
    let mut sizes = Vec::new();
    for o in f
        .folders
        .iter()
        .filter(|o| choice.folders.contains(&o.path))
    {
        if opts.protected.touches(&o.path) {
            c.keep(KeptReason::Protected, 1, o.bytes);
            continue;
        }
        items.push(Leftover::fs(
            LeftoverKind::Directory,
            o.path.clone(),
            o.confidence,
            o.reason.clone(),
            Some(o.bytes),
            o.bytes == 0,
        ));
        sizes.push(o.bytes);
    }
    if items.is_empty() {
        return;
    }
    let ctx = SafetyContext {
        dry_run: false,
        make_backups: opts.make_backups,
    };
    match safety::remove_leftovers(&items, BACKUP_LABEL, &ctx) {
        Ok(outcome) => {
            for (item, bytes) in outcome.items.iter().zip(&sizes) {
                match &item.status {
                    ItemStatus::Removed => {
                        c.freed += bytes;
                        c.removed += 1;
                    }
                    ItemStatus::Failed(e) => c.keep(KeptReason::Failed(e.clone()), 1, *bytes),
                    ItemStatus::AlreadyGone | ItemStatus::WouldRemove => {}
                }
            }
            c.backup = outcome.backup_name;
            if c.backup.is_some() && c.removed > 0 {
                c.notes.push(
                    "moved into the backup; the space comes back once the backup is deleted"
                        .to_string(),
                );
            }
        }
        Err(e) => c.keep(
            KeptReason::Failed(format!("{e:#}")),
            items.len(),
            sizes.iter().sum(),
        ),
    }
}

/// The analysis of this PC, read the way the command line and the window
/// both do it.
pub fn analyse_this_pc(protected: &Protected, recycle_bin_days: u64) -> (Places, Analysis) {
    let places = Places::this_pc();
    let running = crate::system::running_exes();
    let tools = windows::WindowsTools;
    let source = || {
        let programs = crate::registry::enumerate_installed_programs(true);
        let folders = crate::orphans::unclaimed_folders(&programs);
        let removed = removed_programs(&programs);
        let snap = scanner::Snapshot::with_programs(programs);
        score_orphans(&folders, &removed, &snap)
    };
    let opts = Options {
        protected,
        elevated: safety::is_elevated(),
        now: SystemTime::now(),
        running: &running,
        recycle_bin_days,
        tools: &tools,
        orphans: &source,
    };
    let analysis = analyse(&places, &opts);
    (places, analysis)
}

/// Clean on this PC.
pub fn clean_this_pc(
    places: &Places,
    analysis: &Analysis,
    choice: &Choice,
    protected: &Protected,
    make_backups: bool,
) -> Vec<Cleaned> {
    let tools = windows::WindowsTools;
    clean(
        analysis,
        choice,
        &CleanOptions {
            protected,
            now: SystemTime::now(),
            elevated: safety::is_elevated(),
            make_backups,
            tools: &tools,
            system_drive: places.system_drive.clone(),
        },
    )
}

#[cfg(test)]
mod tests;
