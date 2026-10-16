//! `oxidize clean --traces`: a clean slate. The lists Windows keeps of what
//! was opened, run, typed and searched for go, with the jump lists, the
//! thumbnail cache and the clipboard history. The files those lists point
//! to stay where they are.
//!
//! Temporary folders, browser data, mail and the data of programs are never
//! part of it. Pinned items stay. Everything is read first and shown; the
//! clearing then reads it all again and reports what went by comparing the
//! two.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;
use winreg::enums::*;
use winreg::RegKey;

use super::files::{self, Probe};
use super::jumplist;
use super::protect::Protected;
use super::{Kept, KeptReason};
use crate::scanner;

/// Explorer's key under `HKEY_CURRENT_USER`, where its lists are.
pub const EXPLORER_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer";
/// Where a stand-in profile keeps its registry lists, under
/// `HKEY_CURRENT_USER`.
pub const STAND_IN_KEY: &str = r"Software\OxidizeTest";
/// Points the traces at a stand-in profile in that folder instead of the
/// signed-in user's own. For tests and pictures; Windows' own calls never
/// run against a stand-in.
pub const PROFILE_ENV: &str = "OXIDIZE_TRACE_PROFILE";

/// One kind of usage trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trace {
    RecentItems,
    JumpLists,
    RecentDocs,
    DialogHistory,
    RunHistory,
    TypedPaths,
    SearchHistory,
    LaunchCounts,
    Thumbnails,
    Clipboard,
}

impl Trace {
    pub const ALL: [Trace; 10] = [
        Trace::RecentItems,
        Trace::JumpLists,
        Trace::RecentDocs,
        Trace::DialogHistory,
        Trace::RunHistory,
        Trace::TypedPaths,
        Trace::SearchHistory,
        Trace::LaunchCounts,
        Trace::Thumbnails,
        Trace::Clipboard,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Trace::RecentItems => "Recent items",
            Trace::JumpLists => "Jump lists",
            Trace::RecentDocs => "Recent documents",
            Trace::DialogHistory => "Open and Save history",
            Trace::RunHistory => "Run history",
            Trace::TypedPaths => "Typed paths",
            Trace::SearchHistory => "File Explorer searches",
            Trace::LaunchCounts => "Program launch counts",
            Trace::Thumbnails => "Thumbnail cache",
            Trace::Clipboard => "Clipboard history",
        }
    }

    /// One line on what goes.
    pub fn about(self) -> &'static str {
        match self {
            Trace::RecentItems => {
                "shortcuts to the files you opened, as Recent and Start list them"
            }
            Trace::JumpLists => "the recent files each app lists on the taskbar; pinned items stay",
            Trace::RecentDocs => "the files you opened, by type, as Windows records them",
            Trace::DialogHistory => "the files and folders the Open and Save dialogs remember",
            Trace::RunHistory => "commands typed into the Run box",
            Trace::TypedPaths => "addresses typed into the File Explorer address bar",
            Trace::SearchHistory => "what you searched for in File Explorer",
            Trace::LaunchCounts => "which programs you started, how often and when",
            Trace::Thumbnails => {
                "small previews of your pictures and videos; Windows makes new ones"
            }
            Trace::Clipboard => "what you copied, as Windows+V lists it",
        }
    }

    /// The count with its unit: "12 shortcuts".
    pub fn amount(self, n: usize) -> String {
        let (one, many) = match self {
            Trace::RecentItems => ("shortcut", "shortcuts"),
            Trace::JumpLists => ("list", "lists"),
            Trace::RecentDocs | Trace::DialogHistory => ("entry", "entries"),
            Trace::RunHistory => ("command", "commands"),
            Trace::TypedPaths => ("address", "addresses"),
            Trace::SearchHistory => ("search", "searches"),
            Trace::LaunchCounts => ("program", "programs"),
            Trace::Thumbnails => ("file", "files"),
            Trace::Clipboard => ("item", "items"),
        };
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    }

    /// The registry lists of this trace under Explorer's key. Launch counts
    /// sit one level deeper, under each of UserAssist's keys.
    fn keys(self) -> &'static [&'static str] {
        match self {
            Trace::RecentDocs => &["RecentDocs"],
            Trace::DialogHistory => &[
                r"ComDlg32\OpenSavePidlMRU",
                r"ComDlg32\LastVisitedPidlMRU",
                r"ComDlg32\LastVisitedPidlMRULegacy",
                r"ComDlg32\OpenSaveMRU",
                r"ComDlg32\LastVisitedMRU",
                r"ComDlg32\CIDSizeMRU",
            ],
            Trace::RunHistory => &["RunMRU"],
            Trace::TypedPaths => &["TypedPaths"],
            Trace::SearchHistory => &["WordWheelQuery"],
            _ => &[],
        }
    }
}

/// Where the traces are. `this_pc` reads it from the environment; tests and
/// pictures use a stand-in profile.
#[derive(Debug, Clone)]
pub struct TracePlaces {
    /// `%APPDATA%\Microsoft\Windows\Recent`, with the jump lists below it.
    pub recent: Option<PathBuf>,
    /// `%LOCALAPPDATA%\Microsoft\Windows\Explorer`, the thumbnail cache.
    pub thumbnails: Option<PathBuf>,
    /// Explorer's key under `HKEY_CURRENT_USER`.
    pub explorer_key: String,
    /// The signed-in user's own profile. Only then are Windows' own calls
    /// made, since they always act on that profile.
    pub own_profile: bool,
}

impl TracePlaces {
    pub fn this_pc() -> TracePlaces {
        if let Some(root) = scanner::env_dir(PROFILE_ENV) {
            return TracePlaces::stand_in(&root);
        }
        TracePlaces {
            recent: scanner::env_dir("APPDATA").map(|d| d.join(r"Microsoft\Windows\Recent")),
            thumbnails: scanner::env_dir("LOCALAPPDATA")
                .map(|d| d.join(r"Microsoft\Windows\Explorer")),
            explorer_key: EXPLORER_KEY.to_string(),
            own_profile: true,
        }
    }

    /// A profile laid out in `root`, its registry lists under
    /// `HKEY_CURRENT_USER\Software\OxidizeTest\<folder name>`.
    pub fn stand_in(root: &Path) -> TracePlaces {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "profile".to_string());
        TracePlaces {
            recent: Some(root.join(r"Roaming\Microsoft\Windows\Recent")),
            thumbnails: Some(root.join(r"Local\Microsoft\Windows\Explorer")),
            explorer_key: format!(r"{STAND_IN_KEY}\{name}\Explorer"),
            own_profile: false,
        }
    }

    fn automatic(&self) -> Option<PathBuf> {
        self.recent
            .as_ref()
            .map(|r| r.join("AutomaticDestinations"))
    }

    fn custom(&self) -> Option<PathBuf> {
        self.recent.as_ref().map(|r| r.join("CustomDestinations"))
    }
}

/// The clipboard history as Windows reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardState {
    Items(usize),
    /// Turned off in Settings, so there is none.
    Off,
    /// Windows would not say.
    Unreadable,
    /// A stand-in profile has none.
    Absent,
}

/// What Windows does itself, behind a trait so tests never touch the
/// signed-in user's profile.
pub trait Shell: Sync {
    /// Clear the recent items and the jump lists the way Windows does it,
    /// pinned items kept. Explorer hears of it at once.
    fn clear_recent(&self) -> Result<()>;
    fn clipboard(&self) -> ClipboardState;
    fn clear_clipboard(&self) -> Result<()>;
    /// Empty the thumbnail cache in `dir`.
    fn purge_thumbnails(&self, dir: &Path) -> Result<()>;
    /// Tell Explorer these folders changed, so open windows show it.
    fn refresh(&self, dirs: &[PathBuf]);
}

/// The shell for a stand-in profile: no Windows call runs, the thumbnail
/// cache files are deleted directly.
pub struct StandInShell;

impl Shell for StandInShell {
    fn clear_recent(&self) -> Result<()> {
        Ok(())
    }
    fn clipboard(&self) -> ClipboardState {
        ClipboardState::Absent
    }
    fn clear_clipboard(&self) -> Result<()> {
        Ok(())
    }
    fn purge_thumbnails(&self, dir: &Path) -> Result<()> {
        for (path, _) in thumbnail_files(dir) {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
    fn refresh(&self, _dirs: &[PathBuf]) {}
}

/// The shell that fits these places.
pub fn shell_for(places: &TracePlaces) -> Box<dyn Shell> {
    if places.own_profile {
        Box::new(WindowsShell)
    } else {
        Box::new(StandInShell)
    }
}

/// What one trace holds, or what clearing it did.
#[derive(Debug, Clone, Serialize)]
pub struct TraceFinding {
    pub trace: Trace,
    /// What would go, or what went.
    pub count: usize,
    pub bytes: u64,
    /// False when only the size says anything (the thumbnail cache) or
    /// Windows would not say (the clipboard history).
    pub count_known: bool,
    /// What stays, and why.
    pub kept: Vec<Kept>,
    pub notes: Vec<String>,
}

impl TraceFinding {
    pub fn new(trace: Trace) -> Self {
        TraceFinding {
            trace,
            count: 0,
            bytes: 0,
            count_known: true,
            kept: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn keep(&mut self, reason: KeptReason, count: usize, bytes: u64) {
        files::add(&mut self.kept, reason, count, bytes);
    }

    /// Whether clearing it would do anything.
    pub fn actionable(&self) -> bool {
        self.count > 0 || self.bytes > 0 || (!self.count_known && self.trace == Trace::Clipboard)
    }

    /// Something could not be cleared.
    pub fn failed(&self) -> bool {
        self.kept.iter().any(|k| {
            matches!(
                k.reason,
                KeptReason::Failed(_) | KeptReason::InUse | KeptReason::AccessDenied
            )
        })
    }

    /// The count with its unit, or what stands in for it.
    pub fn detail(&self) -> String {
        if !self.count_known {
            return String::new();
        }
        self.trace.amount(self.count)
    }
}

/// Every trace, in order. Changes nothing.
pub fn analyse(
    places: &TracePlaces,
    protected: &Protected,
    shell: &dyn Shell,
) -> Vec<TraceFinding> {
    Trace::ALL
        .iter()
        .map(|&t| look(t, places, protected, shell))
        .collect()
}

/// The items and bytes that would go, or went. Only counts that say
/// something are added up.
pub fn total(findings: &[TraceFinding]) -> (usize, u64) {
    (
        findings
            .iter()
            .filter(|f| f.count_known)
            .map(|f| f.count)
            .sum(),
        findings.iter().map(|f| f.bytes).sum(),
    )
}

fn look(
    trace: Trace,
    places: &TracePlaces,
    protected: &Protected,
    shell: &dyn Shell,
) -> TraceFinding {
    match trace {
        Trace::RecentItems => recent_items(places, protected),
        Trace::JumpLists => jump_lists(places, protected).0,
        Trace::Thumbnails => thumbnails(places, protected),
        Trace::Clipboard => clipboard(shell),
        Trace::LaunchCounts => registry(trace, &launch_count_keys(places), places),
        _ => {
            let keys: Vec<String> = trace.keys().iter().map(|k| k.to_string()).collect();
            registry(trace, &keys, places)
        }
    }
}

/// The files directly in `dir` whose lower-case name passes `keep`, with
/// their sizes. Links and folders are never among them.
fn files_in(dir: &Path, keep: impl Fn(&str) -> bool) -> Vec<(PathBuf, u64)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, u64)> = entries
        .filter_map(Result::ok)
        .filter(|e| keep(&e.file_name().to_string_lossy().to_lowercase()))
        .filter_map(|e| {
            let meta = fs::symlink_metadata(e.path()).ok()?;
            meta.is_file().then(|| (e.path(), meta.len()))
        })
        .collect();
    out.sort();
    out
}

fn recent_items(places: &TracePlaces, protected: &Protected) -> TraceFinding {
    let mut f = TraceFinding::new(Trace::RecentItems);
    let Some(dir) = &places.recent else {
        return f;
    };
    for (path, bytes) in recent_files(dir) {
        if protected.covers(&path) {
            f.keep(KeptReason::Protected, 1, bytes);
            continue;
        }
        f.count += 1;
        f.bytes += bytes;
    }
    f
}

fn recent_files(dir: &Path) -> Vec<(PathBuf, u64)> {
    files_in(dir, |n| n.ends_with(".lnk"))
}

fn thumbnail_files(dir: &Path) -> Vec<(PathBuf, u64)> {
    files_in(dir, |n| n.starts_with("thumbcache_") && n.ends_with(".db"))
}

/// The jump lists, and the files that may go: those without pinned items.
fn jump_lists(places: &TracePlaces, protected: &Protected) -> (TraceFinding, Vec<PathBuf>) {
    let mut f = TraceFinding::new(Trace::JumpLists);
    let mut doomed = Vec::new();
    let mut items = 0u64;
    let mut pinned_lists = 0;
    if let Some(dir) = places.automatic() {
        for (path, bytes) in files_in(&dir, |n| n.ends_with(".automaticdestinations-ms")) {
            if protected.covers(&path) {
                f.keep(KeptReason::Protected, 1, bytes);
                continue;
            }
            match jumplist::read(&path) {
                Ok(d) if d.pinned == 0 => {
                    items += u64::from(d.entries);
                    f.count += 1;
                    f.bytes += bytes;
                    doomed.push(path);
                }
                Ok(d) => {
                    // Windows' own clearing takes the other items; the list
                    // stays for what is pinned.
                    items += u64::from(d.recent());
                    pinned_lists += 1;
                    f.keep(KeptReason::Pinned, 1, bytes);
                }
                Err(_) => f.keep(KeptReason::Unreadable, 1, bytes),
            }
        }
    }
    if let Some(dir) = places.custom() {
        for (path, bytes) in files_in(&dir, |n| n.ends_with(".customdestinations-ms")) {
            if protected.covers(&path) {
                f.keep(KeptReason::Protected, 1, bytes);
                continue;
            }
            f.count += 1;
            f.bytes += bytes;
            doomed.push(path);
        }
    }
    if items > 0 {
        let what = if items == 1 { "item" } else { "items" };
        f.notes.push(format!("{items} recent {what}"));
    }
    if pinned_lists > 0 && places.own_profile {
        f.notes
            .push("lists with pinned items keep only those".to_string());
    }
    (f, doomed)
}

fn thumbnails(places: &TracePlaces, protected: &Protected) -> TraceFinding {
    let mut f = TraceFinding::new(Trace::Thumbnails);
    f.count_known = false;
    let Some(dir) = &places.thumbnails else {
        return f;
    };
    if protected.touches(dir) {
        let files = thumbnail_files(dir);
        let bytes = files.iter().map(|(_, b)| b).sum();
        if !files.is_empty() {
            f.keep(KeptReason::Protected, files.len(), bytes);
        }
        return f;
    }
    let files = thumbnail_files(dir);
    f.count = files.len();
    f.bytes = files.iter().map(|(_, b)| b).sum();
    f
}

fn clipboard(shell: &dyn Shell) -> TraceFinding {
    let mut f = TraceFinding::new(Trace::Clipboard);
    match shell.clipboard() {
        ClipboardState::Items(n) => f.count = n,
        ClipboardState::Off => f.notes.push("clipboard history is off".to_string()),
        ClipboardState::Unreadable => {
            f.count_known = false;
            f.notes
                .push("Windows does not say how many items it holds".to_string());
        }
        ClipboardState::Absent => {}
    }
    f
}

/// Values that only keep the order of a list or Windows' own counters.
fn bookkeeping(name: &str) -> bool {
    name.eq_ignore_ascii_case("MRUList")
        || name.eq_ignore_ascii_case("MRUListEx")
        // UserAssist's session counters, in its ROT13 spelling.
        || name.starts_with("HRZR_")
}

fn hkcu() -> RegKey {
    RegKey::predef(HKEY_CURRENT_USER)
}

fn open(places: &TracePlaces, rel: &str, access: u32) -> io::Result<RegKey> {
    hkcu().open_subkey_with_flags(format!(r"{}\{rel}", places.explorer_key), access)
}

/// The `Count` key under each of UserAssist's keys.
fn launch_count_keys(places: &TracePlaces) -> Vec<String> {
    let Ok(key) = open(places, "UserAssist", KEY_READ) else {
        return Vec::new();
    };
    let mut out: Vec<String> = key
        .enum_keys()
        .filter_map(Result::ok)
        .map(|g| format!(r"UserAssist\{g}\Count"))
        .collect();
    out.sort();
    out
}

/// The entries of a list and the bytes it holds. A list split by type, such
/// as the Open and Save history, counts its `*` part, which holds them all;
/// one without it counts every part.
fn measure(key: &RegKey) -> (usize, u64) {
    let (mut count, mut bytes) = (0, 0);
    for (name, value) in key.enum_values().filter_map(Result::ok) {
        bytes += value.bytes.len() as u64;
        if !bookkeeping(&name) {
            count += 1;
        }
    }
    let subs: Vec<String> = key.enum_keys().filter_map(Result::ok).collect();
    let mut parts = 0;
    let mut star = None;
    for name in &subs {
        if let Ok(sub) = key.open_subkey_with_flags(name, KEY_READ) {
            let (n, b) = measure(&sub);
            bytes += b;
            parts += n;
            if name == "*" {
                star = Some(n);
            }
        }
    }
    if count == 0 {
        count = star.unwrap_or(parts);
    }
    (count, bytes)
}

fn registry(trace: Trace, keys: &[String], places: &TracePlaces) -> TraceFinding {
    let mut f = TraceFinding::new(trace);
    for rel in keys {
        if let Ok(key) = open(places, rel, KEY_READ) {
            let (n, b) = measure(&key);
            f.count += n;
            f.bytes += b;
        }
    }
    f
}

/// Delete every value and subkey of a list. The key itself stays.
fn empty_key(key: &RegKey) -> io::Result<()> {
    let subs: Vec<String> = key.enum_keys().filter_map(Result::ok).collect();
    for s in subs {
        key.delete_subkey_all(&s)?;
    }
    let names: Vec<String> = key
        .enum_values()
        .filter_map(Result::ok)
        .map(|(n, _)| n)
        .collect();
    for n in names {
        key.delete_value(&n)?;
    }
    Ok(())
}

fn reason_of(e: &io::Error) -> KeptReason {
    match e.raw_os_error() {
        Some(32) | Some(33) => KeptReason::InUse,
        Some(5) => KeptReason::AccessDenied,
        _ if e.kind() == io::ErrorKind::PermissionDenied => KeptReason::AccessDenied,
        _ => KeptReason::Failed(e.to_string()),
    }
}

/// Clear every trace, then read them all again. Each result says what went
/// and what stays, and why.
pub fn clear(places: &TracePlaces, protected: &Protected, shell: &dyn Shell) -> Vec<TraceFinding> {
    let before = analyse(places, protected, shell);
    let mut problems: Vec<(Trace, KeptReason, usize, u64)> = Vec::new();
    let mut note = |t: Trace, r: KeptReason, n: usize, b: u64| problems.push((t, r, n, b));

    // Windows first: it clears what it can of the recent items and the jump
    // lists and tells Explorer, so the lists vanish from the taskbar at
    // once. What is left goes file by file.
    if let Err(e) = shell.clear_recent() {
        note(Trace::JumpLists, KeptReason::Failed(format!("{e:#}")), 0, 0);
    }
    if let Some(dir) = &places.recent {
        for (path, bytes) in recent_files(dir) {
            if protected.covers(&path) {
                continue;
            }
            if let Err(e) = fs::remove_file(&path) {
                note(Trace::RecentItems, reason_of(&e), 1, bytes);
            }
        }
    }
    let (_, doomed) = jump_lists(places, protected);
    for path in doomed {
        let bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if files::probe(&path) == Probe::InUse {
            note(Trace::JumpLists, KeptReason::InUse, 1, bytes);
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => note(Trace::JumpLists, reason_of(&e), 1, bytes),
        }
    }

    for trace in Trace::ALL {
        let keys: Vec<String> = match trace {
            Trace::LaunchCounts => launch_count_keys(places),
            _ => trace.keys().iter().map(|k| k.to_string()).collect(),
        };
        for rel in keys {
            match open(places, &rel, KEY_READ | KEY_WRITE) {
                Ok(key) => {
                    if let Err(e) = empty_key(&key) {
                        note(trace, reason_of(&e), 0, 0);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => note(trace, reason_of(&e), 0, 0),
            }
        }
    }

    if let Some(dir) = &places.thumbnails {
        if !protected.touches(dir) && !thumbnail_files(dir).is_empty() {
            if let Err(e) = shell.purge_thumbnails(dir) {
                note(
                    Trace::Thumbnails,
                    KeptReason::Failed(format!("{e:#}")),
                    0,
                    0,
                );
            }
        }
    }

    let clip = before.iter().find(|f| f.trace == Trace::Clipboard);
    if clip.is_some_and(TraceFinding::actionable) {
        if let Err(e) = shell.clear_clipboard() {
            note(Trace::Clipboard, KeptReason::Failed(format!("{e:#}")), 0, 0);
        }
    }

    let mut dirs: Vec<PathBuf> = places.recent.iter().cloned().collect();
    dirs.extend(places.automatic());
    dirs.extend(places.custom());
    shell.refresh(&dirs);

    let after = analyse(places, protected, shell);
    before
        .into_iter()
        .zip(after)
        .map(|(b, a)| {
            let mut done = TraceFinding::new(b.trace);
            done.count_known = b.count_known;
            done.count = b.count.saturating_sub(a.count);
            done.bytes = b.bytes.saturating_sub(a.bytes);
            done.kept = a.kept.clone();
            let mut explained = 0;
            for (_, r, n, bytes) in problems.iter().filter(|p| p.0 == b.trace) {
                explained += n;
                done.keep(r.clone(), *n, *bytes);
            }
            let left = if a.trace == Trace::Thumbnails {
                0
            } else {
                a.count.saturating_sub(explained)
            };
            if left > 0 && b.count > 0 {
                done.keep(
                    KeptReason::Failed("still there afterwards".to_string()),
                    left,
                    0,
                );
            }
            if b.trace == Trace::Clipboard && !b.count_known && !done.failed() {
                done.notes.push("cleared".to_string());
            }
            done
        })
        .collect()
}

/// Windows' own calls, for the signed-in user's profile.
pub struct WindowsShell;

#[cfg(windows)]
impl Shell for WindowsShell {
    fn clear_recent(&self) -> Result<()> {
        use windows::Win32::UI::Shell::{SHAddToRecentDocs, SHARD_PIDL};
        // No item: Windows clears its usage data for every program.
        unsafe { SHAddToRecentDocs(SHARD_PIDL.0 as u32, None) };
        Ok(())
    }

    fn clipboard(&self) -> ClipboardState {
        use windows::ApplicationModel::DataTransfer::{
            Clipboard, ClipboardHistoryItemsResultStatus as Status,
        };
        match Clipboard::IsHistoryEnabled() {
            Ok(false) => return ClipboardState::Off,
            Err(_) => return ClipboardState::Unreadable,
            Ok(true) => {}
        }
        let read = || -> windows::core::Result<ClipboardState> {
            let result = Clipboard::GetHistoryItemsAsync()?.join()?;
            Ok(match result.Status()? {
                Status::Success => ClipboardState::Items(result.Items()?.Size()? as usize),
                Status::ClipboardHistoryDisabled => ClipboardState::Off,
                _ => ClipboardState::Unreadable,
            })
        };
        read().unwrap_or(ClipboardState::Unreadable)
    }

    fn clear_clipboard(&self) -> Result<()> {
        use windows::ApplicationModel::DataTransfer::Clipboard;
        if Clipboard::ClearHistory()? {
            Ok(())
        } else {
            anyhow::bail!("Windows did not clear it")
        }
    }

    fn purge_thumbnails(&self, _dir: &Path) -> Result<()> {
        volume_cache::purge("Thumbnail Cache")
    }

    fn refresh(&self, dirs: &[PathBuf]) {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::UI::Shell::{
            SHChangeNotify, SHCNE_UPDATEDIR, SHCNF_FLUSHNOWAIT, SHCNF_PATHW,
        };
        for d in dirs {
            let wide: Vec<u16> = d.as_os_str().encode_wide().chain([0]).collect();
            unsafe {
                SHChangeNotify(
                    SHCNE_UPDATEDIR,
                    SHCNF_PATHW | SHCNF_FLUSHNOWAIT,
                    Some(wide.as_ptr().cast()),
                    None,
                )
            };
        }
    }
}

#[cfg(not(windows))]
impl Shell for WindowsShell {
    fn clear_recent(&self) -> Result<()> {
        Ok(())
    }
    fn clipboard(&self) -> ClipboardState {
        ClipboardState::Absent
    }
    fn clear_clipboard(&self) -> Result<()> {
        Ok(())
    }
    fn purge_thumbnails(&self, _dir: &Path) -> Result<()> {
        Ok(())
    }
    fn refresh(&self, _dirs: &[PathBuf]) {}
}

/// Disk Cleanup's handlers, called the way Disk Cleanup calls them. The
/// thumbnail cache is Explorer's, which keeps some of its files open; its
/// own handler empties it all the same.
#[cfg(windows)]
mod volume_cache {
    use anyhow::{Context, Result};
    use winreg::enums::*;
    use winreg::RegKey;

    const VOLUME_CACHES: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches";

    pub fn purge(handler: &str) -> Result<()> {
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(
                format!(r"{VOLUME_CACHES}\{handler}"),
                KEY_READ | KEY_WOW64_64KEY,
            )
            .with_context(|| format!("Disk Cleanup has no {handler} handler"))?;
        let clsid: String = key.get_value("").context("reading the handler's class")?;
        let clsid = windows::core::GUID::try_from(clsid.trim_matches(['{', '}']))
            .map_err(|_| anyhow::anyhow!("the handler's class is not a GUID"))?;
        let drive: Vec<u16> = crate::system::windows_dir()
            .ancestors()
            .last()
            .map(|d| d.as_os_str().to_string_lossy().to_string())
            .unwrap_or_else(|| r"C:\".to_string())
            .encode_utf16()
            .chain([0])
            .collect();
        let raw = key.raw_handle() as usize;
        // A thread of its own, so the COM apartment is set up and torn down
        // here and nowhere else.
        std::thread::scope(|s| {
            s.spawn(|| run(clsid, raw, &drive))
                .join()
                .unwrap_or_else(|_| anyhow::bail!("the Disk Cleanup handler stopped"))
        })
    }

    fn run(clsid: windows::core::GUID, key: usize, drive: &[u16]) -> Result<()> {
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
            COINIT_APARTMENTTHREADED,
        };
        use windows::Win32::System::Registry::HKEY;
        use windows::Win32::UI::LegacyWindowsEnvironmentFeatures::{
            IEmptyVolumeCache, IEmptyVolumeCacheCallBack, EMPTY_VOLUME_CACHE_FLAGS,
        };
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .ok()
                .context("starting COM")?;
            let result = (|| -> Result<()> {
                let cache: IEmptyVolumeCache = CoCreateInstance(&clsid, None, CLSCTX_INPROC_SERVER)
                    .context("starting the Disk Cleanup handler")?;
                let (mut name, mut about) = (PWSTR::null(), PWSTR::null());
                let mut flags = EMPTY_VOLUME_CACHE_FLAGS(0);
                cache
                    .Initialize(
                        HKEY(key as *mut core::ffi::c_void),
                        PCWSTR(drive.as_ptr()),
                        &mut name,
                        &mut about,
                        &mut flags,
                    )
                    .context("starting the Disk Cleanup handler")?;
                for p in [name, about] {
                    if !p.is_null() {
                        CoTaskMemFree(Some(p.0 as *const _));
                    }
                }
                let mut used = 0u64;
                cache
                    .GetSpaceUsed(&mut used, None::<&IEmptyVolumeCacheCallBack>)
                    .context("measuring the thumbnail cache")?;
                cache
                    .Purge(used, None::<&IEmptyVolumeCacheCallBack>)
                    .context("emptying the thumbnail cache")?;
                let _ = cache.Deactivate();
                Ok(())
            })();
            CoUninitialize();
            result
        }
    }
}

#[cfg(test)]
mod tests;
