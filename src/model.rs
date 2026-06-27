//! Shared data model for Oxidize.
//!
//! This module is deliberately dependency-free (aside from `serde` for `--json`
//! output): it describes *what* the rest of the program operates on, while the
//! Windows-specific mechanics (winreg, the `windows` crate) live in their own
//! modules. Keeping the model pure makes it trivial to unit-test the matching
//! and formatting logic without touching a real registry.

use std::path::PathBuf;

use serde::Serialize;

/// Which registry hive an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Hive {
    /// `HKEY_LOCAL_MACHINE` — machine-wide installs (needs admin to modify).
    LocalMachine,
    /// `HKEY_CURRENT_USER` — per-user installs (writable without elevation).
    CurrentUser,
}

impl Hive {
    /// The full name used inside a `.reg` file, e.g. `HKEY_LOCAL_MACHINE`.
    pub fn full_name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
            Hive::CurrentUser => "HKEY_CURRENT_USER",
        }
    }

    /// The short name accepted by `reg.exe`, e.g. `HKLM`.
    pub fn short_name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKLM",
            Hive::CurrentUser => "HKCU",
        }
    }
}

/// Which WOW64 view an `HKLM\SOFTWARE` entry lives in.
///
/// On 64-bit Windows the registry is split: 64-bit programs register under the
/// native `SOFTWARE\...` path, while 32-bit programs are physically stored under
/// `SOFTWARE\WOW6432Node\...`. We always address keys by their *physical* path
/// (i.e. we spell out `WOW6432Node` explicitly) so that backup/export/delete all
/// refer to exactly the same key with no redirection surprises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RegistryView {
    /// Native 64-bit view (also the only view that exists on 32-bit Windows).
    Native64,
    /// 32-bit-on-64-bit view, physically under `SOFTWARE\WOW6432Node`.
    Wow6432,
}

impl RegistryView {
    /// The `Uninstall` key base path for this view (relative to the hive root).
    pub fn uninstall_base(self) -> &'static str {
        match self {
            RegistryView::Native64 => r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            RegistryView::Wow6432 => {
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            }
        }
    }

    /// Human label for display.
    pub fn label(self) -> &'static str {
        match self {
            RegistryView::Native64 => "64-bit",
            RegistryView::Wow6432 => "32-bit",
        }
    }
}

/// Where (hive + view) a program's uninstall entry was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RegistrySource {
    pub hive: Hive,
    pub view: RegistryView,
}

impl RegistrySource {
    pub const fn new(hive: Hive, view: RegistryView) -> Self {
        Self { hive, view }
    }

    /// Short human description, e.g. `HKLM/64-bit`.
    pub fn label(self) -> String {
        format!("{}/{}", self.hive.short_name(), self.view.label())
    }
}

/// A single installed program, as read from one Uninstall registry subkey.
#[derive(Debug, Clone, Serialize)]
pub struct Program {
    /// The Uninstall subkey name. For MSI products this is the ProductCode GUID;
    /// otherwise it is an app-chosen string. Used as the stable selection id.
    pub registry_key: String,
    /// Which hive/view this entry came from.
    pub source: RegistrySource,

    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    /// Install date, normalised to `YYYY-MM-DD` when the raw value parses.
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub display_icon: Option<String>,
    /// `EstimatedSize` is stored in KiB.
    pub estimated_size_kb: Option<u32>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub url_info_about: Option<String>,
    /// True when `WindowsInstaller == 1` (an MSI product).
    pub is_windows_installer: bool,
    /// True when `SystemComponent == 1` (hidden OS component).
    pub is_system_component: bool,
}

impl Program {
    /// The selection id (the Uninstall subkey name).
    pub fn id(&self) -> &str {
        &self.registry_key
    }

    /// Path of the program's own Uninstall key, relative to its hive root.
    pub fn uninstall_subpath(&self) -> String {
        format!("{}\\{}", self.source.view.uninstall_base(), self.registry_key)
    }

    /// Estimated on-disk size in bytes (from `EstimatedSize`, KiB → bytes).
    pub fn size_bytes(&self) -> Option<u64> {
        self.estimated_size_kb.map(|kb| kb as u64 * 1024)
    }
}

/// How confident the scanner is that an item is a genuine leftover of the
/// target program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Confidence {
    /// Strong evidence (under the install folder, the program's own orphaned
    /// Uninstall key, an exact name match, a GUID/CLSID key). Safe to remove.
    High,
    /// Plausible but could belong to something else (publisher folder that may
    /// hold sibling products, partial name match). Review before removing.
    Medium,
    /// Weak signal, shown for context only. Off by default.
    Low,
}

/// The kind of thing a leftover is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LeftoverKind {
    /// A whole registry key (and its subtree).
    RegistryKey,
    /// A single named value under a registry key.
    RegistryValue,
    /// A file.
    File,
    /// A directory (and its contents).
    Directory,
}

/// One leftover discovered by the scanner.
#[derive(Debug, Clone, Serialize)]
pub struct Leftover {
    pub kind: LeftoverKind,
    pub confidence: Confidence,
    /// Human-readable reason this was flagged (drives trust + the report).
    pub reason: String,
    /// Display path: a filesystem path, or a full `HKEY_...\...` registry path.
    pub path: String,
    /// Size in bytes for files/directories (best-effort).
    pub size_bytes: Option<u64>,
    /// True if this is an empty directory.
    pub is_empty_dir: bool,

    // --- Registry-only addressing (None for filesystem leftovers) ---
    pub hive: Option<Hive>,
    /// Path under the hive root (no `HKEY_...` prefix), for delete/export.
    pub subpath: Option<String>,
    /// When set, this leftover is a single *value* (not the whole key).
    pub value_name: Option<String>,
}

impl Leftover {
    /// Construct a filesystem leftover (file or directory).
    pub fn fs(
        kind: LeftoverKind,
        path: PathBuf,
        confidence: Confidence,
        reason: impl Into<String>,
        size_bytes: Option<u64>,
        is_empty_dir: bool,
    ) -> Self {
        Leftover {
            kind,
            confidence,
            reason: reason.into(),
            path: path.display().to_string(),
            size_bytes,
            is_empty_dir,
            hive: None,
            subpath: None,
            value_name: None,
        }
    }

    /// Construct a whole-registry-key leftover.
    pub fn reg_key(
        hive: Hive,
        subpath: impl Into<String>,
        confidence: Confidence,
        reason: impl Into<String>,
    ) -> Self {
        let subpath = subpath.into();
        let path = format!("{}\\{}", hive.full_name(), subpath);
        Leftover {
            kind: LeftoverKind::RegistryKey,
            confidence,
            reason: reason.into(),
            path,
            size_bytes: None,
            is_empty_dir: false,
            hive: Some(hive),
            subpath: Some(subpath),
            value_name: None,
        }
    }

    /// Construct a single-registry-value leftover.
    pub fn reg_value(
        hive: Hive,
        subpath: impl Into<String>,
        value_name: impl Into<String>,
        confidence: Confidence,
        reason: impl Into<String>,
    ) -> Self {
        let subpath = subpath.into();
        let value_name = value_name.into();
        let path = format!("{}\\{} :: {}", hive.full_name(), subpath, value_name);
        Leftover {
            kind: LeftoverKind::RegistryValue,
            confidence,
            reason: reason.into(),
            path,
            size_bytes: None,
            is_empty_dir: false,
            hive: Some(hive),
            subpath: Some(subpath),
            value_name: Some(value_name),
        }
    }
}

/// The result of a leftover scan, grouped registry vs. filesystem.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanReport {
    pub program_name: String,
    pub registry: Vec<Leftover>,
    pub filesystem: Vec<Leftover>,
}

impl ScanReport {
    pub fn total(&self) -> usize {
        self.registry.len() + self.filesystem.len()
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// All leftovers, registry first then filesystem.
    pub fn all(&self) -> impl Iterator<Item = &Leftover> {
        self.registry.iter().chain(self.filesystem.iter())
    }

    /// Sum of `size_bytes` across all filesystem leftovers.
    pub fn reclaimable_bytes(&self) -> u64 {
        self.filesystem
            .iter()
            .filter_map(|l| l.size_bytes)
            .sum()
    }
}

/// The "seed" describing the program we are scanning leftovers for. Captured
/// *before* running the uninstaller (a snapshot of the footprint) so we can
/// still recognise leftovers after the entry itself is gone.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub display_name: String,
    pub publisher: Option<String>,
    pub install_location: Option<PathBuf>,
    /// Lower-cased executable basenames seen in DisplayIcon / install dir.
    pub exe_names: Vec<String>,
    /// Significant lower-cased tokens of the display name.
    pub name_tokens: Vec<String>,
    /// Significant lower-cased tokens of the publisher.
    pub publisher_tokens: Vec<String>,
    pub registry_key: String,
    pub source: RegistrySource,
}
