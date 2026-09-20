//! Shared data model. Nothing here touches Windows, so the matching and
//! formatting logic can be unit-tested without a real registry.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Which registry hive an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hive {
    /// `HKEY_LOCAL_MACHINE`, machine-wide. Needs admin to modify.
    LocalMachine,
    /// `HKEY_CURRENT_USER`, per-user. Writable without elevation.
    CurrentUser,
}

impl Hive {
    /// The full name used inside a `.reg` file.
    pub fn full_name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
            Hive::CurrentUser => "HKEY_CURRENT_USER",
        }
    }

    /// The short name accepted by `reg.exe`.
    pub fn short_name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKLM",
            Hive::CurrentUser => "HKCU",
        }
    }
}

/// Which WOW64 view an `HKLM\SOFTWARE` entry lives in. 64-bit programs
/// register under `SOFTWARE\...`, 32-bit ones physically under
/// `SOFTWARE\WOW6432Node\...`. Keys are always addressed by their physical
/// path so backup, export and delete land on the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryView {
    Native64,
    Wow6432,
}

impl RegistryView {
    /// The `Uninstall` key for this view, relative to the hive root.
    pub fn uninstall_base(self) -> &'static str {
        match self {
            RegistryView::Native64 => r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            RegistryView::Wow6432 => {
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            RegistryView::Native64 => "64-bit",
            RegistryView::Wow6432 => "32-bit",
        }
    }
}

/// Where (hive + view) a program's uninstall entry was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySource {
    pub hive: Hive,
    pub view: RegistryView,
}

impl RegistrySource {
    pub const fn new(hive: Hive, view: RegistryView) -> Self {
        Self { hive, view }
    }

    /// Short description, e.g. `HKLM 64-bit`.
    pub fn label(self) -> String {
        format!("{} {}", self.hive.short_name(), self.view.label())
    }
}

/// One installed program, as read from one Uninstall registry subkey.
#[derive(Debug, Clone, Serialize)]
pub struct Program {
    /// The Uninstall subkey name. For MSI products the ProductCode GUID,
    /// otherwise an app-chosen string. Used as the stable selection id.
    pub registry_key: String,
    pub source: RegistrySource,

    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    /// Install date as `YYYY-MM-DD`, when the raw value was a real date.
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub display_icon: Option<String>,
    /// `EstimatedSize` is stored in KiB.
    pub estimated_size_kb: Option<u32>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub url_info_about: Option<String>,
    /// `WindowsInstaller == 1`: an MSI product.
    pub is_windows_installer: bool,
    /// `SystemComponent == 1`: hidden OS component.
    pub is_system_component: bool,
}

impl Program {
    pub fn id(&self) -> &str {
        &self.registry_key
    }

    /// Path of the program's own Uninstall key, relative to its hive root.
    pub fn uninstall_subpath(&self) -> String {
        format!(
            "{}\\{}",
            self.source.view.uninstall_base(),
            self.registry_key
        )
    }

    pub fn size_bytes(&self) -> Option<u64> {
        self.estimated_size_kb.map(|kb| kb as u64 * 1024)
    }
}

/// How sure the scanner is that an item belongs to the target program.
/// Ordered `High < Medium < Low` so "act on everything up to this level"
/// is a plain comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    /// Strong evidence: inside the install folder, the program's own key,
    /// an exact name match. Removed by default.
    High,
    /// Plausible but could belong to something else. Review first.
    Medium,
    /// Weak signal, shown for context.
    Low,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// The kind of thing a leftover is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeftoverKind {
    RegistryKey,
    RegistryValue,
    File,
    Directory,
    /// A Windows service (registered under `SYSTEM\CurrentControlSet\Services`).
    Service,
    /// A Task Scheduler task.
    ScheduledTask,
    /// One entry of the user or machine `Path` variable.
    PathEntry,
    /// A Windows Firewall rule.
    FirewallRule,
}

/// Rendering group for a leftover kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Registry,
    Files,
    System,
}

impl Group {
    pub const ALL: [Group; 3] = [Group::Registry, Group::Files, Group::System];

    pub fn title(self) -> &'static str {
        match self {
            Group::Registry => "registry",
            Group::Files => "files",
            Group::System => "system",
        }
    }
}

impl LeftoverKind {
    pub fn group(self) -> Group {
        match self {
            LeftoverKind::RegistryKey | LeftoverKind::RegistryValue => Group::Registry,
            LeftoverKind::File | LeftoverKind::Directory => Group::Files,
            LeftoverKind::Service
            | LeftoverKind::ScheduledTask
            | LeftoverKind::PathEntry
            | LeftoverKind::FirewallRule => Group::System,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LeftoverKind::RegistryKey => "key",
            LeftoverKind::RegistryValue => "value",
            LeftoverKind::File => "file",
            LeftoverKind::Directory => "folder",
            LeftoverKind::Service => "service",
            LeftoverKind::ScheduledTask => "task",
            LeftoverKind::PathEntry => "path",
            LeftoverKind::FirewallRule => "firewall",
        }
    }
}

/// One leftover discovered by the scanner.
#[derive(Debug, Clone, Serialize)]
pub struct Leftover {
    pub kind: LeftoverKind,
    pub confidence: Confidence,
    /// Short reason it was flagged.
    pub reason: String,
    /// Display string: a filesystem path, a short registry path, or a
    /// description for services, tasks, PATH entries and firewall rules.
    pub path: String,
    /// Size in bytes for files and folders.
    pub size_bytes: Option<u64>,
    pub is_empty_dir: bool,

    /// Registry addressing. `None` for filesystem leftovers and tasks.
    pub hive: Option<Hive>,
    /// Path under the hive root, for export and delete.
    pub subpath: Option<String>,
    /// Set when the leftover is one value, not the whole key.
    pub value_name: Option<String>,
    /// Service name, task path, or the PATH entry text.
    pub name: Option<String>,
}

impl Leftover {
    fn base(
        kind: LeftoverKind,
        confidence: Confidence,
        reason: impl Into<String>,
        path: String,
    ) -> Self {
        Leftover {
            kind,
            confidence,
            reason: reason.into(),
            path,
            size_bytes: None,
            is_empty_dir: false,
            hive: None,
            subpath: None,
            value_name: None,
            name: None,
        }
    }

    pub fn fs(
        kind: LeftoverKind,
        path: PathBuf,
        confidence: Confidence,
        reason: impl Into<String>,
        size_bytes: Option<u64>,
        is_empty_dir: bool,
    ) -> Self {
        let mut l = Self::base(kind, confidence, reason, path.display().to_string());
        l.size_bytes = size_bytes;
        l.is_empty_dir = is_empty_dir;
        l
    }

    pub fn reg_key(
        hive: Hive,
        subpath: impl Into<String>,
        confidence: Confidence,
        reason: impl Into<String>,
    ) -> Self {
        let subpath = subpath.into();
        let path = format!("{}\\{}", hive.short_name(), subpath);
        let mut l = Self::base(LeftoverKind::RegistryKey, confidence, reason, path);
        l.hive = Some(hive);
        l.subpath = Some(subpath);
        l
    }

    pub fn reg_value(
        hive: Hive,
        subpath: impl Into<String>,
        value_name: impl Into<String>,
        confidence: Confidence,
        reason: impl Into<String>,
    ) -> Self {
        let subpath = subpath.into();
        let value_name = value_name.into();
        let path = format!("{}\\{} : {}", hive.short_name(), subpath, value_name);
        let mut l = Self::base(LeftoverKind::RegistryValue, confidence, reason, path);
        l.hive = Some(hive);
        l.subpath = Some(subpath);
        l.value_name = Some(value_name);
        l
    }

    /// A Windows service. `image` is the executable it runs, for display.
    pub fn service(
        name: impl Into<String>,
        image: &str,
        confidence: Confidence,
        reason: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let path = if image.is_empty() {
            format!("service {name}")
        } else {
            format!("service {name}  ({image})")
        };
        let mut l = Self::base(LeftoverKind::Service, confidence, reason, path);
        l.hive = Some(Hive::LocalMachine);
        l.subpath = Some(format!(r"SYSTEM\CurrentControlSet\Services\{name}"));
        l.name = Some(name);
        l
    }

    /// A scheduled task. `task_path` is the full task name including folders,
    /// e.g. `\Vendor\Updater`.
    pub fn task(
        task_path: impl Into<String>,
        command: &str,
        confidence: Confidence,
        reason: impl Into<String>,
    ) -> Self {
        let task_path = task_path.into();
        let path = if command.is_empty() {
            format!("task {task_path}")
        } else {
            format!("task {task_path}  ({command})")
        };
        let mut l = Self::base(LeftoverKind::ScheduledTask, confidence, reason, path);
        l.name = Some(task_path);
        l
    }

    /// One entry of a `Path` variable. `hive` says whether it is the user or
    /// the machine variable.
    pub fn path_entry(
        hive: Hive,
        entry: impl Into<String>,
        confidence: Confidence,
        reason: impl Into<String>,
    ) -> Self {
        let entry = entry.into();
        let scope = match hive {
            Hive::CurrentUser => "user",
            Hive::LocalMachine => "machine",
        };
        let path = format!("PATH entry {entry}  ({scope})");
        let mut l = Self::base(LeftoverKind::PathEntry, confidence, reason, path);
        l.hive = Some(hive);
        l.subpath = Some(environment_key(hive).to_string());
        l.value_name = Some("Path".to_string());
        l.name = Some(entry);
        l
    }

    /// A firewall rule stored under the `FirewallRules` key. `value_name` is
    /// the rule id, `rule_name` its display name, `app` the program it covers.
    pub fn firewall_rule(
        value_name: impl Into<String>,
        rule_name: &str,
        kind: &str,
        app: &str,
        confidence: Confidence,
        reason: impl Into<String>,
    ) -> Self {
        let value_name = value_name.into();
        let path = if kind.is_empty() {
            format!("firewall rule \"{rule_name}\"  ({app})")
        } else {
            format!("firewall rule \"{rule_name}\" {kind}  ({app})")
        };
        let mut l = Self::base(LeftoverKind::FirewallRule, confidence, reason, path);
        l.hive = Some(Hive::LocalMachine);
        l.subpath = Some(FIREWALL_RULES_KEY.to_string());
        l.value_name = Some(value_name);
        l.name = Some(rule_name.to_string());
        l
    }
}

/// The registry key holding the `Path` variable for a hive.
pub fn environment_key(hive: Hive) -> &'static str {
    match hive {
        Hive::CurrentUser => "Environment",
        Hive::LocalMachine => r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    }
}

/// Where Windows Firewall keeps its rules.
pub const FIREWALL_RULES_KEY: &str =
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

/// The result of a leftover scan.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanReport {
    pub program_name: String,
    /// True when the program is still registered, so the items are its
    /// current footprint rather than leftovers.
    pub installed: bool,
    pub items: Vec<Leftover>,
}

impl ScanReport {
    pub fn total(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn all(&self) -> impl Iterator<Item = &Leftover> {
        self.items.iter()
    }

    pub fn group(&self, group: Group) -> impl Iterator<Item = &Leftover> {
        self.items.iter().filter(move |l| l.kind.group() == group)
    }

    /// Sum of `size_bytes` across file and folder leftovers.
    pub fn reclaimable_bytes(&self) -> u64 {
        self.group(Group::Files).filter_map(|l| l.size_bytes).sum()
    }
}

/// The identity of the program being scanned for. Captured before the
/// uninstaller runs so leftovers are still recognised once the entry is gone,
/// or built from a bare name when the program is no longer registered.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    /// True when the product's name says no more than its publisher's and that
    /// publisher has other programs installed. A folder or key with that name
    /// is then the vendor's, shared with everything else they ship.
    pub vendor_is_shared: bool,
    pub display_name: String,
    pub publisher: Option<String>,
    pub install_location: Option<PathBuf>,
    /// Lower-cased executable basenames seen in DisplayIcon / UninstallString.
    pub exe_names: Vec<String>,
    /// Significant lower-cased tokens of the display name.
    pub name_tokens: Vec<String>,
    /// Significant lower-cased tokens of the publisher.
    pub publisher_tokens: Vec<String>,
    /// The Uninstall subkey and its source. `None` for name-only targets.
    pub registry: Option<(String, RegistrySource)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_orders_high_first() {
        // Removal selects everything at or above a threshold with `<=`, so the
        // order of this enum is what makes `--medium` include high.
        assert!(Confidence::High < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::Low);
        let mut levels = [Confidence::Low, Confidence::High, Confidence::Medium];
        levels.sort();
        assert_eq!(
            levels,
            [Confidence::High, Confidence::Medium, Confidence::Low]
        );
    }

    #[test]
    fn a_value_leftover_carries_what_removal_needs() {
        let l = Leftover::reg_value(
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "Vendor",
            Confidence::High,
            "autostart",
        );
        assert_eq!(l.hive, Some(Hive::CurrentUser));
        assert_eq!(l.value_name.as_deref(), Some("Vendor"));
        assert!(l.path.ends_with(" : Vendor"));
        assert_eq!(l.kind.group(), Group::Registry);
    }
}
