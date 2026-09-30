//! Store apps: the MSIX and AppX packages registered for the current user.
//! Oxidize lists them and removes them for the current user only: never for
//! every user and never from the image new accounts are set up from.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Serialize, Serializer};
use windows::core::HSTRING;
use windows::ApplicationModel::{self as appx, PackageSignatureKind};
use windows::Management::Deployment::{PackageManager, PackageTypes};

use crate::model::{Confidence, Leftover, LeftoverKind, Package, SignatureKind};
use crate::scanner;

/// Where the installed packages come from: Windows, or a fixed list in tests.
pub trait PackageStore {
    /// Every main package registered for the current user.
    fn list(&self) -> Result<Vec<Package>>;

    /// Whether any package of this family is still registered for the
    /// current user.
    fn is_registered(&self, family_name: &str) -> Result<bool>;

    /// Remove the package for the current user. An error means Windows
    /// refused or failed; the outcome says whether the family is gone.
    /// Callers run [`package_guard`] first and never pass a refused package.
    fn remove(&self, package: &Package) -> Result<RemovalOutcome>;

    /// Whether Windows installs this family for every new account, so it
    /// can come back. Reading this may need administrator rights.
    fn is_provisioned(&self, family_name: &str) -> Result<bool>;
}

/// What became of a package Windows reported as removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalOutcome {
    /// No package of the family is registered for the current user any more.
    Removed,
    /// Windows reported success, yet the family is still registered.
    StillRegistered,
}

/// The packages Windows has registered, read through `PackageManager`.
/// Reading the current user's packages needs no administrator rights.
pub struct WindowsPackageStore;

impl WindowsPackageStore {
    fn manager() -> Result<PackageManager> {
        PackageManager::new().context("the Windows package manager is not available")
    }
}

impl PackageStore for WindowsPackageStore {
    fn list(&self) -> Result<Vec<Package>> {
        // An empty security id means the current user.
        let found = Self::manager()?
            .FindPackagesByUserSecurityIdWithPackageTypes(&HSTRING::new(), PackageTypes::Main)
            .context("listing the Store apps failed")?;
        found.into_iter().map(|p| read_package(&p)).collect()
    }

    fn is_registered(&self, family_name: &str) -> Result<bool> {
        let found = Self::manager()?
            .FindPackagesByUserSecurityIdPackageFamilyName(
                &HSTRING::new(),
                &HSTRING::from(family_name),
            )
            .with_context(|| format!("looking up {family_name} failed"))?;
        Ok(found.into_iter().next().is_some())
    }

    fn remove(&self, package: &Package) -> Result<RemovalOutcome> {
        // The full name alone, without RemovalOptions: the current user only,
        // never RemoveForAllUsers, and the provisioned copy stays untouched.
        let result = Self::manager()?
            .RemovePackageAsync(&HSTRING::from(package.full_name.as_str()))
            .and_then(|operation| operation.join())
            .with_context(|| format!("Windows did not remove {}", package.display_name))?;
        if let Some(error) = text(result.ErrorText()) {
            bail!("Windows did not remove {}: {error}", package.display_name);
        }
        if self.is_registered(&package.family_name)? {
            Ok(RemovalOutcome::StillRegistered)
        } else {
            Ok(RemovalOutcome::Removed)
        }
    }

    fn is_provisioned(&self, family_name: &str) -> Result<bool> {
        let provisioned = Self::manager()?
            .FindProvisionedPackages()
            .context("reading the provisioned Store apps failed")?;
        for p in provisioned {
            if p.Id()?
                .FamilyName()?
                .to_string()
                .eq_ignore_ascii_case(family_name)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn read_package(p: &appx::Package) -> Result<Package> {
    let id = p.Id()?;
    let name = id.Name()?.to_string();
    let version = id.Version()?;
    let family_name = id.FamilyName()?.to_string();
    let dependencies = p
        .Dependencies()?
        .into_iter()
        .map(|d| Ok(d.Id()?.FamilyName()?.to_string()))
        .collect::<Result<Vec<_>>>()?;
    Ok(Package {
        dependencies: other_families(&family_name, dependencies),
        family_name,
        full_name: id.FullName()?.to_string(),
        display_name: text(p.DisplayName()).unwrap_or_else(|| name.clone()),
        name,
        publisher: text(p.PublisherDisplayName()),
        version: format!(
            "{}.{}.{}.{}",
            version.Major, version.Minor, version.Build, version.Revision
        ),
        signature: signature_kind(p.SignatureKind()?),
        is_framework: p.IsFramework()?,
        is_resource: p.IsResourcePackage()?,
        is_bundle: p.IsBundle()?,
        // Empty for a normal package. When Windows cannot say, count it as
        // sparse: that is the answer that keeps it from being removed.
        is_sparse: p
            .EffectiveExternalPath()
            .map_or(true, |path| !path.is_empty()),
        installed_path: text(p.InstalledPath()),
        installed_date: p
            .InstalledDate()
            .ok()
            .and_then(|d| date_from_ticks(d.UniversalTime)),
    })
}

/// Windows counts an app's own resource packages among its dependencies, and
/// they share its family name. Keep the other families, each once.
fn other_families(own: &str, dependencies: Vec<String>) -> Vec<String> {
    let mut families: Vec<String> = Vec::with_capacity(dependencies.len());
    for family in dependencies {
        let seen = family.eq_ignore_ascii_case(own)
            || families.iter().any(|f| f.eq_ignore_ascii_case(&family));
        if !seen {
            families.push(family);
        }
    }
    families
}

/// A string property, `None` when it is empty or cannot be read.
fn text(value: windows::core::Result<HSTRING>) -> Option<String> {
    value
        .ok()
        .map(|s| s.to_string().trim().to_string())
        .filter(|s| !s.is_empty())
}

fn signature_kind(kind: PackageSignatureKind) -> SignatureKind {
    match kind {
        PackageSignatureKind::Developer => SignatureKind::Developer,
        PackageSignatureKind::Enterprise => SignatureKind::Enterprise,
        PackageSignatureKind::Store => SignatureKind::Store,
        PackageSignatureKind::System => SignatureKind::System,
        _ => SignatureKind::None,
    }
}

/// A WinRT `DateTime`, 100 ns ticks since 1601-01-01 UTC, as a local
/// `YYYY-MM-DD`.
fn date_from_ticks(ticks: i64) -> Option<String> {
    const TICKS_PER_SECOND: i64 = 10_000_000;
    const SECONDS_1601_TO_1970: i64 = 11_644_473_600;
    if ticks <= 0 {
        return None;
    }
    let utc = chrono::DateTime::from_timestamp(ticks / TICKS_PER_SECOND - SECONDS_1601_TO_1970, 0)?;
    Some(
        utc.with_timezone(&chrono::Local)
            .format("%Y-%m-%d")
            .to_string(),
    )
}

/// Why a package must stay. The text is what the list shows next to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Signed as part of Windows.
    System,
    Framework,
    Resource,
    Bundle,
    /// A sparse package: the identity of a normal program.
    Sparse,
    /// On the keep list: the Store, its helpers, Windows components and the
    /// runtimes apps are built on.
    Essential,
    /// Another installed package, named here, depends on it.
    RequiredBy(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::System => f.write_str("part of Windows"),
            Refusal::Framework => f.write_str("a framework other apps run on"),
            Refusal::Resource => f.write_str("a resource package of another app"),
            Refusal::Bundle => f.write_str("a bundle, not an app"),
            Refusal::Sparse => f.write_str("belongs to a program; uninstall the program instead"),
            Refusal::Essential => f.write_str("a Windows component Oxidize keeps"),
            Refusal::RequiredBy(name) => write!(f, "{name} depends on it"),
        }
    }
}

impl Serialize for Refusal {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Identity names of packages Windows or the Store relies on even though
/// they are not signed as part of Windows.
const ESSENTIAL_NAMES: [&str; 8] = [
    "Microsoft.WindowsStore",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.StorePurchaseApp",
    "Microsoft.SecHealthUI",
    // Infrastructure installed as ordinary Store apps: winget's package
    // source, the Xbox and PC Game Pass services, the widgets runtime and
    // the compatibility fixes Windows Update delivers.
    "Microsoft.Winget.Source",
    "Microsoft.GamingServices",
    "Microsoft.WidgetsPlatformRuntime",
    "Microsoft.ApplicationCompatibilityEnhancements",
];

/// Name prefixes of Windows components and of the runtimes apps run on.
const ESSENTIAL_PREFIXES: [&str; 8] = [
    "Microsoft.Windows.",
    "MicrosoftWindows.",
    "Microsoft.VCLibs",
    "Microsoft.UI.Xaml",
    "Microsoft.NET.Native",
    "Microsoft.WindowsAppRuntime",
    // The Windows App SDK runtime's main and singleton packages, which ship
    // under a second publisher name.
    "MicrosoftCorporationII.WinAppRuntime.",
    // Handwriting recognition per language, used by the pen and touch keyboard.
    "Microsoft.Ink.Handwriting.",
];

fn is_essential(name: &str) -> bool {
    ESSENTIAL_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name))
        || ESSENTIAL_PREFIXES.iter().any(|prefix| {
            name.get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        })
}

/// Whether Oxidize may ever remove `package`. `installed` is every package
/// listed with it, so one that another depends on stays. Pure: it decides
/// from the fields alone and asks Windows nothing.
pub fn package_guard(package: &Package, installed: &[Package]) -> Result<(), Refusal> {
    if package.signature == SignatureKind::System {
        return Err(Refusal::System);
    }
    if package.is_framework {
        return Err(Refusal::Framework);
    }
    if package.is_resource {
        return Err(Refusal::Resource);
    }
    if package.is_bundle {
        return Err(Refusal::Bundle);
    }
    if package.is_sparse {
        return Err(Refusal::Sparse);
    }
    if is_essential(&package.name) {
        return Err(Refusal::Essential);
    }
    let family = &package.family_name;
    let dependent = installed.iter().find(|other| {
        !other.family_name.eq_ignore_ascii_case(family)
            && other
                .dependencies
                .iter()
                .any(|d| d.eq_ignore_ascii_case(family))
    });
    match dependent {
        Some(other) => Err(Refusal::RequiredBy(other.display_name.clone())),
        None => Ok(()),
    }
}

/// Whether `name` has the shape of a package family name: an identity name
/// of letters, digits, dots and dashes, an underscore, then the 13-character
/// publisher id. Nothing else may become a folder name below `Packages`.
fn is_family_name(name: &str) -> bool {
    let Some((identity, publisher_id)) = name.rsplit_once('_') else {
        return false;
    };
    let identity_ok = identity
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && identity.chars().any(|c| c.is_ascii_alphanumeric());
    let publisher_ok = publisher_id.len() == 13
        && publisher_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    identity_ok && publisher_ok
}

/// The app's data folder, `<local_appdata>\Packages\<family name>`, when it
/// is still there: a real folder exactly one level below `Packages`, never a
/// link, and only for a name with the family-name shape.
pub fn data_folder(local_appdata: &Path, family_name: &str) -> Option<PathBuf> {
    if !is_family_name(family_name) {
        return None;
    }
    let packages = local_appdata.join("Packages");
    let folder = packages.join(family_name);
    if folder.parent() != Some(packages.as_path()) {
        return None;
    }
    let meta = std::fs::symlink_metadata(&folder).ok()?;
    (meta.is_dir() && !meta.file_type().is_symlink()).then_some(folder)
}

/// Where Windows keeps what belongs to its packages: the `WindowsApps`
/// folders and aliases, every `Packages` folder, the AppModel and
/// AppContainer registry. A scan by name never reports anything there.
fn is_package_managed(leftover: &Leftover) -> bool {
    let path = leftover.path.to_lowercase().replace('/', "\\");
    let in_folder = path
        .split('\\')
        .any(|part| part == "windowsapps" || part == "packages");
    let registry = [leftover.subpath.as_deref(), Some(path.as_str())]
        .into_iter()
        .flatten()
        .map(str::to_lowercase)
        .any(|p| p.contains("appmodel") || p.contains("appcontainer"));
    in_folder || registry
}

/// What a removed Store app left: its data folder under `local_appdata`
/// (High), then what a scan by name found elsewhere, never above Medium and
/// never in a place Windows manages for its packages.
pub fn leftovers(
    package: &Package,
    local_appdata: Option<&Path>,
    by_name: Vec<Leftover>,
) -> Vec<Leftover> {
    let mut items = Vec::new();
    if let Some(folder) = local_appdata.and_then(|dir| data_folder(dir, &package.family_name)) {
        let size = scanner::dir_size(&folder);
        let empty = scanner::is_dir_empty(&folder);
        items.push(Leftover::fs(
            LeftoverKind::Directory,
            folder,
            Confidence::High,
            "the app's data folder, still there after removal",
            Some(size),
            empty,
        ));
    }
    items.extend(
        by_name
            .into_iter()
            .filter(|l| !is_package_managed(l))
            .map(|mut l| {
                l.confidence = l.confidence.max(Confidence::Medium);
                l
            }),
    );
    items
}

/// A fixed list of packages standing in for Windows.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    use std::cell::RefCell;

    /// Packages in memory. `remove` takes one off the list and records it;
    /// nothing reaches Windows.
    pub(crate) struct FakePackageStore {
        packages: RefCell<Vec<Package>>,
        /// Full names passed to `remove`, in order.
        pub(crate) removed: RefCell<Vec<String>>,
        /// Every removal fails with this text, as Windows' `ErrorText` would.
        pub(crate) fail_with: Option<String>,
        /// Windows reports success but keeps the package registered.
        pub(crate) keeps_registered: bool,
        /// Family names Windows installs for new accounts.
        pub(crate) provisioned: Vec<String>,
    }

    impl FakePackageStore {
        pub(crate) fn new(packages: Vec<Package>) -> Self {
            FakePackageStore {
                packages: RefCell::new(packages),
                removed: RefCell::new(Vec::new()),
                fail_with: None,
                keeps_registered: false,
                provisioned: Vec::new(),
            }
        }
    }

    impl PackageStore for FakePackageStore {
        fn list(&self) -> Result<Vec<Package>> {
            Ok(self.packages.borrow().clone())
        }

        fn is_registered(&self, family_name: &str) -> Result<bool> {
            Ok(self
                .packages
                .borrow()
                .iter()
                .any(|p| p.family_name.eq_ignore_ascii_case(family_name)))
        }

        fn remove(&self, package: &Package) -> Result<RemovalOutcome> {
            self.removed.borrow_mut().push(package.full_name.clone());
            if let Some(error) = &self.fail_with {
                bail!("Windows did not remove {}: {error}", package.display_name);
            }
            if self.keeps_registered {
                return Ok(RemovalOutcome::StillRegistered);
            }
            self.packages
                .borrow_mut()
                .retain(|p| p.full_name != package.full_name);
            Ok(RemovalOutcome::Removed)
        }

        fn is_provisioned(&self, family_name: &str) -> Result<bool> {
            Ok(self
                .provisioned
                .iter()
                .any(|f| f.eq_ignore_ascii_case(family_name)))
        }
    }

    /// An ordinary Store app with nothing that protects it.
    pub(crate) fn package(name: &str, display_name: &str) -> Package {
        Package {
            family_name: format!("{name}_8wekyb3d8bbwe"),
            full_name: format!("{name}_1.2.3.0_x64__8wekyb3d8bbwe"),
            name: name.to_string(),
            display_name: display_name.to_string(),
            publisher: Some("Vendor".to_string()),
            version: "1.2.3.0".to_string(),
            signature: SignatureKind::Store,
            is_framework: false,
            is_resource: false,
            is_bundle: false,
            is_sparse: false,
            installed_path: Some(format!(r"C:\Program Files\WindowsApps\{name}")),
            installed_date: Some("2026-09-01".to_string()),
            dependencies: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{package, FakePackageStore};
    use super::*;

    fn refusal(package: &Package) -> Option<Refusal> {
        package_guard(package, std::slice::from_ref(package)).err()
    }

    #[test]
    fn an_ordinary_store_app_may_go() {
        assert_eq!(refusal(&package("Vendor.Notes", "Notes")), None);
        let mut sideloaded = package("Vendor.Notes", "Notes");
        sideloaded.signature = SignatureKind::Developer;
        assert_eq!(refusal(&sideloaded), None);
    }

    #[test]
    fn a_package_signed_as_part_of_windows_stays() {
        let mut p = package("Vendor.Notes", "Notes");
        p.signature = SignatureKind::System;
        assert_eq!(refusal(&p), Some(Refusal::System));
    }

    #[test]
    fn frameworks_resources_and_bundles_stay() {
        let mut framework = package("Vendor.Runtime", "Runtime");
        framework.is_framework = true;
        assert_eq!(refusal(&framework), Some(Refusal::Framework));

        let mut resource = package("Vendor.Notes", "Notes");
        resource.is_resource = true;
        assert_eq!(refusal(&resource), Some(Refusal::Resource));

        let mut bundle = package("Vendor.Notes", "Notes");
        bundle.is_bundle = true;
        assert_eq!(refusal(&bundle), Some(Refusal::Bundle));
    }

    #[test]
    fn a_sparse_package_points_to_its_program() {
        let mut p = package("Vendor.Editor", "Editor");
        p.is_sparse = true;
        assert_eq!(refusal(&p), Some(Refusal::Sparse));
        assert!(Refusal::Sparse
            .to_string()
            .contains("uninstall the program instead"));
    }

    #[test]
    fn the_store_and_its_helpers_stay() {
        for name in [
            "Microsoft.WindowsStore",
            "Microsoft.DesktopAppInstaller",
            "Microsoft.StorePurchaseApp",
            "Microsoft.SecHealthUI",
            "microsoft.windowsstore",
            "Microsoft.Winget.Source",
            "Microsoft.GamingServices",
            "Microsoft.WidgetsPlatformRuntime",
            "Microsoft.ApplicationCompatibilityEnhancements",
        ] {
            assert_eq!(
                refusal(&package(name, name)),
                Some(Refusal::Essential),
                "{name}"
            );
        }
    }

    #[test]
    fn windows_components_and_runtimes_stay_by_name_prefix() {
        for name in [
            "Microsoft.Windows.Photos",
            "MicrosoftWindows.Client.WebExperience",
            "Microsoft.VCLibs.140.00.UWPDesktop",
            "Microsoft.UI.Xaml.2.8",
            "Microsoft.NET.Native.Framework.2.2",
            "Microsoft.WindowsAppRuntime.1.8",
            "MICROSOFT.VCLIBS.140.00",
            "MicrosoftCorporationII.WinAppRuntime.Main.1.8",
            "MicrosoftCorporationII.WinAppRuntime.Singleton",
            "Microsoft.Ink.Handwriting.Main.en-US.1.0.1",
        ] {
            assert_eq!(
                refusal(&package(name, name)),
                Some(Refusal::Essential),
                "{name}"
            );
        }
    }

    #[test]
    fn a_name_that_only_starts_like_a_listed_one_may_go() {
        // `Microsoft.Windows.` needs its dot; the four names match whole.
        for name in [
            "Microsoft.WindowsCalculator",
            "Microsoft.WindowsStoreCompanion",
            "Microsoft.Win",
        ] {
            assert_eq!(refusal(&package(name, name)), None, "{name}");
        }
    }

    #[test]
    fn a_package_another_one_depends_on_stays() {
        let base = package("Vendor.Engine", "Engine");
        let mut app = package("Vendor.Studio", "Studio");
        app.dependencies = vec!["vendor.engine_8wekyb3d8bbwe".to_string()];
        let installed = [base.clone(), app.clone()];
        assert_eq!(
            package_guard(&base, &installed),
            Err(Refusal::RequiredBy("Studio".to_string()))
        );
        assert_eq!(
            Refusal::RequiredBy("Studio".to_string()).to_string(),
            "Studio depends on it"
        );
        // The dependent itself may go, and so may the base once nothing
        // installed depends on it.
        assert_eq!(package_guard(&app, &installed), Ok(()));
        assert_eq!(package_guard(&base, std::slice::from_ref(&base)), Ok(()));
    }

    #[test]
    fn depending_on_its_own_family_protects_nothing() {
        let mut p = package("Vendor.Notes", "Notes");
        p.dependencies = vec![p.family_name.clone()];
        assert_eq!(refusal(&p), None);
    }

    #[test]
    fn a_refusal_serializes_as_its_reason() {
        assert_eq!(
            serde_json::to_value(Refusal::System).unwrap(),
            "part of Windows"
        );
    }

    #[test]
    fn a_winrt_date_becomes_a_calendar_day() {
        // 2024-03-15 12:00 UTC: the same day in every usual time zone.
        let noon = (1_710_504_000 + 11_644_473_600) * 10_000_000;
        assert_eq!(date_from_ticks(noon).as_deref(), Some("2024-03-15"));
        assert_eq!(date_from_ticks(0), None);
    }

    #[test]
    fn an_apps_own_resource_packages_are_not_its_dependencies() {
        let deps = [
            "Microsoft.UI.Xaml.2.8_8wekyb3d8bbwe",
            "Vendor.Notes_8wekyb3d8bbwe",
            "Microsoft.VCLibs.140.00_8wekyb3d8bbwe",
            "vendor.notes_8wekyb3d8bbwe",
            "Microsoft.UI.Xaml.2.8_8wekyb3d8bbwe",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            other_families("Vendor.Notes_8wekyb3d8bbwe", deps),
            [
                "Microsoft.UI.Xaml.2.8_8wekyb3d8bbwe",
                "Microsoft.VCLibs.140.00_8wekyb3d8bbwe"
            ]
        );
    }

    #[test]
    fn every_signature_kind_is_mapped() {
        assert_eq!(
            signature_kind(PackageSignatureKind::System),
            SignatureKind::System
        );
        assert_eq!(
            signature_kind(PackageSignatureKind::Store),
            SignatureKind::Store
        );
        assert_eq!(
            signature_kind(PackageSignatureKind::Developer),
            SignatureKind::Developer
        );
        assert_eq!(
            signature_kind(PackageSignatureKind::Enterprise),
            SignatureKind::Enterprise
        );
        assert_eq!(
            signature_kind(PackageSignatureKind(42)),
            SignatureKind::None
        );
    }

    #[test]
    fn the_fake_store_answers_like_windows() {
        let store = FakePackageStore::new(vec![package("Vendor.Notes", "Notes")]);
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.is_registered("vendor.notes_8wekyb3d8bbwe").unwrap());
        assert!(!store.is_registered("Vendor.Other_8wekyb3d8bbwe").unwrap());
    }

    #[test]
    fn the_fake_store_removes_only_what_it_is_given() {
        let notes = package("Vendor.Notes", "Notes");
        let store = FakePackageStore::new(vec![notes.clone(), package("Vendor.Paint", "Paint")]);
        assert_eq!(store.remove(&notes).unwrap(), RemovalOutcome::Removed);
        assert_eq!(*store.removed.borrow(), [notes.full_name.as_str()]);
        assert!(!store.is_registered(&notes.family_name).unwrap());
        assert!(store.is_registered("Vendor.Paint_8wekyb3d8bbwe").unwrap());

        let mut failing = FakePackageStore::new(vec![notes.clone()]);
        failing.fail_with = Some("0x80073CF1".to_string());
        let err = failing.remove(&notes).unwrap_err();
        assert!(format!("{err:#}").contains("0x80073CF1"));
        assert!(failing.is_registered(&notes.family_name).unwrap());
    }

    /// An empty `Packages` folder below a fresh folder standing in for
    /// `%LOCALAPPDATA%`.
    fn local_appdata(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("oxidize_package_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Packages")).unwrap();
        dir
    }

    #[test]
    fn only_a_family_name_shape_names_a_data_folder() {
        for good in [
            "Vendor.Notes_8wekyb3d8bbwe",
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
            "5319275A.WhatsAppDesktop_cv1g1gvanyjgm",
            "Vendor-App_0123456789abc",
        ] {
            assert!(is_family_name(good), "{good}");
        }
        for bad in [
            "",
            "Vendor.Notes",
            "Vendor.Notes_",
            "_8wekyb3d8bbwe",
            "Vendor.Notes_8wekyb3d8bbw",
            "Vendor.Notes_8wekyb3d8bbwee",
            "Vendor.Notes_8WEKYB3D8BBWE",
            r"..\..\Windows_8wekyb3d8bbwe",
            r"Vendor\Notes_8wekyb3d8bbwe",
            "Vendor/Notes_8wekyb3d8bbwe",
            ".._8wekyb3d8bbwe",
            "C:_8wekyb3d8bbwe",
            "Vendor Notes_8wekyb3d8bbwe",
        ] {
            assert!(!is_family_name(bad), "{bad}");
        }
    }

    #[test]
    fn the_data_folder_is_a_real_folder_one_level_below_packages() {
        let local = local_appdata("data_folder");
        let family = "Vendor.Notes_8wekyb3d8bbwe";
        assert_eq!(data_folder(&local, family), None, "not there");
        std::fs::create_dir_all(local.join("Packages").join(family).join("LocalState")).unwrap();
        assert_eq!(
            data_folder(&local, family),
            Some(local.join("Packages").join(family))
        );
        // A file is not a data folder, and a crafted name never leaves
        // Packages.
        std::fs::write(
            local.join("Packages").join("Vendor.File_8wekyb3d8bbwe"),
            b"x",
        )
        .unwrap();
        assert_eq!(data_folder(&local, "Vendor.File_8wekyb3d8bbwe"), None);
        assert_eq!(data_folder(&local, r"..\Packages_8wekyb3d8bbwe"), None);
        assert_eq!(data_folder(&local, "Packages"), None);
        assert_eq!(data_folder(&local, ""), None);
        let _ = std::fs::remove_dir_all(&local);
    }

    fn found(path: &str, confidence: Confidence) -> Leftover {
        Leftover::fs(
            LeftoverKind::Directory,
            PathBuf::from(path),
            confidence,
            "name match",
            Some(0),
            true,
        )
    }

    #[test]
    fn leftovers_are_the_data_folder_then_name_matches_capped_at_medium() {
        let local = local_appdata("leftovers");
        let notes = package("Vendor.Notes", "Notes");
        let folder = local.join("Packages").join(&notes.family_name);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("settings.dat"), b"12345").unwrap();
        let by_name = vec![
            found(r"C:\Users\x\AppData\Roaming\Notes", Confidence::High),
            found(r"C:\ProgramData\Notes", Confidence::Low),
            found(
                r"C:\Program Files\WindowsApps\Vendor.Notes_1.2.3.0_x64__8wekyb3d8bbwe",
                Confidence::High,
            ),
            found(
                r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\notes.exe",
                Confidence::High,
            ),
            found(
                r"C:\Users\x\AppData\Local\Packages\Vendor.Other_8wekyb3d8bbwe",
                Confidence::High,
            ),
            Leftover::reg_key(
                crate::model::Hive::CurrentUser,
                r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Families\Vendor.Notes_8wekyb3d8bbwe",
                Confidence::High,
                "name match",
            ),
        ];
        let items = leftovers(&notes, Some(&local), by_name);
        let summary: Vec<(String, Confidence)> = items
            .iter()
            .map(|l| (l.path.clone(), l.confidence))
            .collect();
        assert_eq!(
            summary,
            [
                (folder.display().to_string(), Confidence::High),
                (
                    r"C:\Users\x\AppData\Roaming\Notes".to_string(),
                    Confidence::Medium
                ),
                (r"C:\ProgramData\Notes".to_string(), Confidence::Low),
            ]
        );
        assert_eq!(items[0].size_bytes, Some(5));
        assert_eq!(items[0].kind, LeftoverKind::Directory);

        // Gone with the package: nothing of it is reported.
        std::fs::remove_dir_all(&folder).unwrap();
        assert!(leftovers(&notes, Some(&local), Vec::new()).is_empty());
        assert!(leftovers(&notes, None, Vec::new()).is_empty());
        let _ = std::fs::remove_dir_all(&local);
    }
}
