//! Store apps: the MSIX and AppX packages registered for the current user.
//! Oxidize lists them; nothing here removes one.

use std::fmt;

use anyhow::{Context, Result};
use serde::{Serialize, Serializer};
use windows::core::HSTRING;
use windows::ApplicationModel::{self as appx, PackageSignatureKind};
use windows::Management::Deployment::{PackageManager, PackageTypes};

use crate::model::{Package, SignatureKind};

/// Where the installed packages come from: Windows, or a fixed list in tests.
pub trait PackageStore {
    /// Every main package registered for the current user.
    fn list(&self) -> Result<Vec<Package>>;

    /// Whether any package of this family is still registered for the
    /// current user.
    fn is_registered(&self, family_name: &str) -> Result<bool>;
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
const ESSENTIAL_NAMES: [&str; 4] = [
    "Microsoft.WindowsStore",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.StorePurchaseApp",
    "Microsoft.SecHealthUI",
];

/// Name prefixes of Windows components and of the runtimes apps run on.
const ESSENTIAL_PREFIXES: [&str; 6] = [
    "Microsoft.Windows.",
    "MicrosoftWindows.",
    "Microsoft.VCLibs",
    "Microsoft.UI.Xaml",
    "Microsoft.NET.Native",
    "Microsoft.WindowsAppRuntime",
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

/// A fixed list of packages standing in for Windows.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    pub(crate) struct FakePackageStore(pub Vec<Package>);

    impl PackageStore for FakePackageStore {
        fn list(&self) -> Result<Vec<Package>> {
            Ok(self.0.clone())
        }

        fn is_registered(&self, family_name: &str) -> Result<bool> {
            Ok(self
                .0
                .iter()
                .any(|p| p.family_name.eq_ignore_ascii_case(family_name)))
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
        let store = FakePackageStore(vec![package("Vendor.Notes", "Notes")]);
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.is_registered("vendor.notes_8wekyb3d8bbwe").unwrap());
        assert!(!store.is_registered("Vendor.Other_8wekyb3d8bbwe").unwrap());
    }
}
