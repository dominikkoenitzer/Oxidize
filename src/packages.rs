//! Store apps: the MSIX and AppX packages registered for the current user.
//! Oxidize lists them; nothing here removes one.

use anyhow::{Context, Result};
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
