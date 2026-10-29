//! Browser caches, and nothing else a browser keeps.
//!
//! Only folders whose names are on the lists below are emptied: the HTTP
//! cache, compiled scripts and shaders. Cookies, history, sessions, saved
//! logins, site storage, extensions and settings live in other files and
//! folders and are never opened. A browser that is running is skipped.

use std::path::{Path, PathBuf};

use super::files;

/// Cache folders inside a Chromium profile.
pub const CHROMIUM_PROFILE_CACHES: &[&str] = &[
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "Media Cache",
];

/// Cache folders beside the profiles, shared by all of them.
pub const CHROMIUM_SHARED_CACHES: &[&str] = &[
    "GrShaderCache",
    "ShaderCache",
    "GraphiteDawnCache",
    "GPUPersistentCache",
];

/// Cache folders in a Firefox profile's local folder.
pub const FIREFOX_CACHES: &[&str] = &["cache2", "startupCache", "jumpListCache"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Chromium,
    Firefox,
}

/// One installed browser's data.
#[derive(Debug, Clone)]
pub struct Browser {
    pub name: &'static str,
    pub family: Family,
    /// Chromium: the `User Data` folder. Firefox: the local `Profiles` folder.
    pub data: PathBuf,
    /// Firefox: the roaming `Profiles` folder, where its lock file is.
    pub roaming: Option<PathBuf>,
    /// The browser's executable name, lower case.
    pub exe: &'static str,
    /// Part of the path it runs from, lower case, to tell it from another
    /// program with the same executable name.
    pub runs_from: Option<&'static str>,
}

/// name, folder under `%LOCALAPPDATA%`, executable, where it runs from.
const CHROMIUM: &[(&str, &str, &str, &str)] = &[
    (
        "Chrome",
        r"Google\Chrome",
        "chrome.exe",
        r"google\chrome\application",
    ),
    (
        "Chrome Beta",
        r"Google\Chrome Beta",
        "chrome.exe",
        r"google\chrome beta\application",
    ),
    (
        "Chrome Dev",
        r"Google\Chrome Dev",
        "chrome.exe",
        r"google\chrome dev\application",
    ),
    (
        "Chrome Canary",
        r"Google\Chrome SxS",
        "chrome.exe",
        r"google\chrome sxs\application",
    ),
    (
        "Chromium",
        "Chromium",
        "chrome.exe",
        r"chromium\application",
    ),
    (
        "Edge",
        r"Microsoft\Edge",
        "msedge.exe",
        r"microsoft\edge\application",
    ),
    (
        "Edge Beta",
        r"Microsoft\Edge Beta",
        "msedge.exe",
        r"microsoft\edge beta\application",
    ),
    (
        "Edge Dev",
        r"Microsoft\Edge Dev",
        "msedge.exe",
        r"microsoft\edge dev\application",
    ),
    (
        "Edge Canary",
        r"Microsoft\Edge SxS",
        "msedge.exe",
        r"microsoft\edge sxs\application",
    ),
    (
        "Brave",
        r"BraveSoftware\Brave-Browser",
        "brave.exe",
        r"bravesoftware\brave-browser\application",
    ),
    (
        "Brave Beta",
        r"BraveSoftware\Brave-Browser-Beta",
        "brave.exe",
        r"bravesoftware\brave-browser-beta\application",
    ),
    (
        "Brave Nightly",
        r"BraveSoftware\Brave-Browser-Nightly",
        "brave.exe",
        r"bravesoftware\brave-browser-nightly\application",
    ),
    ("Vivaldi", "Vivaldi", "vivaldi.exe", r"vivaldi\application"),
];

/// The browsers with data under `local` (`%LOCALAPPDATA%`) and `roaming`
/// (`%APPDATA%`).
pub fn installed(local: &Path, roaming: Option<&Path>) -> Vec<Browser> {
    let mut out = Vec::new();
    for (name, folder, exe, runs_from) in CHROMIUM {
        let data = local.join(folder).join("User Data");
        if data.is_dir() {
            out.push(Browser {
                name,
                family: Family::Chromium,
                data,
                roaming: None,
                exe,
                runs_from: Some(runs_from),
            });
        }
    }
    let firefox = local.join(r"Mozilla\Firefox\Profiles");
    if firefox.is_dir() {
        out.push(Browser {
            name: "Firefox",
            family: Family::Firefox,
            data: firefox,
            roaming: roaming.map(|r| r.join(r"Mozilla\Firefox\Profiles")),
            exe: "firefox.exe",
            runs_from: None,
        });
    }
    out
}

/// The cache folders of a browser that exist, every profile included.
pub fn cache_dirs(b: &Browser) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&b.data) else {
        return out;
    };
    let profiles: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            e.file_type()
                .map(|t| t.is_dir() && !t.is_symlink())
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();
    match b.family {
        Family::Chromium => {
            for name in CHROMIUM_SHARED_CACHES {
                push_dir(&mut out, b.data.join(name));
            }
            // A profile is a folder with its own Preferences file.
            for profile in profiles.iter().filter(|p| p.join("Preferences").is_file()) {
                for name in CHROMIUM_PROFILE_CACHES {
                    push_dir(&mut out, profile.join(name));
                }
            }
        }
        Family::Firefox => {
            for profile in &profiles {
                for name in FIREFOX_CACHES {
                    push_dir(&mut out, profile.join(name));
                }
            }
        }
    }
    out
}

fn push_dir(out: &mut Vec<PathBuf>, p: PathBuf) {
    if std::fs::symlink_metadata(&p)
        .map(|m| m.is_dir() && !m.file_type().is_symlink())
        .unwrap_or(false)
    {
        out.push(p);
    }
}

/// Is the browser running? Either one of its processes runs from where it is
/// installed, or it holds the lock it keeps on its data while open.
pub fn is_running(b: &Browser, running: &[PathBuf]) -> bool {
    let by_process = running.iter().any(|exe| {
        let path = exe.to_string_lossy().to_lowercase().replace('/', "\\");
        let name_fits = exe
            .file_name()
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case(b.exe))
            .unwrap_or(false);
        name_fits && b.runs_from.is_none_or(|part| path.contains(part))
    });
    by_process || holds_lock(b)
}

fn holds_lock(b: &Browser) -> bool {
    match b.family {
        // Chromium creates this file when it starts and Windows deletes it
        // when the browser ends, a crash included.
        Family::Chromium => b.data.join("lockfile").exists(),
        // Firefox keeps this file but holds it open only while it runs.
        Family::Firefox => {
            let Some(roaming) = &b.roaming else {
                return false;
            };
            let Ok(entries) = std::fs::read_dir(roaming) else {
                return false;
            };
            entries.flatten().any(|e| {
                let lock = e.path().join("parent.lock");
                lock.exists() && files::probe(&lock) == files::Probe::InUse
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean::files::tests::{file_aged, fixture};
    use std::fs;

    /// A Chromium profile with its caches and everything a cache cleaner
    /// must leave alone.
    fn chromium_profile(user_data: &Path, profile: &str) {
        let p = user_data.join(profile);
        file_aged(&p.join("Preferences"), 10, 0);
        for keep in [
            "Cookies",
            "History",
            "Login Data",
            "Web Data",
            "Bookmarks",
            r"Sessions\Session_1",
            r"Local Storage\leveldb\000003.log",
            r"IndexedDB\site\data",
            r"Service Worker\CacheStorage\abc\index",
            r"Extensions\id\manifest.json",
        ] {
            file_aged(&p.join(keep), 5, 0);
        }
        file_aged(&p.join(r"Cache\Cache_Data\data_1"), 100, 0);
        file_aged(&p.join(r"Code Cache\js\index"), 30, 0);
        file_aged(&p.join(r"GPUCache\data_0"), 20, 0);
    }

    #[test]
    fn only_cache_folders_of_each_profile_are_listed() {
        let local = fixture("browsers");
        let user_data = local.join(r"BraveSoftware\Brave-Browser\User Data");
        chromium_profile(&user_data, "Default");
        chromium_profile(&user_data, "Profile 2");
        file_aged(&user_data.join(r"ShaderCache\data_0"), 7, 0);
        file_aged(&user_data.join("Local State"), 7, 0);
        // A folder without Preferences is not a profile.
        file_aged(&user_data.join(r"Crashpad\Cache\x"), 7, 0);

        let browsers = installed(&local, None);
        assert_eq!(browsers.len(), 1);
        assert_eq!(browsers[0].name, "Brave");
        let dirs = cache_dirs(&browsers[0]);
        let rel: Vec<String> = dirs
            .iter()
            .map(|d| d.strip_prefix(&user_data).unwrap().display().to_string())
            .collect();
        assert_eq!(rel.len(), 7, "{rel:?}");
        for d in &rel {
            let leaf = d.rsplit('\\').next().unwrap();
            assert!(
                CHROMIUM_PROFILE_CACHES.contains(&leaf) || CHROMIUM_SHARED_CACHES.contains(&leaf),
                "{d}"
            );
            assert!(!d.starts_with("Crashpad"), "{d}");
        }
    }

    #[test]
    fn cleaning_the_caches_leaves_cookies_history_sessions_and_logins() {
        use crate::clean::files::{delete, walk, Rule};
        use crate::clean::protect::Protected;
        let local = fixture("browsers_clean");
        let user_data = local.join(r"Google\Chrome\User Data");
        chromium_profile(&user_data, "Default");
        let b = &installed(&local, None)[0];
        let now = std::time::SystemTime::now();
        let rule = Rule::default();
        let mut freed = 0;
        for dir in cache_dirs(b) {
            let w = walk(&dir, &rule, &Protected::default(), now);
            freed += delete(&w.candidates, &rule, &Protected::default(), now).freed;
        }
        assert_eq!(freed, 150);
        let p = user_data.join("Default");
        for keep in [
            "Preferences",
            "Cookies",
            "History",
            "Login Data",
            "Web Data",
            "Bookmarks",
            r"Sessions\Session_1",
            r"Local Storage\leveldb\000003.log",
            r"IndexedDB\site\data",
            r"Service Worker\CacheStorage\abc\index",
            r"Extensions\id\manifest.json",
        ] {
            assert!(p.join(keep).exists(), "{keep}");
        }
        // The cache folders themselves stay for the browser to fill again.
        assert!(p.join("Cache").is_dir());
        assert!(!p.join(r"Cache\Cache_Data\data_1").exists());
    }

    #[test]
    fn a_running_browser_is_told_apart_from_a_namesake() {
        let local = fixture("browsers_running");
        let user_data = local.join(r"Google\Chrome\User Data");
        chromium_profile(&user_data, "Default");
        let b = &installed(&local, None)[0];
        let elsewhere = [PathBuf::from(
            r"C:\Users\Example\AppData\Local\ms-playwright\chromium-1\chrome-win\chrome.exe",
        )];
        assert!(!is_running(b, &elsewhere));
        assert!(!is_running(b, &[]));
        let installed_copy = [PathBuf::from(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )];
        assert!(is_running(b, &installed_copy));
        // The lock file alone says it runs, whatever the process list shows.
        fs::write(user_data.join("lockfile"), "").unwrap();
        assert!(is_running(b, &[]));
    }

    #[test]
    fn firefox_runs_while_it_holds_its_profile_lock() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = fixture("firefox");
        let local = root.join("Local");
        let roaming = root.join("Roaming");
        file_aged(
            &local.join(r"Mozilla\Firefox\Profiles\abc.default\cache2\entries\x"),
            40,
            0,
        );
        file_aged(
            &local.join(r"Mozilla\Firefox\Profiles\abc.default\thumbnails\t"),
            4,
            0,
        );
        let lock = roaming.join(r"Mozilla\Firefox\Profiles\abc.default\parent.lock");
        file_aged(&lock, 0, 0);
        let b = &installed(&local, Some(&roaming))[0];
        assert_eq!(b.family, Family::Firefox);
        assert_eq!(cache_dirs(b).len(), 1);
        assert!(!is_running(b, &[]));
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&lock)
            .unwrap();
        assert!(is_running(b, &[]));
        drop(held);
        assert!(is_running(
            b,
            &[PathBuf::from(r"D:\Apps\Firefox\firefox.exe")]
        ));
    }
}
