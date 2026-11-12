// The real program against a stand-in user folder, under a name nothing else carries.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const NAME: &str = "Quillmarkfixture";

/// `oxidize_<name>_<process id>` under the system temp folder, so two runs at once never share it.
fn home_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("oxidize_{name}_{}", std::process::id()))
}

/// The stand-in user folder with its two AppData folders, removed when the test ends, passed or failed.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let path = home_path(name);
        // A run that was killed before its guard ran can leave the folder, and the process id comes round again.
        if let Err(e) = fs::remove_dir_all(&path) {
            assert!(
                e.kind() == std::io::ErrorKind::NotFound,
                "cannot clear {}: {e}",
                path.display()
            );
        }
        let app_data = path.join("AppData");
        fs::create_dir_all(app_data.join("Roaming")).unwrap();
        fs::create_dir_all(app_data.join("Local")).unwrap();
        Home(path)
    }
}

impl std::ops::Deref for Home {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(home: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_oxidize"))
        .args(args)
        .arg("--json")
        .env("USERPROFILE", home)
        .env("APPDATA", home.join(r"AppData\Roaming"))
        .env("LOCALAPPDATA", home.join(r"AppData\Local"))
        .output()
        .unwrap();
    let json = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "no JSON from {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap(), json)
}

fn found(report: &serde_json::Value) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = report["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| PathBuf::from(item["path"].as_str().unwrap()))
        .collect();
    paths.sort();
    paths
}

#[test]
fn settings_in_the_user_folder_are_found_removed_and_restored() {
    let home = Home::new("user_folder");
    let file = home.join("quillmarkfixture.json");
    let folder = home.join(r".config\quillmarkfixture");
    let notes = home.join("quillmarkfixture.txt");
    fs::create_dir_all(&folder).unwrap();
    fs::write(&file, "{}").unwrap();
    fs::write(folder.join("settings.toml"), "a = 1").unwrap();
    fs::write(&notes, "the user's own").unwrap();

    let (code, report) = run(&home, &["scan", NAME]);
    assert_eq!(code, 0);
    assert_eq!(found(&report), [folder.clone(), file.clone()]);

    let (code, out) = run(&home, &["scan", NAME, "--remove", "-y", "--backup"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["removal"]["failed"], 0);
    assert_eq!(out["removal"]["permanent"], false);
    assert!(!file.exists() && !folder.exists());
    assert!(notes.exists());
    // `.config` stood empty after that and is not ours to take.
    assert!(home.join(".config").is_dir());

    let (code, report) = run(&home, &["scan", NAME]);
    assert_eq!(code, 0);
    assert!(found(&report).is_empty(), "{report}");

    let backup = out["removal"]["backup"].as_str().unwrap();
    let (code, restored) = run(&home, &["restore", backup, "-y"]);
    assert_eq!(code, 0, "{restored}");
    assert_eq!(fs::read_to_string(&file).unwrap(), "{}");
    assert_eq!(
        fs::read_to_string(folder.join("settings.toml")).unwrap(),
        "a = 1"
    );
}

#[test]
fn without_backup_a_removal_keeps_nothing_to_restore() {
    let home = Home::new("user_folder_permanent");
    let file = home.join("quillmarkfixture.json");
    fs::write(&file, "{}").unwrap();

    let (code, out) = run(&home, &["scan", NAME, "--remove", "-y"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["removal"]["failed"], 0);
    assert_eq!(out["removal"]["permanent"], true);
    assert!(out["removal"]["backup"].is_null(), "{out}");
    assert!(!file.exists());
    assert!(!home.join(r"AppData\Local\Oxidize\backups").exists());
}

#[test]
fn a_failed_run_leaves_no_stand_in_home_behind() {
    let path = home_path("user_folder_unwind");
    let outcome = std::panic::catch_unwind(|| {
        let home = Home::new("user_folder_unwind");
        fs::write(home.join("quillmarkfixture.json"), "{}").unwrap();
        panic!("an assert failed halfway through");
    });
    assert!(outcome.is_err());
    let left = path.exists();
    let _ = fs::remove_dir_all(&path);
    assert!(!left, "the failed run left {} behind", path.display());
}

#[test]
fn a_new_run_starts_without_what_an_old_one_left() {
    let path = home_path("user_folder_leftover");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("from_an_earlier_run.txt"), "old").unwrap();
    let home = Home::new("user_folder_leftover");
    let stale = home.join("from_an_earlier_run.txt").exists();
    drop(home);
    let _ = fs::remove_dir_all(&path);
    assert!(!stale, "the new run started on top of an old run's files");
}
