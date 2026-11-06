// The real program against a stand-in user folder, under a name nothing else carries.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const NAME: &str = "Quillmarkfixture";

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
    let home = std::env::temp_dir().join(format!("oxidize_user_folder_{}", std::process::id()));
    fs::create_dir_all(home.join(r"AppData\Roaming")).unwrap();
    fs::create_dir_all(home.join(r"AppData\Local")).unwrap();
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

    let (code, out) = run(&home, &["scan", NAME, "--remove", "-y"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["removal"]["failed"], 0);
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

    fs::remove_dir_all(&home).unwrap();
}
