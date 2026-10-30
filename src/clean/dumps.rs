//! Crash dumps one by one, with the program each belongs to, so a cleaning
//! can take single dumps or leave the dumps of one program.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::files::Candidate;
use super::DUMPS;

/// One dump: a dump file, or an error report's folder with all it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dump {
    pub path: PathBuf,
    pub bytes: u64,
    pub files: usize,
    /// The program that crashed, by its file name, where the dump's name
    /// says it.
    pub program: Option<String>,
}

/// The program a dump's name names: `app.exe.1234.dmp`, the way Windows
/// names a program's own dump, or `AppCrash_app.exe_1f2e..._3a4b...`, the
/// way it names an error report.
pub fn program_of(name: &str) -> Option<String> {
    if let Some((stem, ext)) = name.rsplit_once('.') {
        if DUMPS.contains(&ext.to_ascii_lowercase().as_str()) {
            let (program, pid) = stem.rsplit_once('.')?;
            let pid_only = !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit());
            return (pid_only && !program.is_empty()).then(|| program.to_string());
        }
    }
    let (_, rest) = name.split_once('_')?;
    let end = rest.to_ascii_lowercase().find(".exe_")? + ".exe".len();
    (end > ".exe".len()).then(|| rest[..end].to_string())
}

/// Do the two name the same program? Case and a trailing `.exe` do not
/// count.
pub fn same_program(a: &str, b: &str) -> bool {
    let key = |s: &str| {
        let s = s.trim().to_lowercase();
        s.strip_suffix(".exe").map(str::to_string).unwrap_or(s)
    };
    key(a) == key(b)
}

/// The dumps among the candidates of a walk of `root`: each file right in
/// `root` is one, and so is each folder right in it with everything below.
/// A walk of a single file has that file as its one dump.
pub fn group(root: &Path, candidates: &[Candidate]) -> Vec<Dump> {
    let mut out: Vec<Dump> = Vec::new();
    for c in candidates.iter().filter(|c| !c.dir) {
        let path = match c.path.strip_prefix(root) {
            Ok(rest) => match rest.components().next() {
                Some(first) => root.join(first),
                None => c.path.clone(),
            },
            Err(_) => c.path.clone(),
        };
        match out.iter_mut().find(|d| d.path == path) {
            Some(d) => {
                d.bytes += c.bytes;
                d.files += 1;
            }
            None => out.push(Dump {
                program: path
                    .file_name()
                    .and_then(|n| program_of(&n.to_string_lossy())),
                path,
                bytes: c.bytes,
                files: 1,
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dump_names_its_program_the_way_windows_writes_it() {
        assert_eq!(program_of("app.exe.1234.dmp").as_deref(), Some("app.exe"));
        assert_eq!(
            program_of("Some Tool.exe.88.MDMP").as_deref(),
            Some("Some Tool.exe")
        );
        assert_eq!(
            program_of("AppCrash_my_tool.exe_1f2e3d_4c5b6a_cab_0a1b").as_deref(),
            Some("my_tool.exe")
        );
        assert_eq!(
            program_of("AppHang_Viewer.EXE_77aa_bb88").as_deref(),
            Some("Viewer.EXE")
        );
    }

    #[test]
    fn a_dump_without_a_program_in_its_name_has_none() {
        for name in [
            "MEMORY.DMP",
            "103025-12345-01.dmp",
            "app.exe.dmp",
            ".1234.dmp",
            "notes.txt",
            "WATCHDOG",
            "AppCrash_.exe_1f2e",
            "Kernel_141_abc",
        ] {
            assert_eq!(program_of(name), None, "{name}");
        }
    }

    #[test]
    fn a_program_is_the_same_with_or_without_exe_in_any_case() {
        assert!(same_program("App.exe", "app"));
        assert!(same_program("app", "APP.EXE"));
        assert!(!same_program("app.exe", "apps.exe"));
    }

    #[test]
    fn the_files_of_one_report_folder_make_one_dump() {
        let root = Path::new(r"C:\Dumps");
        let cand = |rel: &str, bytes: u64, dir: bool| Candidate {
            path: root.join(rel),
            bytes,
            dir,
            key: String::new(),
        };
        let dumps = group(
            root,
            &[
                cand("app.exe.1.dmp", 400, false),
                cand(r"AppCrash_x.exe_1f_2e\Report.wer", 60, false),
                cand(r"AppCrash_x.exe_1f_2e\memory.hdmp", 900, false),
                cand(r"AppCrash_x.exe_1f_2e", 0, true),
            ],
        );
        assert_eq!(
            dumps,
            [
                Dump {
                    path: root.join("app.exe.1.dmp"),
                    bytes: 400,
                    files: 1,
                    program: Some("app.exe".into()),
                },
                Dump {
                    path: root.join("AppCrash_x.exe_1f_2e"),
                    bytes: 960,
                    files: 2,
                    program: Some("x.exe".into()),
                },
            ]
        );
    }

    #[test]
    fn a_single_file_walked_on_its_own_is_its_own_dump() {
        let root = Path::new(r"C:\Windows\MEMORY.DMP");
        let dumps = group(
            root,
            &[Candidate {
                path: root.to_path_buf(),
                bytes: 7,
                dir: false,
                key: String::new(),
            }],
        );
        assert_eq!(dumps.len(), 1);
        assert_eq!(dumps[0].path, root);
        assert_eq!(dumps[0].program, None);
    }
}
