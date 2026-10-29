//! The traces on a stand-in profile: a folder the tests make and a key
//! under `HKEY_CURRENT_USER\Software\OxidizeTest` that each test deletes
//! again. Windows' own calls are faked; nothing of the signed-in user's
//! profile is read or changed.

use std::fs;
use std::sync::Mutex;

use winreg::{enums::RegType, RegValue};

use super::*;
use crate::clean::files::tests::fixture;
use crate::clean::jumplist::tests::jump_list;

/// Windows as the tests see it. Clearing the recent items leaves only the
/// pinned items in a list, as Windows does; the thumbnail cache is emptied
/// to its header.
struct FakeShell {
    calls: Mutex<Vec<&'static str>>,
    clipboard: Mutex<ClipboardState>,
    recent_dir: Option<PathBuf>,
    fail: bool,
}

impl FakeShell {
    fn new(places: &TracePlaces, clipboard: ClipboardState) -> Self {
        FakeShell {
            calls: Mutex::new(Vec::new()),
            clipboard: Mutex::new(clipboard),
            recent_dir: places.automatic(),
            fail: false,
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

impl Shell for FakeShell {
    fn clear_recent(&self) -> Result<()> {
        self.calls.lock().unwrap().push("clear_recent");
        if self.fail {
            anyhow::bail!("refused");
        }
        let Some(dir) = &self.recent_dir else {
            return Ok(());
        };
        for (path, _) in files_in(dir, |n| n.ends_with(".automaticdestinations-ms")) {
            if let Ok(d) = jumplist::read(&path) {
                if d.pinned > 0 {
                    fs::write(&path, jump_list(d.pinned, d.pinned)).unwrap();
                }
            }
        }
        Ok(())
    }
    fn clipboard(&self) -> ClipboardState {
        *self.clipboard.lock().unwrap()
    }
    fn clear_clipboard(&self) -> Result<()> {
        self.calls.lock().unwrap().push("clear_clipboard");
        let mut c = self.clipboard.lock().unwrap();
        if let ClipboardState::Items(_) = *c {
            *c = ClipboardState::Items(0);
        }
        Ok(())
    }
    fn purge_thumbnails(&self, dir: &Path) -> Result<()> {
        self.calls.lock().unwrap().push("purge_thumbnails");
        if self.fail {
            anyhow::bail!("refused");
        }
        for (path, _) in thumbnail_files(dir) {
            fs::write(&path, [0u8; 24]).unwrap();
        }
        Ok(())
    }
    fn refresh(&self, dirs: &[PathBuf]) {
        assert!(!dirs.is_empty());
        self.calls.lock().unwrap().push("refresh");
    }
}

/// A stand-in profile. Its registry key and folder go when the test ends,
/// also when it fails.
struct Profile {
    root: crate::backup::TestDir,
    places: TracePlaces,
    key: String,
}

impl Drop for Profile {
    fn drop(&mut self) {
        let _ = hkcu().delete_subkey_all(&self.key);
        // The parent goes once no other test uses it.
        let _ = hkcu().delete_subkey(STAND_IN_KEY);
    }
}

impl Profile {
    fn new(name: &str) -> Profile {
        let root = fixture(&format!("traces_{name}"));
        let places = TracePlaces::stand_in(&root);
        let key = places
            .explorer_key
            .strip_suffix(r"\Explorer")
            .unwrap()
            .to_string();
        let _ = hkcu().delete_subkey_all(&key);
        Profile { root, places, key }
    }

    fn recent(&self) -> PathBuf {
        self.places.recent.clone().unwrap()
    }

    fn thumbs(&self) -> PathBuf {
        self.places.thumbnails.clone().unwrap()
    }

    fn file(&self, path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn explorer(&self, rel: &str) -> RegKey {
        let path = if rel.is_empty() {
            self.places.explorer_key.clone()
        } else {
            format!(r"{}\{rel}", self.places.explorer_key)
        };
        hkcu().create_subkey(path).unwrap().0
    }

    fn set(&self, rel: &str, name: &str, data: &str) {
        self.explorer(rel).set_value(name, &data).unwrap();
    }

    fn set_bin(&self, rel: &str, name: &str, len: usize) {
        self.explorer(rel)
            .set_raw_value(
                name,
                &RegValue {
                    bytes: vec![1; len].into(),
                    vtype: RegType::REG_BINARY,
                },
            )
            .unwrap();
    }

    fn values(&self, rel: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .explorer(rel)
            .enum_values()
            .filter_map(Result::ok)
            .map(|(n, _)| n)
            .collect();
        v.sort();
        v
    }

    fn subkeys(&self, rel: &str) -> Vec<String> {
        self.explorer(rel)
            .enum_keys()
            .filter_map(Result::ok)
            .collect()
    }

    /// Everything a used profile holds, and what lies beside it.
    fn used(name: &str) -> Profile {
        let p = Profile::new(name);
        let recent = p.recent();
        for n in ["shot-1.png.lnk", "shot-2.png.lnk", "Notes.lnk"] {
            p.file(&recent.join(n), &[1; 100]);
        }
        p.file(&recent.join("desktop.ini"), b"[.ShellClassInfo]");
        let auto = recent.join("AutomaticDestinations");
        p.file(&auto.join("a1.automaticDestinations-ms"), &jump_list(5, 0));
        p.file(&auto.join("b2.automaticDestinations-ms"), &jump_list(4, 2));
        p.file(&auto.join("c3.automaticDestinations-ms"), b"broken");
        let custom = recent.join("CustomDestinations");
        p.file(&custom.join("d4.customDestinations-ms"), &[2; 300]);
        p.file(&custom.join("notes.txt"), b"not a list");
        let thumbs = p.thumbs();
        p.file(&thumbs.join("thumbcache_256.db"), &[3; 1000]);
        p.file(&thumbs.join("thumbcache_idx.db"), &[3; 100]);
        p.file(&thumbs.join("iconcache_32.db"), &[4; 500]);
        // The files the lists point to.
        p.file(&p.root.join(r"Pictures\Screenshots\shot-1.png"), &[5; 64]);

        p.set("RunMRU", "a", r"cmd\1");
        p.set("RunMRU", "b", r"regedit\1");
        p.set("RunMRU", "MRUList", "ba");
        for (i, v) in ["C:\\", "D:\\Games", "%TEMP%"].iter().enumerate() {
            p.set("TypedPaths", &format!("url{}", i + 1), v);
        }
        p.set_bin("WordWheelQuery", "0", 12);
        p.set_bin("WordWheelQuery", "1", 12);
        p.set_bin("WordWheelQuery", "MRUListEx", 12);
        for i in 0..3 {
            p.set_bin("RecentDocs", &i.to_string(), 40);
        }
        p.set_bin("RecentDocs", "MRUListEx", 16);
        p.set_bin(r"RecentDocs\.png", "0", 40);
        p.set_bin(r"RecentDocs\.png", "1", 40);
        for i in 0..3 {
            p.set_bin(r"ComDlg32\OpenSavePidlMRU\*", &i.to_string(), 30);
        }
        p.set_bin(r"ComDlg32\OpenSavePidlMRU\png", "0", 30);
        p.set_bin(r"ComDlg32\OpenSavePidlMRU\png", "1", 30);
        p.set_bin(r"ComDlg32\CIDSizeMRU", "0", 20);
        p.set_bin(r"ComDlg32\CIDSizeMRU", "MRUListEx", 8);
        let count = r"UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";
        for n in [
            "{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\\abgrcnq.rkr",
            "Zvpebfbsg.Cubgbf",
            "n",
            "o",
        ] {
            p.set_bin(count, n, 72);
        }
        p.set_bin(count, "HRZR_PGYFRFFVBA", 72);
        p.explorer(r"UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}")
            .set_value("Version", &5u32)
            .unwrap();
        // Beside the lists: settings, and a dialog's first folder.
        p.explorer("Advanced").set_value("Hidden", &1u32).unwrap();
        p.set_bin(r"ComDlg32\FirstFolder", "0", 20);
        p
    }
}

fn find(findings: &[TraceFinding], t: Trace) -> &TraceFinding {
    findings.iter().find(|f| f.trace == t).unwrap()
}

#[test]
fn the_analysis_counts_every_trace_and_changes_nothing() {
    let p = Profile::used("analyse");
    let shell = FakeShell::new(&p.places, ClipboardState::Items(7));
    let a = analyse(&p.places, &Protected::default(), &shell);
    assert_eq!(a.len(), Trace::ALL.len());

    let recent = find(&a, Trace::RecentItems);
    assert_eq!((recent.count, recent.bytes), (3, 300));

    let lists = find(&a, Trace::JumpLists);
    // The list without pins and the custom one go; the pinned one and the
    // broken one stay.
    assert_eq!(lists.count, 2);
    assert_eq!(
        lists
            .kept
            .iter()
            .map(|k| (k.reason.code(), k.count))
            .collect::<Vec<_>>(),
        [("pinned", 1), ("unreadable", 1)]
    );
    assert_eq!(lists.notes, ["7 recent items"]);

    let n = |t| find(&a, t).count;
    assert_eq!(n(Trace::RunHistory), 2);
    assert_eq!(n(Trace::TypedPaths), 3);
    assert_eq!(n(Trace::SearchHistory), 2);
    // The list across all types, not each file twice.
    assert_eq!(n(Trace::RecentDocs), 3);
    assert_eq!(n(Trace::DialogHistory), 3 + 1);
    assert_eq!(n(Trace::LaunchCounts), 4);
    assert_eq!(n(Trace::Clipboard), 7);
    assert_eq!(find(&a, Trace::RecentDocs).bytes, 3 * 40 + 16 + 2 * 40);

    let thumbs = find(&a, Trace::Thumbnails);
    assert!(!thumbs.count_known);
    assert_eq!(thumbs.bytes, 1100, "the icon cache is not part of it");

    let (count, _) = total(&a);
    assert_eq!(count, 3 + 2 + 2 + 3 + 2 + 3 + 4 + 4 + 7);
    assert!(shell.calls().is_empty(), "an analysis calls nothing");
    assert_eq!(p.values("RunMRU"), ["MRUList", "a", "b"]);
    assert!(p.recent().join("Notes.lnk").exists());
}

#[test]
fn clearing_empties_the_lists_and_keeps_files_pins_and_settings() {
    let p = Profile::used("clear");
    let shell = FakeShell::new(&p.places, ClipboardState::Items(7));
    let done = clear(&p.places, &Protected::default(), &shell);

    assert_eq!(
        shell.calls(),
        [
            "clear_recent",
            "purge_thumbnails",
            "clear_clipboard",
            "refresh"
        ]
    );
    let recent = p.recent();
    assert!(!recent.join("Notes.lnk").exists());
    assert!(!recent.join("shot-1.png.lnk").exists());
    assert!(recent.join("desktop.ini").exists());
    let auto = recent.join("AutomaticDestinations");
    assert!(!auto.join("a1.automaticDestinations-ms").exists());
    let pinned = jumplist::read(&auto.join("b2.automaticDestinations-ms")).unwrap();
    assert_eq!((pinned.entries, pinned.pinned), (2, 2), "the pins stay");
    assert!(auto.join("c3.automaticDestinations-ms").exists());
    let custom = recent.join("CustomDestinations");
    assert!(!custom.join("d4.customDestinations-ms").exists());
    assert!(custom.join("notes.txt").exists());
    assert_eq!(
        fs::metadata(p.thumbs().join("thumbcache_256.db"))
            .unwrap()
            .len(),
        24
    );
    assert_eq!(
        fs::metadata(p.thumbs().join("iconcache_32.db"))
            .unwrap()
            .len(),
        500
    );
    assert!(p.root.join(r"Pictures\Screenshots\shot-1.png").exists());

    for rel in [
        "RunMRU",
        "TypedPaths",
        "WordWheelQuery",
        "RecentDocs",
        r"ComDlg32\CIDSizeMRU",
    ] {
        assert!(p.values(rel).is_empty(), "{rel} is empty");
        assert!(p.subkeys(rel).is_empty(), "{rel} has no parts left");
    }
    assert!(p.subkeys(r"ComDlg32\OpenSavePidlMRU").is_empty());
    let guid = r"UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";
    assert!(p.values(&format!(r"{guid}\Count")).is_empty());
    assert_eq!(p.values(guid), ["Version"]);
    assert_eq!(p.values("Advanced"), ["Hidden"]);
    assert_eq!(p.values(r"ComDlg32\FirstFolder"), ["0"]);

    let n = |t| find(&done, t).count;
    assert_eq!(n(Trace::RecentItems), 3);
    assert_eq!(n(Trace::JumpLists), 2);
    assert_eq!(n(Trace::RunHistory), 2);
    assert_eq!(n(Trace::LaunchCounts), 4);
    assert_eq!(n(Trace::Clipboard), 7);
    assert_eq!(find(&done, Trace::Thumbnails).bytes, 1100 - 48);
    assert!(done.iter().all(|f| !f.failed()), "{done:#?}");
    let lists = find(&done, Trace::JumpLists);
    assert!(lists.kept.iter().any(|k| k.reason == KeptReason::Pinned));

    // A second run finds nothing more to clear.
    let again = analyse(&p.places, &Protected::default(), &shell);
    let (count, _) = total(&again);
    assert_eq!(count, 0);
}

#[test]
fn a_protected_folder_keeps_its_traces() {
    let p = Profile::used("protected");
    let shell = FakeShell::new(&p.places, ClipboardState::Off);
    let protected = Protected::new([p.recent().display().to_string()]);
    let a = analyse(&p.places, &protected, &shell);
    let recent = find(&a, Trace::RecentItems);
    assert_eq!(recent.count, 0);
    assert_eq!(recent.kept[0].reason, KeptReason::Protected);
    assert_eq!(recent.kept[0].count, 3);
    clear(&p.places, &protected, &shell);
    assert!(p.recent().join("Notes.lnk").exists());
    assert!(p
        .recent()
        .join(r"AutomaticDestinations\a1.automaticDestinations-ms")
        .exists());
    assert!(p.values("RunMRU").is_empty(), "the registry lists still go");
}

#[test]
fn a_list_held_open_stays_and_says_why() {
    use std::os::windows::fs::OpenOptionsExt;
    let p = Profile::used("held");
    let shell = FakeShell::new(&p.places, ClipboardState::Absent);
    let path = p
        .recent()
        .join(r"AutomaticDestinations\a1.automaticDestinations-ms");
    // Readable, but not deletable while open, as Explorer holds a list it
    // is writing.
    let _held = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)
        .unwrap();
    let done = clear(&p.places, &Protected::default(), &shell);
    let lists = find(&done, Trace::JumpLists);
    assert!(path.exists());
    assert_eq!(lists.count, 1, "the custom list still went");
    assert!(lists.failed());
    assert!(lists
        .kept
        .iter()
        .any(|k| k.reason == KeptReason::InUse && k.count == 1));
    let stays = crate::clean::stays_text(&lists.kept).unwrap();
    assert!(stays.contains("in use"), "{stays}");
}

#[test]
fn windows_refusing_is_reported() {
    let p = Profile::used("refused");
    let mut shell = FakeShell::new(&p.places, ClipboardState::Absent);
    shell.fail = true;
    let done = clear(&p.places, &Protected::default(), &shell);
    let thumbs = find(&done, Trace::Thumbnails);
    assert!(thumbs.failed());
    assert_eq!(thumbs.bytes, 0);
    assert!(find(&done, Trace::JumpLists).failed());
    // Its own work still happened.
    assert!(!p.recent().join("Notes.lnk").exists());
    assert!(p.values("TypedPaths").is_empty());
}

#[test]
fn the_clipboard_is_cleared_only_when_there_is_one() {
    let p = Profile::new("clipboard");
    for (state, actionable) in [
        (ClipboardState::Off, false),
        (ClipboardState::Absent, false),
        (ClipboardState::Items(0), false),
        (ClipboardState::Items(3), true),
        (ClipboardState::Unreadable, true),
    ] {
        let shell = FakeShell::new(&p.places, state);
        let f = clipboard(&shell);
        assert_eq!(f.actionable(), actionable, "{state:?}");
        let done = clear(&p.places, &Protected::default(), &shell);
        assert_eq!(
            shell.calls().contains(&"clear_clipboard"),
            actionable,
            "{state:?}"
        );
        let c = find(&done, Trace::Clipboard);
        if state == ClipboardState::Unreadable {
            assert_eq!(c.notes, ["cleared"]);
        }
    }
    assert_eq!(
        clipboard(&FakeShell::new(&p.places, ClipboardState::Off)).notes,
        ["clipboard history is off"]
    );
}

#[test]
fn an_empty_profile_has_nothing_to_clear() {
    let p = Profile::new("empty");
    let shell = FakeShell::new(&p.places, ClipboardState::Absent);
    let a = analyse(&p.places, &Protected::default(), &shell);
    assert!(a.iter().all(|f| !f.actionable()));
    let done = clear(&p.places, &Protected::default(), &shell);
    assert!(done.iter().all(|f| f.count == 0 && !f.failed()));
    assert!(!shell.calls().contains(&"purge_thumbnails"));
}

#[test]
fn a_stand_in_profile_never_reaches_windows() {
    let root = PathBuf::from(r"C:\Fixtures\profile-7");
    let places = TracePlaces::stand_in(&root);
    assert!(!places.own_profile);
    assert_eq!(
        places.explorer_key,
        r"Software\OxidizeTest\profile-7\Explorer"
    );
    assert_eq!(
        places.recent.unwrap(),
        root.join(r"Roaming\Microsoft\Windows\Recent")
    );
    assert_eq!(
        shell_for(&TracePlaces::stand_in(&root)).clipboard(),
        ClipboardState::Absent
    );
}

#[test]
fn the_stand_in_shell_deletes_only_thumbnail_caches() {
    let p = Profile::used("standin");
    StandInShell.purge_thumbnails(&p.thumbs()).unwrap();
    assert!(!p.thumbs().join("thumbcache_256.db").exists());
    assert!(p.thumbs().join("iconcache_32.db").exists());
}

#[test]
fn bookkeeping_values_are_not_entries() {
    for n in ["MRUList", "mrulistex", "HRZR_PGYFRFFVBA"] {
        assert!(bookkeeping(n), "{n}");
    }
    for n in ["a", "0", "url1", "Zvpebfbsg.Cubgbf"] {
        assert!(!bookkeeping(n), "{n}");
    }
}

#[test]
fn amounts_read_as_words() {
    assert_eq!(Trace::RecentItems.amount(1), "1 shortcut");
    assert_eq!(Trace::SearchHistory.amount(2), "2 searches");
    assert_eq!(Trace::TypedPaths.amount(0), "0 addresses");
    for t in Trace::ALL {
        assert!(!t.title().is_empty() && !t.about().is_empty());
    }
}

#[test]
fn a_file_explorer_took_first_is_not_a_failure() {
    let dir = fixture("traces_gone_first");
    let file = dir.join("recent.lnk");
    fs::write(&file, "x").unwrap();
    remove_if_there(&file).unwrap();
    assert!(!file.exists());
    // Gone already: the state that was asked for.
    remove_if_there(&file).unwrap();
    // Anything else is still an error.
    fs::create_dir_all(dir.join("a folder")).unwrap();
    assert!(remove_if_there(&dir.join("a folder")).is_err());
}
