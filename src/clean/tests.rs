//! The analysis and the cleaning end to end, on folders the tests make.

use std::fs;
use std::sync::Mutex;

use super::files::tests::{age, file_aged, fixture};
use super::recycle::tests::recycled;
use super::windows::StoreReport;
use super::*;

/// Windows' tools as the tests see them: each call is recorded, nothing
/// runs.
#[derive(Default)]
struct FakeTools {
    calls: Mutex<Vec<&'static str>>,
    delivery: Mutex<(usize, u64)>,
    /// The Delivery Optimization cache cannot be read once it is deleted.
    delivery_unreadable_after: Mutex<bool>,
    /// What the Delivery Optimization cache still holds after its delete.
    delivery_left: Mutex<(usize, u64)>,
    /// The previous Windows that Disk Cleanup removes; with none it stays.
    windows_old: Mutex<Option<PathBuf>>,
    /// What runs by the time the cleaning starts.
    running: Mutex<Vec<PathBuf>>,
    /// What git says about each checkout: uncommitted work or not, or None
    /// when it cannot tell.
    uncommitted: Mutex<Option<bool>>,
}

impl FakeTools {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
    fn call(&self, name: &'static str) {
        self.calls.lock().unwrap().push(name);
    }
}

impl Tools for FakeTools {
    fn component_store(&self) -> anyhow::Result<StoreReport> {
        self.call("component_store");
        Ok(StoreReport {
            reclaimable_packages: Some(2),
            cleanup_recommended: Some(true),
            ..Default::default()
        })
    }
    fn component_cleanup(&self) -> anyhow::Result<()> {
        self.call("component_cleanup");
        Ok(())
    }
    fn delivery_cache(&self) -> anyhow::Result<(usize, u64)> {
        self.call("delivery_cache");
        if *self.delivery_unreadable_after.lock().unwrap()
            && self.calls().contains(&"delete_delivery_cache")
        {
            anyhow::bail!("the cache could not be read");
        }
        Ok(*self.delivery.lock().unwrap())
    }
    fn delete_delivery_cache(&self) -> anyhow::Result<()> {
        self.call("delete_delivery_cache");
        *self.delivery.lock().unwrap() = *self.delivery_left.lock().unwrap();
        Ok(())
    }
    fn remove_windows_old(&self) -> anyhow::Result<()> {
        self.call("remove_windows_old");
        if let Some(dir) = self.windows_old.lock().unwrap().as_ref() {
            fs::remove_dir_all(dir).unwrap();
        }
        Ok(())
    }
    fn free_bytes(&self, _path: &Path) -> Option<u64> {
        Some(1000)
    }
    fn running_exes(&self) -> Vec<PathBuf> {
        self.running.lock().unwrap().clone()
    }
    fn uncommitted(&self, _dir: &Path) -> Option<bool> {
        self.call("uncommitted");
        *self.uncommitted.lock().unwrap()
    }
}

/// A PC in a folder: temp folders, dumps, a Recycle Bin, a browser and a
/// previous Windows.
struct Pc {
    root: crate::backup::TestDir,
    places: Places,
}

impl Pc {
    fn new(name: &str) -> Pc {
        let root = fixture(name);
        let user_temp = root.join("Temp");
        let windows_temp = root.join(r"Windows\Temp");
        let local = root.join("Local");
        let bin = root.join(r"$Recycle.Bin\S-1-5-21-1");
        for d in [&user_temp, &windows_temp, &local, &bin] {
            fs::create_dir_all(d).unwrap();
        }
        let places = Places {
            user_temp: Some(user_temp),
            windows_temp: Some(windows_temp),
            temp_check: TempCheck::default(),
            user_dumps: vec![
                Spot {
                    path: local.join("CrashDumps"),
                    extensions: Some(DUMPS),
                },
                Spot {
                    path: local.join(r"Microsoft\Windows\WER\ReportQueue"),
                    extensions: None,
                },
            ],
            machine_dumps: vec![Spot {
                path: root.join(r"Windows\Minidump"),
                extensions: Some(DUMPS),
            }],
            recycle_bins: vec![bin],
            local_appdata: Some(local),
            roaming_appdata: Some(root.join("Roaming")),
            windows_old: Some(root.join("Windows.old")),
            system_drive: Some(root.to_path_buf()),
            build_roots: vec![root.to_path_buf()],
        };
        Pc { root, places }
    }

    fn temp(&self) -> &Path {
        self.places.user_temp.as_deref().unwrap()
    }

    fn local(&self) -> &Path {
        self.places.local_appdata.as_deref().unwrap()
    }

    /// A little of everything.
    fn fill(&self) {
        let t = self.temp();
        file_aged(&t.join("old-setup.log"), 1000, 20);
        file_aged(&t.join("fresh.tmp"), 30, 1);
        file_aged(&t.join(r"unpacked\big.bin"), 500, 10);
        age(&t.join("unpacked"), 10);
        file_aged(&t.join(r"tools\helper.py"), 70, 60);
        age(&t.join("tools"), 60);
        let w = self.places.windows_temp.as_deref().unwrap();
        file_aged(&w.join("system.log"), 200, 30);
        let l = self.local();
        file_aged(&l.join(r"CrashDumps\app.exe.1234.dmp"), 400, 2);
        file_aged(&l.join(r"CrashDumps\notes.txt"), 9, 2);
        file_aged(
            &l.join(r"Microsoft\Windows\WER\ReportQueue\AppCrash_x\Report.wer"),
            60,
            2,
        );
        file_aged(&self.root.join(r"Windows\Minidump\101626-1.dmp"), 300, 2);
        let profile = l.join(r"Google\Chrome\User Data\Default");
        file_aged(&profile.join("Preferences"), 10, 0);
        file_aged(&profile.join("Cookies"), 10, 0);
        file_aged(&profile.join(r"Cache\Cache_Data\f_000001"), 800, 0);
        let bin = &self.places.recycle_bins[0];
        recycled(
            bin,
            "AAAAAA.zip",
            5000,
            60,
            r"C:\Users\Example\Downloads\old.zip",
        );
        recycled(
            bin,
            "BBBBBB.txt",
            40,
            2,
            r"C:\Users\Example\Desktop\note.txt",
        );
        file_aged(&self.root.join(r"Windows.old\Windows\big.sys"), 9000, 400);
    }

    fn orphan(&self, name: &str, bytes: usize) -> OrphanFolder {
        let path = self.root.join("AppData").join(name);
        file_aged(&path.join("data.bin"), bytes, 100);
        OrphanFolder {
            path,
            size_bytes: bytes as u64,
            modified: Some("2026-01-01".into()),
        }
    }

    /// Every file under the PC's folder with its size, to prove an analysis
    /// changed nothing.
    fn snapshot(&self) -> Vec<(PathBuf, u64)> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap().flatten() {
                let m = fs::symlink_metadata(e.path()).unwrap();
                if m.is_dir() {
                    stack.push(e.path());
                }
                out.push((e.path(), m.len()));
            }
        }
        out.sort();
        out
    }
}

fn analyse_with(
    pc: &Pc,
    protected: &Protected,
    elevated: bool,
    running: &[PathBuf],
    tools: &FakeTools,
    orphans: &(dyn Fn() -> Vec<OrphanItem> + Sync),
) -> Analysis {
    analyse(
        &pc.places,
        &Options {
            protected,
            elevated,
            now: SystemTime::now(),
            running,
            recycle_bin_days: RECYCLE_DAYS,
            tools,
            orphans,
        },
    )
}

fn no_orphans() -> Vec<OrphanItem> {
    Vec::new()
}

fn clean_with(
    pc: &Pc,
    a: &Analysis,
    choice: &Choice,
    protected: &Protected,
    elevated: bool,
    tools: &FakeTools,
) -> Vec<Cleaned> {
    clean(
        a,
        choice,
        &CleanOptions {
            protected,
            now: SystemTime::now(),
            elevated,
            make_backups: true,
            tools,
            system_drive: pc.places.system_drive.clone(),
        },
    )
}

fn kept(list: &[Kept], reason: &KeptReason) -> (usize, u64) {
    list.iter()
        .find(|k| &k.reason == reason)
        .map(|k| (k.count, k.bytes))
        .unwrap_or((0, 0))
}

#[test]
fn the_analysis_counts_every_category_and_changes_nothing() {
    let pc = Pc::new("analysis");
    pc.fill();
    let before = pc.snapshot();
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    assert_eq!(
        pc.snapshot(),
        before,
        "an analysis must not change anything"
    );

    let temp = a.finding(Category::Temp).unwrap();
    assert_eq!((temp.count, temp.bytes), (3, 1570));
    assert_eq!(kept(&temp.kept, &KeptReason::Recent(7)), (1, 30));
    // Windows' own temp folder is counted, but needs administrator rights.
    assert_eq!(kept(&temp.kept, &KeptReason::NeedsAdmin), (1, 200));
    assert!(temp.needs_admin);

    let dumps = a.finding(Category::CrashDumps).unwrap();
    assert_eq!((dumps.count, dumps.bytes), (2, 460));
    assert_eq!(kept(&dumps.kept, &KeptReason::NeedsAdmin), (1, 300));

    let bin = a.finding(Category::RecycleBin).unwrap();
    assert_eq!((bin.count, bin.bytes), (1, 5000));
    assert_eq!(kept(&bin.kept, &KeptReason::RecentlyDeleted(30)), (1, 40));

    let caches = a.finding(Category::BrowserCache).unwrap();
    assert_eq!((caches.count, caches.bytes), (1, 800));
    assert_eq!(caches.notes, ["Chrome"]);

    let old = a.finding(Category::WindowsOld).unwrap();
    assert!(old.needs_admin && !old.preselected);
    assert_eq!(kept(&old.kept, &KeptReason::NeedsAdmin), (1, 9000));

    // Without administrator rights DISM is not even asked.
    let store = a.finding(Category::ComponentStore).unwrap();
    assert!(store.needs_admin && !store.actionable());
    assert_eq!(tools.calls(), ["delivery_cache"]);
}

#[test]
fn a_temp_folder_inside_windows_one_is_counted_once() {
    for elevated in [false, true] {
        let mut pc = Pc::new(&format!("temp_inside_{elevated}"));
        pc.fill();
        let inner = pc.places.windows_temp.as_ref().unwrap().join("1");
        file_aged(&inner.join("old.log"), 100, 20);
        file_aged(&inner.join(r"setup\data.bin"), 400, 20);
        age(&inner.join("setup"), 20);
        age(&inner, 20);
        pc.places.user_temp = Some(inner.clone());
        let tools = FakeTools::default();
        let a = analyse_with(
            &pc,
            &Protected::default(),
            elevated,
            &[],
            &tools,
            &no_orphans,
        );
        let temp = a.finding(Category::Temp).unwrap();
        // The user's two files, and Windows' own log beside the folder.
        let (counted, needs_admin) = if elevated {
            ((3, 700), (0, 0))
        } else {
            ((2, 500), (1, 200))
        };
        assert_eq!((temp.count, temp.bytes), counted, "elevated {elevated}");
        assert_eq!(
            kept(&temp.kept, &KeptReason::NeedsAdmin),
            needs_admin,
            "elevated {elevated}"
        );
        let done = clean_with(
            &pc,
            &a,
            &a.choice(&[Category::Temp], Confidence::High),
            &Protected::default(),
            elevated,
            &tools,
        );
        assert_eq!(
            (done[0].removed, done[0].freed),
            counted,
            "elevated {elevated}"
        );
        // The user's temp folder itself is not Windows' to take.
        assert!(inner.is_dir(), "elevated {elevated}");
    }
    // The same folder named twice is walked once.
    for elevated in [false, true] {
        let mut pc = Pc::new(&format!("temp_same_{elevated}"));
        pc.fill();
        pc.places.user_temp = pc.places.windows_temp.clone();
        let tools = FakeTools::default();
        let a = analyse_with(
            &pc,
            &Protected::default(),
            elevated,
            &[],
            &tools,
            &no_orphans,
        );
        let temp = a.finding(Category::Temp).unwrap();
        assert_eq!((temp.count, temp.bytes), (1, 200), "elevated {elevated}");
        assert_eq!(kept(&temp.kept, &KeptReason::NeedsAdmin), (0, 0));
    }
}

#[test]
fn the_safe_set_is_chosen_unless_the_user_says_otherwise() {
    let pc = Pc::new("safe_set");
    pc.fill();
    let tools = FakeTools::default();
    *tools.delivery.lock().unwrap() = (3, 700);
    let a = analyse_with(&pc, &Protected::default(), true, &[], &tools, &no_orphans);
    let choice = a.default_choice();
    assert_eq!(
        choice.categories,
        [Category::Temp, Category::CrashDumps, Category::BrowserCache]
    );
    for opt_in in [
        Category::RecycleBin,
        Category::ComponentStore,
        Category::DeliveryOptimization,
        Category::WindowsOld,
    ] {
        assert!(!a.finding(opt_in).unwrap().preselected, "{opt_in:?}");
        assert!(a.finding(opt_in).unwrap().actionable(), "{opt_in:?}");
    }
    // Elevated, the analysis reads the store but cleans nothing.
    let mut calls = tools.calls();
    calls.sort_unstable();
    assert_eq!(calls, ["component_store", "delivery_cache"]);
}

#[test]
fn the_summaries_add_up_per_category_and_count_what_the_list_kept() {
    let pc = Pc::new("clean_summary");
    pc.fill();
    let tools = FakeTools::default();
    let protected = Protected::new([pc.temp().join("tools").display().to_string()]);
    let a = analyse_with(&pc, &protected, false, &[], &tools, &no_orphans);
    let before = a.summary();
    assert_eq!(before.categories.len(), a.findings.len());
    for f in &a.findings {
        let s = &before.categories[f.category.id()];
        assert_eq!((s.bytes, s.count), (f.bytes, f.count), "{:?}", f.category);
    }
    assert_eq!(
        before.bytes,
        a.findings.iter().map(|f| f.bytes).sum::<u64>()
    );
    assert_eq!(before.categories["temp"].protected.count, 1);
    assert_eq!(before.protected.count, 1);

    let done = clean_with(&pc, &a, &a.default_choice(), &protected, false, &tools);
    let after = cleaned_summary(&done);
    let temp = done.iter().find(|d| d.category == Category::Temp).unwrap();
    assert_eq!(
        (
            after.categories["temp"].bytes,
            after.categories["temp"].count
        ),
        (temp.freed, temp.removed)
    );
    assert_eq!(after.bytes, done.iter().map(|c| c.freed).sum::<u64>());
    // The protected folder stayed, and the run says so as the plan did.
    assert_eq!(
        after.categories["temp"].protected,
        before.categories["temp"].protected
    );
    assert!(pc.temp().join(r"tools\helper.py").exists());
    // Only what was chosen is in the run's summary.
    assert_eq!(after.categories.len(), done.len());
    let json = serde_json::to_value(&after).unwrap();
    assert_eq!(json["protected"]["count"], 1);
    assert!(json["categories"]["temp"]["bytes"].is_u64());
}

#[test]
fn cleaning_the_safe_set_frees_what_was_counted_and_reports_the_rest() {
    use std::os::windows::fs::OpenOptionsExt;
    let pc = Pc::new("clean_safe");
    pc.fill();
    file_aged(&pc.temp().join("held.log"), 25, 30);
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(pc.temp().join("held.log"))
        .unwrap();
    let tools = FakeTools::default();
    let protected = Protected::new([pc.temp().join("tools").display().to_string()]);
    let a = analyse_with(&pc, &protected, false, &[], &tools, &no_orphans);
    let temp = a.finding(Category::Temp).unwrap();
    assert_eq!(kept(&temp.kept, &KeptReason::InUse), (1, 25));
    assert_eq!(kept(&temp.kept, &KeptReason::Protected).0, 1);

    let done = clean_with(&pc, &a, &a.default_choice(), &protected, false, &tools);
    let by = |c: Category| done.iter().find(|d| d.category == c).unwrap();
    let t = by(Category::Temp);
    assert_eq!((t.removed, t.freed), (2, 1500));
    assert_eq!(kept(&t.kept, &KeptReason::InUse), (1, 25));
    assert_eq!(kept(&t.kept, &KeptReason::Recent(7)), (1, 30));
    assert_eq!(kept(&t.kept, &KeptReason::NeedsAdmin), (1, 200));
    assert!(pc.temp().join(r"tools\helper.py").exists());
    assert!(pc.temp().join("fresh.tmp").exists());
    assert!(pc.temp().join("held.log").exists());
    assert!(!pc.temp().join("unpacked").exists());

    let d = by(Category::CrashDumps);
    assert_eq!((d.removed, d.freed), (2, 460));
    assert!(pc.local().join(r"CrashDumps\notes.txt").exists());
    assert!(pc.root.join(r"Windows\Minidump\101626-1.dmp").exists());
    assert!(pc
        .places
        .windows_temp
        .as_ref()
        .unwrap()
        .join("system.log")
        .exists());

    let b = by(Category::BrowserCache);
    assert_eq!((b.removed, b.freed), (1, 800));
    assert!(pc
        .local()
        .join(r"Google\Chrome\User Data\Default\Cookies")
        .exists());

    // Nothing that was not chosen was touched.
    assert_eq!(done.len(), 3);
    assert!(pc.places.recycle_bins[0].join("$RAAAAAA.zip").exists());
    assert!(pc.root.join(r"Windows.old\Windows\big.sys").exists());
    assert!(tools
        .calls()
        .iter()
        .all(|c| !c.starts_with("remove") && !c.ends_with("cleanup")));
    drop(held);
}

#[test]
fn a_protected_folder_inside_temp_is_left_whole() {
    let pc = Pc::new("protect_temp");
    let t = pc.temp();
    file_aged(&t.join(r"my-tools\a\b\old.js"), 10, 90);
    file_aged(&t.join(r"my-tools\notes.md"), 10, 90);
    age(&t.join(r"my-tools\a\b"), 90);
    age(&t.join(r"my-tools\a"), 90);
    age(&t.join("my-tools"), 90);
    file_aged(&t.join("lock.md"), 5, 90);
    file_aged(&t.join("junk.tmp"), 5, 90);
    std::env::set_var("OXIDIZE_TEST_TEMP", t);
    let protected = Protected::new([
        "%OXIDIZE_TEST_TEMP%\\my-tools".to_string(),
        t.join("lock.md").display().to_string(),
    ]);
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &protected, false, &[], &tools, &no_orphans);
    let done = clean_with(
        &pc,
        &a,
        &a.choice(&[Category::Temp], Confidence::High),
        &protected,
        false,
        &tools,
    );
    assert_eq!(done[0].removed, 1);
    assert!(t.join(r"my-tools\a\b\old.js").exists());
    assert!(t.join(r"my-tools\notes.md").exists());
    assert!(t.join("lock.md").exists());
    assert!(!t.join("junk.tmp").exists());
}

#[test]
fn a_running_browser_keeps_its_cache_and_says_why() {
    let pc = Pc::new("browser_running");
    pc.fill();
    let running = [PathBuf::from(
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    )];
    let tools = FakeTools::default();
    let a = analyse_with(
        &pc,
        &Protected::default(),
        false,
        &running,
        &tools,
        &no_orphans,
    );
    let f = a.finding(Category::BrowserCache).unwrap();
    assert_eq!(f.count, 0);
    assert_eq!(
        kept(&f.kept, &KeptReason::Running("Chrome".into())),
        (1, 800)
    );
    assert!(!f.actionable());
    let choice = a.choice(&[Category::BrowserCache], Confidence::High);
    assert!(choice.categories.is_empty());
    clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    assert!(pc
        .local()
        .join(r"Google\Chrome\User Data\Default\Cache\Cache_Data\f_000001")
        .exists());
}

#[test]
fn a_browser_started_after_the_analysis_keeps_its_cache() {
    let pc = Pc::new("browser_started");
    pc.fill();
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    let f = a.finding(Category::BrowserCache).unwrap();
    assert_eq!((f.count, f.bytes), (1, 800));
    let choice = a.choice(&[Category::BrowserCache], Confidence::High);

    // The user starts the browser before clicking Clean.
    *tools.running.lock().unwrap() = vec![PathBuf::from(
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    )];
    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    let c = &done[0];
    assert_eq!((c.removed, c.freed), (0, 0));
    assert_eq!(
        kept(&c.kept, &KeptReason::Running("Chrome".into())),
        (1, 800)
    );
    let cache = pc
        .local()
        .join(r"Google\Chrome\User Data\Default\Cache\Cache_Data\f_000001");
    assert!(cache.exists());

    // Closed again, the same analysis cleans it.
    tools.running.lock().unwrap().clear();
    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    assert_eq!((done[0].removed, done[0].freed), (1, 800));
    assert!(!cache.exists());
}

#[test]
fn the_recycle_bin_goes_only_when_chosen_and_only_old_items() {
    let pc = Pc::new("bin_category");
    pc.fill();
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    assert!(!a
        .default_choice()
        .categories
        .contains(&Category::RecycleBin));
    let done = clean_with(
        &pc,
        &a,
        &a.choice(&[Category::RecycleBin], Confidence::High),
        &Protected::default(),
        false,
        &tools,
    );
    assert_eq!((done[0].removed, done[0].freed), (1, 5000));
    let bin = &pc.places.recycle_bins[0];
    assert!(!bin.join("$RAAAAAA.zip").exists());
    assert!(bin.join("$RBBBBBB.txt").exists());

    // A shorter age takes the newer item as well.
    let a = analyse(
        &pc.places,
        &Options {
            protected: &Protected::default(),
            elevated: false,
            now: SystemTime::now(),
            running: &[],
            recycle_bin_days: 1,
            tools: &tools,
            orphans: &no_orphans,
        },
    );
    assert_eq!(a.finding(Category::RecycleBin).unwrap().count, 1);
    assert_eq!(a.recycle_bin_days, 1);
}

#[test]
fn windows_tools_run_only_when_chosen_and_elevated() {
    let pc = Pc::new("tools");
    pc.fill();
    let tools = FakeTools::default();
    *tools.delivery.lock().unwrap() = (4, 900);
    let a = analyse_with(&pc, &Protected::default(), true, &[], &tools, &no_orphans);
    let old = a.finding(Category::WindowsOld).unwrap();
    assert_eq!(old.bytes, 9000);
    assert!(old.notes.iter().any(|n| n.contains("way back")));

    clean_with(
        &pc,
        &a,
        &a.default_choice(),
        &Protected::default(),
        true,
        &tools,
    );
    assert!(!tools.calls().contains(&"remove_windows_old"));
    assert!(!tools.calls().contains(&"component_cleanup"));

    let all = [
        Category::ComponentStore,
        Category::DeliveryOptimization,
        Category::WindowsOld,
    ];
    let done = clean_with(
        &pc,
        &a,
        &a.choice(&all, Confidence::High),
        &Protected::default(),
        true,
        &tools,
    );
    let calls = tools.calls();
    for call in [
        "component_cleanup",
        "delete_delivery_cache",
        "remove_windows_old",
    ] {
        assert_eq!(calls.iter().filter(|c| **c == call).count(), 1, "{call}");
    }
    let dopt = done
        .iter()
        .find(|d| d.category == Category::DeliveryOptimization)
        .unwrap();
    assert_eq!(dopt.freed, 900);
}

#[test]
fn a_delivery_cache_that_cannot_be_read_again_is_not_measured() {
    let pc = Pc::new("delivery_unread");
    let tools = FakeTools::default();
    *tools.delivery.lock().unwrap() = (4, 900);
    *tools.delivery_unreadable_after.lock().unwrap() = true;
    let a = analyse_with(&pc, &Protected::default(), true, &[], &tools, &no_orphans);
    let done = clean_with(
        &pc,
        &a,
        &a.choice(&[Category::DeliveryOptimization], Confidence::High),
        &Protected::default(),
        true,
        &tools,
    );
    assert!(tools.calls().contains(&"delete_delivery_cache"));
    let dopt = &done[0];
    assert_eq!(dopt.category, Category::DeliveryOptimization);
    assert_eq!((dopt.freed, dopt.removed), (0, 0));
    assert!(
        dopt.notes.iter().any(|n| n.starts_with("not measured")),
        "{:?}",
        dopt.notes
    );
    assert!(!dopt.failed());
}

#[test]
fn delivery_files_still_in_the_cache_are_not_reported_as_removed() {
    let pc = Pc::new("delivery-left");
    let tools = FakeTools::default();
    *tools.delivery.lock().unwrap() = (4, 900);
    *tools.delivery_left.lock().unwrap() = (1, 300);
    let a = analyse_with(&pc, &Protected::default(), true, &[], &tools, &no_orphans);
    let done = clean_with(
        &pc,
        &a,
        &a.choice(&[Category::DeliveryOptimization], Confidence::High),
        &Protected::default(),
        true,
        &tools,
    );
    assert_eq!((done[0].removed, done[0].freed), (3, 600));
    let left = KeptReason::Failed("still there afterwards".to_string());
    assert_eq!(kept(&done[0].kept, &left), (1, 300));
}

#[test]
fn windows_old_counts_as_removed_only_once_it_is_gone() {
    let pc = Pc::new("windows-old-left");
    pc.fill();
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &Protected::default(), true, &[], &tools, &no_orphans);
    let choice = a.choice(&[Category::WindowsOld], Confidence::High);
    let done = clean_with(&pc, &a, &choice, &Protected::default(), true, &tools);
    assert_eq!(done[0].removed, 0);
    let left = KeptReason::Failed("still there afterwards".to_string());
    assert_eq!(kept(&done[0].kept, &left), (1, 9000));

    *tools.windows_old.lock().unwrap() = Some(pc.root.join("Windows.old"));
    let done = clean_with(&pc, &a, &choice, &Protected::default(), true, &tools);
    assert_eq!(done[0].removed, 1);
    assert!(!done[0].failed());
}

#[test]
fn only_a_high_match_to_a_removed_program_is_chosen_and_it_comes_back() {
    let pc = Pc::new("orphans");
    let exact = pc.orphan("Quillmark Studio", 120);
    let loose = pc.orphan("Quillmark", 30);
    let other = pc.orphan("PortableThing", 50);
    let kept_folder = pc.orphan("Kept Folder", 10);
    let removed = vec![("Quillmark Studio".to_string(), None)];
    let snap = scanner::Snapshot::with_programs(Vec::new());
    let scored = score_orphans(
        &[
            exact.clone(),
            loose.clone(),
            other.clone(),
            kept_folder.clone(),
        ],
        &removed,
        &snap,
    );
    let conf = |p: &Path| scored.iter().find(|o| o.path == p).unwrap().confidence;
    assert_eq!(conf(&exact.path), Confidence::High);
    assert_eq!(conf(&other.path), Confidence::Low);
    assert_ne!(conf(&loose.path), Confidence::High);

    let protected = Protected::new([kept_folder.path.display().to_string()]);
    let source = move || scored.clone();
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &protected, false, &[], &tools, &source);
    let f = a.finding(Category::Orphans).unwrap();
    assert!(f.preselected);
    assert_eq!(f.folders.len(), 3);
    assert_eq!(kept(&f.kept, &KeptReason::Protected).0, 1);
    let choice = a.default_choice();
    assert_eq!(choice.folders, std::slice::from_ref(&exact.path));
    assert_eq!(
        a.chosen_bytes(&a.choice(&[Category::Orphans], Confidence::High)),
        120
    );

    let done = clean_with(
        &pc,
        &a,
        &a.choice(&[Category::Orphans], Confidence::High),
        &protected,
        false,
        &tools,
    );
    let o = &done[0];
    let base = crate::backup::backups_base().unwrap();
    let _cleanup = crate::backup::TestCleanup(o.backup.iter().map(|b| base.join(b)).collect());
    assert_eq!((o.removed, o.freed), (1, 120));
    assert!(!exact.path.exists());
    assert!(loose.path.exists() && other.path.exists() && kept_folder.path.exists());

    // The folder went into a backup and comes back from it.
    let name = o.backup.clone().expect("a backup");
    let info = crate::backup::find_backup(&name).unwrap();
    let restored = crate::restore::restore(&info, false).unwrap();
    assert!(restored.iter().all(|r| r.result.is_ok()));
    assert_eq!(fs::read(exact.path.join("data.bin")).unwrap().len(), 120);
    crate::backup::delete_backup(&info).unwrap();
}

#[test]
fn installer_removal_events_name_the_products_that_went() {
    let xml = "<Event><System><EventID>1034</EventID></System><EventData>\
        <Data>Quillmark Studio</Data><Data>2.1</Data><Data>1033</Data><Data>0</Data>\
        <Data>Quill &amp; Ink Ltd</Data><Data>(NULL)</Data><Binary>00</Binary></EventData></Event>\
        <Event><EventData><Data>Failed Thing</Data><Data>1</Data><Data>1033</Data>\
        <Data>1603</Data><Data>Someone</Data></EventData></Event>\
        <Event><EventData><Data>No Maker</Data><Data>1</Data><Data>1033</Data><Data>0</Data>\
        <Data>(NULL)</Data></EventData></Event>";
    assert_eq!(
        parse_installer_removals(xml),
        [
            (
                "Quillmark Studio".to_string(),
                Some("Quill & Ink Ltd".to_string())
            ),
            ("No Maker".to_string(), None),
        ]
    );
}

#[test]
fn installer_removal_events_keep_accented_names() {
    // Without /uni:true wevtutil writes the ANSI code page, which cannot hold every name.
    assert!(
        INSTALLER_EVENTS.contains(&"/uni:true"),
        "{INSTALLER_EVENTS:?}"
    );
    let xml = "<Event><EventData><Data>Bürotext Éditeur</Data><Data>3.0</Data>\
        <Data>1031</Data><Data>0</Data><Data>Zürcher Werkstatt</Data></EventData></Event>";
    let wide: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(xml.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    assert_eq!(
        parse_installer_removals(&installer_events_text(&wide)),
        [(
            "Bürotext Éditeur".to_string(),
            Some("Zürcher Werkstatt".to_string())
        )]
    );
}

#[test]
fn the_json_of_an_analysis_names_categories_and_reasons() {
    let pc = Pc::new("json");
    pc.fill();
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    let v = serde_json::to_value(&a).unwrap();
    let first = &v["findings"][0];
    assert_eq!(first["category"], "temp");
    assert_eq!(first["kept"][0]["code"], "recent");
    assert_eq!(first["kept"][0]["reason"], "changed in the last 7 days");
    assert!(first.get("work").is_none());
    let ids: Vec<&str> = Category::ALL.iter().map(|c| c.id()).collect();
    for (i, f) in v["findings"].as_array().unwrap().iter().enumerate() {
        assert_eq!(f["category"], ids[i]);
    }
}

#[test]
fn what_could_not_be_read_is_counted_in_items() {
    let kept = |count| Kept {
        reason: KeptReason::Unreadable,
        count,
        bytes: 0,
    };
    assert_eq!(
        stays_text(&[kept(1)]).as_deref(),
        Some("stays: 1 item could not be read")
    );
    assert_eq!(
        stays_text(&[kept(33)]).as_deref(),
        Some("stays: 33 items could not be read")
    );
}

#[test]
fn a_huge_number_of_days_keeps_everything_instead_of_wrapping_around() {
    assert_eq!(days_ago(30), Duration::from_secs(30 * 86_400));
    assert_eq!(days_ago(u64::MAX), Duration::from_secs(u64::MAX));
    assert!(days_ago(u64::MAX / 1000) > days_ago(1_000_000));
}

/// A profile laid out in the PC's folder, its files a month old, and a
/// check that knows where its folders are.
fn fake_profile(pc: &Pc) -> (PathBuf, TempCheck) {
    let me = pc.root.join(r"Users\me");
    let local = me.join(r"AppData\Local");
    file_aged(&me.join("notes.txt"), 20, 60);
    file_aged(&me.join(r"Documents\thesis.docx"), 100, 60);
    file_aged(&me.join(r"Projects\app\main.rs"), 70, 60);
    file_aged(&me.join(r"AppData\Roaming\Vendor\settings.json"), 30, 60);
    file_aged(&local.join(r"Oxidize\backups\one\manifest.json"), 40, 60);
    file_aged(&local.join(r"Temp\old.tmp"), 50, 60);
    for d in [
        r"Documents",
        r"Projects\app",
        r"Projects",
        r"AppData\Roaming\Vendor",
        r"AppData\Local\Oxidize\backups\one",
    ] {
        age(&me.join(d), 60);
    }
    let check = TempCheck {
        kept: vec![
            pc.root.join("Users"),
            me.clone(),
            me.join("Documents"),
            me.join(r"AppData\Roaming"),
            local.clone(),
            local.join("Oxidize"),
        ],
        homes: vec![local.join("Temp")],
        profile: Some(me.clone()),
    };
    (me, check)
}

#[test]
fn a_temp_folder_that_is_no_temp_folder_is_never_walked_or_cleaned() {
    for (name, inside) in [
        ("profile", ""),
        ("appdata", "AppData"),
        ("local", r"AppData\Local"),
        ("documents", "Documents"),
        ("projects", "Projects"),
    ] {
        let mut pc = Pc::new(&format!("not_temp_{name}"));
        let (me, check) = fake_profile(&pc);
        let given = if inside.is_empty() {
            me.clone()
        } else {
            me.join(inside)
        };
        pc.places.user_temp = Some(given.clone());
        // Windows' temp folder named as the folder of all profiles, walked
        // with administrator rights if it were let through.
        pc.places.windows_temp = Some(pc.root.join("Users"));
        pc.places.temp_check = check;
        let before = pc.snapshot();
        let tools = FakeTools::default();
        let a = analyse_with(&pc, &Protected::default(), true, &[], &tools, &no_orphans);
        let temp = a.finding(Category::Temp).unwrap();
        assert_eq!((temp.count, temp.bytes), (0, 0), "{name}");
        assert!(temp.kept.is_empty(), "{name}: {:?}", temp.kept);
        assert_eq!(temp.notes.len(), 2, "{name}: {:?}", temp.notes);
        assert!(
            temp.notes[0].starts_with(&given.display().to_string())
                && temp.notes[0].contains("not a temp folder")
                && temp.notes[0].contains("TMP and TEMP"),
            "{name}: {}",
            temp.notes[0]
        );
        // Chosen by hand, though the analysis offers nothing to choose.
        let chosen = Choice {
            categories: vec![Category::Temp],
            folders: Vec::new(),
            outright: Vec::new(),
        };
        let done = clean_with(&pc, &a, &chosen, &Protected::default(), true, &tools);
        assert_eq!((done[0].removed, done[0].freed), (0, 0), "{name}");
        assert_eq!(pc.snapshot(), before, "{name}: something was touched");
    }
    let mut pc = Pc::new("not_temp_control");
    let (me, check) = fake_profile(&pc);
    pc.places.user_temp = Some(me.join(r"AppData\Local\Temp"));
    pc.places.temp_check = check;
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    assert!(a.finding(Category::Temp).unwrap().notes.is_empty());
    let done = clean_with(
        &pc,
        &a,
        &a.choice(&[Category::Temp], Confidence::High),
        &Protected::default(),
        false,
        &tools,
    );
    assert_eq!((done[0].removed, done[0].freed), (1, 50));
    assert!(!me.join(r"AppData\Local\Temp\old.tmp").exists());
    for kept in [
        "notes.txt",
        r"Documents\thesis.docx",
        r"Projects\app\main.rs",
        r"AppData\Roaming\Vendor\settings.json",
        r"AppData\Local\Oxidize\backups\one\manifest.json",
    ] {
        assert!(me.join(kept).exists(), "{kept}");
    }
}

fn tools_uncommitted(answer: Option<bool>) -> FakeTools {
    let tools = FakeTools::default();
    *tools.uncommitted.lock().unwrap() = answer;
    tools
}

/// Two dumps of each of two programs: dump files in CrashDumps, and an
/// error report in the report queue.
fn dumps_of_two_programs(pc: &Pc) -> [PathBuf; 4] {
    let l = pc.local();
    let app = l.join(r"CrashDumps\app.exe.1234.dmp");
    let app_late = l.join(r"CrashDumps\app.exe.999.dmp");
    let tool = l.join(r"CrashDumps\tool.exe.77.dmp");
    let report = l.join(r"Microsoft\Windows\WER\ReportQueue\AppCrash_tool.exe_5e1_9a2");
    file_aged(&app, 400, 2);
    file_aged(&app_late, 50, 2);
    file_aged(&tool, 100, 2);
    file_aged(&report.join("Report.wer"), 60, 2);
    file_aged(&report.join("memory.hdmp"), 40, 2);
    [app, app_late, tool, report]
}

#[test]
fn each_dump_is_listed_with_the_program_it_belongs_to() {
    let pc = Pc::new("dumps_listed");
    let [app, app_late, tool, report] = dumps_of_two_programs(&pc);
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    let f = a.finding(Category::CrashDumps).unwrap();
    assert_eq!((f.count, f.bytes), (5, 650));
    let mut listed: Vec<_> = f
        .dumps
        .iter()
        .map(|d| (d.path.clone(), d.bytes, d.files, d.program.clone()))
        .collect();
    listed.sort();
    let mut want: Vec<(PathBuf, u64, usize, Option<String>)> = vec![
        (app, 400, 1, Some("app.exe".to_string())),
        (app_late, 50, 1, Some("app.exe".to_string())),
        (tool, 100, 1, Some("tool.exe".to_string())),
        (report, 100, 2, Some("tool.exe".to_string())),
    ];
    want.sort();
    assert_eq!(listed, want);
}

#[test]
fn the_dumps_of_one_program_can_be_left_out() {
    let pc = Pc::new("dumps_skip");
    let [app, app_late, tool, report] = dumps_of_two_programs(&pc);
    let tools = FakeTools::default();
    let mut a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    a.narrow_dumps(&[], &["TOOL".to_string(), "nothing.exe".to_string()]);
    let f = a.finding(Category::CrashDumps).unwrap();
    assert_eq!((f.count, f.bytes), (2, 450));
    assert_eq!(kept(&f.kept, &KeptReason::LeftOut), (3, 200));
    assert!(f
        .dumps
        .iter()
        .all(|d| d.program.as_deref() == Some("app.exe")));
    assert_eq!(f.notes, ["no dumps of nothing.exe were found"]);
    let choice = a.choice(&[Category::CrashDumps], Confidence::High);
    assert_eq!(a.chosen_bytes(&choice), 450);

    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    assert_eq!((done[0].removed, done[0].freed), (2, 450));
    assert_eq!(kept(&done[0].kept, &KeptReason::LeftOut), (3, 200));
    assert!(!app.exists() && !app_late.exists());
    assert!(tool.exists() && report.join("memory.hdmp").exists());
}

#[test]
fn single_dumps_can_be_picked() {
    let pc = Pc::new("dumps_pick");
    let [app, app_late, tool, report] = dumps_of_two_programs(&pc);
    let tools = FakeTools::default();
    let mut a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    let missing = pc.local().join(r"CrashDumps\gone.exe.1.dmp");
    // A path is matched whatever its case.
    let picked = PathBuf::from(report.display().to_string().to_uppercase());
    a.narrow_dumps(&[app_late.clone(), picked, missing.clone()], &[]);
    let f = a.finding(Category::CrashDumps).unwrap();
    assert_eq!((f.count, f.bytes), (3, 150));
    assert_eq!(kept(&f.kept, &KeptReason::LeftOut), (2, 500));
    assert_eq!(
        f.notes,
        [format!(
            "{} is not among the dumps found",
            missing.display()
        )]
    );

    let choice = a.choice(&[Category::CrashDumps], Confidence::High);
    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    assert_eq!((done[0].removed, done[0].freed), (3, 150));
    assert!(!app_late.exists() && !report.join("Report.wer").exists());
    assert!(app.exists() && tool.exists());
}

/// Folders of two removed programs, both matched at high confidence, and
/// the analysis of them.
fn two_removed_programs(
    pc: &Pc,
    tools: &FakeTools,
    living: bool,
) -> (OrphanFolder, OrphanFolder, Analysis) {
    let quill = pc.orphan("Quillmark Studio", 120);
    let ink = pc.orphan("Inkwell Studio", 80);
    file_aged(&ink.path.join(r"bin\inkwell.exe"), 30, 100);
    if living {
        file_aged(&ink.path.join("today.log"), 5, 0);
    }
    let removed = vec![
        ("Quillmark Studio".to_string(), None),
        ("Inkwell Studio".to_string(), None),
    ];
    let snap = scanner::Snapshot::with_programs(Vec::new());
    let scored = score_orphans(&[quill.clone(), ink.clone()], &removed, &snap);
    assert!(scored.iter().all(|o| o.confidence == Confidence::High));
    let source = move || scored.clone();
    let a = analyse_with(pc, &Protected::default(), false, &[], tools, &source);
    (quill, ink, a)
}

#[test]
fn a_dead_folder_is_deleted_outright_and_a_living_one_goes_into_the_backup() {
    let pc = Pc::new("orphans_dead");
    let tools = FakeTools::default();
    let (quill, ink, a) = two_removed_programs(&pc, &tools, true);
    let f = a.finding(Category::Orphans).unwrap();
    let dead = |p: &Path| f.folders.iter().find(|o| o.path == p).unwrap().proven_dead;
    assert!(dead(&quill.path));
    assert!(!dead(&ink.path));

    let mut choice = a.choice(&[Category::Orphans], Confidence::High);
    assert!(choice.outright.is_empty(), "outright only when asked");
    a.delete_dead(&mut choice);
    assert_eq!(choice.outright, std::slice::from_ref(&quill.path));

    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    let o = &done[0];
    let base = crate::backup::backups_base().unwrap();
    let _cleanup = crate::backup::TestCleanup(o.backup.iter().map(|b| base.join(b)).collect());
    assert_eq!(o.removed, 2);
    assert!(!quill.path.exists() && !ink.path.exists());
    assert!(o
        .notes
        .contains(&"1 proven dead, deleted without a backup".to_string()));

    // Only the living folder is in the backup.
    let info = crate::backup::find_backup(o.backup.as_ref().expect("a backup")).unwrap();
    let restored = crate::restore::restore(&info, false).unwrap();
    assert!(restored.iter().all(|r| r.result.is_ok()));
    assert!(ink.path.join("today.log").exists());
    assert!(!quill.path.exists());
    crate::backup::delete_backup(&info).unwrap();
}

#[test]
fn a_folder_that_came_alive_since_the_analysis_goes_into_the_backup() {
    let pc = Pc::new("orphans_revived");
    let tools = FakeTools::default();
    let (quill, ink, a) = two_removed_programs(&pc, &tools, false);
    let f = a.finding(Category::Orphans).unwrap();
    assert!(f.folders.iter().all(|o| o.proven_dead));
    let mut choice = a.choice(&[Category::Orphans], Confidence::High);
    a.delete_dead(&mut choice);
    assert_eq!(choice.outright.len(), 2);

    // One was written to, and the other's program started again.
    file_aged(&quill.path.join("new.txt"), 5, 0);
    *tools.running.lock().unwrap() = vec![ink.path.join(r"bin\inkwell.exe")];
    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    let o = &done[0];
    let base = crate::backup::backups_base().unwrap();
    let _cleanup = crate::backup::TestCleanup(o.backup.iter().map(|b| base.join(b)).collect());
    assert_eq!(o.removed, 2);
    assert!(o
        .notes
        .contains(&"2 no longer proven dead, so into the backup instead".to_string()));
    assert!(!o.notes.iter().any(|n| n.contains("without a backup")));

    let info = crate::backup::find_backup(o.backup.as_ref().expect("a backup")).unwrap();
    let restored = crate::restore::restore(&info, false).unwrap();
    assert!(restored.iter().all(|r| r.result.is_ok()));
    assert!(quill.path.join("new.txt").exists());
    assert!(ink.path.join(r"bin\inkwell.exe").exists());
    crate::backup::delete_backup(&info).unwrap();
}

#[test]
fn only_a_high_confidence_folder_is_ever_deleted_outright() {
    let pc = Pc::new("orphans_unsure");
    let tools = FakeTools::default();
    let medium = pc.orphan("Quillmark Studio", 120);
    let low = pc.orphan("Inkwell Studio", 80);
    let items: Vec<OrphanItem> = [(&medium, Confidence::Medium), (&low, Confidence::Low)]
        .into_iter()
        .map(|(f, confidence)| OrphanItem {
            path: f.path.clone(),
            bytes: f.size_bytes,
            modified: f.modified.clone(),
            confidence,
            reason: "a plausible match".to_string(),
            needs_admin: false,
            proven_dead: false,
        })
        .collect();
    let source = move || items.clone();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &source);
    let f = a.finding(Category::Orphans).unwrap();
    assert_eq!(f.folders.len(), 2);
    assert!(f.folders.iter().all(|o| !o.proven_dead));
    let mut choice = a.choice(&[Category::Orphans], Confidence::Low);
    assert_eq!(choice.folders.len(), 2);
    a.delete_dead(&mut choice);
    assert!(choice.outright.is_empty());

    // A choice made by hand that names them outright still backs them up.
    choice.outright = choice.folders.clone();
    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    let o = &done[0];
    let base = crate::backup::backups_base().unwrap();
    let _cleanup = crate::backup::TestCleanup(o.backup.iter().map(|b| base.join(b)).collect());
    assert_eq!(o.removed, 2);
    assert!(!o.notes.iter().any(|n| n.contains("without a backup")));
    let info = crate::backup::find_backup(o.backup.as_ref().expect("a backup")).unwrap();
    let restored = crate::restore::restore(&info, false).unwrap();
    assert!(restored.iter().all(|r| r.result.is_ok()));
    assert!(medium.path.join("data.bin").exists());
    assert!(low.path.join("data.bin").exists());
    crate::backup::delete_backup(&info).unwrap();
}

#[test]
fn stale_build_output_goes_for_good_and_the_rest_stays_with_its_reason() {
    use super::build::tests::{age_tree, cache};
    let pc = Pc::new("build_output");
    let code = pc.root.join(r"Profile\code");
    let stale = code.join(r"app\target");
    let stale_bytes = cache(&stale, 300, 60);
    let fresh = code.join(r"new\target");
    let fresh_bytes = cache(&fresh, 50, 2);
    let nested = code.join(r"vendored\target");
    cache(&nested, 20, 60);
    fs::create_dir_all(nested.join(r"src\.git")).unwrap();
    age_tree(&nested, 60);
    let in_temp = pc.temp().join(r"build\target");
    cache(&in_temp, 70, 60);
    let checkout = code.join("work");
    fs::create_dir_all(checkout.join(".git")).unwrap();
    let dirty = checkout.join("target");
    let dirty_bytes = cache(&dirty, 40, 60);
    let tools = tools_uncommitted(Some(true));

    let before = pc.snapshot();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    assert_eq!(
        pc.snapshot(),
        before,
        "an analysis must not change anything"
    );
    let f = a.finding(Category::BuildOutput).unwrap();
    assert!(!f.preselected && f.actionable());
    assert!(!a
        .default_choice()
        .categories
        .contains(&Category::BuildOutput));
    assert_eq!((f.count, f.bytes), (1, stale_bytes));
    assert_eq!(f.build_folders[0].path, stale);
    assert!(f.build_folders[0].unchanged_days >= 59);
    assert_eq!(f.build_folders[0].checkout, None);
    assert_eq!(kept(&f.kept, &KeptReason::Recent(30)), (1, fresh_bytes));
    assert_eq!(kept(&f.kept, &KeptReason::Uncommitted), (1, dirty_bytes));
    assert_eq!(kept(&f.kept, &KeptReason::Repository).0, 1);
    let mut calls = tools.calls();
    calls.sort_unstable();
    assert_eq!(calls, ["delivery_cache", "uncommitted"]);

    let choice = a.choice(&[Category::BuildOutput], Confidence::High);
    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    let b = &done[0];
    assert_eq!((b.removed, b.freed), (1, stale_bytes));
    assert_eq!(b.backup, None);
    assert!(!stale.exists());
    assert!(code.join("app").exists(), "only the tagged folder goes");
    for stays in [&fresh, &nested, &in_temp, &dirty] {
        assert!(stays.join("CACHEDIR.TAG").exists(), "{}", stays.display());
    }
}

#[test]
fn build_output_in_a_clean_checkout_goes_and_git_is_asked_once_per_checkout() {
    use super::build::tests::cache;
    let pc = Pc::new("build_clean_checkout");
    let checkout = pc.root.join(r"Profile\code\work");
    fs::create_dir_all(checkout.join(".git")).unwrap();
    let one = cache(&checkout.join(r"app\target"), 30, 60);
    let two = cache(&checkout.join(r"lib\target"), 20, 60);
    let tools = tools_uncommitted(Some(false));
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    let f = a.finding(Category::BuildOutput).unwrap();
    assert_eq!((f.count, f.bytes), (2, one + two));
    assert!(f
        .build_folders
        .iter()
        .all(|b| b.checkout.as_deref() == Some(checkout.as_path())));
    let asked = |t: &FakeTools| t.calls().iter().filter(|c| **c == "uncommitted").count();
    assert_eq!(asked(&tools), 1);

    let choice = a.choice(&[Category::BuildOutput], Confidence::High);
    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    assert_eq!((done[0].removed, done[0].freed), (2, one + two));
    assert_eq!(asked(&tools), 2, "asked again right before");
    assert!(checkout.join(".git").exists());
}

#[test]
fn with_administrator_rights_git_is_never_run_and_checkout_output_stays() {
    use super::build::tests::cache;
    let pc = Pc::new("build_elevated");
    let checkout = pc.root.join(r"Profile\code\work");
    fs::create_dir_all(checkout.join(".git")).unwrap();
    let inside = checkout.join("target");
    let inside_bytes = cache(&inside, 30, 60);
    let outside = pc.root.join(r"Profile\packages\tool");
    let outside_bytes = cache(&outside, 20, 60);
    let tools = tools_uncommitted(Some(false));
    let a = analyse_with(&pc, &Protected::default(), true, &[], &tools, &no_orphans);
    let f = a.finding(Category::BuildOutput).unwrap();
    assert_eq!((f.count, f.bytes), (1, outside_bytes));
    assert_eq!(
        kept(&f.kept, &KeptReason::CheckoutUnknown),
        (1, inside_bytes)
    );
    assert!(f.notes.iter().any(|n| n.contains("administrator rights")));

    let choice = a.choice(&[Category::BuildOutput], Confidence::High);
    let done = clean_with(&pc, &a, &choice, &Protected::default(), true, &tools);
    assert_eq!(done[0].removed, 1);
    assert!(!outside.exists() && inside.exists());
    assert!(!tools.calls().contains(&"uncommitted"));
}

#[test]
fn build_output_written_to_or_protected_since_the_analysis_stays() {
    use super::build::tests::cache;
    let pc = Pc::new("build_changed");
    let used = pc.root.join(r"Profile\code\app\target");
    cache(&used, 30, 60);
    let kept_dir = pc.root.join(r"Profile\code\lib\target");
    cache(&kept_dir, 20, 60);
    let tools = FakeTools::default();
    let a = analyse_with(&pc, &Protected::default(), false, &[], &tools, &no_orphans);
    assert_eq!(a.finding(Category::BuildOutput).unwrap().count, 2);

    file_aged(&used.join(r"debug\fresh.bin"), 10, 0);
    let protected = Protected::new([kept_dir.display().to_string()]);
    let choice = a.choice(&[Category::BuildOutput], Confidence::High);
    let done = clean_with(&pc, &a, &choice, &protected, false, &tools);
    assert_eq!((done[0].removed, done[0].freed), (0, 0));
    assert_eq!(kept(&done[0].kept, &KeptReason::Recent(30)).0, 1);
    assert_eq!(kept(&done[0].kept, &KeptReason::Protected).0, 1);
    assert!(used.join("CACHEDIR.TAG").exists());
    assert!(kept_dir.join("CACHEDIR.TAG").exists());
}

#[test]
fn build_output_a_program_runs_from_or_holds_open_stays_whole() {
    use super::build::tests::cache;
    let pc = Pc::new("build_in_use");
    let code = pc.root.join(r"Profile\code");
    let ran = code.join(r"one\target");
    let open = code.join(r"two\target");
    let runs = code.join(r"three\target");
    for dir in [&ran, &open, &runs] {
        cache(dir, 30, 60);
    }
    let tools = FakeTools::default();
    let at_analysis = [ran.join(r"debug\tool.exe")];
    let a = analyse_with(
        &pc,
        &Protected::default(),
        false,
        &at_analysis,
        &tools,
        &no_orphans,
    );
    let f = a.finding(Category::BuildOutput).unwrap();
    assert_eq!(f.count, 2);
    assert_eq!(kept(&f.kept, &KeptReason::InUse).0, 1);

    let _held = fs::File::open(open.join(r"debug\deps\out.bin")).unwrap();
    *tools.running.lock().unwrap() = vec![runs.join(r"debug\tool.exe")];
    let choice = a.choice(&[Category::BuildOutput], Confidence::High);
    let done = clean_with(&pc, &a, &choice, &Protected::default(), false, &tools);
    assert_eq!((done[0].removed, done[0].freed), (0, 0));
    assert_eq!(kept(&done[0].kept, &KeptReason::InUse).0, 2);
    for dir in [&ran, &open, &runs] {
        assert!(
            dir.join(r"debug\deps\out.bin").exists(),
            "{}",
            dir.display()
        );
    }
}
