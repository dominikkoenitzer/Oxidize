//! `oxidize-gui`, the graphical front-end, built on egui/eframe.
//!
//! A window over the same engine the CLI uses: an overview of what is
//! installed, a table of programs to sort and filter, and a details panel to
//! remove one completely, run its uninstaller or scan for its leftovers. Slow
//! work runs on a worker thread and reports back over a channel. The dry-run
//! and backup toggles and the confirmation work as they do on the command line.

// Hide the console window in release builds (keep it in debug for logs).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};

use chrono::NaiveDate;
use eframe::egui::{self, Color32, RichText};

use oxidize::complete::{self, CloseHow, Outcome, VendorStep};
use oxidize::model::{Confidence, Hive, Leftover, LeftoverKind, Program, ScanReport};
use oxidize::restore::RestoreItem;
use oxidize::safety::{self, DeletionOutcome, ItemStatus, SafetyContext};
use oxidize::{backup, clean, registry, restore, scanner, system, uninstall, util};

// The tab lives beside this file, not in src/bin, where Cargo would take it
// for a program of its own.
#[path = "oxidize-gui/cleanup.rs"]
mod cleanup;
#[path = "oxidize-gui/slate.rs"]
mod slate;

/// The lowest confidence "Remove completely" removes.
const COMPLETE_LEVEL: Confidence = Confidence::High;

/// The status line while the program list is read.
const LOADING: &str = "Loading installed programs...";

/// A program at least this big counts as large for the quick filter.
const LARGE_BYTES: u64 = 1024 * 1024 * 1024;
/// A program installed at most this many days ago counts as recent.
const RECENT_DAYS: i64 = 30;
/// The height of one row in the program table.
const ROW_HEIGHT: f32 = 30.0;

/// The Oxidize mark for the window, the same artwork the executables embed.
fn window_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../../assets/oxidize.png"))
        .expect("assets/oxidize.png is a valid PNG")
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("Oxidize")
            // The window's own icon; without one eframe shows the egui logo in
            // the title bar and taskbar.
            .with_icon(window_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "Oxidize",
        options,
        Box::new(|cc| Ok(Box::new(OxidizeApp::new(cc)))),
    )
}

/// Messages sent from background worker threads back to the UI thread.
enum Msg {
    Programs(Vec<Program>),
    Scan {
        id: String,
        report: ScanReport,
    },
    Uninstalled {
        program: Program,
        message: String,
        still_installed: bool,
    },
    Removed(DeletionOutcome),
    /// A complete removal ended.
    Completed {
        program: Program,
        outcome: Box<Outcome>,
        dry_run: bool,
    },
    /// An undo from a backup ended.
    Restored {
        backup: String,
        result: Result<Vec<RestoreItem>, String>,
        dry_run: bool,
    },
    /// An extracted program icon (raw RGBA), keyed by the program's id.
    Icon {
        id: String,
        rgba: Vec<u8>,
        w: u32,
        h: u32,
    },
    /// An analysis for the Clean up tab ended.
    Analysed(Box<(clean::Places, clean::Analysis)>),
    /// The build output the analysis left out was looked for.
    BuildFound(Box<clean::Finding>),
    /// A cleaning ended.
    Cleaned(Vec<clean::Cleaned>),
    /// The usage traces were read.
    TracesFound(Vec<clean::traces::TraceFinding>),
    /// The usage traces were cleared.
    TracesCleared(Vec<clean::traces::TraceFinding>),
    Error(String),
}

/// The window's two views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Programs,
    Cleanup,
}

/// A pending destructive action awaiting confirmation.
#[allow(clippy::large_enum_variant)] // these are constructed at most once per click
enum Confirm {
    Uninstall(Program, bool),
    Remove(Vec<Leftover>, String, SafetyContext),
    Complete(Program, SafetyContext),
    /// What to clean, and the question that asks about it.
    Clean(clean::Choice, String),
    /// Clear the usage traces; the question that asks about it.
    Traces(String),
}

/// The last complete removal, shown for its program until the user moves on.
struct Completed {
    program: Program,
    outcome: Outcome,
    dry_run: bool,
}

/// An action requested during rendering, executed after the panels are drawn
/// (keeps borrow handling simple).
#[allow(clippy::large_enum_variant)] // constructed at most once per frame, on a click
enum Action {
    Refresh,
    Scan(Program),
    Uninstall(Program),
    Remove(Vec<Leftover>, String),
    RemoveCompletely(Program),
    /// Restore the named backup.
    Undo(String),
    RestartAdmin,
    /// Analyse what the Clean up tab can clean.
    Analyse,
    /// Look for the build output the analysis left out.
    FindBuildOutput,
    /// Clean what was ticked.
    Clean(clean::Choice),
    /// Clear every usage trace.
    ClearTraces,
}

struct OxidizeApp {
    // Data.
    programs: Vec<Program>,
    /// Per-program icon textures, keyed by program id (loaded progressively).
    icons: HashMap<String, egui::TextureHandle>,
    scan: Option<ScanReport>,
    /// Id of the program the scan belongs to.
    scan_for: Option<String>,
    checked: Vec<bool>,
    /// The program whose uninstaller ran last. Once it leaves the installed
    /// list it can only be reached through this, for its leftovers.
    uninstalled: Option<Program>,
    complete: Option<Completed>,
    cleanup: cleanup::Cleanup,

    // UI state.
    tab: Tab,
    filter: String,
    quick: QuickFilter,
    selected: Option<String>, // selected program's registry-key id
    sort: Sort,
    /// The search field takes the keyboard once, when the window opens.
    focus_search: bool,
    /// Scroll the table to the selected program on the next frame.
    reveal: bool,
    /// The table's scroll offset and visible height, from the last frame.
    table_view: (f32, f32),
    show_log: bool,

    // Options (mirror the CLI flags).
    dry_run: bool,
    make_backups: bool,
    silent: bool,
    include_system: bool,

    elevated: bool,
    /// Work running on worker threads. One removal starts a scan and a
    /// list reload at once, so a single flag that the first answer clears
    /// would let a second removal start while the first one runs.
    jobs: usize,
    /// The window was asked to close while work ran; it closes once that
    /// work is done.
    close_when_done: bool,
    status: String,
    log: Vec<String>,
    confirm: Option<Confirm>,

    // Channel to receive worker results.
    tx: Sender<Msg>,
    rx: Receiver<Msg>,

    /// What Undo runs on its worker thread; a test puts a stand-in here.
    restore_backup: fn(&str, bool) -> Result<Vec<RestoreItem>, String>,
}

/// Finds the backup by name and puts it back, or only checks it in a dry run.
fn restore_backup(name: &str, dry_run: bool) -> Result<Vec<RestoreItem>, String> {
    backup::find_backup(name)
        .and_then(|info| restore::restore(&info, dry_run))
        .map_err(|e| format!("{e:#}"))
}

impl OxidizeApp {
    /// The window's state before anything is loaded: no programs, the
    /// default settings, nothing running, and `cleanup` as the Clean up tab.
    fn blank(cleanup: cleanup::Cleanup) -> Self {
        let (tx, rx) = channel();
        OxidizeApp {
            programs: Vec::new(),
            icons: HashMap::new(),
            scan: None,
            scan_for: None,
            checked: Vec::new(),
            uninstalled: None,
            complete: None,
            cleanup,
            tab: Tab::Programs,
            filter: String::new(),
            quick: QuickFilter::All,
            selected: None,
            sort: Sort::default(),
            focus_search: true,
            reveal: false,
            table_view: (0.0, 0.0),
            show_log: false,
            dry_run: false,
            make_backups: true,
            silent: false,
            include_system: false,
            elevated: false,
            jobs: 0,
            close_when_done: false,
            status: String::new(),
            log: Vec::new(),
            confirm: None,
            tx,
            rx,
            restore_backup,
        }
    }

    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_style(&cc.egui_ctx);
        let mut app = OxidizeApp::blank(cleanup::Cleanup::new());
        app.elevated = safety::is_elevated();
        app.jobs = 1;
        app.status = LOADING.to_string();
        // Kick off the initial program load on a worker thread.
        let tx = app.tx.clone();
        let ctx = cc.egui_ctx.clone();
        let include_system = app.include_system;
        std::thread::spawn(move || {
            let programs = registry::enumerate_installed_programs(include_system);
            let _ = tx.send(Msg::Programs(programs));
            ctx.request_repaint();
        });
        app
    }

    /// Is anything running? Nothing else may start while it is.
    fn busy(&self) -> bool {
        self.jobs > 0
    }

    /// One job sent its answer.
    fn job_done(&mut self) {
        self.jobs = self.jobs.saturating_sub(1);
    }

    /// What closing the window does. While work runs it waits: a removal
    /// or a cleaning cut off halfway leaves the program or the folder half
    /// done. The window closes by itself once the work is.
    fn close_step(&mut self, requested: bool) -> Option<egui::ViewportCommand> {
        if requested && self.busy() {
            self.close_when_done = true;
            self.status = "Oxidize closes once the work under way is done.".to_string();
            return Some(egui::ViewportCommand::CancelClose);
        }
        (self.close_when_done && !self.busy()).then_some(egui::ViewportCommand::Close)
    }

    /// Run `f` on a worker thread and repaint when it sends its result.
    /// Each run sends exactly one message, which ends it.
    fn spawn<F: FnOnce() -> Msg + Send + 'static>(&mut self, ctx: &egui::Context, f: F) {
        self.jobs += 1;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // A panic in the engine would otherwise take the answer with it and
            // leave the window busy with nothing to wait for.
            let msg = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
                .unwrap_or_else(|_| Msg::Error("the operation stopped unexpectedly".to_string()));
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }

    fn safety_ctx(&self) -> SafetyContext {
        SafetyContext {
            dry_run: self.dry_run,
            make_backups: self.make_backups,
            keep_emptied_parents: false,
        }
    }

    fn load_programs(&mut self, ctx: &egui::Context) {
        self.status = LOADING.to_string();
        self.reload_programs(ctx);
    }

    /// Read the program list again after an action, leaving that action's
    /// result in the status line.
    fn reload_programs(&mut self, ctx: &egui::Context) {
        let include_system = self.include_system;
        self.spawn(ctx, move || {
            Msg::Programs(registry::enumerate_installed_programs(include_system))
        });
    }

    /// Extract icons (on a background thread) for any programs we don't have a
    /// texture for yet, sending each back as it's ready.
    fn spawn_icon_load(&self, ctx: &egui::Context) {
        let items: Vec<Program> = self
            .programs
            .iter()
            .filter(|p| !self.icons.contains_key(p.id()))
            .cloned()
            .collect();
        if items.is_empty() {
            return;
        }
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            for program in items {
                if let Some((_, (rgba, w, h))) = program_icon(&program) {
                    let id = program.id().to_string();
                    if tx.send(Msg::Icon { id, rgba, w, h }).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                }
            }
        });
    }

    fn start_scan(&mut self, ctx: &egui::Context, program: Program) {
        self.status = format!("Scanning for leftovers of {}...", program.display_name);
        self.spawn(ctx, move || {
            // One reading of the machine serves both steps.
            let snap = scanner::Snapshot::new();
            let target = scanner::build_target_with(&program, &snap);
            let installed = uninstall::still_installed(&program);
            let report = scanner::scan_with(&target, installed, &snap);
            Msg::Scan {
                id: program.id().to_string(),
                report,
            }
        });
    }

    fn start_uninstall(&mut self, ctx: &egui::Context, program: Program, silent: bool) {
        self.status = format!("Running the uninstaller for {}...", program.display_name);
        self.spawn(ctx, move || match uninstall::plan(&program, silent) {
            Ok(plan) => match uninstall::run(&plan) {
                Ok(status) => Msg::Uninstalled {
                    message: format!(
                        "{}: uninstaller {}",
                        program.display_name,
                        uninstall::describe_exit(status, plan.is_msi)
                    ),
                    still_installed: uninstall::still_installed(&program),
                    program,
                },
                Err(e) => Msg::Error(window_error(&format!("Uninstall failed: {e:#}"))),
            },
            Err(e) => Msg::Error(format!("Cannot uninstall {}: {e:#}", program.display_name)),
        });
    }

    fn start_remove(
        &mut self,
        ctx: &egui::Context,
        items: Vec<Leftover>,
        label: String,
        safety_ctx: SafetyContext,
    ) {
        self.status = format!("Removing {}...", count(items.len(), "item", "items"));
        self.spawn(ctx, move || {
            match safety::remove_leftovers(&items, &label, &safety_ctx) {
                Ok(outcome) => Msg::Removed(outcome),
                Err(e) => Msg::Error(format!("Removal failed: {e:#}")),
            }
        });
    }

    fn start_remove_completely(
        &mut self,
        ctx: &egui::Context,
        program: Program,
        safety_ctx: SafetyContext,
    ) {
        self.complete = None;
        let dry_run = safety_ctx.dry_run;
        let line = if dry_run {
            format!("dry run: removing {} completely...", program.display_name)
        } else {
            format!("Removing {} completely...", program.display_name)
        };
        self.log.push(line.clone());
        self.status = line;
        self.spawn(ctx, move || {
            // The footprint and the uninstaller are read before anything runs.
            let target = scanner::build_target(&program);
            let plan = match uninstall::plan(&program, true) {
                Ok(plan) => plan,
                Err(e) => {
                    return Msg::Error(format!("Cannot remove {}: {e:#}", program.display_name))
                }
            };
            let pc = complete::ThisPc {
                safety: safety_ctx,
                quiet: true,
            };
            let opts = complete::Options {
                level: COMPLETE_LEVEL,
                dry_run,
                use_uninstaller: false,
            };
            let outcome = complete::remove_completely(&pc, &program, &target, &plan, &opts);
            Msg::Completed {
                program,
                outcome: Box::new(outcome),
                dry_run,
            }
        });
    }

    fn start_undo(&mut self, ctx: &egui::Context, name: String) {
        let line = format!("Restoring {name}...");
        self.log.push(line.clone());
        self.status = line;
        let (restore_backup, dry_run) = (self.restore_backup, self.dry_run);
        self.spawn(ctx, move || {
            let result = restore_backup(&name, dry_run);
            Msg::Restored {
                backup: name,
                result,
                dry_run,
            }
        });
    }

    fn start_analyse(&mut self, ctx: &egui::Context) {
        self.status = "Analysing what can be cleaned...".to_string();
        let protected = self.cleanup.protected.clone();
        self.spawn(ctx, move || {
            let (places, analysis) =
                clean::analyse_this_pc(&protected, clean::RECYCLE_DAYS, clean::Asked::default());
            Msg::Analysed(Box::new((places, analysis)))
        });
        let protected = self.cleanup.protected.clone();
        self.spawn(ctx, move || {
            let places = clean::traces::TracePlaces::this_pc();
            let shell = clean::traces::shell_for(&places);
            Msg::TracesFound(clean::traces::analyse(&places, &protected, shell.as_ref()))
        });
    }

    fn start_find_build_output(&mut self, ctx: &egui::Context) {
        let Some((places, _)) = &self.cleanup.analysis else {
            return;
        };
        let places = places.clone();
        self.status = "Looking for build output...".to_string();
        let protected = self.cleanup.protected.clone();
        self.spawn(ctx, move || {
            Msg::BuildFound(Box::new(clean::build_output_this_pc(&places, &protected)))
        });
    }

    fn start_clear_traces(&mut self, ctx: &egui::Context) {
        self.status = "Clearing usage traces...".to_string();
        self.log.push("Clearing usage traces".to_string());
        let protected = self.cleanup.protected.clone();
        self.spawn(ctx, move || {
            let places = clean::traces::TracePlaces::this_pc();
            let shell = clean::traces::shell_for(&places);
            Msg::TracesCleared(clean::traces::clear(&places, &protected, shell.as_ref()))
        });
    }

    /// Take in a finished clearing of the usage traces.
    fn on_traces_cleared(&mut self, results: Vec<clean::traces::TraceFinding>) {
        self.job_done();
        for f in &results {
            let what = if f.count_known {
                f.detail()
            } else {
                util::human_size(f.bytes)
            };
            self.log
                .push(format!("{}: {what} cleared", f.trace.title()));
            if let Some(stays) = clean::stays_text(&f.kept) {
                self.log.push(format!("  {stays}"));
            }
        }
        let (n, _) = clean::traces::total(&results);
        self.status = format!("{} cleared.", count(n, "usage trace", "usage traces"));
        self.cleanup.slate.take_results(results);
    }

    fn start_clean(&mut self, ctx: &egui::Context, choice: clean::Choice) {
        let Some((places, analysis)) = self.cleanup.analysis.take() else {
            return;
        };
        self.status = "Cleaning...".to_string();
        self.cleanup.cleaning = true;
        self.log.push(format!(
            "Cleaning {}",
            count(choice.categories.len(), "category", "categories")
        ));
        let protected = self.cleanup.protected.clone();
        let make_backups = self.make_backups;
        self.spawn(ctx, move || {
            Msg::Cleaned(clean::clean_this_pc(
                &places,
                &analysis,
                &choice,
                &protected,
                make_backups,
            ))
        });
    }

    /// Take in a finished cleaning.
    fn on_cleaned(&mut self, results: Vec<clean::Cleaned>) {
        self.job_done();
        self.cleanup.cleaning = false;
        for c in &results {
            self.log.push(format!(
                "{}: {} freed, {} removed",
                c.category.title(),
                util::human_size(c.freed),
                c.removed
            ));
            if let Some(stays) = clean::stays_text(&c.kept) {
                self.log.push(format!("  {stays}"));
            }
            if let Some(name) = &c.backup {
                self.log.push(format!(
                    "Undo from the command line: oxidize restore \"{name}\""
                ));
            }
        }
        let freed: u64 = results.iter().map(|c| c.freed).sum();
        self.status = format!(
            "{} freed. Analyse again to see what is left.",
            util::human_size(freed)
        );
        self.cleanup.results = Some(results);
    }

    /// Take in a finished complete removal. True when the program list
    /// should be read again because something changed.
    fn on_completed(&mut self, program: Program, outcome: Outcome, dry_run: bool) -> bool {
        self.log.extend(with_tool_lines(
            complete_log(&program.display_name, &outcome, dry_run),
            system::take_tool_log(),
        ));
        self.status = complete_status(&program.display_name, &outcome, dry_run);
        self.job_done();
        if !dry_run {
            // Keeps it selected once it leaves the installed list.
            self.uninstalled = Some(program.clone());
            self.scan = None;
            self.scan_for = None;
        }
        self.complete = Some(Completed {
            program,
            outcome,
            dry_run,
        });
        !dry_run
    }

    /// Take in a finished undo. True when the program list should be read
    /// again.
    fn on_restored(
        &mut self,
        name: &str,
        result: Result<Vec<RestoreItem>, String>,
        dry_run: bool,
    ) -> bool {
        self.job_done();
        match result {
            Ok(items) => {
                let mut restored = 0;
                let mut failed = 0;
                for item in &items {
                    match &item.result {
                        Ok(()) => {
                            restored += 1;
                            let done = if dry_run { "would restore" } else { "restored" };
                            self.log.push(format!("{done} {}", item.path));
                        }
                        Err(e) => {
                            failed += 1;
                            self.log.push(format!("failed {}: {e}", item.path));
                        }
                    }
                }
                self.log.extend(system::take_tool_log());
                let mut line = if dry_run {
                    format!(
                        "dry run: {} from {name} would be restored",
                        count(restored, "item", "items")
                    )
                } else {
                    format!("Restored {} from {name}", count(restored, "item", "items"))
                };
                if failed > 0 {
                    line.push_str(&format!(", {failed} failed"));
                } else if !dry_run {
                    self.cleanup.restored(name);
                }
                self.log.push(line.clone());
                self.status = line;
                // A dry run changed nothing, so the result on screen and the list still hold.
                if dry_run {
                    return false;
                }
                // The result on screen no longer holds, if it was this
                // backup's. Undoing a cleaning leaves a removal's own undo,
                // and what failed stays in the backup for Undo to try again.
                if failed == 0
                    && self
                        .complete
                        .as_ref()
                        .and_then(|c| c.outcome.removal.as_ref())
                        .and_then(|r| r.backup_name.as_deref())
                        == Some(name)
                {
                    self.complete = None;
                }
                true
            }
            Err(e) => {
                self.log.extend(system::take_tool_log());
                self.log.push(format!("ERROR: Undo failed: {e}"));
                self.status = format!("Undo failed: {e}");
                false
            }
        }
    }

    /// The backup the last complete removal of the selected program made,
    /// which "Undo" restores. None after a dry run or without backups.
    fn undo_backup(&self) -> Option<&str> {
        let done = self.complete.as_ref()?;
        if done.dry_run || self.selected.as_deref() != Some(done.program.id()) {
            return None;
        }
        done.outcome.removal.as_ref()?.backup_name.as_deref()
    }

    /// The complete removal to show for the selected program, if any.
    fn shown_complete(&self) -> Option<&Completed> {
        self.complete
            .as_ref()
            .filter(|c| self.selected.as_deref() == Some(c.program.id()))
    }

    /// Drain any pending messages from worker threads.
    fn drain_messages(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Programs(programs) => {
                    let was_listed = self
                        .selected
                        .as_ref()
                        .is_some_and(|id| self.programs.iter().any(|p| p.id() == id));
                    self.programs = programs;
                    self.job_done();
                    // The count stands beside the search field; the line
                    // here keeps what the last action did.
                    if self.status == LOADING {
                        self.status.clear();
                    }
                    // Drop a stale selection, unless it is the program just
                    // uninstalled: what it left behind is scanned now.
                    if let Some(id) = self.selected.clone() {
                        if !self.programs.iter().any(|p| p.id() == id) {
                            match self.uninstalled.clone().filter(|p| p.id() == id) {
                                Some(program) => {
                                    // After a complete removal its own
                                    // second scan is already on screen.
                                    if was_listed && self.shown_complete().is_none() {
                                        self.scan = None;
                                        self.start_scan(ctx, program);
                                    }
                                }
                                None => {
                                    self.selected = None;
                                    self.scan = None;
                                }
                            }
                        }
                    }
                    // Forget icons for programs that no longer exist, then load
                    // icons for any new ones.
                    {
                        let ids: std::collections::HashSet<&str> =
                            self.programs.iter().map(|p| p.id()).collect();
                        self.icons.retain(|k, _| ids.contains(k.as_str()));
                    }
                    self.spawn_icon_load(ctx);
                }
                Msg::Scan { id, report } if self.selected.as_deref() == Some(id.as_str()) => {
                    // High-confidence items start checked, as on the command line.
                    // A program that is still installed shows its footprint with
                    // nothing checked.
                    self.checked = report
                        .all()
                        .map(|l| !report.installed && l.confidence == Confidence::High)
                        .collect();
                    self.status = if report.installed {
                        format!(
                            "{} up {}. It is still installed.",
                            count(report.total(), "item makes", "items make"),
                            report.program_name
                        )
                    } else {
                        format!(
                            "{} of {}.",
                            count(report.total(), "leftover", "leftovers"),
                            report.program_name
                        )
                    };
                    self.scan_for = Some(id);
                    self.scan = Some(report);
                    self.job_done();
                }
                // A scan the user has already moved on from.
                Msg::Scan { .. } => self.job_done(),
                Msg::Uninstalled {
                    program,
                    message,
                    still_installed,
                } => {
                    self.uninstalled = Some(program);
                    self.log.push(message);
                    self.status = if still_installed {
                        "Uninstaller finished. The program is still registered.".to_string()
                    } else {
                        "Program removed from the installed list.".to_string()
                    };
                    self.job_done();
                    self.reload_programs(ctx);
                }
                Msg::Removed(outcome) => {
                    // As the removal ran, not as the setting reads now.
                    let dry_run = outcome.dry_run;
                    let lines =
                        with_tool_lines(removal_log(&outcome, dry_run), system::take_tool_log());
                    let line = lines.last().cloned().unwrap_or_default();
                    self.log.extend(lines);
                    if let Some(name) = &outcome.backup_name {
                        self.log.push(format!(
                            "Undo from the command line: oxidize restore \"{name}\""
                        ));
                    }
                    if outcome.failed > 0 {
                        self.log.push(
                            "Some removals failed, usually missing administrator rights."
                                .to_string(),
                        );
                    }
                    self.status = line;
                    self.job_done();
                    if !dry_run {
                        // Re-scan to show what remains, and refresh the list.
                        self.scan = None;
                        if let Some(program) = self.selected_program() {
                            let program = program.clone();
                            self.start_scan(ctx, program);
                        }
                        self.reload_programs(ctx);
                    }
                }
                Msg::Completed {
                    program,
                    outcome,
                    dry_run,
                } => {
                    if self.on_completed(program, *outcome, dry_run) {
                        self.reload_programs(ctx);
                    }
                }
                Msg::Restored {
                    backup,
                    result,
                    dry_run,
                } => {
                    if self.on_restored(&backup, result, dry_run) {
                        self.reload_programs(ctx);
                    }
                }
                Msg::Icon { id, rgba, w, h } => {
                    let image =
                        egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
                    let tex =
                        ctx.load_texture(format!("ico-{id}"), image, egui::TextureOptions::LINEAR);
                    self.icons.insert(id, tex);
                }
                Msg::Analysed(found) => {
                    let (places, analysis) = *found;
                    self.status = analysed_status(&analysis);
                    self.cleanup.take_analysis(places, analysis);
                    self.job_done();
                }
                Msg::BuildFound(found) => {
                    self.cleanup.take_build_output(*found);
                    if let Some((_, analysis)) = &self.cleanup.analysis {
                        self.status = analysed_status(analysis);
                    }
                    self.job_done();
                }
                Msg::Cleaned(results) => self.on_cleaned(results),
                Msg::TracesFound(found) => {
                    self.cleanup.slate.take_found(found);
                    self.job_done();
                }
                Msg::TracesCleared(results) => self.on_traces_cleared(results),
                Msg::Error(e) => {
                    // A cleaning that stopped is no longer under way.
                    self.cleanup.cleaning = false;
                    self.cleanup.drop_look_tick();
                    self.log.extend(system::take_tool_log());
                    self.log.push(format!("ERROR: {e}"));
                    self.status = e;
                    self.job_done();
                }
            }
        }
    }

    fn selected_program(&self) -> Option<&Program> {
        let id = self.selected.as_ref()?;
        self.programs
            .iter()
            .find(|p| p.id() == id)
            .or_else(|| self.uninstalled.as_ref().filter(|p| p.id() == id))
    }

    /// The programs the table shows, as indices into `self.programs`: the ones
    /// the search and the quick filter let through, in the table's order.
    fn display_indices(&self, today: NaiveDate) -> Vec<usize> {
        let terms = search_terms(&self.filter);
        let mut idx: Vec<usize> = self
            .programs
            .iter()
            .enumerate()
            .filter(|(_, p)| shows(p, &terms, self.quick, today))
            .map(|(i, _)| i)
            .collect();
        sort_indices(&self.programs, &mut idx, self.sort);
        idx
    }

    /// Select the program with this id. A different program drops the scan
    /// of the one before.
    fn select(&mut self, id: &str) {
        if self.selected.as_deref() != Some(id) {
            self.selected = Some(id.to_string());
            self.scan = None;
            self.scan_for = None;
        }
    }

    /// Move the selection with the arrow and page keys. The search field
    /// keeps its own keys; up and down are the table's even while typing.
    fn keyboard(&mut self, ctx: &egui::Context, display: &[usize]) {
        if self.confirm.is_some() || self.tab != Tab::Programs {
            return;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
            self.focus_search = true;
        }
        if display.is_empty() {
            return;
        }
        let page = ((self.table_view.1 / ROW_HEIGHT).floor() as isize).max(1);
        let step = ctx.input_mut(|i| {
            use egui::{Key, Modifiers};
            [
                (Key::ArrowDown, 1),
                (Key::ArrowUp, -1),
                (Key::PageDown, page),
                (Key::PageUp, -page),
            ]
            .into_iter()
            .find(|(key, _)| i.consume_key(Modifiers::NONE, *key))
            .map(|(_, by)| by)
        });
        let Some(by) = step else { return };
        let at = self
            .selected
            .as_deref()
            .and_then(|id| display.iter().position(|&i| self.programs[i].id() == id));
        if let Some(row) = moved(at, display.len(), by) {
            let id = self.programs[display[row]].id().to_string();
            self.select(&id);
            self.reveal = true;
        }
    }

    /// Render the confirmation modal, if any, and act on the user's choice.
    fn show_confirm(&mut self, ctx: &egui::Context) {
        if self.confirm.is_none() {
            return;
        }
        let message = match self.confirm.as_ref().unwrap() {
            Confirm::Uninstall(p, _) => uninstall_confirm_text(&p.display_name),
            Confirm::Remove(items, _, ctx) => {
                if ctx.make_backups {
                    format!(
                        "Remove {}? A backup is kept, so this can be undone.",
                        count(items.len(), "item", "items")
                    )
                } else {
                    format!(
                        "Remove {} permanently?",
                        count(items.len(), "item", "items")
                    )
                }
            }
            Confirm::Complete(p, ctx) => complete_confirm_text(&p.display_name, ctx),
            Confirm::Clean(_, text) => text.clone(),
            Confirm::Traces(text) => text.clone(),
        };
        // The button says what happens, and is red when it cannot be undone.
        let (verb, for_good) = match self.confirm.as_ref().unwrap() {
            Confirm::Uninstall(..) => ("Run uninstaller".to_string(), false),
            Confirm::Remove(items, _, ctx) => (
                format!("Remove {}", count(items.len(), "item", "items")),
                !ctx.make_backups,
            ),
            Confirm::Complete(_, ctx) => ("Remove completely".to_string(), !ctx.make_backups),
            Confirm::Clean(choice, _) => (
                match &self.cleanup.analysis {
                    Some((_, a)) => format!("Clean {}", util::human_size(a.chosen_bytes(choice))),
                    None => "Clean".to_string(),
                },
                choice.categories.iter().any(|c| !c.backed_up()),
            ),
            Confirm::Traces(_) => ("Clear".to_string(), true),
        };

        let mut decision: Option<bool> = None;
        // A question can stay open while a reload or a scan finishes; it is
        // answered only once nothing else runs.
        let idle = !self.busy();
        let frame =
            egui::Frame::popup(&ctx.style_of(ctx.theme())).inner_margin(egui::Margin::same(20));
        let modal = egui::Modal::new(egui::Id::unique("confirm"))
            .frame(frame)
            .show(ctx, |ui| {
                let t = Tint::for_ui(ui);
                ui.set_width(420.0);
                ui.add(egui::Label::new(RichText::new(message).size(15.0).color(t.text)).wrap());
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    let size = egui::vec2(0.0, 32.0);
                    let button = if for_good {
                        danger_button(&t, &verb)
                    } else {
                        primary_button(&t, &verb)
                    };
                    if ui.add_enabled(idle, button.min_size(size)).clicked() {
                        decision = Some(true);
                    }
                    if ui.add(egui::Button::new("Cancel").min_size(size)).clicked() {
                        decision = Some(false);
                    }
                });
            });
        // Escape and a click beside the question are a cancel.
        if decision.is_none() && modal.should_close() {
            decision = Some(false);
        }

        match decision {
            Some(true) if !idle => {}
            Some(true) => match self.confirm.take().unwrap() {
                Confirm::Uninstall(p, silent) => self.start_uninstall(ctx, p, silent),
                Confirm::Remove(items, label, safety) => {
                    self.start_remove(ctx, items, label, safety)
                }
                Confirm::Complete(p, safety) => self.start_remove_completely(ctx, p, safety),
                Confirm::Clean(choice, _) => self.start_clean(ctx, choice),
                Confirm::Traces(_) => self.start_clear_traces(ctx),
            },
            Some(false) => self.confirm = None,
            None => {}
        }
    }
}

/// The question "Remove completely" asks, worded from the window's settings.
fn complete_confirm_text(name: &str, ctx: &SafetyContext) -> String {
    let level = match COMPLETE_LEVEL {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    };
    if ctx.dry_run {
        format!(
            "Preview removing {name} completely? Dry run is on: nothing is closed or removed, \
             the result lists what would go at {level} confidence."
        )
    } else if ctx.make_backups {
        // The backup holds only what Oxidize removes itself.
        format!(
            "Remove {name} completely? Running copies are asked to close, everything found at \
             {level} confidence is removed, a backup is kept. What its own uninstaller removes, \
             if it runs, is not in the backup."
        )
    } else {
        format!(
            "Remove {name} completely? Running copies are asked to close, everything found at \
             {level} confidence is removed permanently, no backup is kept."
        )
    }
}

/// The question "Run uninstaller" asks. The backup setting does not reach
/// what a program's own uninstaller removes, so it says so either way.
fn uninstall_confirm_text(name: &str) -> String {
    format!("Run the uninstaller for {name}? What it removes is not backed up.")
}

/// "1 running process", "2 running processes".
fn running_processes(n: usize) -> String {
    if n == 1 {
        "1 running process".to_string()
    } else {
        format!("{n} running processes")
    }
}

/// `lines` with what console tools `said` put in before the last line, the
/// summary.
fn with_tool_lines(mut lines: Vec<String>, said: Vec<String>) -> Vec<String> {
    let at = lines.len().saturating_sub(1);
    lines.splice(at..at, said);
    lines
}

/// The log lines for one removal: each item, then a summary line last.
fn removal_log(outcome: &DeletionOutcome, dry_run: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for item in &outcome.items {
        match &item.status {
            ItemStatus::Removed => lines.push(format!("removed {}", item.path)),
            ItemStatus::RemovedAfterRestart => {
                lines.push(format!("{} goes at the next restart", item.path))
            }
            ItemStatus::AlreadyGone => lines.push(format!("already gone {}", item.path)),
            ItemStatus::Failed(e) => lines.push(format!("failed {}: {e}", item.path)),
            ItemStatus::WouldRemove => lines.push(format!("would remove {}", item.path)),
        }
    }
    for p in &outcome.emptied_parents {
        lines.push(format!("removed {} (emptied folder)", p.display()));
    }
    for k in &outcome.emptied_keys {
        lines.push(format!("removed {k} (emptied key)"));
    }
    lines.push(if dry_run {
        format!(
            "dry run: {} would be removed",
            count(outcome.attempted, "item", "items")
        )
    } else {
        let mut parts = vec![format!("{} removed", outcome.deleted)];
        if outcome.skipped > 0 {
            parts.push(format!("{} already gone", outcome.skipped));
        }
        if outcome.failed > 0 {
            parts.push(format!("{} failed", outcome.failed));
        }
        parts.join(", ")
    });
    lines
}

/// The log lines for a complete removal, in the order its steps ran.
fn complete_log(name: &str, out: &Outcome, dry_run: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if dry_run {
        if !out.would_close.is_empty() {
            lines.push(format!(
                "dry run: would close {}",
                running_processes(out.would_close.len())
            ));
        }
        lines.push(match &out.vendor {
            VendorStep::Skip { reason } => format!("dry run: would skip the uninstaller: {reason}"),
            VendorStep::Run { reason, .. } => {
                format!("dry run: would run the uninstaller: {reason}")
            }
        });
        lines.push(format!(
            "dry run: {} would be removed",
            count(out.selected.len(), "item", "items")
        ));
        return lines;
    }
    let closed = out
        .closed
        .iter()
        .filter(|c| c.how == CloseHow::Closed)
        .count();
    if closed > 0 {
        lines.push(format!("Closed {}", running_processes(closed)));
    }
    for c in out.closed.iter().filter(|c| c.how == CloseHow::Failed) {
        lines.push(format!(
            "Could not close {}: {}",
            c.exe,
            c.error.as_deref().unwrap_or("unknown error")
        ));
    }
    match (&out.vendor, &out.uninstaller) {
        (VendorStep::Skip { reason }, _) => {
            lines.push(format!("Skipped the uninstaller: {reason}"))
        }
        (VendorStep::Run { .. }, Some(how)) => lines.push(format!("Uninstaller {how}")),
        // It did not start; the error says why.
        (VendorStep::Run { .. }, None) => {}
    }
    if let Some(removal) = &out.removal {
        lines.extend(removal_log(removal, false));
        if let Some(backup) = &removal.backup_name {
            lines.push(format!("Backup kept: {backup}"));
        }
    }
    if let Some(e) = &out.error {
        lines.push(format!("ERROR: {}", window_error(e)));
    }
    lines.push(complete_status(name, out, false));
    lines
}

/// An error as the window shows it: the window has a button where the
/// command line has a flag.
fn window_error(text: &str) -> String {
    if text.contains(uninstall::NEEDS_ADMIN) {
        "The uninstaller needs administrator rights: Restart as administrator, then try again."
            .to_string()
    } else if text.contains(uninstall::UNINSTALLER_MISSING) {
        "The uninstaller file is missing.".to_string()
    } else {
        text.to_string()
    }
}

/// The removal stopped because the uninstaller it needed did not start.
fn never_started(out: &Outcome) -> bool {
    out.error.is_some() && out.vendor.runs() && out.uninstaller.is_none()
}

/// One line on how a complete removal ended, for the status bar.
fn complete_status(name: &str, out: &Outcome, dry_run: bool) -> String {
    if dry_run {
        format!(
            "dry run: {} of {name} would be removed",
            count(out.selected.len(), "item", "items")
        )
    } else if out.complete() {
        format!("{name}: nothing left.")
    } else if let Some(stop) = complete::still_running(&out.closed) {
        stop
    } else if never_started(out) {
        format!("{name}: the uninstaller did not start. Nothing was removed.")
    } else if let Some(e) = &out.error {
        e.clone()
    } else if out.verdict.still_installed {
        format!(
            "{name} is still registered. The uninstaller may have been cancelled or is still running."
        )
    } else if !out.verdict.remaining.is_empty() {
        format!(
            "{name}: {} still there.",
            count(out.verdict.remaining.len(), "item is", "items are")
        )
    } else {
        format!("{name}: some items could not be removed.")
    }
}

/// How many items a complete removal took: each removed item and every
/// folder or key it left empty.
fn removed_count(out: &Outcome) -> usize {
    out.removal.as_ref().map_or(0, |o| {
        o.deleted + o.emptied_parents.len() + o.emptied_keys.len()
    })
}

impl eframe::App for OxidizeApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Panels take a `Ui`, but the worker helpers and the confirmation
        // window still need the `Context`; cloning it is just an Arc bump.
        let ctx = ui.ctx().clone();
        let ctx = &ctx;
        let t = Tint::for_ui(ui);
        let today = chrono::Local::now().date_naive();

        self.drain_messages(ctx);
        let requested = ctx.input(|i| i.viewport().close_requested());
        if let Some(cmd) = self.close_step(requested) {
            ctx.send_viewport_cmd(cmd);
        }
        self.show_confirm(ctx);
        let display = self.display_indices(today);
        self.keyboard(ctx, &display);

        let mut action: Option<Action> = None;

        egui::Panel::top("toolbar")
            .frame(bar_frame(t.chrome))
            .show(ui, |ui| self.toolbar(ui, &t, &mut action));

        egui::Panel::bottom("status")
            .frame(bar_frame(t.chrome))
            .show(ui, |ui| self.status_bar(ui, &t));

        if self.show_log {
            egui::Panel::bottom("log")
                .resizable(true)
                .default_size(150.0)
                .size_range(80.0..=360.0)
                .frame(
                    egui::Frame::new()
                        .fill(t.base)
                        .inner_margin(egui::Margin::symmetric(14, 8)),
                )
                .show(ui, |ui| self.log_view(ui, &t));
        }

        if self.tab == Tab::Cleanup {
            self.cleanup_tab(ui, &t, &mut action);
        } else {
            self.programs_tab(ui, &t, today, &mut action);
        }

        focus_ring(ctx, &t);

        // ---- Execute the requested action (outside the panel borrows) ----
        if let Some(action) = action {
            self.act(ctx, action);
        }
    }
}

/// Outline whatever holds the keyboard focus in copper, as the search field
/// outlines itself, so Tab never lands on something that looks untouched.
fn focus_ring(ctx: &egui::Context, t: &Tint) {
    // Only a widget drawn in this pass: one that just went keeps its place
    // from the last pass, where something else may sit now.
    let Some(response) = ctx
        .memory(|m| m.focused())
        .filter(|&id| ctx.viewport(|v| v.this_pass.widgets.contains(id)))
        .and_then(|id| ctx.read_response(id))
    else {
        return;
    };
    // A text field draws its own outline.
    if response.sense.senses_drag() {
        return;
    }
    let radius = ctx
        .data(|d| d.get_temp::<f32>(response.id.with(RING_RADIUS)))
        .unwrap_or(4.0);
    ctx.layer_painter(response.layer_id)
        .with_clip_rect(response.interact_rect)
        .rect_stroke(
            response.rect,
            radius,
            egui::Stroke::new(1.0, t.copper),
            egui::StrokeKind::Inside,
        );
}

/// Where a widget with rounder corners leaves the radius for its focus ring.
const RING_RADIUS: &str = "focus ring radius";

impl OxidizeApp {
    /// The program overview, table and details panel.
    fn programs_tab(
        &mut self,
        ui: &mut egui::Ui,
        t: &Tint,
        today: NaiveDate,
        action: &mut Option<Action>,
    ) {
        let t = *t;
        let frame = egui::Frame::new()
            .fill(t.side)
            .inner_margin(egui::Margin::same(20));
        if is_tall(ui.available_size()) {
            // A portrait window: the details under the table, so the table
            // keeps the full width and its publisher column.
            let tallest = (ui.available_height() * 0.6).max(260.0);
            egui::Panel::bottom("details_below")
                .resizable(true)
                .default_size((ui.available_height() * 0.42).max(260.0))
                .size_range(220.0..=tallest)
                .frame(frame)
                .show(ui, |ui| self.details(ui, &t, action));
        } else {
            // The table takes what it reads best at and the details the
            // rest, so a wide window has no empty stretch beside the table.
            let width = details_width(ui.available_width());
            egui::Panel::right("details")
                .resizable(false)
                .exact_size(width)
                .frame(frame)
                .show(ui, |ui| self.details(ui, &t, action));
        }

        let overview = overview(&self.programs, today);
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(t.base).inner_margin(egui::Margin {
                left: 20,
                right: 20,
                top: 16,
                bottom: 0,
            }))
            .show(ui, |ui| {
                self.filter_row(ui, &t, &overview, today);
                // The search or a quick filter may have changed just now.
                let display = self.display_indices(today);
                self.table(ui, &t, &display);
            });
    }

    /// The Clean up tab, with the protected folders beside it.
    fn cleanup_tab(&mut self, ui: &mut egui::Ui, t: &Tint, action: &mut Option<Action>) {
        let (busy, dry_run) = (self.busy(), self.dry_run);
        self.cleanup.busy = busy;
        // The same layout as the program view: the list, and beside it (or
        // under it on a portrait screen) the panel for what is in focus.
        let frame = egui::Frame::new()
            .fill(t.side)
            .inner_margin(egui::Margin::same(20));
        if is_tall(ui.available_size()) {
            let tallest = (ui.available_height() * 0.6).max(260.0);
            egui::Panel::bottom("cleanup_side_below")
                .resizable(true)
                .default_size((ui.available_height() * 0.38).max(240.0))
                .size_range(200.0..=tallest)
                .frame(frame)
                .show(ui, |ui| cleanup::side(ui, t, &mut self.cleanup));
        } else {
            egui::Panel::right("cleanup_side")
                .resizable(false)
                .exact_size(details_width(ui.available_width()))
                .frame(frame)
                .show(ui, |ui| cleanup::side(ui, t, &mut self.cleanup));
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(t.base).inner_margin(egui::Margin {
                left: 20,
                right: 20,
                top: 16,
                bottom: 0,
            }))
            .show(ui, |ui| {
                cleanup::strip(ui, t, &mut self.cleanup, busy, dry_run, action);
                cleanup::view(ui, t, &mut self.cleanup, busy, action);
            });
    }

    /// Carry out what a click asked for, after the panels are drawn.
    fn act(&mut self, ctx: &egui::Context, action: Action) {
        // One thing at a time: a Refresh, a second removal or a restart
        // while a removal runs would act on what it is still changing, and
        // a restart would end it halfway.
        if self.busy() {
            return;
        }
        // An unreadable protected list stands in as an empty one, which
        // would protect nothing.
        if let Some(why) = self.cleanup.refusal(&action) {
            if matches!(action, Action::FindBuildOutput) {
                self.cleanup.drop_look_tick();
            }
            self.status = why;
            return;
        }
        {
            match action {
                Action::Refresh => self.load_programs(ctx),
                Action::Scan(p) => {
                    // The scan replaces the result of a complete removal.
                    self.complete = None;
                    self.start_scan(ctx, p);
                }
                Action::Uninstall(p) if self.confirm.is_none() => {
                    if self.dry_run {
                        match uninstall::plan(&p, self.silent) {
                            Ok(plan) => {
                                let line = format!("dry run: would run {}", plan.display());
                                self.log.push(line.clone());
                                self.status = line;
                            }
                            Err(e) => {
                                let line = format!("Cannot uninstall {}: {e:#}", p.display_name);
                                self.log.push(line.clone());
                                self.status = line;
                            }
                        }
                    } else {
                        self.confirm = Some(Confirm::Uninstall(p, self.silent));
                    }
                }
                Action::Remove(items, label) if self.confirm.is_none() => {
                    if self.dry_run {
                        let safety = self.safety_ctx();
                        self.start_remove(ctx, items, label, safety);
                    } else {
                        self.confirm = Some(Confirm::Remove(items, label, self.safety_ctx()));
                    }
                }
                Action::RemoveCompletely(p) if self.confirm.is_none() => {
                    self.confirm = Some(Confirm::Complete(p, self.safety_ctx()));
                }
                // A question is already on screen: let the user answer it first.
                Action::Uninstall(_) | Action::Remove(..) | Action::RemoveCompletely(_) => {}
                Action::Undo(name) => self.start_undo(ctx, name),
                Action::RestartAdmin => match safety::relaunch_elevated() {
                    Ok(()) => std::process::exit(0),
                    Err(e) => self.log.push(format!("Could not elevate: {e:#}")),
                },
                Action::Analyse => self.start_analyse(ctx),
                Action::FindBuildOutput => self.start_find_build_output(ctx),
                Action::Clean(choice) if self.confirm.is_none() => {
                    let Some((_, analysis)) = &self.cleanup.analysis else {
                        return;
                    };
                    if self.dry_run {
                        let line = format!(
                            "dry run: {} in {} would be cleaned",
                            util::human_size(analysis.chosen_bytes(&choice)),
                            count(choice.categories.len(), "category", "categories")
                        );
                        self.log.push(line.clone());
                        self.status = line;
                    } else {
                        let text = cleanup::confirm_text(analysis, &choice, self.make_backups);
                        self.confirm = Some(Confirm::Clean(choice, text));
                    }
                }
                Action::Clean(_) => {}
                Action::ClearTraces if self.confirm.is_none() => {
                    let Some(found) = &self.cleanup.slate.found else {
                        return;
                    };
                    if self.dry_run {
                        let (n, _) = clean::traces::total(found);
                        let line = format!(
                            "dry run: {} would be cleared",
                            count(n, "usage trace", "usage traces")
                        );
                        self.log.push(line.clone());
                        self.status = line;
                    } else {
                        self.confirm = Some(Confirm::Traces(slate::confirm_text(found)));
                    }
                }
                Action::ClearTraces => {}
            }
        }
    }
}

/// The status line after an analysis.
fn analysed_status(analysis: &clean::Analysis) -> String {
    let chosen = analysis.default_choice();
    format!(
        "Analysed. The ticked categories hold {}.",
        util::human_size(analysis.chosen_bytes(&chosen))
    )
}

// The window's parts, top to bottom.
// ------------------------------------------------------------------------

impl OxidizeApp {
    /// The bar across the top: the name and the two tabs on the left; the
    /// settings, the administrator state and Refresh on the right. The
    /// settings live in one menu, and a dry run says so in the bar, since it
    /// changes what every button does.
    fn toolbar(&mut self, ui: &mut egui::Ui, t: &Tint, action: &mut Option<Action>) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Oxidize").size(16.0).strong().color(t.text));
            ui.add_space(20.0);
            for (tab, label) in [(Tab::Programs, "Programs"), (Tab::Cleanup, "Clean up")] {
                if tab_label(ui, t, self.tab == tab, label).clicked() {
                    self.tab = tab;
                }
                ui.add_space(8.0);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // What runs was started with these settings and this list;
                // they stay as they are until it is done.
                let idle = !self.busy();
                if self.tab == Tab::Programs
                    && ui.add_enabled(idle, egui::Button::new("Refresh")).clicked()
                {
                    *action = Some(Action::Refresh);
                }
                ui.menu_button("Options", |ui| {
                    ui.set_min_width(240.0);
                    ui.add_enabled_ui(idle, |ui| {
                        for setting in Setting::ALL {
                            if setting == Setting::System {
                                ui.separator();
                            }
                            self.setting(ui, setting, action);
                        }
                    });
                });
                if self.elevated {
                    ui.label(RichText::new("Administrator").color(t.weak))
                        .on_hover_text("Running with administrator rights");
                } else if ui
                    .add_enabled(
                        idle,
                        egui::Button::new(RichText::new("Restart as administrator").color(t.weak))
                            .frame(false),
                    )
                    .on_hover_text(
                        "Programs installed for all users and Windows' own stores \
                         need administrator rights",
                    )
                    .clicked()
                {
                    *action = Some(Action::RestartAdmin);
                }
                if self.dry_run {
                    badge(ui, t, "Dry run: nothing changes", t.amber);
                }
            });
        });
    }

    fn setting(&mut self, ui: &mut egui::Ui, setting: Setting, action: &mut Option<Action>) {
        match setting {
            Setting::DryRun => {
                ui.checkbox(&mut self.dry_run, "Dry run, change nothing")
                    .on_hover_text("Show what would happen without changing anything");
            }
            Setting::Backups => {
                ui.checkbox(&mut self.make_backups, "Back up before deleting")
                    .on_hover_text(
                        "Export registry keys to .reg and quarantine files before Oxidize deletes \
                         them. What a program's own uninstaller removes is not covered.",
                    );
            }
            Setting::Silent => {
                ui.checkbox(&mut self.silent, "Uninstall silently where possible")
                    .on_hover_text(
                        "Use the program's unattended uninstall switches where available",
                    );
            }
            Setting::System => {
                if ui
                    .checkbox(&mut self.include_system, "Show system components")
                    .on_hover_text("Also list the components Windows hides from its own list")
                    .changed()
                {
                    *action = Some(Action::Refresh);
                }
            }
        }
    }

    /// The line at the bottom: what is happening, and the log behind it.
    fn status_bar(&mut self, ui: &mut egui::Ui, t: &Tint) {
        ui.horizontal(|ui| {
            let toggle = 96.0;
            let room = egui::vec2(
                (ui.available_width() - toggle).max(0.0),
                ui.spacing().interact_size.y,
            );
            ui.allocate_ui_with_layout(
                room,
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    if self.busy() {
                        ui.spinner();
                    }
                    ui.add(egui::Label::new(RichText::new(&self.status).color(t.weak)).truncate());
                },
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if self.log.is_empty() {
                    "Log".to_string()
                } else {
                    format!("Log ({})", self.log.len())
                };
                if ui.selectable_label(self.show_log, label).clicked() {
                    self.show_log = !self.show_log;
                }
            });
        });
    }

    fn log_view(&self, ui: &mut egui::Ui, t: &Tint) {
        egui::ScrollArea::vertical()
            .id_salt("log_scroll")
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if self.log.is_empty() {
                    ui.label(RichText::new("Nothing has run yet.").color(t.weak));
                }
                for line in &self.log {
                    let color = if line.starts_with("ERROR") || line.starts_with("failed ") {
                        t.red
                    } else {
                        t.text
                    };
                    ui.label(RichText::new(line).monospace().color(color));
                }
            });
    }

    /// The search field, the quick filters, and how many programs show and
    /// how much all of them take.
    fn filter_row(&mut self, ui: &mut egui::Ui, t: &Tint, ov: &Overview, today: NaiveDate) {
        let narrow = ui.available_width() < 640.0;
        let chips = |app: &mut OxidizeApp, ui: &mut egui::Ui| {
            for quick in QuickFilter::ALL {
                if chip(ui, t, app.quick == quick, quick.label(), ov.count(quick))
                    .on_hover_text(quick.hint())
                    .clicked()
                {
                    app.quick = quick;
                }
            }
        };
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let width = if narrow {
                (ui.available_width() - 140.0).max(120.0)
            } else {
                260.0
            };
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Search name or publisher  (Ctrl+F)")
                    .desired_width(width)
                    .margin(egui::Margin::symmetric(8, 5)),
            );
            if self.focus_search {
                search.request_focus();
                self.focus_search = false;
            }
            if !narrow {
                ui.add_space(6.0);
                chips(self, ui);
            }
            let terms = search_terms(&self.filter);
            let shown = self
                .programs
                .iter()
                .filter(|p| shows(p, &terms, self.quick, today))
                .count();
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // The longest wording that fits beside the filters.
                let lines = count_lines(shown, ov.programs, ov.total_bytes);
                let galleys = lines.each_ref().map(|line| {
                    egui::WidgetText::from(RichText::new(line).color(t.weak)).into_galley(
                        ui,
                        Some(egui::TextWrapMode::Extend),
                        f32::INFINITY,
                        egui::TextStyle::Body,
                    )
                });
                let room = ui.available_width();
                let pick = galleys
                    .iter()
                    .position(|g| g.size().x <= room)
                    .unwrap_or(galleys.len() - 1);
                let label = ui.label(galleys[pick].clone());
                if pick > 0 {
                    label.on_hover_text(&lines[0]);
                }
            });
        });
        if narrow {
            ui.horizontal(|ui| chips(self, ui));
        }
        ui.add_space(8.0);
    }

    /// The program table: a header to sort by and one row per program,
    /// drawn only where it is visible.
    fn table(&mut self, ui: &mut egui::Ui, t: &Tint, display: &[usize]) {
        let cols = columns(ui.available_width());
        self.table_header(ui, t, &cols);
        if display.is_empty() {
            // In place of the rows, on the names' left edge.
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.add_space(ROW_PAD + ICON + 10.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 8.0;
                    if self.programs.is_empty() && self.busy() {
                        ui.label(RichText::new("Reading the installed programs...").color(t.weak));
                    } else if self.programs.is_empty() {
                        ui.label(RichText::new("No installed programs were found.").color(t.text));
                        ui.label(
                            RichText::new("Refresh reads the list from Windows again.")
                                .color(t.weak),
                        );
                    } else {
                        let what = if self.filter.trim().is_empty() {
                            format!("No programs in {}.", self.quick.label())
                        } else {
                            format!("No programs match \u{201c}{}\u{201d}.", self.filter.trim())
                        };
                        ui.label(RichText::new(what).color(t.text));
                        if ui.button("Show all programs").clicked() {
                            self.filter.clear();
                            self.quick = QuickFilter::All;
                        }
                    }
                });
            });
            return;
        }
        let mut offset = None;
        if std::mem::take(&mut self.reveal) {
            let row = self
                .selected
                .as_deref()
                .and_then(|id| display.iter().position(|&i| self.programs[i].id() == id));
            if let Some(row) = row {
                offset = scroll_to_show(row, self.table_view.0, self.table_view.1);
            }
        }
        let body = egui::TextStyle::Body.resolve(ui.style());
        ui.scope(|ui| {
            // Rows sit flush, so row n starts at n * ROW_HEIGHT.
            ui.spacing_mut().item_spacing.y = 0.0;
            let mut area = egui::ScrollArea::vertical()
                .id_salt("programs")
                .auto_shrink([false, false]);
            if let Some(y) = offset {
                area = area.vertical_scroll_offset(y);
            }
            let out = area.show_rows(ui, ROW_HEIGHT, display.len(), |ui, rows| {
                let mut clicked = None;
                for row in rows {
                    let i = display[row];
                    if self.program_row(ui, t, &cols, i, &body) {
                        clicked = Some(i);
                    }
                }
                clicked
            });
            self.table_view = (out.state.clamped_offset().y, out.inner_rect.height());
            if let Some(i) = out.inner {
                let id = self.programs[i].id().to_string();
                self.select(&id);
            }
        });
    }

    fn table_header(&mut self, ui: &mut egui::Ui, t: &Tint, cols: &[Placed]) {
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 28.0), egui::Sense::hover());
        let painter = ui.painter().clone();
        let font = egui::FontId::proportional(12.0);
        for col in cols {
            let cell = col.cell(rect);
            // The name's header also covers the icon in front of it.
            let hit = if col.column == Column::Name {
                cell.with_min_x(rect.left())
            } else {
                cell
            };
            let id = ui.scope_id().with(("sort", col.column.title()));
            let response = ui.interact(hit, id, egui::Sense::click());
            response.widget_info(|| {
                egui::WidgetInfo::labeled(egui::Role::Button, true, col.column.title())
            });
            let active = self.sort.column == col.column;
            let color = if active || response.hovered() {
                t.text
            } else {
                t.weak
            };
            let galley =
                painter.layout_no_wrap(col.column.title().to_string(), font.clone(), color);
            let arrow = if active { 12.0 } else { 0.0 };
            let x = if col.column.right_aligned() {
                cell.right() - galley.size().x - arrow
            } else {
                cell.left()
            };
            let y = cell.center().y - galley.size().y / 2.0;
            let text_right = x + galley.size().x;
            painter.galley(egui::pos2(x, y), galley, color);
            if active {
                let center = egui::pos2(text_right + 7.0, cell.center().y);
                sort_arrow(&painter, center, self.sort.descending, t.copper);
            }
            if response.clicked() {
                self.sort = self.sort.clicked(col.column);
            }
        }
        painter.hline(
            rect.x_range(),
            rect.bottom() - 0.5,
            egui::Stroke::new(1.0, t.line),
        );
    }

    /// One program's row. True when it was clicked.
    fn program_row(
        &self,
        ui: &mut egui::Ui,
        t: &Tint,
        cols: &[Placed],
        i: usize,
        font: &egui::FontId,
    ) -> bool {
        let program = &self.programs[i];
        let selected = self.selected.as_deref() == Some(program.id());
        let (rect, response) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), ROW_HEIGHT),
            egui::Sense::click(),
        );
        response.widget_info(|| {
            egui::WidgetInfo::selected(egui::Role::Button, true, selected, &program.display_name)
        });
        if !ui.is_rect_visible(rect) {
            return response.clicked();
        }
        let painter = ui.painter_at(rect);
        if selected {
            painter.rect_filled(rect, 4.0, t.selected);
            let mark = egui::Rect::from_min_size(rect.left_top(), egui::vec2(3.0, rect.height()))
                .shrink2(egui::vec2(0.0, 6.0));
            painter.rect_filled(mark, 1.5, t.copper);
        } else if response.hovered() {
            painter.rect_filled(rect, 4.0, t.hover);
        }
        if let Some(tex) = self.icons.get(program.id()) {
            let icon = egui::Rect::from_center_size(
                egui::pos2(rect.left() + ROW_PAD + ICON / 2.0, rect.center().y),
                egui::vec2(ICON, ICON),
            );
            let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
            painter.image(tex.id(), icon, uv, Color32::WHITE);
        }
        for col in cols {
            let cell = col.cell(rect);
            let weak = |text: &str| {
                cell_text(&painter, cell, text, font.clone(), t.weak, egui::Align::Min)
            };
            match col.column {
                Column::Name => cell_text(
                    &painter,
                    cell,
                    &program.display_name,
                    font.clone(),
                    t.text,
                    egui::Align::Min,
                ),
                Column::Publisher => weak(program.publisher.as_deref().unwrap_or("")),
                Column::Size => size_cell(&painter, t, cell, program.size_bytes(), font),
                Column::Installed => weak(program.install_date.as_deref().unwrap_or("")),
                Column::Source => weak(scope_label(program)),
            }
        }
        response.clicked()
    }

    /// The panel on the right: the selected program, its three actions, what
    /// is known about it, and the result of the last scan or removal.
    fn details(&mut self, ui: &mut egui::Ui, t: &Tint, action: &mut Option<Action>) {
        let Some(program) = self.selected_program().cloned() else {
            ui.add_space(4.0);
            ui.spacing_mut().item_spacing.y = 8.0;
            ui.label(
                RichText::new("No program selected")
                    .size(16.0)
                    .color(t.text),
            );
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Pick one in the list to remove it completely, run its own \
                         uninstaller, or see what it left behind.",
                    )
                    .color(t.weak),
                )
                .wrap(),
            );
            ui.add(
                egui::Label::new(
                    RichText::new("Up and Down move through the list, Ctrl+F searches it.")
                        .color(t.weak),
                )
                .wrap(),
            );
            return;
        };
        // Taken for the frame and put back, so the report is not copied.
        let scan = self.scan.take();
        let mut checked = std::mem::take(&mut self.checked);
        egui::ScrollArea::vertical()
            .id_salt("details_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.details_head(ui, t, &program, action);
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);

                // The last complete removal of this program, until it is
                // scanned again or undone.
                if let Some(done) = self.shown_complete() {
                    let undo = self.undo_backup().map(str::to_string);
                    if show_complete(ui, t, done, undo.is_some(), !self.busy()) {
                        *action = undo.map(Action::Undo);
                    }
                    return;
                }

                // Scan results, only when they belong to the selected program.
                let belongs = self.scan_for.as_deref() == Some(program.id());
                match (&scan, belongs) {
                    (Some(report), true) => {
                        scan_results(ui, t, &program, report, &mut checked, self.dry_run, action)
                    }
                    _ => {
                        ui.label(
                            RichText::new(
                                "Scan for leftovers to list what it keeps in its folders, \
                                 the registry and the system.",
                            )
                            .color(t.weak),
                        );
                    }
                }
            });
        self.scan = scan;
        self.checked = checked;
    }

    fn details_head(
        &self,
        ui: &mut egui::Ui,
        t: &Tint,
        program: &Program,
        action: &mut Option<Action>,
    ) {
        ui.horizontal_top(|ui| {
            if let Some(tex) = self.icons.get(program.id()) {
                ui.image(egui::load::SizedTexture::new(
                    tex.id(),
                    egui::vec2(32.0, 32.0),
                ));
                ui.add_space(4.0);
            }
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add(
                    egui::Label::new(
                        RichText::new(&program.display_name)
                            .size(18.0)
                            .color(t.text),
                    )
                    .wrap(),
                );
                let line: Vec<String> = [
                    program
                        .display_version
                        .as_deref()
                        .map(|v| format!("Version {v}")),
                    program.publisher.clone(),
                ]
                .into_iter()
                .flatten()
                .collect();
                if !line.is_empty() {
                    ui.add(
                        egui::Label::new(RichText::new(line.join("  ·  ")).color(t.weak)).wrap(),
                    );
                }
            });
        });
        ui.add_space(14.0);
        let idle = !self.busy();
        let full = egui::vec2(ui.available_width(), 34.0);
        if ui
            .add_enabled(idle, primary_button(t, "Remove completely").min_size(full))
            .clicked()
        {
            *action = Some(Action::RemoveCompletely(program.clone()));
        }
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            let half = egui::vec2(
                (ui.available_width() - ui.spacing().item_spacing.x) / 2.0,
                30.0,
            );
            if ui
                .add_enabled(idle, egui::Button::new("Run uninstaller").min_size(half))
                .clicked()
            {
                *action = Some(Action::Uninstall(program.clone()));
            }
            if ui
                .add_enabled(idle, egui::Button::new("Scan for leftovers").min_size(half))
                .clicked()
            {
                *action = Some(Action::Scan(program.clone()));
            }
        });
        ui.add_space(14.0);
        let size = program.size_bytes().map(util::human_size);
        fact(ui, t, "Size", size.as_deref().unwrap_or("-"));
        fact(
            ui,
            t,
            "Installed",
            program.install_date.as_deref().unwrap_or("-"),
        );
        fact(ui, t, "Installed for", scope_label(program));
        fact(ui, t, "Registry", &program.source.label());
        fact(
            ui,
            t,
            "Location",
            program.install_location.as_deref().unwrap_or("-"),
        );
    }
}

/// The settings in the top bar, in reading order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setting {
    DryRun,
    Backups,
    Silent,
    System,
}

impl Setting {
    const ALL: [Setting; 4] = [
        Setting::DryRun,
        Setting::Backups,
        Setting::Silent,
        Setting::System,
    ];
}

/// The findings of a scan: a summary, the buttons to tick and remove them,
/// and the findings grouped by kind.
fn scan_results(
    ui: &mut egui::Ui,
    t: &Tint,
    program: &Program,
    report: &ScanReport,
    checked: &mut [bool],
    dry_run: bool,
    action: &mut Option<Action>,
) {
    if report.installed {
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Still installed. These items are its current footprint, not leftovers.",
                )
                .color(t.amber),
            )
            .wrap(),
        );
        ui.add_space(4.0);
    }
    let reclaim = report.reclaimable_bytes();
    let mut summary = count(report.total(), "item", "items");
    if reclaim > 0 {
        summary.push_str(&format!(", {} in files", util::human_size(reclaim)));
    }
    ui.label(RichText::new(summary).size(15.0).color(t.text));
    if report.is_empty() {
        ui.label(RichText::new("Nothing found.").color(t.verdigris));
        return;
    }
    ui.horizontal(|ui| {
        if ui.small_button("Check High").clicked() {
            for (i, l) in report.all().enumerate() {
                checked[i] = l.confidence == Confidence::High;
            }
        }
        if ui.small_button("Check all").clicked() {
            checked.iter_mut().for_each(|c| *c = true);
        }
        if ui.small_button("Uncheck all").clicked() {
            checked.iter_mut().for_each(|c| *c = false);
        }
    });
    let n_checked = checked.iter().filter(|c| **c).count();
    let remove_label = if dry_run {
        format!("Preview removal of {}", count(n_checked, "item", "items"))
    } else {
        format!(
            "Remove {}",
            count(n_checked, "checked item", "checked items")
        )
    };
    let full = egui::vec2(ui.available_width(), 30.0);
    if ui
        .add_enabled(
            n_checked > 0 && !report.installed,
            danger_button(t, &remove_label).min_size(full),
        )
        .clicked()
    {
        let items: Vec<Leftover> = report
            .all()
            .enumerate()
            .filter(|(i, _)| checked[*i])
            .map(|(_, l)| l.clone())
            .collect();
        *action = Some(Action::Remove(items, program.display_name.clone()));
    }
    ui.add_space(8.0);
    render_sections(ui, t, &report.items, checked, "scan");
}

/// Render how a complete removal ended. True when "Undo" was clicked; the
/// button shows only when `undo` is true and works only when `idle`.
fn show_complete(ui: &mut egui::Ui, t: &Tint, done: &Completed, undo: bool, idle: bool) -> bool {
    let out = &done.outcome;
    let v = &out.verdict;
    let mut clicked = false;
    if done.dry_run {
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "Dry run: {} would be removed, {} would be closed.",
                    count(out.selected.len(), "item", "items"),
                    running_processes(out.would_close.len())
                ))
                .color(t.text),
            )
            .wrap(),
        );
        ui.add_space(8.0);
        render_sections(ui, t, &out.selected, &mut [], "dry_run");
        return false;
    }
    if out.complete() {
        ui.label(RichText::new("Nothing left.").size(18.0).color(t.verdigris));
        ui.label(
            RichText::new(format!(
                "Removed {} in {:.1} s",
                count(removed_count(out), "item", "items"),
                out.seconds
            ))
            .color(t.weak),
        );
    } else if v.still_installed && !never_started(out) {
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{} is still registered. The uninstaller may have been cancelled or is still running.",
                    done.program.display_name
                ))
                .color(t.amber),
            )
            .wrap(),
        );
    }
    if v.below_level > 0 {
        ui.label(
            RichText::new(count(
                v.below_level,
                "lower-confidence item was kept",
                "lower-confidence items were kept",
            ))
            .color(t.weak),
        );
    }
    if let Some(e) = &out.error {
        ui.add(egui::Label::new(RichText::new(window_error(e)).color(t.red)).wrap());
    }
    if undo {
        ui.add_space(6.0);
        clicked = ui
            .add_enabled(
                idle,
                egui::Button::new("Undo").min_size(egui::vec2(96.0, 28.0)),
            )
            .clicked();
    }
    if !v.remaining.is_empty() {
        ui.add_space(10.0);
        ui.label(RichText::new("Still there").color(t.text));
        render_sections(ui, t, &v.remaining, &mut [], "remaining");
    }
    clicked
}

/// Leftovers grouped by kind, each group folding open and shut. `checked` is
/// indexed like `items`; an empty one shows no checkboxes.
fn render_sections(
    ui: &mut egui::Ui,
    t: &Tint,
    items: &[Leftover],
    checked: &mut [bool],
    salt: &str,
) {
    let font = egui::TextStyle::Body.resolve(ui.style());
    for section in Section::ALL {
        let indices: Vec<usize> = items
            .iter()
            .enumerate()
            .filter(|(_, l)| Section::of(l) == section)
            .map(|(i, _)| i)
            .collect();
        if indices.is_empty() {
            continue;
        }
        let bytes: u64 = indices.iter().filter_map(|&i| items[i].size_bytes).sum();
        let count = if bytes > 0 {
            format!("{}  ·  {}", indices.len(), util::human_size(bytes))
        } else {
            indices.len().to_string()
        };
        let mut title = egui::text::LayoutJob::default();
        title.append(
            section.title(),
            0.0,
            egui::TextFormat::simple(font.clone(), t.text),
        );
        title.append(&count, 10.0, egui::TextFormat::simple(font.clone(), t.weak));
        egui::CollapsingHeader::new(title)
            .id_salt((salt, section.title()))
            // A long list starts folded, so the groups after it stay in view.
            .default_open(indices.len() <= 100)
            .show(ui, |ui| {
                for &i in &indices {
                    leftover_row(ui, t, &items[i], checked.get_mut(i));
                }
            });
    }
}

/// One leftover: its checkbox, how sure the scan is, where it is and why it
/// was found.
fn leftover_row(ui: &mut egui::Ui, t: &Tint, item: &Leftover, checked: Option<&mut bool>) {
    ui.horizontal_top(|ui| {
        if let Some(checked) = checked {
            ui.add(egui::Checkbox::without_text(checked));
        }
        let (tag, _) = ui.allocate_exact_size(egui::vec2(46.0, 18.0), egui::Sense::hover());
        ui.painter().text(
            tag.left_center(),
            egui::Align2::LEFT_CENTER,
            item.confidence.label(),
            egui::FontId::proportional(11.5),
            t.confidence(item.confidence),
        );
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.add(egui::Label::new(RichText::new(&item.path).color(t.text)).wrap());
            let mut about = item.reason.clone();
            if let Some(bytes) = item.size_bytes {
                about.push_str(&format!(", {}", util::human_size(bytes)));
            }
            if item.is_empty_dir {
                about.push_str(", empty");
            }
            ui.add(egui::Label::new(RichText::new(about).small().color(t.weak)).wrap());
        });
    });
    ui.add_space(4.0);
}

/// A window clearly taller than it is wide, such as one on a portrait
/// screen.
fn is_tall(size: egui::Vec2) -> bool {
    size.y > size.x * 1.15
}

/// `n` and the noun that goes with it: "1 program", "20 programs".
fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// One line of facts in the details panel: a name, and its value wrapping
/// beside it.
fn fact(ui: &mut egui::Ui, t: &Tint, name: &str, value: &str) {
    ui.horizontal_top(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(100.0, 18.0), egui::Sense::hover());
        ui.painter().text(
            rect.left_center(),
            egui::Align2::LEFT_CENTER,
            name,
            egui::TextStyle::Body.resolve(ui.style()),
            t.weak,
        );
        ui.add(egui::Label::new(RichText::new(value).color(t.text)).wrap());
    });
}

/// A small rounded label in `color`, such as "Administrator".
fn badge(ui: &mut egui::Ui, t: &Tint, text: &str, color: Color32) {
    // Half way to the text colour, so it still reads on its own tinted fill.
    let ink = color.lerp_to_gamma(t.text, 0.5);
    let galley =
        ui.painter()
            .layout_no_wrap(text.to_string(), egui::FontId::proportional(12.0), ink);
    let size = galley.size() + egui::vec2(16.0, 6.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, text));
    if ui.is_rect_visible(rect) {
        ui.painter()
            .rect_filled(rect, rect.height() / 2.0, color.gamma_multiply(0.16));
        ui.painter()
            .galley(rect.center() - galley.size() / 2.0, galley, ink);
    }
}

/// A tab in the top bar: plain text, the open one brighter and underlined in
/// copper.
fn tab_label(ui: &mut egui::Ui, t: &Tint, open: bool, label: &str) -> egui::Response {
    let font = egui::FontId::proportional(14.0);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font, t.text);
    let size = egui::vec2(galley.size().x + 8.0, 28.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::Button, true, open, label));
    if ui.is_rect_visible(rect) {
        let color = if open || response.hovered() {
            t.text
        } else {
            t.weak
        };
        let pos = egui::pos2(
            rect.center().x - galley.size().x / 2.0,
            rect.center().y - galley.size().y / 2.0 - 1.0,
        );
        ui.painter().galley(pos, galley, color);
        if open {
            let line = egui::Rect::from_min_max(
                egui::pos2(rect.left() + 4.0, rect.bottom() - 2.0),
                egui::pos2(rect.right() - 4.0, rect.bottom()),
            );
            ui.painter().rect_filled(line, 1.0, t.copper);
        }
    }
    response
}

/// A quick filter above the table: its name and how many it lets through.
fn chip(ui: &mut egui::Ui, t: &Tint, selected: bool, label: &str, count: usize) -> egui::Response {
    let font = egui::FontId::proportional(13.0);
    let mut job = egui::text::LayoutJob::default();
    let color = if selected { t.text } else { t.weak };
    job.append(label, 0.0, egui::TextFormat::simple(font.clone(), color));
    job.append(
        &count.to_string(),
        6.0,
        egui::TextFormat::simple(font, color),
    );
    let galley = ui.painter().layout_job(job);
    let size = egui::vec2(galley.size().x + 22.0, 26.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::Button, true, selected, label));
    if response.has_focus() {
        ui.data_mut(|d| d.insert_temp(response.id.with(RING_RADIUS), 13.0f32));
    }
    if ui.is_rect_visible(rect) {
        let fill = if selected {
            t.button_active
        } else if response.hovered() {
            t.hover
        } else {
            Color32::TRANSPARENT
        };
        let stroke = if selected { t.line_strong } else { t.line };
        ui.painter().rect_filled(rect, 13.0, fill);
        ui.painter().rect_stroke(
            rect,
            13.0,
            egui::Stroke::new(1.0, stroke),
            egui::StrokeKind::Inside,
        );
        let pos = rect.center() - galley.size() / 2.0;
        ui.painter().galley(pos, galley, t.text);
    }
    response
}

/// A size, right-aligned so the units line up down the column.
fn size_cell(
    painter: &egui::Painter,
    t: &Tint,
    cell: egui::Rect,
    bytes: Option<u64>,
    font: &egui::FontId,
) {
    let Some(bytes) = bytes else { return };
    cell_text(
        painter,
        cell,
        &util::human_size(bytes),
        font.clone(),
        t.text,
        egui::Align::Max,
    );
}

/// `text` on one line in `cell`, cut with an ellipsis when it does not fit.
fn cell_text(
    painter: &egui::Painter,
    cell: egui::Rect,
    text: &str,
    font: egui::FontId,
    color: Color32,
    align: egui::Align,
) {
    if text.is_empty() || cell.width() <= 0.0 {
        return;
    }
    let mut job = egui::text::LayoutJob::simple_singleline(text.to_string(), font, color);
    job.wrap = egui::text::TextWrapping::truncate_at_width(cell.width());
    let galley = painter.layout_job(job);
    let x = match align {
        egui::Align::Max => cell.right() - galley.size().x,
        _ => cell.left(),
    };
    let y = cell.center().y - galley.size().y / 2.0;
    painter.galley(egui::pos2(x, y), galley, color);
}

/// The triangle beside the column the table is sorted by.
fn sort_arrow(painter: &egui::Painter, center: egui::Pos2, descending: bool, color: Color32) {
    let (w, h) = (4.0, 3.0);
    let (tip, base) = if descending { (h, -h) } else { (-h, h) };
    let points = vec![
        egui::pos2(center.x - w, center.y + base),
        egui::pos2(center.x + w, center.y + base),
        egui::pos2(center.x, center.y + tip),
    ];
    painter.add(egui::Shape::convex_polygon(
        points,
        color,
        egui::Stroke::NONE,
    ));
}

/// "All users" or "This user", from the hive the program is registered in.
fn scope_label(program: &Program) -> &'static str {
    match program.source.hive {
        Hive::LocalMachine => "All users",
        Hive::CurrentUser => "This user",
    }
}

// The look.
// ------------------------------------------------------------------------

/// The window's colours for one theme. Copper and verdigris come from the
/// Oxidize mark; everything else is a warm grey.
#[derive(Debug, Clone, Copy)]
struct Tint {
    dark: bool,
    /// The bars at the top and the bottom.
    chrome: Color32,
    /// Behind the overview and the table.
    base: Color32,
    /// Behind the details panel.
    side: Color32,
    /// Inside the search field.
    field: Color32,
    text: Color32,
    weak: Color32,
    line: Color32,
    line_strong: Color32,
    button: Color32,
    button_hover: Color32,
    button_active: Color32,
    /// A row under the pointer.
    hover: Color32,
    /// The selected row and quick filter.
    selected: Color32,
    copper: Color32,
    /// Text on a copper fill.
    on_copper: Color32,
    verdigris: Color32,
    amber: Color32,
    red: Color32,
}

impl Tint {
    fn of(dark: bool) -> Tint {
        let rgb = Color32::from_rgb;
        if dark {
            Tint {
                dark,
                chrome: rgb(0x15, 0x13, 0x12),
                base: rgb(0x1b, 0x19, 0x18),
                side: rgb(0x22, 0x1f, 0x1d),
                field: rgb(0x11, 0x10, 0x0f),
                text: rgb(0xeb, 0xe6, 0xe1),
                weak: rgb(0x9d, 0x96, 0x8f),
                line: rgb(0x33, 0x2f, 0x2c),
                line_strong: rgb(0x4a, 0x44, 0x3e),
                button: rgb(0x29, 0x26, 0x24),
                button_hover: rgb(0x32, 0x2e, 0x2b),
                button_active: rgb(0x3b, 0x36, 0x32),
                hover: rgb(0x25, 0x22, 0x20),
                selected: rgb(0x2f, 0x2b, 0x28),
                copper: rgb(0xe2, 0x79, 0x3d),
                on_copper: rgb(0x1b, 0x12, 0x0c),
                verdigris: rgb(0x5e, 0xc3, 0xb3),
                amber: rgb(0xdb, 0xa5, 0x43),
                red: rgb(0xec, 0x72, 0x62),
            }
        } else {
            Tint {
                dark,
                chrome: rgb(0xf2, 0xef, 0xeb),
                base: rgb(0xfa, 0xf9, 0xf7),
                side: rgb(0xff, 0xff, 0xff),
                field: rgb(0xff, 0xff, 0xff),
                text: rgb(0x1f, 0x1c, 0x19),
                weak: rgb(0x6a, 0x64, 0x5c),
                line: rgb(0xe4, 0xde, 0xd6),
                line_strong: rgb(0xcf, 0xc6, 0xbb),
                button: rgb(0xff, 0xff, 0xff),
                button_hover: rgb(0xf6, 0xf2, 0xee),
                button_active: rgb(0xed, 0xe7, 0xe0),
                hover: rgb(0xf1, 0xed, 0xe8),
                selected: rgb(0xea, 0xe4, 0xdd),
                copper: rgb(0xb5, 0x52, 0x1d),
                on_copper: rgb(0xff, 0xff, 0xff),
                verdigris: rgb(0x21, 0x7a, 0x6e),
                amber: rgb(0x94, 0x63, 0x00),
                red: rgb(0xbd, 0x3a, 0x2a),
            }
        }
    }

    fn for_ui(ui: &egui::Ui) -> Tint {
        Tint::of(ui.visuals().dark_mode)
    }

    fn confidence(&self, confidence: Confidence) -> Color32 {
        match confidence {
            Confidence::High => self.verdigris,
            Confidence::Medium => self.amber,
            Confidence::Low => self.weak,
        }
    }
}

/// egui's visuals in the window's colours.
fn visuals(t: &Tint) -> egui::Visuals {
    let mut v = if t.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    // Small enough that a checkbox stays a box.
    let radius = egui::CornerRadius::same(4);
    v.panel_fill = t.base;
    v.window_fill = t.side;
    v.window_stroke = egui::Stroke::new(1.0, t.line);
    v.window_corner_radius = egui::CornerRadius::same(10);
    v.menu_corner_radius = egui::CornerRadius::same(8);
    v.extreme_bg_color = t.field;
    v.text_edit_bg_color = Some(t.field);
    v.faint_bg_color = t.hover;
    v.code_bg_color = t.hover;
    v.hyperlink_color = t.verdigris;
    v.warn_fg_color = t.amber;
    v.error_fg_color = t.red;
    v.weak_text_color = Some(t.weak);
    v.selection.bg_fill = t.selected;
    v.selection.stroke = egui::Stroke::new(1.0, t.copper);
    let widgets = &mut v.widgets;
    widgets.noninteractive.fg_stroke.color = t.text;
    widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, t.line);
    widgets.noninteractive.corner_radius = radius;
    for (state, fill, stroke) in [
        (&mut widgets.inactive, t.button, t.line),
        (&mut widgets.hovered, t.button_hover, t.line_strong),
        (&mut widgets.active, t.button_active, t.line_strong),
        (&mut widgets.open, t.button_hover, t.line_strong),
    ] {
        state.weak_bg_fill = fill;
        state.bg_fill = fill;
        state.bg_stroke = egui::Stroke::new(1.0, stroke);
        state.corner_radius = radius;
        state.fg_stroke.color = t.text;
    }
    v
}

/// Give both themes the window's colours, type sizes and spacing. Which one
/// shows follows Windows.
fn apply_style(ctx: &egui::Context) {
    use egui::{FontFamily, FontId, TextStyle};
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        let tint = Tint::of(theme == egui::Theme::Dark);
        ctx.style_mut_of(theme, |style| {
            style.visuals = visuals(&tint);
            style.text_styles = [
                (
                    TextStyle::Heading,
                    FontId::new(20.0, FontFamily::Proportional),
                ),
                (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
                (
                    TextStyle::Button,
                    FontId::new(13.5, FontFamily::Proportional),
                ),
                (
                    TextStyle::Small,
                    FontId::new(11.5, FontFamily::Proportional),
                ),
                (
                    TextStyle::Monospace,
                    FontId::new(12.5, FontFamily::Monospace),
                ),
            ]
            .into();
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(10.0, 4.0);
            style.spacing.interact_size.y = 24.0;
            // Labels are read, not selected like text in a document.
            style.interaction.selectable_labels = false;
        });
    }
}

/// The frame of the bars at the top and the bottom.
fn bar_frame(fill: Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .inner_margin(egui::Margin::symmetric(20, 8))
}

/// The one copper button of a view.
fn primary_button(t: &Tint, text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).color(t.on_copper))
        .fill(t.copper)
        .stroke(egui::Stroke::NONE)
}

/// A button that deletes something.
fn danger_button(t: &Tint, text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).color(t.red))
        .stroke(egui::Stroke::new(1.0, t.red.gamma_multiply(0.5)))
}

// The program list: filtering, sorting, the overview and the table's
// geometry. Nothing here draws, so all of it is tested.
// ------------------------------------------------------------------------

/// A column of the program table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Column {
    Name,
    Publisher,
    Size,
    Installed,
    Source,
}

impl Column {
    fn title(self) -> &'static str {
        match self {
            Column::Name => "Name",
            Column::Publisher => "Publisher",
            Column::Size => "Size",
            Column::Installed => "Installed",
            Column::Source => "Installed for",
        }
    }

    /// Sizes and dates sort biggest and newest first on the first click.
    fn starts_descending(self) -> bool {
        matches!(self, Column::Size | Column::Installed)
    }

    fn right_aligned(self) -> bool {
        self == Column::Size
    }

    /// The width of a column that does not stretch.
    fn fixed_width(self) -> Option<f32> {
        match self {
            Column::Size => Some(88.0),
            Column::Installed => Some(92.0),
            Column::Source => Some(96.0),
            Column::Name | Column::Publisher => None,
        }
    }
}

/// The order of the table: a column and its direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sort {
    column: Column,
    descending: bool,
}

impl Default for Sort {
    fn default() -> Self {
        Sort {
            column: Column::Name,
            descending: false,
        }
    }
}

impl Sort {
    /// The order after a click on `column`'s header: the same column turns
    /// around, another one starts in its own direction.
    fn clicked(self, column: Column) -> Sort {
        if column == self.column {
            Sort {
                column,
                descending: !self.descending,
            }
        } else {
            Sort {
                column,
                descending: column.starts_descending(),
            }
        }
    }
}

/// Compare two values in the given direction, a missing one last either way.
fn present_first<T: Ord>(a: Option<T>, b: Option<T>, descending: bool) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) if descending => b.cmp(&a),
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Put `idx`, positions in `programs`, in `sort`'s order. A program without
/// the value sorted by goes last in both directions; equal values keep the
/// name order.
fn sort_indices(programs: &[Program], idx: &mut [usize], sort: Sort) {
    // Lower-cased once, not on every comparison.
    let names: Vec<String> = programs
        .iter()
        .map(|p| p.display_name.to_lowercase())
        .collect();
    let publishers: Vec<Option<String>> = programs
        .iter()
        .map(|p| {
            p.publisher
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase)
        })
        .collect();
    let descending = sort.descending;
    idx.sort_by(|&a, &b| {
        let (pa, pb) = (&programs[a], &programs[b]);
        let by_name = names[a].cmp(&names[b]).then_with(|| pa.id().cmp(pb.id()));
        let first = match sort.column {
            Column::Name if descending => return by_name.reverse(),
            Column::Name => return by_name,
            Column::Publisher => present_first(
                publishers[a].as_deref(),
                publishers[b].as_deref(),
                descending,
            ),
            Column::Size => present_first(pa.size_bytes(), pb.size_bytes(), descending),
            Column::Installed => present_first(
                pa.install_date.as_deref(),
                pb.install_date.as_deref(),
                descending,
            ),
            Column::Source => {
                present_first(Some(scope_label(pa)), Some(scope_label(pb)), descending)
            }
        };
        first.then(by_name)
    });
}

/// The quick filters above the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuickFilter {
    All,
    Large,
    Recent,
    PerUser,
}

impl QuickFilter {
    const ALL: [QuickFilter; 4] = [
        QuickFilter::All,
        QuickFilter::Large,
        QuickFilter::Recent,
        QuickFilter::PerUser,
    ];

    fn label(self) -> &'static str {
        match self {
            QuickFilter::All => "All",
            QuickFilter::Large => "Large",
            QuickFilter::Recent => "Recent",
            QuickFilter::PerUser => "Per user",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            QuickFilter::All => "Every program",
            QuickFilter::Large => "1 GB or more",
            QuickFilter::Recent => "Installed in the last 30 days",
            QuickFilter::PerUser => "Installed for this user only",
        }
    }

    fn lets_through(self, program: &Program, today: NaiveDate) -> bool {
        match self {
            QuickFilter::All => true,
            QuickFilter::Large => program.size_bytes().is_some_and(|b| b >= LARGE_BYTES),
            QuickFilter::Recent => installed_on(program).is_some_and(|d| is_recent(d, today)),
            QuickFilter::PerUser => program.source.hive == Hive::CurrentUser,
        }
    }
}

/// The search as lower-cased words.
fn search_terms(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_lowercase).collect()
}

/// True when `program` passes the quick filter and each search word is in
/// its name or its publisher.
fn shows(program: &Program, terms: &[String], quick: QuickFilter, today: NaiveDate) -> bool {
    if !quick.lets_through(program, today) {
        return false;
    }
    if terms.is_empty() {
        return true;
    }
    let name = program.display_name.to_lowercase();
    let publisher = program.publisher.as_deref().unwrap_or("").to_lowercase();
    terms
        .iter()
        .all(|term| name.contains(term.as_str()) || publisher.contains(term.as_str()))
}

/// The day the program was installed, when it has a real date.
fn installed_on(program: &Program) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(program.install_date.as_deref()?, "%Y-%m-%d").ok()
}

/// Installed at most `RECENT_DAYS` days before `today`. A date after today
/// comes from a clock that was off and counts as recent too.
fn is_recent(date: NaiveDate, today: NaiveDate) -> bool {
    (today - date).num_days() <= RECENT_DAYS
}

/// What the overview says about the installed programs.
#[derive(Debug, Default, PartialEq)]
struct Overview {
    programs: usize,
    total_bytes: u64,
    large: usize,
    recent: usize,
    per_user: usize,
}

impl Overview {
    /// How many programs a quick filter lets through, before any search.
    fn count(&self, quick: QuickFilter) -> usize {
        match quick {
            QuickFilter::All => self.programs,
            QuickFilter::Large => self.large,
            QuickFilter::Recent => self.recent,
            QuickFilter::PerUser => self.per_user,
        }
    }
}

fn overview(programs: &[Program], today: NaiveDate) -> Overview {
    let count = |quick: QuickFilter| {
        programs
            .iter()
            .filter(|p| quick.lets_through(p, today))
            .count()
    };
    Overview {
        programs: programs.len(),
        total_bytes: programs.iter().filter_map(Program::size_bytes).sum(),
        large: count(QuickFilter::Large),
        recent: count(QuickFilter::Recent),
        per_user: count(QuickFilter::PerUser),
    }
}

/// How many programs show out of how many, and what all of them take: the
/// full wording, a shorter one and the count alone, for less and less room.
fn count_lines(shown: usize, programs: usize, total_bytes: u64) -> [String; 3] {
    let noun = if programs == 1 { "program" } else { "programs" };
    let count = if shown == programs {
        format!("{programs} {noun}")
    } else {
        format!("{shown} of {programs}")
    };
    if total_bytes == 0 {
        return [count.clone(), count.clone(), count];
    }
    let size = util::human_size(total_bytes);
    let full = if shown == programs {
        format!("{count} · {size} in total")
    } else {
        format!("{count} {noun} · {size} in total")
    };
    [full, format!("{count} · {size}"), count]
}

/// The groups a scan's findings are listed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Files,
    Shortcuts,
    Registry,
    LinkTypes,
    Services,
    Tasks,
    PathEntries,
    Firewall,
}

impl Section {
    const ALL: [Section; 8] = [
        Section::Files,
        Section::Shortcuts,
        Section::Registry,
        Section::LinkTypes,
        Section::Services,
        Section::Tasks,
        Section::PathEntries,
        Section::Firewall,
    ];

    fn title(self) -> &'static str {
        match self {
            Section::Files => "Files and folders",
            Section::Shortcuts => "Shortcuts",
            Section::Registry => "Registry",
            Section::LinkTypes => "Link and file types",
            Section::Services => "Services",
            Section::Tasks => "Scheduled tasks",
            Section::PathEntries => "PATH entries",
            Section::Firewall => "Firewall rules",
        }
    }

    fn of(item: &Leftover) -> Section {
        match item.kind {
            LeftoverKind::File if is_shortcut(&item.path) => Section::Shortcuts,
            LeftoverKind::File | LeftoverKind::Directory => Section::Files,
            LeftoverKind::RegistryKey | LeftoverKind::RegistryValue if is_link_type(item) => {
                Section::LinkTypes
            }
            LeftoverKind::RegistryKey | LeftoverKind::RegistryValue => Section::Registry,
            LeftoverKind::Service => Section::Services,
            LeftoverKind::ScheduledTask => Section::Tasks,
            LeftoverKind::PathEntry => Section::PathEntries,
            LeftoverKind::FirewallRule => Section::Firewall,
        }
    }
}

fn is_shortcut(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.ends_with(".lnk") || path.ends_with(".url")
}

/// A key or value under `Classes` that registers a link type, a file type
/// or an application to open them with, or a browser's permission to open
/// a link type without asking. Windows Installer's and COM's own keys under
/// `Classes` are plain registry.
fn is_link_type(item: &Leftover) -> bool {
    let path = item
        .subpath
        .as_deref()
        .unwrap_or(&item.path)
        .to_ascii_lowercase();
    if path.contains(r"\protocolexecute") || path.contains(r"\urlassociations") {
        return true;
    }
    let mut parts = path.split('\\');
    if parts.by_ref().all(|part| part != "classes") {
        return false;
    }
    parts.next().is_some_and(|next| {
        !matches!(
            next,
            "installer" | "clsid" | "interface" | "typelib" | "appid" | "wow6432node"
        )
    })
}

/// The row a move by `by` rows lands on from `at`, in a list of `len` rows,
/// kept inside the list. Without a selection the move starts at the top.
fn moved(at: Option<usize>, len: usize, by: isize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    Some(match at {
        None => 0,
        Some(at) => (at as isize).saturating_add(by).clamp(0, len as isize - 1) as usize,
    })
}

/// The scroll offset that brings `row` into a view `height` tall that is
/// scrolled to `offset`. None when the row is already in view.
fn scroll_to_show(row: usize, offset: f32, height: f32) -> Option<f32> {
    let top = row as f32 * ROW_HEIGHT;
    let bottom = top + ROW_HEIGHT;
    if top < offset {
        Some(top)
    } else if bottom > offset + height {
        Some((bottom - height).max(0.0))
    } else {
        None
    }
}

/// Room left of the name for the program's icon.
const ICON: f32 = 18.0;
/// Space at both ends of a row.
const ROW_PAD: f32 = 10.0;

/// A column as laid out: where it starts and how wide it is, from the
/// table's left edge.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Placed {
    column: Column,
    x: f32,
    width: f32,
}

impl Placed {
    /// The column's part of a row or the header at `row`.
    fn cell(&self, row: egui::Rect) -> egui::Rect {
        egui::Rect::from_min_max(
            egui::pos2(row.left() + self.x, row.top()),
            egui::pos2(row.left() + self.x + self.width, row.bottom()),
        )
    }
}

/// The table width that reads best: wide enough for long names and
/// publishers, narrow enough that a size stays within reach of its name.
const TABLE_IDEAL: f32 = 1180.0;

/// The details panel's width beside a table in a window `available` wide:
/// whatever the table does not need, between a usable and a readable width.
fn details_width(available: f32) -> f32 {
    // The table's own margins and the panel's separator.
    (available - TABLE_IDEAL - 41.0).clamp(340.0, 720.0)
}

/// The columns a table `width` wide has room for, laid out. Name and size
/// always show; the date, the publisher and the source join as it widens.
fn columns(width: f32) -> Vec<Placed> {
    const GAP: f32 = 16.0;
    let publisher = width >= 680.0;
    let mut shown = vec![Column::Name];
    if publisher {
        shown.push(Column::Publisher);
    }
    shown.push(Column::Size);
    if width >= 560.0 {
        shown.push(Column::Installed);
    }
    if width >= 820.0 {
        shown.push(Column::Source);
    }
    let lead = ROW_PAD + ICON + 10.0;
    let fixed: f32 = shown.iter().filter_map(|c| c.fixed_width()).sum();
    let gaps = GAP * (shown.len() - 1) as f32;
    let flexible = (width - lead - ROW_PAD - fixed - gaps).max(120.0);
    let mut x = lead;
    shown
        .into_iter()
        .map(|column| {
            let width = column.fixed_width().unwrap_or(match column {
                Column::Publisher => flexible * 0.4,
                _ if publisher => flexible * 0.6,
                _ => flexible,
            });
            let placed = Placed { column, x, width };
            x += width + GAP;
            placed
        })
        .collect()
}

// Program icons, used by spawn_icon_load.
// ------------------------------------------------------------------------

/// An icon as raw RGBA bytes, with its width and height.
type Rgba = (Vec<u8>, u32, u32);

/// A place a program's icon can come from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IconSource {
    /// An icon inside a file (an executable, a library or an icon file) and
    /// its index.
    File(String, i32),
    /// A folder whose main executable carries the icon.
    Folder(String),
}

impl IconSource {
    fn same_as(&self, other: &IconSource) -> bool {
        match (self, other) {
            (Self::File(a, i), Self::File(b, j)) => i == j && a.eq_ignore_ascii_case(b),
            (Self::Folder(a), Self::Folder(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        }
    }
}

/// A program's icon and where it came from: the first of [`icon_sources`]
/// that gives one. `None` when none does; the list then shows a placeholder.
#[cfg(windows)]
fn program_icon(program: &Program) -> Option<(IconSource, Rgba)> {
    let product_icon = product_icon(program);
    let name_tokens = util::significant_tokens(&program.display_name);
    icon_sources(program, product_icon.as_deref())
        .into_iter()
        .find_map(|source| {
            let icon = match &source {
                IconSource::File(path, index) => {
                    if std::path::Path::new(path).is_file() {
                        unsafe { icon_from_file(path, *index) }
                    } else {
                        None
                    }
                }
                IconSource::Folder(dir) => find_main_exe(std::path::Path::new(dir), &name_tokens)
                    .and_then(|exe| unsafe { icon_from_file(&exe, 0) }),
            };
            icon.map(|icon| (source, icon))
        })
}

#[cfg(not(windows))]
fn program_icon(_program: &Program) -> Option<(IconSource, Rgba)> {
    None
}

/// Where to look for a program's icon, best first. The icons the program
/// declares come first: its `DisplayIcon`, then the `ProductIcon` of its
/// Windows Installer product (`product_icon`). Then the main executable in
/// its folders: the install folder, the folder of the `DisplayIcon` file and
/// the folder of its uninstaller. The Windows folder is never searched, so a
/// program removed through `MsiExec.exe` does not get an icon from there.
fn icon_sources(program: &Program, product_icon: Option<&str>) -> Vec<IconSource> {
    let display_icon = program.display_icon.as_deref().and_then(parse_icon_spec);
    let files = [display_icon.clone(), product_icon.and_then(parse_icon_spec)]
        .into_iter()
        .flatten()
        .map(|(path, index)| IconSource::File(path, index));
    let folders = [
        program
            .install_location
            .as_deref()
            .and_then(|loc| search_folder(&util::expand_env_vars(loc.trim().trim_matches('"')))),
        display_icon.and_then(|(path, _)| parent_folder(&path)),
        program
            .uninstall_string
            .as_deref()
            .and_then(uninstaller_folder),
        program
            .quiet_uninstall_string
            .as_deref()
            .and_then(uninstaller_folder),
    ]
    .into_iter()
    .flatten()
    .map(IconSource::Folder);
    let mut sources: Vec<IconSource> = Vec::new();
    for source in files.chain(folders) {
        if !sources.iter().any(|s| s.same_as(&source)) {
            sources.push(source);
        }
    }
    sources
}

/// The `ProductIcon` Windows Installer keeps for the program's product, read
/// only when the program is a Windows Installer product keyed by its product
/// code. Windows Installer files a machine-wide product under the machine and
/// a per-user one under the user; the program's own hive is read first.
#[cfg(windows)]
fn product_icon(program: &Program) -> Option<String> {
    if !program.is_windows_installer {
        return None;
    }
    let packed = packed_product_code(program.id())?;
    let machine = (
        Hive::LocalMachine,
        format!(r"SOFTWARE\Classes\Installer\Products\{packed}"),
    );
    let user = (
        Hive::CurrentUser,
        format!(r"Software\Microsoft\Installer\Products\{packed}"),
    );
    let order = match program.source.hive {
        Hive::CurrentUser => [user, machine],
        Hive::LocalMachine => [machine, user],
    };
    order
        .into_iter()
        .find_map(|(hive, key)| registry::read_string(hive, &key, "ProductIcon"))
}

/// A product code in the packed form Windows Installer files its products
/// under: the first three groups reversed character by character, the last
/// two pair by pair, so `{12345678-ABCD-EF01-2345-6789ABCDEF01}` becomes
/// `87654321DCBA10FE32547698BADCFE10`. `None` unless `code` is a GUID in
/// braces.
fn packed_product_code(code: &str) -> Option<String> {
    let groups: Vec<&str> = code
        .strip_prefix('{')?
        .strip_suffix('}')?
        .split('-')
        .collect();
    let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    if lengths != [8, 4, 4, 4, 12]
        || !groups
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    let mut packed = String::with_capacity(32);
    for group in &groups[..3] {
        packed.extend(group.chars().rev());
    }
    for group in &groups[3..] {
        for pair in group.as_bytes().chunks(2) {
            packed.push(pair[1] as char);
            packed.push(pair[0] as char);
        }
    }
    Some(packed.to_ascii_uppercase())
}

/// Read an icon reference the way installers write them: a path, quoted or
/// not, with an optional `,index`, `%VARIABLES%`, and sometimes arguments
/// after it. `None` when no absolute path is left.
fn parse_icon_spec(raw: &str) -> Option<(String, i32)> {
    let raw = raw.trim();
    let (path, index) = match raw.strip_prefix('"').and_then(|s| s.split_once('"')) {
        // `"C:\App\app.exe",1`, `"C:\App\app.exe,1"` or `"C:\App\app.exe" -x`.
        Some((quoted, rest)) => match rest.trim_start().strip_prefix(',') {
            Some(index) => (quoted, parse_index(index)),
            None => split_icon_path(quoted),
        },
        // `C:\App\app.exe,1`, stray quotes, or arguments after the path.
        None => {
            let (path, index) = split_icon_path(raw);
            (strip_arguments(path.trim().trim_matches('"')), index)
        }
    };
    let path = util::expand_env_vars(path.trim());
    is_absolute_path(&path).then_some((path, index))
}

/// Split a `path,index` icon spec into the path and the (signed) index.
fn split_icon_path(raw: &str) -> (&str, i32) {
    match raw.rsplit_once(',') {
        Some((left, right)) if right.trim().parse::<i32>().is_ok() => {
            (left, right.trim().parse().unwrap_or(0))
        }
        _ => (raw, 0),
    }
}

/// The signed number at the start of `s`, or 0.
fn parse_index(s: &str) -> i32 {
    let s = s.trim_start();
    let end = s
        .char_indices()
        .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
        .map_or(s.len(), |(i, _)| i);
    s[..end].parse().unwrap_or(0)
}

/// An unquoted path with arguments after it, cut after the file: at the first
/// `.exe`, `.dll` or `.ico` that a space follows. A path that ends in one of
/// these stays whole, spaces and all.
fn strip_arguments(path: &str) -> &str {
    const ICON_FILES: [&str; 3] = [".exe", ".dll", ".ico"];
    // Only ASCII changes case, so positions in `lower` are positions in `path`.
    let lower = path.to_ascii_lowercase();
    if ICON_FILES.iter().any(|ext| lower.ends_with(ext)) {
        return path;
    }
    ICON_FILES
        .iter()
        .filter_map(|ext| {
            lower
                .match_indices(ext)
                .map(|(i, _)| i + ext.len())
                .find(|&end| matches!(lower.as_bytes().get(end), Some(b' ' | b'\t')))
        })
        .min()
        .map_or(path, |end| &path[..end])
}

/// True for `C:\...` and `\\server\share\...` paths.
fn is_absolute_path(path: &str) -> bool {
    let b = path.as_bytes();
    path.starts_with(r"\\")
        || (b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'\\' | b'/'))
}

/// `dir` as a folder to search for a program's executable: absolute, below a
/// drive root and outside the Windows folder, without a trailing separator.
fn search_folder(dir: &str) -> Option<String> {
    let dir = dir.trim().trim_end_matches(['\\', '/']);
    let parts: Vec<&str> = dir.split(['\\', '/']).collect();
    let below_root = parts.iter().filter(|p| !p.is_empty()).count() >= 2;
    let windows = parts
        .get(1)
        .is_some_and(|top| top.eq_ignore_ascii_case("windows"));
    (is_absolute_path(dir) && below_root && !windows).then(|| dir.to_string())
}

/// The folder of the file at `path`, when [`search_folder`] accepts it.
fn parent_folder(path: &str) -> Option<String> {
    let (dir, _) = path
        .trim_end_matches(['\\', '/'])
        .rsplit_once(['\\', '/'])?;
    search_folder(dir)
}

/// The folder of the program an uninstall command runs. A bare program name
/// such as `MsiExec.exe` has none.
fn uninstaller_folder(command: &str) -> Option<String> {
    let argv = util::split_uninstall_command(&util::expand_env_vars(command));
    parent_folder(argv.first()?)
}

/// The most likely main executable of the program in `dir`: the largest
/// `.exe` that is not an uninstaller or setup stub. When `dir` holds none, the
/// folders one level down that are called `bin` or share a word with the
/// program's name (`name_tokens`) are searched the same way.
fn find_main_exe(dir: &std::path::Path, name_tokens: &[String]) -> Option<String> {
    if let Some((_, exe)) = largest_exe(dir) {
        return Some(exe);
    }
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|entry| is_program_subfolder(&entry.file_name().to_string_lossy(), name_tokens))
        .filter_map(|entry| largest_exe(&entry.path()))
        .max_by_key(|(size, _)| *size)
        .map(|(_, exe)| exe)
}

/// The largest `.exe` directly in `dir` that can be a main executable, with
/// its size. Non-recursive.
fn largest_exe(dir: &std::path::Path) -> Option<(u64, String)> {
    let mut best: Option<(u64, String)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let is_file = entry.file_type().is_ok_and(|t| t.is_file());
        if !is_file || !is_main_exe_candidate(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if best.as_ref().is_none_or(|(s, _)| size > *s) {
            best = Some((size, entry.path().to_string_lossy().to_string()));
        }
    }
    best
}

/// True for an `.exe` that can be a program's main executable: not an
/// uninstaller (`unins000.exe`, `uninstall.exe`, `Uninstall App.exe`) and not
/// `setup.exe`.
fn is_main_exe_candidate(file_name: &str) -> bool {
    let name = file_name.to_lowercase();
    name.ends_with(".exe")
        && !name.starts_with("unins")
        && !name.contains("uninst")
        && name != "setup.exe"
}

/// True for a folder one level below the install folder that can hold the
/// main executable: `bin`, or one whose name shares a word with the
/// program's name (`example-win-x64` for Example Player).
fn is_program_subfolder(folder: &str, name_tokens: &[String]) -> bool {
    folder.eq_ignore_ascii_case("bin")
        || util::significant_tokens(folder)
            .iter()
            .any(|t| name_tokens.contains(t))
}

/// Extract an icon from a file at the given index (ExtractIconEx honours the
/// index; SHGetFileInfo is the fallback). The file must already exist.
#[cfg(windows)]
unsafe fn icon_from_file(path: &str, index: i32) -> Option<(Vec<u8>, u32, u32)> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
    use windows::Win32::UI::Shell::{
        ExtractIconExW, SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON,
    };
    use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, HICON};

    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // ExtractIconExW honours the icon index.
    let mut hicon = HICON::default();
    let n = ExtractIconExW(PCWSTR(wide.as_ptr()), index, Some(&mut hicon), None, 1);
    if n > 0 && n != u32::MAX && !hicon.is_invalid() {
        let r = hicon_to_rgba(hicon);
        let _ = DestroyIcon(hicon);
        if r.is_some() {
            return r;
        }
    } else if !hicon.is_invalid() {
        let _ = DestroyIcon(hicon);
    }

    // Fallback: the shell's associated icon (index 0).
    let mut info = SHFILEINFOW::default();
    let ok = SHGetFileInfoW(
        PCWSTR(wide.as_ptr()),
        FILE_FLAGS_AND_ATTRIBUTES(0),
        Some(&mut info),
        std::mem::size_of::<SHFILEINFOW>() as u32,
        SHGFI_ICON | SHGFI_LARGEICON,
    );
    if ok != 0 && !info.hIcon.is_invalid() {
        let r = hicon_to_rgba(info.hIcon);
        let _ = DestroyIcon(info.hIcon);
        return r;
    }
    None
}

/// Convert an `HICON` to top-down RGBA bytes via GDI.
#[cfg(windows)]
unsafe fn hicon_to_rgba(
    hicon: windows::Win32::UI::WindowsAndMessaging::HICON,
) -> Option<(Vec<u8>, u32, u32)> {
    use std::ffi::c_void;
    use windows::Win32::Graphics::Gdi::{
        DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO,
        BITMAPINFOHEADER, DIB_RGB_COLORS, HGDIOBJ,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetIconInfo, ICONINFO};

    let mut info = ICONINFO::default();
    GetIconInfo(hicon, &mut info).ok()?;

    let cleanup = |info: &ICONINFO| {
        let _ = DeleteObject(HGDIOBJ(info.hbmColor.0));
        let _ = DeleteObject(HGDIOBJ(info.hbmMask.0));
    };

    let mut bm = BITMAP::default();
    let got = GetObjectW(
        HGDIOBJ(info.hbmColor.0),
        std::mem::size_of::<BITMAP>() as i32,
        Some(&mut bm as *mut _ as *mut c_void),
    );
    let (w, h) = (bm.bmWidth, bm.bmHeight);
    if got == 0 || w <= 0 || h <= 0 {
        cleanup(&info);
        return None;
    }

    let mut bi = BITMAPINFO::default();
    bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h; // negative => top-down rows
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = 0; // BI_RGB

    let hdc = GetDC(None);
    let mut buf = vec![0u8; (w as usize) * (h as usize) * 4];
    let lines = GetDIBits(
        hdc,
        info.hbmColor,
        0,
        h as u32,
        Some(buf.as_mut_ptr() as *mut c_void),
        &mut bi,
        DIB_RGB_COLORS,
    );
    ReleaseDC(None, hdc);
    cleanup(&info);
    if lines == 0 {
        return None;
    }

    // GDI gives BGRA; egui wants RGBA.
    let (pixels, _) = buf.as_chunks_mut::<4>();
    for px in pixels.iter_mut() {
        px.swap(0, 2);
    }
    // Some icons report no alpha at all (all zero); treat those as opaque.
    if pixels.iter().all(|p| p[3] == 0) {
        for px in pixels.iter_mut() {
            px[3] = 255;
        }
    }
    Some((buf, w as u32, h as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidize::model::{Hive, RegistrySource, RegistryView};

    /// The window with a stand-in protected list, so no test reads the
    /// user's own.
    fn app() -> OxidizeApp {
        OxidizeApp::blank(cleanup::Cleanup::from_file(Ok(stand_in_list())))
    }

    fn stand_in_list() -> std::path::PathBuf {
        std::env::temp_dir().join("oxidize-gui-test-protected.txt")
    }

    #[test]
    fn the_tests_keep_to_a_stand_in_protected_list() {
        assert_eq!(app().cleanup.list_file, Ok(stand_in_list()));
    }

    #[test]
    fn nothing_is_cleaned_while_the_protected_list_cannot_be_read() {
        let ctx = egui::Context::default();
        let mut app = app();
        app.cleanup.unreadable =
            Some(r"reading C:\Example\protected.txt: stream did not contain valid UTF-8".into());
        let analysis = clean::Analysis {
            findings: Vec::new(),
            elevated: false,
            recycle_bin_days: clean::RECYCLE_DAYS,
            protected: Vec::new(),
        };
        app.cleanup.analysis = Some((clean::Places::default(), analysis));
        app.cleanup.slate.found = Some(Vec::new());
        let why = r"Cannot clean up: reading C:\Example\protected.txt: stream did not contain valid UTF-8";
        for dry_run in [false, true] {
            app.dry_run = dry_run;
            for action in [Action::Clean(clean::Choice::default()), Action::ClearTraces] {
                app.status.clear();
                app.act(&ctx, action);
                assert!(app.confirm.is_none());
                assert_eq!(app.status, why);
            }
        }
        assert!(app.log.is_empty(), "{:?}", app.log);
        assert_eq!(app.jobs, 0);
    }

    /// An analysis with the build output row ticked to look, as a click
    /// leaves it before the look runs.
    fn ticked_to_look(app: &mut OxidizeApp) {
        app.cleanup
            .take_analysis(clean::Places::default(), cleanup::tests::analysis());
        let (_, analysis) = app.cleanup.analysis.as_ref().unwrap();
        let skipped = analysis
            .finding(clean::Category::BuildOutput)
            .unwrap()
            .clone();
        assert!(skipped.skipped);
        app.cleanup.set(&skipped, true);
        assert!(app.cleanup.ticked.contains(&clean::Category::BuildOutput));
    }

    #[test]
    fn a_refused_look_for_build_output_leaves_no_tick() {
        let ctx = egui::Context::default();
        let mut app = app();
        ticked_to_look(&mut app);
        app.cleanup.unreadable =
            Some(r"reading C:\Example\protected.txt: stream did not contain valid UTF-8".into());
        app.act(&ctx, Action::FindBuildOutput);
        assert!(
            app.status.starts_with("Cannot clean up: "),
            "{}",
            app.status
        );
        assert_eq!(app.jobs, 0);
        assert!(!app.cleanup.ticked.contains(&clean::Category::BuildOutput));
    }

    #[test]
    fn a_failed_look_for_build_output_leaves_no_tick() {
        let ctx = egui::Context::default();
        let mut app = app();
        ticked_to_look(&mut app);
        app.jobs = 1;
        app.tx
            .send(Msg::Error("the operation stopped unexpectedly".to_string()))
            .unwrap();
        app.drain_messages(&ctx);
        assert!(!app.cleanup.ticked.contains(&clean::Category::BuildOutput));

        // Build output that was found keeps its tick when other work fails.
        let (_, analysis) = app.cleanup.analysis.as_ref().unwrap();
        let mut found = analysis
            .finding(clean::Category::BuildOutput)
            .unwrap()
            .clone();
        found.skipped = false;
        found.count = 2;
        found.bytes = 300;
        app.cleanup.take_build_output(found.clone());
        app.cleanup.set(&found, true);
        app.jobs = 1;
        app.tx
            .send(Msg::Error("the clean stopped".to_string()))
            .unwrap();
        app.drain_messages(&ctx);
        assert!(app.cleanup.ticked.contains(&clean::Category::BuildOutput));
    }

    #[test]
    fn an_uninstalled_program_stays_selected_for_its_leftovers() {
        let name = "Oxidize Gui Test Leftovers";
        let program = Program {
            registry_key: name.to_string(),
            source: RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
            display_name: name.to_string(),
            display_version: None,
            publisher: None,
            install_date: None,
            install_location: None,
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        };
        let ctx = egui::Context::default();
        let mut app = app();
        app.programs = vec![program.clone()];
        app.selected = Some(program.id().to_string());

        // The uninstaller ran and the program left the installed list.
        app.tx
            .send(Msg::Uninstalled {
                program: program.clone(),
                message: "done".to_string(),
                still_installed: false,
            })
            .unwrap();
        app.tx.send(Msg::Programs(Vec::new())).unwrap();
        app.drain_messages(&ctx);

        assert_eq!(app.selected.as_deref(), Some(program.id()));
        assert_eq!(app.selected_program().map(Program::id), Some(program.id()));

        // And it is scanned again, now as a program that is gone, so its
        // leftovers can be ticked and removed.
        let start = std::time::Instant::now();
        while app.scan.is_none() && start.elapsed() < std::time::Duration::from_secs(300) {
            std::thread::sleep(std::time::Duration::from_millis(50));
            app.drain_messages(&ctx);
        }
        let report = app.scan.as_ref().expect("the program is scanned again");
        assert_eq!(app.scan_for.as_deref(), Some(program.id()));
        assert!(!report.installed);
        assert_eq!(app.selected.as_deref(), Some(program.id()));
    }

    #[test]
    fn the_first_answer_of_two_running_jobs_leaves_the_window_busy() {
        let ctx = egui::Context::default();
        let mut app = app();
        // A removal ended and started a rescan and a list reload together.
        app.jobs = 2;
        app.selected = Some("example".to_string());
        app.tx.send(Msg::Programs(Vec::new())).unwrap();
        app.drain_messages(&ctx);
        assert!(app.busy(), "the rescan still runs");

        // Nothing new starts meanwhile: no Refresh, no second removal.
        app.act(&ctx, Action::Refresh);
        app.act(&ctx, Action::RemoveCompletely(example_program()));
        assert_eq!(app.jobs, 1);
        assert!(app.confirm.is_none());
        assert!(!app.status.starts_with("Loading"), "{}", app.status);

        app.tx
            .send(Msg::Error("the scan stopped".to_string()))
            .unwrap();
        app.drain_messages(&ctx);
        assert!(!app.busy());
        // And a stray extra answer never takes the count below zero.
        app.job_done();
        assert_eq!(app.jobs, 0);
    }

    #[test]
    fn the_window_waits_for_running_work_before_it_closes() {
        let mut app = app();
        assert_eq!(app.close_step(false), None);
        app.jobs = 1;
        assert_eq!(
            app.close_step(true),
            Some(egui::ViewportCommand::CancelClose)
        );
        assert_eq!(app.close_step(false), None);
        app.job_done();
        assert_eq!(app.close_step(false), Some(egui::ViewportCommand::Close));
        // Nothing running: closing is closing.
        let mut idle = OxidizeApp::blank(cleanup::Cleanup::from_file(Ok(stand_in_list())));
        assert_eq!(idle.close_step(true), None);
    }

    #[test]
    fn a_removal_is_reported_as_it_ran_not_as_the_setting_reads_now() {
        let ctx = egui::Context::default();
        let mut app = app();
        app.jobs = 1;
        // A preview started, then the dry run was switched off.
        app.dry_run = false;
        let outcome = DeletionOutcome {
            attempted: 2,
            dry_run: true,
            ..DeletionOutcome::default()
        };
        app.tx.send(Msg::Removed(outcome)).unwrap();
        app.drain_messages(&ctx);
        assert!(app.status.starts_with("dry run"), "{}", app.status);
        // A preview changes nothing, so nothing is read again.
        assert!(!app.busy());
    }

    #[test]
    fn undoing_one_backup_leaves_the_undo_of_another() {
        let program = example_program();
        let mut app = app();
        app.selected = Some(program.id().to_string());
        app.on_completed(program.clone(), finished(Some("example-player-1")), false);
        assert_eq!(app.undo_backup(), Some("example-player-1"));

        // The Clean up tab's backup is restored.
        let restored = Ok(vec![RestoreItem {
            path: "a folder".to_string(),
            result: Ok(()),
        }]);
        app.on_restored("Oxidize clean", restored.clone(), false);
        assert_eq!(app.undo_backup(), Some("example-player-1"));

        app.on_restored("example-player-1", restored, false);
        assert_eq!(app.undo_backup(), None);
    }

    #[test]
    fn the_status_line_keeps_the_last_result_while_the_list_reloads() {
        let ctx = egui::Context::default();
        let mut app = app();
        app.status = LOADING.to_string();
        app.jobs = 1;
        app.tx.send(Msg::Programs(Vec::new())).unwrap();
        app.drain_messages(&ctx);
        // The count stands beside the search field, not here as well.
        assert_eq!(app.status, "");

        app.status = "Uninstaller finished. The program is still registered.".to_string();
        app.jobs = 1;
        app.tx.send(Msg::Programs(Vec::new())).unwrap();
        app.drain_messages(&ctx);
        assert_eq!(
            app.status,
            "Uninstaller finished. The program is still registered."
        );
    }

    #[test]
    fn one_cleared_usage_trace_is_counted_as_one() {
        let ctx = egui::Context::default();
        let mut app = app();
        let mut found = clean::traces::TraceFinding::new(clean::traces::Trace::RecentItems);
        found.count = 1;
        app.jobs = 1;
        app.tx.send(Msg::TracesCleared(vec![found])).unwrap();
        app.drain_messages(&ctx);
        assert_eq!(app.status, "1 usage trace cleared.");
    }

    fn example_program() -> Program {
        Program {
            registry_key: "example-player".to_string(),
            source: RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
            display_name: "Example Player".to_string(),
            display_version: None,
            publisher: None,
            install_date: None,
            install_location: None,
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    /// A complete removal that closed one process, skipped the uninstaller
    /// and removed two items, with `backup` as its backup.
    fn finished(backup: Option<&str>) -> Outcome {
        Outcome {
            closed: vec![complete::Closed {
                pid: 100,
                exe: r"C:\Users\me\AppData\Local\ExamplePlayer\player.exe".to_string(),
                how: CloseHow::Closed,
                error: None,
                windowless: false,
            }],
            would_close: Vec::new(),
            vendor: VendorStep::Skip {
                reason: "installed for this user only".to_string(),
            },
            uninstaller: None,
            report: ScanReport::default(),
            selected: Vec::new(),
            removal: Some(DeletionOutcome {
                attempted: 2,
                deleted: 2,
                backup_name: backup.map(str::to_string),
                ..DeletionOutcome::default()
            }),
            verdict: complete::Verdict {
                nothing_left: true,
                still_installed: false,
                remaining: Vec::new(),
                below_level: 1,
                kept: Vec::new(),
            },
            error: None,
            seconds: 4.2,
        }
    }

    #[test]
    fn a_complete_removal_is_stored_with_its_undo_backup() {
        let program = example_program();
        let mut app = app();
        app.selected = Some(program.id().to_string());
        app.jobs = 1;

        let reload = app.on_completed(program.clone(), finished(Some("example-player-1")), false);

        assert!(reload, "the program list is read again");
        assert!(!app.busy());
        let done = app.shown_complete().expect("the result is shown");
        assert!(done.outcome.complete());
        assert_eq!(app.undo_backup(), Some("example-player-1"));
        // It stays reachable once it leaves the installed list.
        assert_eq!(app.selected_program().map(Program::id), Some(program.id()));
        assert_eq!(app.status, "Example Player: nothing left.");
        for line in [
            "Closed 1 running process",
            "Skipped the uninstaller: installed for this user only",
            "2 removed",
            "Example Player: nothing left.",
        ] {
            assert!(app.log.iter().any(|l| l == line), "{line} in {:?}", app.log);
        }
        assert_eq!(removed_count(&done.outcome), 2);
    }

    #[test]
    fn a_dry_run_comes_through_the_channel_and_changes_nothing() {
        let program = example_program();
        let ctx = egui::Context::default();
        let mut app = app();
        app.selected = Some(program.id().to_string());
        let mut outcome = finished(Some("example-player-1"));
        outcome.closed.clear();
        outcome.removal = None;
        outcome.selected = vec![Leftover::reg_key(
            Hive::CurrentUser,
            r"Software\Example Studio",
            Confidence::High,
            "the vendor's key",
        )];
        app.tx
            .send(Msg::Completed {
                program,
                outcome: Box::new(outcome),
                dry_run: true,
            })
            .unwrap();
        app.drain_messages(&ctx);

        assert!(app.shown_complete().is_some());
        assert!(app.uninstalled.is_none());
        assert!(!app.busy(), "no reload was started");
        assert_eq!(
            app.status,
            "dry run: 1 item of Example Player would be removed"
        );
    }

    #[test]
    fn undo_shows_only_with_a_backup() {
        let program = example_program();
        let mut app = app();
        app.selected = Some(program.id().to_string());

        app.on_completed(program.clone(), finished(None), false);
        assert_eq!(app.undo_backup(), None, "no backup was made");

        app.on_completed(program.clone(), finished(Some("example-player-1")), true);
        assert_eq!(app.undo_backup(), None, "a dry run made none");

        app.on_completed(program.clone(), finished(Some("example-player-1")), false);
        assert_eq!(app.undo_backup(), Some("example-player-1"));
        app.selected = Some("other-program".to_string());
        assert_eq!(
            app.undo_backup(),
            None,
            "only for the program it belongs to"
        );
    }

    #[test]
    fn what_the_tools_said_comes_before_the_summary() {
        let said =
            vec![r"sc delete Svc ended with code 87: [SC] DeleteService FAILED 87".to_string()];
        assert_eq!(
            with_tool_lines(
                vec![
                    "failed Svc: Windows could not remove the service.".to_string(),
                    "Removed 0 of 1".to_string()
                ],
                said.clone()
            ),
            [
                "failed Svc: Windows could not remove the service.",
                r"sc delete Svc ended with code 87: [SC] DeleteService FAILED 87",
                "Removed 0 of 1",
            ]
        );
        assert_eq!(with_tool_lines(Vec::new(), said.clone()), said);
    }

    #[test]
    fn undo_logs_each_item_and_clears_the_result_once_all_is_back() {
        let program = example_program();
        let mut app = app();
        app.selected = Some(program.id().to_string());
        app.on_completed(program, finished(Some("example-player-1")), false);

        let items = vec![
            RestoreItem {
                path: r"C:\Users\me\AppData\Local\ExamplePlayer".to_string(),
                result: Ok(()),
            },
            RestoreItem {
                path: r"HKCU\Software\Example Studio".to_string(),
                result: Err("access denied".to_string()),
            },
        ];
        assert!(app.on_restored("example-player-1", Ok(items), false));
        // What failed waits in the backup, so Undo is offered again.
        assert_eq!(app.undo_backup(), Some("example-player-1"));
        assert_eq!(
            app.status,
            "Restored 1 item from example-player-1, 1 failed"
        );
        assert!(app
            .log
            .iter()
            .any(|l| l == r"failed HKCU\Software\Example Studio: access denied"));

        let rest = vec![RestoreItem {
            path: "Example Studio".to_string(),
            result: Ok(()),
        }];
        assert!(app.on_restored("example-player-1", Ok(rest), false));
        assert!(app.complete.is_none());

        // A backup that cannot be found changes nothing and keeps the result.
        app.on_completed(example_program(), finished(Some("example-player-1")), false);
        assert!(!app.on_restored(
            "example-player-1",
            Err("no backup named that".to_string()),
            false
        ));
        assert!(app.undo_backup().is_some());
    }

    #[test]
    fn undo_in_a_dry_run_puts_nothing_back() {
        static ASKED: std::sync::Mutex<Vec<bool>> = std::sync::Mutex::new(Vec::new());
        fn stand_in(_: &str, dry_run: bool) -> Result<Vec<RestoreItem>, String> {
            ASKED.lock().unwrap().push(dry_run);
            Ok(vec![RestoreItem {
                path: r"D:\Games\ExamplePlayer".to_string(),
                result: Ok(()),
            }])
        }
        let program = example_program();
        let ctx = egui::Context::default();
        let mut app = app();
        app.restore_backup = stand_in;
        app.dry_run = true;
        app.selected = Some(program.id().to_string());
        app.on_completed(program, finished(Some("example-player-1")), false);

        app.act(&ctx, Action::Undo("example-player-1".to_string()));
        let start = std::time::Instant::now();
        while app.busy() && start.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(10));
            app.drain_messages(&ctx);
        }

        assert_eq!(*ASKED.lock().unwrap(), [true]);
        assert_eq!(
            app.status,
            "dry run: 1 item from example-player-1 would be restored"
        );
        assert!(app
            .log
            .iter()
            .any(|l| l == r"would restore D:\Games\ExamplePlayer"));
        assert_eq!(app.undo_backup(), Some("example-player-1"));
    }

    #[test]
    fn the_confirm_text_follows_the_settings() {
        let ctx = |dry_run, make_backups| SafetyContext {
            dry_run,
            keep_emptied_parents: false,
            make_backups,
        };
        assert_eq!(
            complete_confirm_text("Example Player", &ctx(false, true)),
            "Remove Example Player completely? Running copies are asked to close, everything \
             found at high confidence is removed, a backup is kept. What its own uninstaller \
             removes, if it runs, is not in the backup."
        );
        assert_eq!(
            complete_confirm_text("Example Player", &ctx(false, false)),
            "Remove Example Player completely? Running copies are asked to close, everything \
             found at high confidence is removed permanently, no backup is kept."
        );
        assert!(complete_confirm_text("Example Player", &ctx(true, true))
            .contains("nothing is closed or removed"));
    }

    #[test]
    fn running_an_uninstaller_never_promises_a_backup() {
        assert_eq!(
            uninstall_confirm_text("Example Player"),
            "Run the uninstaller for Example Player? What it removes is not backed up."
        );
    }

    #[test]
    fn a_failed_uninstaller_and_stuck_items_are_named() {
        let mut out = finished(None);
        out.vendor = VendorStep::Run {
            silent: true,
            reason: "installed for all users".to_string(),
        };
        out.uninstaller = Some("finished with exit code 0".to_string());
        out.verdict.nothing_left = false;
        out.verdict.remaining = vec![Leftover::reg_key(
            Hive::CurrentUser,
            r"Software\Example Studio",
            Confidence::High,
            "the vendor's key",
        )];
        let lines = complete_log("Example Player", &out, false);
        assert!(lines.contains(&"Uninstaller finished with exit code 0".to_string()));
        assert_eq!(
            lines.last().map(String::as_str),
            Some("Example Player: 1 item is still there.")
        );
    }

    #[test]
    fn a_process_that_stays_is_named_and_never_counted_closed() {
        let mut out = finished(None);
        out.closed[0].how = CloseHow::Running;
        out.removal = None;
        out.verdict.nothing_left = false;
        out.verdict.still_installed = true;
        out.error = complete::still_running(&out.closed);
        let lines = complete_log("Example Player", &out, false);
        let stop = "player.exe is still running, so nothing was removed. Close it and try again.";
        assert!(!lines.iter().any(|l| l.starts_with("Closed")), "{lines:?}");
        assert_eq!(lines.last().map(String::as_str), Some(stop));
        assert_eq!(complete_status("Example Player", &out, false), stop);
    }

    #[test]
    fn a_process_that_stays_is_named_before_an_uninstaller_that_never_ran() {
        let mut out = finished(None);
        out.vendor = VendorStep::Run {
            silent: true,
            reason: "installed for all users".to_string(),
        };
        out.closed[0].how = CloseHow::Running;
        out.removal = None;
        out.verdict.nothing_left = false;
        out.verdict.still_installed = true;
        out.error = complete::still_running(&out.closed);
        let stop = "player.exe is still running, so nothing was removed. Close it and try again.";
        assert_eq!(complete_status("Example Player", &out, false), stop);
    }

    #[test]
    fn a_product_code_packs_the_way_windows_installer_files_it() {
        assert_eq!(
            packed_product_code("{12345678-ABCD-EF01-2345-6789ABCDEF01}").as_deref(),
            Some("87654321DCBA10FE32547698BADCFE10")
        );
        assert_eq!(
            packed_product_code("{12345678-abcd-ef01-2345-6789abcdef01}").as_deref(),
            Some("87654321DCBA10FE32547698BADCFE10")
        );
        for not_a_code in [
            "example-player",
            "12345678-ABCD-EF01-2345-6789ABCDEF01",
            "{12345678-ABCD-EF01-2345-6789ABCDEF01}.old",
            "{12345678-ABCD-EF01-2345-6789ABCDEF0}",
            "{12345678-ABCD-EF01-2345-6789ABCDEFGH}",
            "{12345678ABCD-EF01-2345-6789ABCDEF01}",
        ] {
            assert_eq!(packed_product_code(not_a_code), None, "{not_a_code}");
        }
    }

    #[test]
    fn icon_references_are_read_the_way_installers_write_them() {
        let app = r"C:\Program Files\Example Player\player.exe";
        for (raw, index) in [
            (app.to_string(), 0),
            (format!("{app},0"), 0),
            (format!("{app},3"), 3),
            (format!("{app},-101"), -101),
            (format!("{app}, 2"), 2),
            (format!("\"{app}\""), 0),
            (format!("\"{app}\",2"), 2),
            (format!("\"{app},2\""), 2),
            (format!("\"{app}\" ,2"), 2),
            (format!("  \"{app}\"  "), 0),
            // A stray quote, and one that is never closed.
            (format!("{app}\",2"), 2),
            (format!("\"{app}"), 0),
            // Arguments after the path.
            (format!("\"{app}\" --uninstall"), 0),
            (format!("{app} --uninstall"), 0),
        ] {
            assert_eq!(
                parse_icon_spec(&raw),
                Some((app.to_string(), index)),
                "{raw}"
            );
        }
        // An icon file without an extension and a comma in a folder name.
        for whole in [
            r"C:\Windows\Installer\{12345678-ABCD-EF01-2345-6789ABCDEF01}\Player Icon",
            r"C:\Example, Studio\player.ico",
        ] {
            assert_eq!(parse_icon_spec(whole), Some((whole.to_string(), 0)));
        }
        for nothing in [
            "",
            "  ",
            "player.exe",
            "MsiExec.exe",
            r"\player.ico",
            r"%OXIDIZE_NO_SUCH_VARIABLE%\player.exe",
        ] {
            assert_eq!(parse_icon_spec(nothing), None, "{nothing}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn icon_references_expand_environment_variables() {
        let root = std::env::var("SystemRoot").expect("Windows sets SystemRoot");
        assert_eq!(
            parse_icon_spec(r#""%SystemRoot%\Installer\player.ico",0"#),
            Some((format!(r"{root}\Installer\player.ico"), 0))
        );
        assert_eq!(
            parse_icon_spec(r"%SystemRoot%\system32\shell32.dll,-16"),
            Some((format!(r"{root}\system32\shell32.dll"), -16))
        );
    }

    #[test]
    fn declared_icons_come_before_the_folders() {
        let mut program = example_program();
        program.display_icon =
            Some(r#""C:\Program Files\Example Player\player.exe",1"#.to_string());
        program.install_location = Some(r"C:\Program Files\Example Player\".to_string());
        program.uninstall_string =
            Some(r#""C:\Program Files\Example Player\Tools\remove.exe" /S"#.to_string());
        let product = r"C:\Windows\Installer\{12345678-ABCD-EF01-2345-6789ABCDEF01}\player.ico";
        assert_eq!(
            icon_sources(&program, Some(product)),
            vec![
                IconSource::File(r"C:\Program Files\Example Player\player.exe".into(), 1),
                IconSource::File(product.into(), 0),
                // The install folder, which is also the DisplayIcon's.
                IconSource::Folder(r"C:\Program Files\Example Player".into()),
                IconSource::Folder(r"C:\Program Files\Example Player\Tools".into()),
            ]
        );
    }

    #[test]
    fn a_windows_installer_product_falls_back_to_its_product_icon() {
        let mut program = example_program();
        program.registry_key = "{12345678-ABCD-EF01-2345-6789ABCDEF01}".to_string();
        program.is_windows_installer = true;
        program.uninstall_string =
            Some("MsiExec.exe /X{12345678-ABCD-EF01-2345-6789ABCDEF01}".to_string());
        let product = r"C:\Windows\Installer\{12345678-ABCD-EF01-2345-6789ABCDEF01}\ProductIcon";
        assert_eq!(
            icon_sources(&program, Some(product)),
            vec![IconSource::File(product.into(), 0)]
        );
        // Without one nothing is left: MsiExec.exe names no folder.
        assert_eq!(icon_sources(&program, None), Vec::new());
    }

    #[test]
    fn the_folders_of_a_missing_icon_and_of_the_uninstaller_are_searched() {
        let mut program = example_program();
        program.display_icon = Some(r"C:\Program Files\Example Player\gone.ico".to_string());
        program.uninstall_string =
            Some(r#""C:\Users\me\.example\bin\player.exe" self uninstall"#.to_string());
        program.quiet_uninstall_string =
            Some(r"C:\Program Files\Example Player\Remove\remove.exe /S".to_string());
        assert_eq!(
            icon_sources(&program, None),
            vec![
                IconSource::File(r"C:\Program Files\Example Player\gone.ico".into(), 0),
                IconSource::Folder(r"C:\Program Files\Example Player".into()),
                IconSource::Folder(r"C:\Users\me\.example\bin".into()),
                IconSource::Folder(r"C:\Program Files\Example Player\Remove".into()),
            ]
        );
    }

    #[test]
    fn windows_own_folders_and_drive_roots_are_never_searched() {
        let mut program = example_program();
        for (location, uninstall) in [
            (
                r"C:\",
                r"C:\Windows\System32\rundll32.exe C:\Example\remove.dll,Remove",
            ),
            (r"C:\Windows\", r"RunDll32.exe C:\Example\remove.dll,Remove"),
            (
                r"D:\WINDOWS\Installer",
                "winget uninstall --id Example.Player",
            ),
            (
                r"%OXIDIZE_NO_SUCH_VARIABLE%\Example",
                r#""C:\remove.exe" /S"#,
            ),
        ] {
            program.install_location = Some(location.to_string());
            program.uninstall_string = Some(uninstall.to_string());
            assert_eq!(icon_sources(&program, None), Vec::new(), "{location}");
        }
        program.install_location = Some(r#""C:\Program Files\Example Player""#.to_string());
        assert_eq!(
            icon_sources(&program, None),
            vec![IconSource::Folder(
                r"C:\Program Files\Example Player".into()
            )]
        );
    }

    #[test]
    fn the_main_executable_is_found_one_level_down_when_the_folder_has_none() {
        /// Removes the folder when the test ends, passed or failed.
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root =
            std::env::temp_dir().join(format!("oxidize_icon_main_exe_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let _cleanup = Cleanup(root.clone());
        let write = |rel: &str, len: usize| {
            let path = rel
                .split('/')
                .fold(root.clone(), |path, part| path.join(part));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, vec![0u8; len]).unwrap();
            path.to_string_lossy().to_string()
        };
        let tokens = util::significant_tokens("Example Player");
        // Only stubs in the folder itself.
        write("unins000.exe", 900);
        write("Uninstall Example Player.exe", 900);
        write("setup.exe", 900);
        // Below it: a folder named after the program, `bin`, and an unrelated
        // folder with the largest file.
        let named = write("example-win-x64/player.exe", 500);
        write("bin/player-cli.exe", 300);
        write("plugins/codec.exe", 5000);
        assert_eq!(find_main_exe(&root, &tokens), Some(named));

        // An executable in the folder itself wins over the ones below it.
        let own = write("player.exe", 10);
        assert_eq!(find_main_exe(&root, &tokens), Some(own));
    }

    #[test]
    fn stubs_are_not_main_executables_and_bin_is_searched() {
        for stub in [
            "unins000.exe",
            "uninstall.exe",
            "Uninstall Example Player.exe",
            "ExampleUninstaller.exe",
            "setup.exe",
            "player.dll",
        ] {
            assert!(!is_main_exe_candidate(stub), "{stub}");
        }
        assert!(is_main_exe_candidate("Player.EXE"));
        let tokens = util::significant_tokens("Example Player");
        assert!(is_program_subfolder("bin", &tokens));
        assert!(is_program_subfolder("BIN", &tokens));
        assert!(is_program_subfolder("example-win-x64", &tokens));
        assert!(!is_program_subfolder("plugins", &tokens));
        // A generic word in common is not enough.
        assert!(!is_program_subfolder("player-data", &tokens));
    }

    /// Resolves the icon of every program installed on this machine and
    /// prints where each came from and which have none. Reads only.
    #[test]
    #[ignore = "reads the programs installed on this machine"]
    fn icons_of_the_installed_programs() {
        let programs = registry::enumerate_installed_programs(false);
        let mut missing = Vec::new();
        for program in &programs {
            match program_icon(program) {
                Some((source, _)) => println!("{}: {source:?}", program.display_name),
                None => missing.push(program.display_name.as_str()),
            }
        }
        println!(
            "{} of {} programs have no icon",
            missing.len(),
            programs.len()
        );
        for name in missing {
            println!("  {name}");
        }
    }

    #[test]
    fn window_icon_decodes() {
        let icon = super::window_icon();
        assert_eq!((icon.width, icon.height), (256, 256));
        assert_eq!(icon.rgba.len(), 256 * 256 * 4);
    }

    fn day(text: &str) -> NaiveDate {
        NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
    }

    /// A program for the list tests, `size_mb` megabytes big.
    fn listed(
        name: &str,
        publisher: Option<&str>,
        size_mb: Option<u32>,
        date: Option<&str>,
        hive: Hive,
    ) -> Program {
        let mut program = example_program();
        program.registry_key = name.to_lowercase().replace(' ', "-");
        program.display_name = name.to_string();
        program.publisher = publisher.map(str::to_string);
        program.estimated_size_kb = size_mb.map(|mb| mb * 1024);
        program.install_date = date.map(str::to_string);
        program.source = RegistrySource::new(hive, RegistryView::Native64);
        program
    }

    fn list() -> Vec<Program> {
        vec![
            listed(
                "Quillmark",
                Some("Example Studio"),
                Some(300),
                Some("2026-10-01"),
                Hive::CurrentUser,
            ),
            listed(
                "brightway Studio",
                Some("Brightway"),
                Some(2048),
                Some("2025-03-14"),
                Hive::LocalMachine,
            ),
            listed("Atlas Notes", None, None, None, Hive::LocalMachine),
            listed(
                "Delta Sync",
                Some("example studio"),
                Some(1500),
                Some("2026-09-20"),
                Hive::LocalMachine,
            ),
            listed(
                "Cobalt",
                Some(" "),
                Some(300),
                Some("2026-10-10"),
                Hive::CurrentUser,
            ),
        ]
    }

    fn names(programs: &[Program], idx: &[usize]) -> Vec<String> {
        idx.iter()
            .map(|&i| programs[i].display_name.clone())
            .collect()
    }

    fn sorted(programs: &[Program], column: Column, descending: bool) -> Vec<String> {
        let mut idx: Vec<usize> = (0..programs.len()).collect();
        sort_indices(programs, &mut idx, Sort { column, descending });
        names(programs, &idx)
    }

    #[test]
    fn the_table_sorts_by_each_column_with_missing_values_last() {
        let programs = list();
        assert_eq!(
            sorted(&programs, Column::Name, false),
            [
                "Atlas Notes",
                "brightway Studio",
                "Cobalt",
                "Delta Sync",
                "Quillmark"
            ]
        );
        assert_eq!(
            sorted(&programs, Column::Name, true),
            [
                "Quillmark",
                "Delta Sync",
                "Cobalt",
                "brightway Studio",
                "Atlas Notes"
            ]
        );
        // Equal sizes keep the name order; no size goes last both ways.
        assert_eq!(
            sorted(&programs, Column::Size, true),
            [
                "brightway Studio",
                "Delta Sync",
                "Cobalt",
                "Quillmark",
                "Atlas Notes"
            ]
        );
        assert_eq!(
            sorted(&programs, Column::Size, false),
            [
                "Cobalt",
                "Quillmark",
                "Delta Sync",
                "brightway Studio",
                "Atlas Notes"
            ]
        );
        assert_eq!(
            sorted(&programs, Column::Installed, true),
            [
                "Cobalt",
                "Quillmark",
                "Delta Sync",
                "brightway Studio",
                "Atlas Notes"
            ]
        );
        // Publishers compare without case; a blank one counts as none.
        assert_eq!(
            sorted(&programs, Column::Publisher, false),
            [
                "brightway Studio",
                "Delta Sync",
                "Quillmark",
                "Atlas Notes",
                "Cobalt"
            ]
        );
        assert_eq!(
            sorted(&programs, Column::Publisher, true),
            [
                "Delta Sync",
                "Quillmark",
                "brightway Studio",
                "Atlas Notes",
                "Cobalt"
            ]
        );
        assert_eq!(
            sorted(&programs, Column::Source, false),
            [
                "Atlas Notes",
                "brightway Studio",
                "Delta Sync",
                "Cobalt",
                "Quillmark"
            ]
        );
    }

    #[test]
    fn a_header_click_turns_the_order_around_or_starts_a_new_one() {
        let by = |column, descending| Sort { column, descending };
        let name = Sort::default();
        assert_eq!(name, by(Column::Name, false));
        assert_eq!(name.clicked(Column::Name), by(Column::Name, true));
        // Sizes and dates start biggest and newest first.
        let size = name.clicked(Column::Size);
        assert_eq!(size, by(Column::Size, true));
        assert_eq!(size.clicked(Column::Size), by(Column::Size, false));
        assert_eq!(name.clicked(Column::Installed), by(Column::Installed, true));
        assert_eq!(
            size.clicked(Column::Publisher),
            by(Column::Publisher, false)
        );
        assert_eq!(size.clicked(Column::Source), by(Column::Source, false));
    }

    #[test]
    fn the_search_and_the_quick_filters_pick_the_rows() {
        let programs = list();
        let today = day("2026-10-11");
        let shown = |text: &str, quick: QuickFilter| {
            let terms = search_terms(text);
            programs
                .iter()
                .filter(|p| shows(p, &terms, quick, today))
                .map(|p| p.display_name.as_str())
                .collect::<Vec<_>>()
        };
        // Name or publisher, any case, every word somewhere.
        assert_eq!(
            shown("STUDIO", QuickFilter::All),
            ["Quillmark", "brightway Studio", "Delta Sync"]
        );
        assert_eq!(shown("example  sync", QuickFilter::All), ["Delta Sync"]);
        assert!(shown("nothing like it", QuickFilter::All).is_empty());
        assert_eq!(shown("", QuickFilter::All).len(), programs.len());
        assert_eq!(
            shown("", QuickFilter::Large),
            ["brightway Studio", "Delta Sync"]
        );
        assert_eq!(
            shown("", QuickFilter::Recent),
            ["Quillmark", "Delta Sync", "Cobalt"]
        );
        assert_eq!(shown("", QuickFilter::PerUser), ["Quillmark", "Cobalt"]);
        assert_eq!(shown("Q", QuickFilter::PerUser), ["Quillmark"]);
    }

    #[test]
    fn recent_means_the_last_thirty_days() {
        let today = day("2026-10-11");
        assert!(is_recent(day("2026-10-11"), today));
        assert!(is_recent(day("2026-09-11"), today));
        assert!(!is_recent(day("2026-09-10"), today));
        assert!(
            is_recent(day("2026-10-20"), today),
            "a clock that was ahead"
        );
        let mut program = example_program();
        program.install_date = Some("not a date".to_string());
        assert_eq!(installed_on(&program), None);
        program.install_date = Some("2026-02-30".to_string());
        assert_eq!(installed_on(&program), None);
    }

    #[test]
    fn the_overview_counts_the_programs_and_their_size() {
        let mut programs = list();
        for n in 0..10u32 {
            programs.push(listed(
                &format!("Tool {n}"),
                None,
                Some(10 + n),
                None,
                Hive::LocalMachine,
            ));
        }
        let ov = overview(&programs, day("2026-10-11"));
        let mb = 1024 * 1024;
        assert_eq!(ov.programs, 15);
        assert_eq!(ov.total_bytes, 4293 * mb);
        let counts = QuickFilter::ALL.map(|q| ov.count(q));
        assert_eq!(counts, [15, 2, 3, 2]);
        assert_eq!(overview(&[], day("2026-10-11")), Overview::default());
    }

    #[test]
    fn the_count_line_gets_shorter_with_less_room() {
        let gb = 1024 * 1024 * 1024;
        assert_eq!(
            count_lines(15, 15, 19 * gb),
            [
                "15 programs · 19.0 GB in total",
                "15 programs · 19.0 GB",
                "15 programs"
            ]
        );
        assert_eq!(
            count_lines(3, 15, 19 * gb),
            [
                "3 of 15 programs · 19.0 GB in total",
                "3 of 15 · 19.0 GB",
                "3 of 15"
            ]
        );
        assert_eq!(
            count_lines(1, 1, 0),
            ["1 program", "1 program", "1 program"]
        );
    }

    #[test]
    fn the_table_shows_the_filtered_programs_and_a_new_selection_drops_the_scan() {
        let today = day("2026-10-11");
        let mut app = app();
        app.programs = list();
        app.sort = Sort {
            column: Column::Size,
            descending: true,
        };
        app.quick = QuickFilter::Recent;
        let shown = |app: &OxidizeApp| names(&app.programs, &app.display_indices(today));
        assert_eq!(shown(&app), ["Delta Sync", "Cobalt", "Quillmark"]);
        app.filter = "studio".to_string();
        assert_eq!(shown(&app), ["Delta Sync", "Quillmark"]);

        app.select("quillmark");
        app.scan = Some(ScanReport::default());
        app.scan_for = Some("quillmark".to_string());
        app.select("quillmark");
        assert!(app.scan.is_some(), "the same program keeps its scan");
        app.select("cobalt");
        assert!(app.scan.is_none() && app.scan_for.is_none());
        assert_eq!(app.selected.as_deref(), Some("cobalt"));
    }

    #[test]
    fn findings_are_grouped_by_what_they_are() {
        use std::path::PathBuf;
        let high = Confidence::High;
        let fs =
            |kind, path: &str| Leftover::fs(kind, PathBuf::from(path), high, "found", None, false);
        let key = |hive, path: &str| Leftover::reg_key(hive, path, high, "found");
        let home = r"C:\Program Files\Quillmark";
        let cases = [
            (
                fs(
                    LeftoverKind::Directory,
                    r"C:\Users\me\AppData\Local\Quillmark",
                ),
                Section::Files,
            ),
            (
                fs(
                    LeftoverKind::File,
                    r"C:\Users\me\AppData\Local\Quillmark\notes.db",
                ),
                Section::Files,
            ),
            (
                fs(LeftoverKind::File, r"C:\Users\me\Desktop\Quillmark.LNK"),
                Section::Shortcuts,
            ),
            (
                fs(LeftoverKind::File, r"C:\Users\me\Favorites\Quillmark.url"),
                Section::Shortcuts,
            ),
            (
                key(Hive::CurrentUser, r"Software\Example Studio\Quillmark"),
                Section::Registry,
            ),
            (
                key(Hive::CurrentUser, r"Software\Classes\quillmark"),
                Section::LinkTypes,
            ),
            (
                key(Hive::LocalMachine, r"SOFTWARE\Classes\.qmk"),
                Section::LinkTypes,
            ),
            (
                key(
                    Hive::LocalMachine,
                    r"SOFTWARE\Classes\Applications\quillmark.exe",
                ),
                Section::LinkTypes,
            ),
            (
                key(
                    Hive::LocalMachine,
                    r"SOFTWARE\WOW6432Node\Classes\Quillmark.Doc",
                ),
                Section::LinkTypes,
            ),
            (
                key(
                    Hive::LocalMachine,
                    r"SOFTWARE\Classes\Installer\Products\87654321DCBA10FE32547698BADCFE10",
                ),
                Section::Registry,
            ),
            (
                key(
                    Hive::LocalMachine,
                    r"SOFTWARE\Classes\CLSID\{12345678-ABCD-EF01-2345-6789ABCDEF01}",
                ),
                Section::Registry,
            ),
            (
                key(Hive::LocalMachine, r"SOFTWARE\Classes"),
                Section::Registry,
            ),
            (
                Leftover::reg_value(
                    Hive::CurrentUser,
                    r"Software\Microsoft\Internet Explorer\ProtocolExecute\quillmark",
                    "WarnOnOpen",
                    high,
                    "found",
                ),
                Section::LinkTypes,
            ),
            (
                Leftover::service(
                    "QuillmarkUpdate",
                    &format!(r"{home}\update.exe"),
                    high,
                    "found",
                ),
                Section::Services,
            ),
            (
                Leftover::task(r"\Example Studio\Quillmark Update", "", high, "found"),
                Section::Tasks,
            ),
            (
                Leftover::path_entry(Hive::CurrentUser, format!(r"{home}\bin"), high, "found"),
                Section::PathEntries,
            ),
            (
                Leftover::firewall_rule(
                    "{rule}",
                    "Quillmark",
                    "",
                    &format!(r"{home}\quillmark.exe"),
                    high,
                    "found",
                ),
                Section::Firewall,
            ),
        ];
        for (item, section) in &cases {
            assert_eq!(Section::of(item), *section, "{}", item.path);
        }
    }

    #[test]
    fn arrow_keys_stay_inside_the_list_and_the_view_follows() {
        assert_eq!(moved(None, 0, 1), None);
        assert_eq!(moved(None, 5, 1), Some(0));
        assert_eq!(moved(None, 5, -1), Some(0));
        assert_eq!(moved(Some(0), 5, -1), Some(0));
        assert_eq!(moved(Some(3), 5, 1), Some(4));
        assert_eq!(moved(Some(4), 5, 1), Some(4));
        assert_eq!(moved(Some(1), 5, 10), Some(4));
        assert_eq!(moved(Some(4), 5, -10), Some(0));

        // A view ten rows tall.
        let height = 10.0 * ROW_HEIGHT;
        assert_eq!(scroll_to_show(3, 0.0, height), None);
        assert_eq!(scroll_to_show(10, 0.0, height), Some(ROW_HEIGHT));
        assert_eq!(
            scroll_to_show(2, 5.0 * ROW_HEIGHT, height),
            Some(2.0 * ROW_HEIGHT)
        );
        assert_eq!(scroll_to_show(14, 5.0 * ROW_HEIGHT, height), None);
    }

    #[test]
    fn the_table_drops_columns_as_it_narrows() {
        let shown = |width: f32| columns(width).iter().map(|c| c.column).collect::<Vec<_>>();
        assert_eq!(
            shown(1000.0),
            [
                Column::Name,
                Column::Publisher,
                Column::Size,
                Column::Installed,
                Column::Source
            ]
        );
        assert_eq!(
            shown(700.0),
            [
                Column::Name,
                Column::Publisher,
                Column::Size,
                Column::Installed
            ]
        );
        assert_eq!(
            shown(600.0),
            [Column::Name, Column::Size, Column::Installed]
        );
        assert_eq!(shown(400.0), [Column::Name, Column::Size]);
        // Left to right without overlapping, inside the row.
        for width in [400.0, 600.0, 700.0, 1000.0, 1600.0] {
            let cols = columns(width);
            for pair in cols.windows(2) {
                assert!(pair[0].x + pair[0].width <= pair[1].x, "{width}: {pair:?}");
            }
            let last = cols.last().unwrap();
            assert!(last.x + last.width <= width - ROW_PAD + 0.01, "{width}");
        }
    }

    #[test]
    fn a_wide_window_gives_its_room_to_the_details_not_to_a_gap() {
        // A small window: the details keep a usable width.
        assert_eq!(details_width(1180.0), 340.0);
        // Maximised at 1080p: the table gets its ideal width, the details
        // the rest.
        let w = details_width(1920.0);
        assert!(w > 600.0 && w <= 720.0, "{w}");
        assert!((1920.0 - w - 41.0 - TABLE_IDEAL).abs() < 1.0);
        // Very wide: the details stop at a readable width.
        assert_eq!(details_width(2560.0), 720.0);
    }

    #[test]
    fn a_portrait_window_is_tall_and_a_landscape_one_is_not() {
        assert!(is_tall(egui::vec2(1080.0, 1872.0)));
        assert!(!is_tall(egui::vec2(1920.0, 1032.0)));
        assert!(!is_tall(egui::vec2(1180.0, 760.0)));
        // Square-ish windows keep the details beside the table.
        assert!(!is_tall(egui::vec2(900.0, 1000.0)));
    }

    #[test]
    fn counts_take_the_right_noun() {
        assert_eq!(count(1, "program", "programs"), "1 program");
        assert_eq!(count(0, "program", "programs"), "0 programs");
        assert_eq!(count(20, "program", "programs"), "20 programs");
    }

    #[test]
    fn copy_and_paste_reach_the_windows_clipboard() {
        // Without eframe's clipboard feature, Ctrl+C and Ctrl+V stay inside the window.
        let manifest = include_str!("../../Cargo.toml");
        let eframe = &manifest[manifest.find("\neframe = ").unwrap()..];
        let features = &eframe[..eframe.find("] }").unwrap()];
        assert!(features.contains("\"clipboard\""), "{features}");
    }

    #[test]
    fn one_item_is_counted_as_one_item() {
        let ctx = egui::Context::default();
        let program = example_program();
        let item = Leftover::fs(
            LeftoverKind::Directory,
            std::path::PathBuf::from(r"D:\Games\Example Player"),
            Confidence::High,
            "found",
            None,
            false,
        );
        let mut app = app();
        app.selected = Some(program.id().to_string());
        app.jobs = 1;
        let report = ScanReport {
            program_name: "Example Player".to_string(),
            installed: false,
            items: vec![item.clone()],
        };
        app.tx
            .send(Msg::Scan {
                id: program.id().to_string(),
                report,
            })
            .unwrap();
        app.drain_messages(&ctx);
        assert_eq!(app.status, "1 leftover of Example Player.");

        let dry = DeletionOutcome {
            attempted: 1,
            dry_run: true,
            ..DeletionOutcome::default()
        };
        let lines = removal_log(&dry, true);
        assert!(
            lines.contains(&"dry run: 1 item would be removed".to_string()),
            "{lines:?}"
        );

        let mut out = finished(None);
        out.selected = vec![item.clone()];
        assert_eq!(
            complete_status("Example Player", &out, true),
            "dry run: 1 item of Example Player would be removed"
        );
        let lines = complete_log("Example Player", &out, true);
        assert!(
            lines.contains(&"dry run: 1 item would be removed".to_string()),
            "{lines:?}"
        );
        out.verdict.nothing_left = false;
        out.verdict.remaining = vec![item];
        assert_eq!(
            complete_status("Example Player", &out, false),
            "Example Player: 1 item is still there."
        );
    }

    #[test]
    fn the_assistant_skill_names_the_settings_as_the_window_shows_them() {
        let guide = include_str!("../../site/skill/oxidize/references/window-app.md");
        let settings = [
            "Options",
            "Dry run, change nothing",
            "Back up before deleting",
            "Uninstall silently where possible",
            "Show system components",
        ];
        for label in settings {
            assert!(guide.contains(label), "{label}");
        }
        // The window counts with the right noun, never "item(s)".
        for gone in [
            "Not elevated",
            "Backups ticked",
            "Silent uninstall box",
            "item(s)",
        ] {
            assert!(!guide.contains(gone), "{gone}");
        }
    }

    #[test]
    fn a_missing_uninstaller_is_named_in_one_plain_sentence() {
        let plan = uninstall::UninstallPlan {
            argv: vec!["oxidize-test-no-such-uninstaller.exe".to_string()],
            is_msi: false,
            source: "UninstallString".to_string(),
            unattended: false,
        };
        let e = uninstall::run_with(
            &plan,
            std::process::Stdio::null(),
            std::process::Stdio::null(),
        )
        .unwrap_err();
        let shown = window_error(&format!("Uninstall failed: {e:#}"));
        assert_eq!(shown, "The uninstaller file is missing.");
    }

    #[test]
    fn a_dry_run_of_the_uninstaller_reads_like_every_other_dry_run() {
        let ctx = egui::Context::default();
        let mut app = app();
        app.dry_run = true;
        let mut program = example_program();
        program.uninstall_string = Some(r"D:\Apps\Example\uninstall.exe".to_string());
        app.act(&ctx, Action::Uninstall(program));
        assert_eq!(
            app.status,
            r"dry run: would run D:\Apps\Example\uninstall.exe"
        );
    }

    #[test]
    fn a_dry_run_without_an_uninstaller_says_so_in_the_status_line() {
        let ctx = egui::Context::default();
        let mut app = app();
        app.dry_run = true;
        app.act(&ctx, Action::Uninstall(example_program()));
        assert!(
            app.status.starts_with("Cannot uninstall Example Player"),
            "{}",
            app.status
        );
        assert!(app.confirm.is_none());
    }

    #[test]
    fn an_uninstaller_refused_for_rights_points_to_the_restart_button() {
        let shown = window_error(&format!("Uninstall failed: {}", uninstall::NEEDS_ADMIN));
        assert!(shown.contains("Restart as administrator"), "{shown}");
        assert!(!shown.contains("--elevate"), "{shown}");

        // Remove completely: the uninstaller never started, nothing went.
        let mut out = finished(None);
        out.vendor = VendorStep::Run {
            silent: true,
            reason: "installed for all users".to_string(),
        };
        out.removal = None;
        out.verdict.nothing_left = false;
        out.verdict.still_installed = true;
        out.error = Some(uninstall::NEEDS_ADMIN.to_string());
        let status = complete_status("Example Player", &out, false);
        assert!(status.contains("did not start"), "{status}");
        assert!(!status.contains("cancelled"), "{status}");
        let log = complete_log("Example Player", &out, false).join("\n");
        assert!(!log.contains("--elevate"), "{log}");
    }

    #[test]
    fn an_uninstaller_that_never_started_is_not_called_cancelled_in_the_details() {
        let mut out = finished(None);
        out.vendor = VendorStep::Run {
            silent: true,
            reason: "installed for all users".to_string(),
        };
        out.removal = None;
        out.verdict.nothing_left = false;
        out.verdict.still_installed = true;
        out.error = Some(uninstall::NEEDS_ADMIN.to_string());
        let done = Completed {
            program: example_program(),
            outcome: out,
            dry_run: false,
        };
        let ctx = egui::Context::default();
        apply_style(&ctx);
        let t = Tint::of(ctx.global_style().visuals.dark_mode);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            show_complete(ui, &t, &done, false, true);
        });
        output.textures_delta.clear();
        let mut shown = String::new();
        for clipped in &output.shapes {
            if let egui::Shape::Text(text) = &clipped.shape {
                shown.push_str(text.galley.text());
                shown.push('\n');
            }
        }
        assert!(shown.contains("Restart as administrator"), "{shown}");
        assert!(!shown.contains("cancelled"), "{shown}");
    }

    /// True when `shapes` hold a copper outline drawn on `rect`.
    fn has_ring(shapes: &[egui::Shape], rect: egui::Rect, copper: Color32) -> bool {
        shapes.iter().any(|shape| match shape {
            egui::Shape::Vec(inner) => has_ring(inner, rect, copper),
            egui::Shape::Rect(r) => {
                r.stroke.color == copper && r.stroke.width >= 1.0 && r.rect == rect
            }
            _ => false,
        })
    }

    /// The contrast ratio of two opaque colours, as WCAG counts it.
    fn contrast(a: Color32, b: Color32) -> f32 {
        let lum = |c: Color32| {
            let linear = |v: u8| {
                let v = f32::from(v) / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * linear(c.r()) + 0.7152 * linear(c.g()) + 0.0722 * linear(c.b())
        };
        let (hi, lo) = (lum(a).max(lum(b)), lum(a).min(lum(b)));
        (hi + 0.05) / (lo + 0.05)
    }

    /// Every text colour drawn by `draw`, with the fill of the shape it sits on
    /// laid over `under`.
    fn text_on_fill(draw: impl FnMut(&mut egui::Ui), under: Color32) -> Vec<(Color32, Color32)> {
        let ctx = egui::Context::default();
        let mut draw = draw;
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| draw(ui));
        output.textures_delta.clear();
        let mut fill = under;
        let mut pairs = Vec::new();
        for clipped in &output.shapes {
            match &clipped.shape {
                egui::Shape::Rect(r) if r.fill.a() > 0 => {
                    let a = f32::from(r.fill.a()) / 255.0;
                    let mix =
                        |f: u8, u: u8| (f32::from(f) + f32::from(u) * (1.0 - a)).round() as u8;
                    fill = Color32::from_rgb(
                        mix(r.fill.r(), under.r()),
                        mix(r.fill.g(), under.g()),
                        mix(r.fill.b(), under.b()),
                    );
                }
                egui::Shape::Text(text) => {
                    for section in &text.galley.job.sections {
                        pairs.push((section.format.color, fill));
                    }
                }
                _ => {}
            }
        }
        pairs
    }

    #[test]
    fn the_selected_quick_filter_is_readable_in_both_themes() {
        for dark in [false, true] {
            let t = Tint::of(dark);
            let pairs = text_on_fill(|ui| _ = chip(ui, &t, true, "All", 12), t.base);
            assert!(!pairs.is_empty());
            for (text, fill) in pairs {
                let ratio = contrast(text, fill);
                assert!(
                    ratio >= 4.5,
                    "dark {dark}: {text:?} on {fill:?} is {ratio:.2}"
                );
            }
        }
    }

    #[test]
    fn the_dry_run_badge_is_readable_in_both_themes() {
        for dark in [false, true] {
            let t = Tint::of(dark);
            let pairs = text_on_fill(
                |ui| badge(ui, &t, "Dry run: nothing changes", t.amber),
                t.chrome,
            );
            assert!(!pairs.is_empty());
            for (text, fill) in pairs {
                let ratio = contrast(text, fill);
                assert!(
                    ratio >= 4.5,
                    "dark {dark}: {text:?} on {fill:?} is {ratio:.2}"
                );
            }
        }
    }

    #[test]
    fn grey_text_on_the_selected_row_is_readable_in_both_themes() {
        for dark in [false, true] {
            let t = Tint::of(dark);
            let ratio = contrast(t.weak, t.selected);
            assert!(ratio >= 4.5, "dark {dark}: {ratio:.2}");
        }
    }

    #[test]
    fn every_stop_tab_reaches_shows_where_the_focus_is() {
        use eframe::App as _;
        let ctx = egui::Context::default();
        apply_style(&ctx);
        let mut app = app();
        let mut other = example_program();
        other.registry_key = "example-editor".to_string();
        other.display_name = "Example Editor".to_string();
        app.programs = vec![example_program(), other];
        let mut frame = eframe::Frame::_new_kittest();
        let input = |tab: bool| egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1180.0, 760.0),
            )),
            events: if tab {
                vec![egui::Event::Key {
                    key: egui::Key::Tab,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        let mut run = |tab: bool| {
            let mut out = ctx.run_ui(input(tab), |ui| app.ui(ui, &mut frame));
            out.textures_delta.clear();
            out
        };
        run(false);
        let copper = Tint::of(ctx.global_style().visuals.dark_mode).copper;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..40 {
            run(true);
            let out = run(false);
            let id = ctx
                .memory(|m| m.focused())
                .expect("Tab gives something focus");
            if !seen.insert(id) {
                break;
            }
            let rect = ctx
                .read_response(id)
                .expect("the focused widget is shown")
                .rect;
            let shapes: Vec<egui::Shape> = out.shapes.into_iter().map(|c| c.shape).collect();
            assert!(has_ring(&shapes, rect, copper), "no focus ring at {rect:?}");
        }
        assert!(seen.len() > 5, "{}", seen.len());
    }

    #[test]
    fn a_focused_row_that_leaves_the_list_leaves_no_ring_behind() {
        use eframe::App as _;
        let ctx = egui::Context::default();
        apply_style(&ctx);
        let mut app = app();
        app.programs = vec![example_program()];
        let mut frame = eframe::Frame::_new_kittest();
        let input = |tab: bool| egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1180.0, 760.0),
            )),
            events: if tab {
                vec![egui::Event::Key {
                    key: egui::Key::Tab,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        let mut run = |app: &mut OxidizeApp, tab: bool| {
            let mut out = ctx.run_ui(input(tab), |ui| app.ui(ui, &mut frame));
            out.textures_delta.clear();
            out
        };
        run(&mut app, false);
        let copper = Tint::of(ctx.global_style().visuals.dark_mode).copper;
        let mut row = None;
        for _ in 0..40 {
            run(&mut app, true);
            run(&mut app, false);
            let id = ctx
                .memory(|m| m.focused())
                .expect("Tab gives something focus");
            let rect = ctx
                .read_response(id)
                .expect("the focused widget is shown")
                .rect;
            // Only the table row spans the width of the table.
            if rect.width() > 500.0 {
                row = Some(rect);
                break;
            }
        }
        let rect = row.expect("Tab reaches the row");
        // A refresh after an uninstall takes the row away.
        app.programs.clear();
        let out = run(&mut app, false);
        let shapes: Vec<egui::Shape> = out.shapes.into_iter().map(|c| c.shape).collect();
        assert!(!has_ring(&shapes, rect, copper), "ring left at {rect:?}");
    }
}
