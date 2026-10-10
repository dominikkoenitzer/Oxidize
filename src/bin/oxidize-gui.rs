//! `oxidize-gui`, the graphical front-end, built on egui/eframe.
//!
//! A window over the same engine the CLI uses: pick a program, scan for
//! leftovers, tick the ones to remove, then uninstall or remove. Slow work runs
//! on a worker thread and reports back over a channel. The dry-run and backup
//! toggles and the confirmation work as they do on the command line.

// Hide the console window in release builds (keep it in debug for logs).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui::{self, Color32, RichText};

use oxidize::complete::{self, CloseHow, Outcome, VendorStep};
use oxidize::model::{Confidence, Group, Leftover, Program, ScanReport};
use oxidize::restore::RestoreItem;
use oxidize::safety::{self, DeletionOutcome, ItemStatus, SafetyContext};
use oxidize::{backup, registry, restore, scanner, uninstall, util};

/// The lowest confidence "Remove completely" removes.
const COMPLETE_LEVEL: Confidence = Confidence::High;

/// The Oxidize mark for the window, the same artwork the executables embed.
fn window_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../../assets/oxidize.png"))
        .expect("assets/oxidize.png is a valid PNG")
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 700.0])
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
    },
    /// An extracted program icon (raw RGBA), keyed by the program's id.
    Icon {
        id: String,
        rgba: Vec<u8>,
        w: u32,
        h: u32,
    },
    Error(String),
}

/// A pending destructive action awaiting confirmation.
#[allow(clippy::large_enum_variant)] // these are constructed at most once per click
enum Confirm {
    Uninstall(Program, bool),
    Remove(Vec<Leftover>, String, SafetyContext),
    Complete(Program, SafetyContext),
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

    // UI state.
    filter: String,
    selected: Option<String>, // selected program's registry-key id
    sort_by_size: bool,

    // Options (mirror the CLI flags).
    dry_run: bool,
    make_backups: bool,
    silent: bool,
    include_system: bool,

    elevated: bool,
    busy: bool,
    status: String,
    log: Vec<String>,
    confirm: Option<Confirm>,

    // Channel to receive worker results.
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl OxidizeApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel();
        let app = OxidizeApp {
            programs: Vec::new(),
            icons: HashMap::new(),
            scan: None,
            scan_for: None,
            checked: Vec::new(),
            uninstalled: None,
            complete: None,
            filter: String::new(),
            selected: None,
            sort_by_size: false,
            dry_run: false,
            make_backups: true,
            silent: false,
            include_system: false,
            elevated: safety::is_elevated(),
            busy: false,
            status: "Loading installed programs...".to_string(),
            log: Vec::new(),
            confirm: None,
            tx,
            rx,
        };
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

    /// Run `f` on a worker thread and repaint when it sends its result.
    fn spawn<F: FnOnce() -> Msg + Send + 'static>(&self, ctx: &egui::Context, f: F) {
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
        }
    }

    fn load_programs(&mut self, ctx: &egui::Context) {
        self.busy = true;
        self.status = "Loading installed programs...".to_string();
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
        self.busy = true;
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
        self.busy = true;
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
                Err(e) => Msg::Error(format!("Uninstall failed: {e:#}")),
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
        self.busy = true;
        self.status = format!("Removing {} item(s)...", items.len());
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
        self.busy = true;
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
        self.busy = true;
        let line = format!("Restoring {name}...");
        self.log.push(line.clone());
        self.status = line;
        self.spawn(ctx, move || {
            let result = backup::find_backup(&name)
                .and_then(|info| restore::restore(&info, false))
                .map_err(|e| format!("{e:#}"));
            Msg::Restored {
                backup: name,
                result,
            }
        });
    }

    /// Take in a finished complete removal. True when the program list
    /// should be read again because something changed.
    fn on_completed(&mut self, program: Program, outcome: Outcome, dry_run: bool) -> bool {
        self.log
            .extend(complete_log(&program.display_name, &outcome, dry_run));
        self.status = complete_status(&program.display_name, &outcome, dry_run);
        self.busy = false;
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
    fn on_restored(&mut self, name: &str, result: Result<Vec<RestoreItem>, String>) -> bool {
        self.busy = false;
        match result {
            Ok(items) => {
                let mut restored = 0;
                let mut failed = 0;
                for item in &items {
                    match &item.result {
                        Ok(()) => {
                            restored += 1;
                            self.log.push(format!("restored {}", item.path));
                        }
                        Err(e) => {
                            failed += 1;
                            self.log.push(format!("failed {}: {e}", item.path));
                        }
                    }
                }
                let mut line = format!("Restored {restored} items from {name}");
                if failed > 0 {
                    line.push_str(&format!(", {failed} failed"));
                }
                self.log.push(line.clone());
                self.status = line;
                // The result on screen no longer holds.
                self.complete = None;
                true
            }
            Err(e) => {
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
                    self.busy = false;
                    self.status = format!("{} program(s) installed.", self.programs.len());
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
                            "{} items make up {}. It is still installed.",
                            report.total(),
                            report.program_name
                        )
                    } else {
                        format!("{} leftovers of {}.", report.total(), report.program_name)
                    };
                    self.scan_for = Some(id);
                    self.scan = Some(report);
                    self.busy = false;
                }
                // A scan the user has already moved on from.
                Msg::Scan { .. } => self.busy = false,
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
                    self.busy = false;
                    self.load_programs(ctx);
                }
                Msg::Removed(outcome) => {
                    let lines = removal_log(&outcome, self.dry_run);
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
                    self.busy = false;
                    if !self.dry_run {
                        // Re-scan to show what remains, and refresh the list.
                        self.scan = None;
                        if let Some(program) = self.selected_program() {
                            let program = program.clone();
                            self.start_scan(ctx, program);
                        }
                        self.load_programs(ctx);
                    }
                }
                Msg::Completed {
                    program,
                    outcome,
                    dry_run,
                } => {
                    if self.on_completed(program, *outcome, dry_run) {
                        self.load_programs(ctx);
                    }
                }
                Msg::Restored { backup, result } => {
                    if self.on_restored(&backup, result) {
                        self.load_programs(ctx);
                    }
                }
                Msg::Icon { id, rgba, w, h } => {
                    let image =
                        egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
                    let tex =
                        ctx.load_texture(format!("ico-{id}"), image, egui::TextureOptions::LINEAR);
                    self.icons.insert(id, tex);
                }
                Msg::Error(e) => {
                    self.log.push(format!("ERROR: {e}"));
                    self.status = e;
                    self.busy = false;
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

    /// Filtered + sorted indices into `self.programs`.
    fn display_indices(&self) -> Vec<usize> {
        let needle = self.filter.to_lowercase();
        let mut idx: Vec<usize> = self
            .programs
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                needle.is_empty()
                    || p.display_name.to_lowercase().contains(&needle)
                    || p.publisher
                        .as_deref()
                        .map(|s| s.to_lowercase().contains(&needle))
                        .unwrap_or(false)
            })
            .map(|(i, _)| i)
            .collect();
        if self.sort_by_size {
            idx.sort_by(|&a, &b| {
                self.programs[b]
                    .size_bytes()
                    .unwrap_or(0)
                    .cmp(&self.programs[a].size_bytes().unwrap_or(0))
            });
        } else {
            idx.sort_by(|&a, &b| {
                self.programs[a]
                    .display_name
                    .to_lowercase()
                    .cmp(&self.programs[b].display_name.to_lowercase())
            });
        }
        idx
    }

    /// Render the confirmation modal, if any, and act on the user's choice.
    fn show_confirm(&mut self, ctx: &egui::Context) {
        if self.confirm.is_none() {
            return;
        }
        let message = match self.confirm.as_ref().unwrap() {
            Confirm::Uninstall(p, _) => format!("Run the uninstaller for {}?", p.display_name),
            Confirm::Remove(items, _, ctx) => {
                if ctx.make_backups {
                    format!(
                        "Remove {} items? A backup is kept, so this can be undone.",
                        items.len()
                    )
                } else {
                    format!("Remove {} items permanently?", items.len())
                }
            }
            Confirm::Complete(p, ctx) => complete_confirm_text(&p.display_name, ctx),
        };

        let mut decision: Option<bool> = None;
        egui::Window::new("Confirm")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(message);
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Yes").strong()).clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });

        match decision {
            Some(true) => match self.confirm.take().unwrap() {
                Confirm::Uninstall(p, silent) => self.start_uninstall(ctx, p, silent),
                Confirm::Remove(items, label, safety) => {
                    self.start_remove(ctx, items, label, safety)
                }
                Confirm::Complete(p, safety) => self.start_remove_completely(ctx, p, safety),
            },
            Some(false) => self.confirm = None,
            None => {}
        }
    }
}

fn conf_color(conf: Confidence) -> Color32 {
    match conf {
        Confidence::High => Color32::from_rgb(40, 170, 90),
        Confidence::Medium => Color32::from_rgb(210, 150, 0),
        Confidence::Low => Color32::from_rgb(140, 140, 140),
    }
}

fn conf_tag(conf: Confidence) -> &'static str {
    match conf {
        Confidence::High => "high",
        Confidence::Medium => "med",
        Confidence::Low => "low",
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
        format!(
            "Remove {name} completely? Running copies are closed, everything found at {level} \
             confidence is removed, a backup is kept."
        )
    } else {
        format!(
            "Remove {name} completely? Running copies are closed, everything found at {level} \
             confidence is removed permanently, no backup is kept."
        )
    }
}

/// "1 running process", "2 running processes".
fn running_processes(n: usize) -> String {
    if n == 1 {
        "1 running process".to_string()
    } else {
        format!("{n} running processes")
    }
}

/// The log lines for one removal: each item, then a summary line last.
fn removal_log(outcome: &DeletionOutcome, dry_run: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for item in &outcome.items {
        match &item.status {
            ItemStatus::Removed => lines.push(format!("removed {}", item.path)),
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
        format!("dry run: {} items would be removed", outcome.attempted)
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
            "dry run: {} items would be removed",
            out.selected.len()
        ));
        return lines;
    }
    let closed = out
        .closed
        .iter()
        .filter(|c| c.how != CloseHow::Failed)
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
        lines.push(format!("ERROR: {e}"));
    }
    lines.push(complete_status(name, out, false));
    lines
}

/// One line on how a complete removal ended, for the status bar.
fn complete_status(name: &str, out: &Outcome, dry_run: bool) -> String {
    if dry_run {
        format!(
            "dry run: {} items of {name} would be removed",
            out.selected.len()
        )
    } else if out.complete() {
        format!("{name}: nothing left.")
    } else if out.verdict.still_installed {
        format!(
            "{name} is still registered. The uninstaller may have been cancelled or is still running."
        )
    } else if !out.verdict.remaining.is_empty() {
        format!(
            "{name}: {} items are still there.",
            out.verdict.remaining.len()
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

        self.drain_messages(ctx);
        self.show_confirm(ctx);

        let display = self.display_indices();
        let mut action: Option<Action> = None;

        // ---- Top toolbar -------------------------------------------------
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.heading("Oxidize");
                ui.separator();
                if self.elevated {
                    ui.colored_label(conf_color(Confidence::High), "Administrator");
                } else {
                    ui.colored_label(Color32::from_rgb(210, 70, 70), "Not elevated");
                    if ui.button("Restart as admin").clicked() {
                        action = Some(Action::RestartAdmin);
                    }
                }
                ui.separator();
                if ui.button("Refresh").clicked() {
                    action = Some(Action::Refresh);
                }
                if self.busy {
                    ui.spinner();
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.dry_run, "Dry run")
                    .on_hover_text("Show what would happen without changing anything");
                ui.checkbox(&mut self.make_backups, "Create backups")
                    .on_hover_text(
                        "Export registry keys to .reg and quarantine files before deleting",
                    );
                ui.checkbox(&mut self.silent, "Silent uninstall")
                    .on_hover_text(
                        "Use the program's unattended uninstall switches where available",
                    );
                if ui
                    .checkbox(&mut self.include_system, "Show system components")
                    .changed()
                {
                    action = Some(Action::Refresh);
                }
                ui.checkbox(&mut self.sort_by_size, "Sort by size");
            });
            ui.add_space(4.0);
        });

        // ---- Bottom status / log ----------------------------------------
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.add_space(2.0);
            ui.label(RichText::new(&self.status).italics());
            egui::ScrollArea::vertical()
                .id_salt("log_scroll")
                .max_height(90.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log {
                        ui.label(line);
                    }
                });
            ui.add_space(2.0);
        });

        // ---- Left: program list -----------------------------------------
        egui::Panel::left("programs")
            .default_size(400.0)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("Search:");
                    ui.text_edit_singleline(&mut self.filter);
                });
                ui.label(format!("{} shown", display.len()));
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("prog_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let icon_size = egui::vec2(18.0, 18.0);
                        for &i in &display {
                            // Compute the row's text first so the borrow of
                            // `self.programs` ends before we touch other fields.
                            let (id, label, is_selected) = {
                                let p = &self.programs[i];
                                let size = p
                                    .size_bytes()
                                    .map(util::human_size)
                                    .unwrap_or_else(|| "-".to_string());
                                (
                                    p.id().to_string(),
                                    format!("{}   ({size})", p.display_name),
                                    self.selected.as_deref() == Some(p.id()),
                                )
                            };
                            ui.horizontal(|ui| {
                                // The program's own icon, or a blank of the same size.
                                match self.icons.get(&id) {
                                    Some(tex) => {
                                        ui.image(egui::load::SizedTexture::new(
                                            tex.id(),
                                            icon_size,
                                        ));
                                    }
                                    None => {
                                        ui.allocate_space(icon_size);
                                    }
                                }
                                if ui.selectable_label(is_selected, label).clicked() {
                                    self.selected = Some(id);
                                    self.scan = None;
                                    self.scan_for = None;
                                }
                            });
                        }
                    });
            });

        // Snapshot what the central panel needs, without holding borrows of self.
        let selected_program = self.selected_program().cloned();
        let scan = self.scan.clone();
        let scan_for = self.scan_for.clone();
        let mut checked = std::mem::take(&mut self.checked);

        // ---- Central: details + scan results ----------------------------
        egui::CentralPanel::default().show(ui, |ui| {
            let Some(program) = &selected_program else {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("Select a program on the left to begin.").size(16.0));
                });
                return;
            };

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if let Some(tex) = self.icons.get(program.id()) {
                    ui.image(egui::load::SizedTexture::new(tex.id(), egui::vec2(32.0, 32.0)));
                }
                ui.heading(&program.display_name);
            });
            egui::Grid::new("details").num_columns(2).show(ui, |ui| {
                let row = |ui: &mut egui::Ui, k: &str, v: &str| {
                    ui.label(RichText::new(k).strong());
                    ui.label(v);
                    ui.end_row();
                };
                row(ui, "Version", program.display_version.as_deref().unwrap_or("-"));
                row(ui, "Publisher", program.publisher.as_deref().unwrap_or("-"));
                row(
                    ui,
                    "Size",
                    &program.size_bytes().map(util::human_size).unwrap_or_else(|| "-".to_string()),
                );
                row(ui, "Installed", program.install_date.as_deref().unwrap_or("-"));
                row(ui, "Source", &program.source.label());
                row(
                    ui,
                    "Location",
                    program.install_location.as_deref().unwrap_or("-"),
                );
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.busy, egui::Button::new(RichText::new("Remove completely").strong()))
                    .clicked()
                {
                    action = Some(Action::RemoveCompletely(program.clone()));
                }
                if ui.button("Run uninstaller").clicked() {
                    action = Some(Action::Uninstall(program.clone()));
                }
                if ui.button("Scan for leftovers").clicked() {
                    action = Some(Action::Scan(program.clone()));
                }
            });

            ui.separator();

            // The last complete removal of this program, until it is scanned
            // again or undone.
            if let Some(done) = self.shown_complete() {
                let undo = self.undo_backup().map(str::to_string);
                if show_complete(ui, done, undo.is_some(), !self.busy) {
                    action = undo.map(Action::Undo);
                }
                return;
            }

            // Scan results, only when they belong to the selected program.
            let belongs = scan_for.as_deref() == Some(program.id());
            match (&scan, belongs) {
                (Some(report), true) => {
                    if report.installed {
                        ui.label(
                            RichText::new("Still installed. These items are its current footprint, not leftovers.")
                                .color(conf_color(Confidence::Medium)),
                        );
                    }
                    ui.horizontal_wrapped(|ui| {
                        let reclaim = report.reclaimable_bytes();
                        ui.label(format!(
                            "{} items{}",
                            report.total(),
                            if reclaim > 0 {
                                format!(", {} in files", util::human_size(reclaim))
                            } else {
                                String::new()
                            }
                        ));
                        ui.separator();
                        if ui.button("Check High").clicked() {
                            for (i, l) in report.all().enumerate() {
                                checked[i] = l.confidence == Confidence::High;
                            }
                        }
                        if ui.button("Check all").clicked() {
                            checked.iter_mut().for_each(|c| *c = true);
                        }
                        if ui.button("Uncheck all").clicked() {
                            checked.iter_mut().for_each(|c| *c = false);
                        }
                    });

                    let n_checked = checked.iter().filter(|c| **c).count();
                    let remove_label = if self.dry_run {
                        format!("Preview removal of {n_checked} item(s)")
                    } else {
                        format!("Remove {n_checked} checked item(s)")
                    };
                    ui.add_enabled_ui(n_checked > 0 && !report.installed, |ui| {
                        if ui
                            .button(RichText::new(remove_label).color(Color32::from_rgb(210, 80, 80)))
                            .clicked()
                        {
                            let items: Vec<Leftover> = report
                                .all()
                                .enumerate()
                                .filter(|(i, _)| checked[*i])
                                .map(|(_, l)| l.clone())
                                .collect();
                            action = Some(Action::Remove(items, program.display_name.clone()));
                        }
                    });

                    ui.add_space(4.0);
                    egui::ScrollArea::vertical()
                        .id_salt("scan_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            // `checked` is indexed like `report.all()`, so walk the
                            // items in that order and pick the group per item.
                            for group in Group::ALL {
                                let indices: Vec<usize> = report
                                    .all()
                                    .enumerate()
                                    .filter(|(_, l)| l.kind.group() == group)
                                    .map(|(i, _)| i)
                                    .collect();
                                if indices.is_empty() {
                                    continue;
                                }
                                render_group(ui, group.title(), &report.items, &indices, &mut checked);
                                ui.add_space(6.0);
                            }
                            if report.is_empty() {
                                ui.label(RichText::new("Nothing found.").color(conf_color(Confidence::High)));
                            }
                        });
                }
                _ => {
                    ui.label(
                        RichText::new("Run a scan to find this program's registry/filesystem leftovers.")
                            .italics(),
                    );
                }
            }
        });

        // Persist checkbox state back into self.
        self.checked = checked;

        // ---- Execute the requested action (outside the panel borrows) ----
        if let Some(action) = action {
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
                                let line = format!("[dry-run] would run: {}", plan.display());
                                self.log.push(line.clone());
                                self.status = line;
                            }
                            Err(e) => self.log.push(format!("Cannot uninstall: {e:#}")),
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
            }
        }
    }
}

/// Render how a complete removal ended. True when "Undo" was clicked; the
/// button shows only when `undo` is true and works only when `idle`.
fn show_complete(ui: &mut egui::Ui, done: &Completed, undo: bool, idle: bool) -> bool {
    let out = &done.outcome;
    let v = &out.verdict;
    let mut clicked = false;
    if done.dry_run {
        ui.label(format!(
            "Dry run: {} items would be removed, {} would be closed.",
            out.selected.len(),
            running_processes(out.would_close.len())
        ));
        render_items(ui, &out.selected);
        return false;
    }
    if out.complete() {
        ui.label(RichText::new("Nothing left.").color(conf_color(Confidence::High)));
        ui.label(format!(
            "Removed {} items in {:.1} s",
            removed_count(out),
            out.seconds
        ));
    } else if v.still_installed {
        ui.label(
            RichText::new(format!(
                "{} is still registered. The uninstaller may have been cancelled or is still running.",
                done.program.display_name
            ))
            .color(conf_color(Confidence::Medium)),
        );
    }
    if v.below_level > 0 {
        ui.label(format!(
            "{} lower-confidence items were kept",
            v.below_level
        ));
    }
    if let Some(e) = &out.error {
        ui.colored_label(Color32::from_rgb(210, 70, 70), e);
    }
    if undo {
        ui.add_space(4.0);
        clicked = ui.add_enabled(idle, egui::Button::new("Undo")).clicked();
    }
    if !v.remaining.is_empty() {
        ui.add_space(6.0);
        ui.label(RichText::new("Still there:").strong());
        render_items(ui, &v.remaining);
    }
    clicked
}

/// A list of leftovers without checkboxes, grouped like a scan.
fn render_items(ui: &mut egui::Ui, items: &[Leftover]) {
    egui::ScrollArea::vertical()
        .id_salt("complete_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for group in Group::ALL {
                let indices: Vec<usize> = items
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| l.kind.group() == group)
                    .map(|(i, _)| i)
                    .collect();
                if indices.is_empty() {
                    continue;
                }
                render_group(ui, group.title(), items, &indices, &mut []);
                ui.add_space(6.0);
            }
        });
}

/// Render one group of leftovers with checkboxes. `indices` are positions
/// into `items` and into `checked`; an empty `checked` shows no checkboxes.
fn render_group(
    ui: &mut egui::Ui,
    title: &str,
    items: &[Leftover],
    indices: &[usize],
    checked: &mut [bool],
) {
    ui.label(RichText::new(format!("{title} ({})", indices.len())).strong());
    for &i in indices {
        let item = &items[i];
        ui.horizontal(|ui| {
            if i < checked.len() {
                ui.checkbox(&mut checked[i], "");
            }
            ui.colored_label(conf_color(item.confidence), conf_tag(item.confidence));
            let size = item
                .size_bytes
                .map(|b| format!("  [{}]", util::human_size(b)))
                .unwrap_or_default();
            let empty = if item.is_empty_dir { "  (empty)" } else { "" };
            ui.label(format!("{}{size}{empty}", item.path));
        });
        ui.label(RichText::new(format!("      {}", item.reason)).weak());
    }
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
    use oxidize::model::Hive;
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

    fn app() -> OxidizeApp {
        let (tx, rx) = channel();
        OxidizeApp {
            programs: Vec::new(),
            icons: HashMap::new(),
            scan: None,
            scan_for: None,
            checked: Vec::new(),
            uninstalled: None,
            complete: None,
            filter: String::new(),
            selected: None,
            sort_by_size: false,
            dry_run: false,
            make_backups: true,
            silent: false,
            include_system: false,
            elevated: false,
            busy: false,
            status: String::new(),
            log: Vec::new(),
            confirm: None,
            tx,
            rx,
        }
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
        app.busy = true;

        let reload = app.on_completed(program.clone(), finished(Some("example-player-1")), false);

        assert!(reload, "the program list is read again");
        assert!(!app.busy);
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
        assert!(!app.busy, "no reload was started");
        assert_eq!(
            app.status,
            "dry run: 1 items of Example Player would be removed"
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
    fn undo_logs_each_item_and_clears_the_result() {
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
        assert!(app.on_restored("example-player-1", Ok(items)));
        assert!(app.complete.is_none());
        assert_eq!(
            app.status,
            "Restored 1 items from example-player-1, 1 failed"
        );
        assert!(app
            .log
            .iter()
            .any(|l| l == r"failed HKCU\Software\Example Studio: access denied"));

        // A backup that cannot be found changes nothing and keeps the result.
        app.on_completed(example_program(), finished(Some("example-player-1")), false);
        assert!(!app.on_restored("example-player-1", Err("no backup named that".to_string())));
        assert!(app.undo_backup().is_some());
    }

    #[test]
    fn the_confirm_text_follows_the_settings() {
        let ctx = |dry_run, make_backups| SafetyContext {
            dry_run,
            make_backups,
        };
        assert_eq!(
            complete_confirm_text("Example Player", &ctx(false, true)),
            "Remove Example Player completely? Running copies are closed, everything found at \
             high confidence is removed, a backup is kept."
        );
        assert_eq!(
            complete_confirm_text("Example Player", &ctx(false, false)),
            "Remove Example Player completely? Running copies are closed, everything found at \
             high confidence is removed permanently, no backup is kept."
        );
        assert!(complete_confirm_text("Example Player", &ctx(true, true))
            .contains("nothing is closed or removed"));
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
            Some("Example Player: 1 items are still there.")
        );
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
        let root = std::env::temp_dir().join("oxidize_icon_main_exe_test");
        let _ = std::fs::remove_dir_all(&root);
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
        std::fs::remove_dir_all(&root).unwrap();
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
}
