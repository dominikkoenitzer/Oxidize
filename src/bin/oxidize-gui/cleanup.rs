//! The "Clean up" tab: analyse, tick, clean, and the protected folders.

use std::path::PathBuf;

use eframe::egui::{self, RichText};

use oxidize::clean::{self, protect, Analysis, Category, Choice, Cleaned, Finding, Places};
use oxidize::model::Confidence;
use oxidize::util;

use super::{danger_button, primary_button, Action, Tint};

/// What the tab holds between frames.
pub struct Cleanup {
    /// The last analysis and where it looked.
    pub analysis: Option<(Places, Analysis)>,
    /// The ticked categories.
    pub ticked: Vec<Category>,
    /// The ticked folders of removed programs.
    pub folders: Vec<PathBuf>,
    /// How the last cleaning went.
    pub results: Option<Vec<Cleaned>>,
    pub protected: protect::Protected,
    /// The folder being typed into the protected list.
    pub new_protected: String,
    /// A problem reading or saving the protected list.
    pub protect_error: Option<String>,
}

impl Cleanup {
    pub fn new() -> Self {
        let (protected, protect_error) = match protect::load() {
            Ok(p) => (p, None),
            Err(e) => (protect::Protected::default(), Some(format!("{e:#}"))),
        };
        Cleanup {
            analysis: None,
            ticked: Vec::new(),
            folders: Vec::new(),
            results: None,
            protected,
            new_protected: String::new(),
            protect_error,
        }
    }

    /// Take in a new analysis with the safe set ticked.
    pub fn take_analysis(&mut self, places: Places, analysis: Analysis) {
        let choice = analysis.default_choice();
        self.ticked = choice.categories;
        self.folders = choice.folders;
        self.results = None;
        self.analysis = Some((places, analysis));
    }

    /// What the ticks amount to: only categories that can be cleaned, and
    /// the folders only while their category is ticked.
    #[cfg(test)]
    pub fn choice(&self) -> Choice {
        match &self.analysis {
            Some((_, a)) => self.choice_in(a),
            None => Choice::default(),
        }
    }

    fn choice_in(&self, a: &Analysis) -> Choice {
        let categories: Vec<Category> = Category::ALL
            .into_iter()
            .filter(|c| self.ticked.contains(c))
            .filter(|c| a.finding(*c).is_some_and(Finding::actionable))
            .collect();
        let folders = if categories.contains(&Category::Orphans) {
            self.folders.clone()
        } else {
            Vec::new()
        };
        Choice {
            categories,
            folders,
        }
    }

    /// Tick or untick the category of `f`. Ticking the folders of removed
    /// programs with none of them ticked takes the high-confidence ones.
    pub fn set(&mut self, f: &Finding, on: bool) {
        let c = f.category;
        self.ticked.retain(|t| *t != c);
        if on {
            self.ticked.push(c);
            if c == Category::Orphans && self.folders.is_empty() {
                self.folders = f
                    .folders
                    .iter()
                    .filter(|o| o.confidence == Confidence::High)
                    .map(|o| o.path.clone())
                    .collect();
            }
        }
    }

    pub fn set_folder(&mut self, path: &PathBuf, on: bool) {
        self.folders.retain(|p| p != path);
        if on {
            self.folders.push(path.clone());
        }
    }

    fn add_protected(&mut self) {
        let entry = self.new_protected.trim().to_string();
        if entry.is_empty() {
            return;
        }
        if self.protected.add(&entry) {
            self.save_protected();
        }
        self.new_protected.clear();
    }

    fn remove_protected(&mut self, entry: &str) {
        if self.protected.remove(entry) {
            self.save_protected();
        }
    }

    fn save_protected(&mut self) {
        self.protect_error = protect::save(&self.protected)
            .err()
            .map(|e| format!("{e:#}"));
        // An analysis made before the list changed may hold what is now
        // protected; the cleaning checks the list again, but the numbers on
        // screen would be wrong.
        if self.analysis.is_some() {
            self.analysis = None;
            self.results = None;
        }
    }
}

/// The question before a cleaning.
pub fn confirm_text(analysis: &Analysis, choice: &Choice, make_backups: bool) -> String {
    let bytes = util::human_size(analysis.chosen_bytes(choice));
    let n = choice.categories.len();
    let what = if n == 1 {
        "1 category".to_string()
    } else {
        format!("{n} categories")
    };
    let mut text = format!("Clean {what}, {bytes}? Deleted files do not go to the Recycle Bin.");
    if choice.categories.contains(&Category::Orphans) && !choice.folders.is_empty() {
        text.push_str(if make_backups {
            " The folders of removed programs go into a backup and can be put back."
        } else {
            " Backups are off, so the folders of removed programs are deleted for good."
        });
    }
    if choice.categories.contains(&Category::WindowsOld) {
        text.push_str(
            " The previous Windows installation is removed too; after that there is no going back to it.",
        );
    }
    if choice.categories.contains(&Category::ComponentStore) {
        text.push_str(" DISM can take several minutes.");
    }
    text
}

/// The tab's main area.
pub fn view(
    ui: &mut egui::Ui,
    t: &Tint,
    state: &mut Cleanup,
    busy: bool,
    dry_run: bool,
    action: &mut Option<Action>,
) {
    ui.add_space(14.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Clean up").size(20.0).color(t.text));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = if state.analysis.is_some() {
                "Analyse again"
            } else {
                "Analyse"
            };
            if ui
                .add_enabled(
                    !busy,
                    primary_button(t, label).min_size(egui::vec2(120.0, 30.0)),
                )
                .clicked()
            {
                *action = Some(Action::Analyse);
            }
        });
    });
    ui.add(
        egui::Label::new(
            RichText::new(
                "The analysis counts what each category holds and changes nothing. \
                 Tick what you want gone, then clean.",
            )
            .color(t.weak),
        )
        .wrap(),
    );
    ui.add_space(10.0);

    egui::ScrollArea::vertical()
        .id_salt("cleanup_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if let Some(results) = &state.results {
                show_results(ui, t, results, busy, action);
                ui.add_space(12.0);
            }
            // Taken for the frame and put back, so the analysis is not copied.
            let Some((places, analysis)) = state.analysis.take() else {
                if !busy {
                    ui.add_space(24.0);
                    ui.label(RichText::new("Nothing analysed yet.").color(t.weak));
                }
                return;
            };
            for f in &analysis.findings {
                category_row(ui, t, state, f);
                ui.add_space(6.0);
            }
            ui.add_space(8.0);
            let choice = state.choice_in(&analysis);
            let bytes = util::human_size(analysis.chosen_bytes(&choice));
            let n = choice.categories.len();
            let label = if dry_run {
                format!("Preview cleaning {n} categories, {bytes}")
            } else {
                format!("Clean {n} ticked categories, {bytes}")
            };
            let full = egui::vec2(ui.available_width().min(420.0), 34.0);
            if ui
                .add_enabled(!busy && n > 0, danger_button(t, &label).min_size(full))
                .clicked()
            {
                *action = Some(Action::Clean(choice));
            }
            if !analysis.elevated && analysis.findings.iter().any(|f| f.needs_admin) {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "Some of it needs administrator rights: Restart as administrator, then analyse again.",
                    )
                    .small()
                    .color(t.weak),
                );
            }
            state.analysis = Some((places, analysis));
        });
}

/// One category: its tick, title and size, what it is, and what stays.
fn category_row(ui: &mut egui::Ui, t: &Tint, state: &mut Cleanup, f: &Finding) {
    egui::Frame::new()
        .fill(t.side)
        .stroke(egui::Stroke::new(1.0, t.line))
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let mut on = state.ticked.contains(&f.category) && f.actionable();
                let response =
                    ui.add_enabled(f.actionable(), egui::Checkbox::without_text(&mut on));
                if response.changed() {
                    state.set(f, on);
                }
                ui.label(RichText::new(f.category.title()).size(15.0).color(t.text));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let size = if !f.size_known && f.bytes == 0 {
                        "size known afterwards".to_string()
                    } else if !f.actionable() && f.bytes == 0 {
                        "nothing found".to_string()
                    } else {
                        util::human_size(f.bytes)
                    };
                    ui.label(RichText::new(size).color(t.text));
                });
            });
            let weak = |ui: &mut egui::Ui, text: &str, color| {
                ui.add(egui::Label::new(RichText::new(text).small().color(color)).wrap());
            };
            weak(ui, f.category.about(), t.weak);
            for note in &f.notes {
                let color = if f.category == Category::WindowsOld {
                    t.amber
                } else {
                    t.weak
                };
                weak(ui, note, color);
            }
            if let Some(stays) = clean::stays_text(&f.kept) {
                weak(ui, &stays, if f.needs_admin { t.amber } else { t.weak });
            }
            if f.category == Category::Orphans && !f.folders.is_empty() {
                folder_list(ui, t, state, f);
            }
        });
}

/// The folders of removed programs, each with its own tick.
fn folder_list(ui: &mut egui::Ui, t: &Tint, state: &mut Cleanup, f: &Finding) {
    let ticked = f
        .folders
        .iter()
        .filter(|o| state.folders.contains(&o.path))
        .count();
    egui::CollapsingHeader::new(format!("{} folders, {ticked} ticked", f.folders.len()))
        .id_salt("cleanup_folders")
        .default_open(f.folders.len() <= 20)
        .show(ui, |ui| {
            for o in &f.folders {
                ui.horizontal_top(|ui| {
                    let mut on = state.folders.contains(&o.path);
                    if ui.add(egui::Checkbox::without_text(&mut on)).changed() {
                        state.set_folder(&o.path, on);
                        if on && !state.ticked.contains(&Category::Orphans) {
                            state.ticked.push(Category::Orphans);
                        }
                    }
                    let (tag, _) =
                        ui.allocate_exact_size(egui::vec2(46.0, 18.0), egui::Sense::hover());
                    ui.painter().text(
                        tag.left_center(),
                        egui::Align2::LEFT_CENTER,
                        o.confidence.label(),
                        egui::FontId::proportional(11.5),
                        t.confidence(o.confidence),
                    );
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.add(
                            egui::Label::new(
                                RichText::new(o.path.display().to_string()).color(t.text),
                            )
                            .wrap(),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "{}, {}",
                                    util::human_size(o.bytes),
                                    o.reason
                                ))
                                .small()
                                .color(t.weak),
                            )
                            .wrap(),
                        );
                    });
                });
            }
        });
}

/// How the last cleaning went, category by category.
fn show_results(
    ui: &mut egui::Ui,
    t: &Tint,
    results: &[Cleaned],
    busy: bool,
    action: &mut Option<Action>,
) {
    let freed: u64 = results.iter().map(|c| c.freed).sum();
    ui.label(
        RichText::new(format!("{} freed", util::human_size(freed)))
            .size(18.0)
            .color(t.verdigris),
    );
    for c in results {
        ui.label(
            RichText::new(format!(
                "{}: {}, {} removed",
                c.category.title(),
                util::human_size(c.freed),
                c.removed
            ))
            .color(t.text),
        );
        for note in &c.notes {
            ui.label(RichText::new(note).small().color(t.weak));
        }
        if let Some(stays) = clean::stays_text(&c.kept) {
            let color = if c.failed() { t.red } else { t.weak };
            ui.add(egui::Label::new(RichText::new(stays).small().color(color)).wrap());
        }
        if let Some(name) = &c.backup {
            if ui
                .add_enabled(!busy, egui::Button::new("Undo"))
                .on_hover_text(format!("Put the folders back from {name}"))
                .clicked()
            {
                *action = Some(Action::Undo(name.clone()));
            }
        }
    }
}

/// The panel beside the tab: the folders that are never cleaned.
pub fn protected_panel(ui: &mut egui::Ui, t: &Tint, state: &mut Cleanup) {
    ui.label(RichText::new("Protected folders").size(16.0).color(t.text));
    ui.add(
        egui::Label::new(
            RichText::new(
                "Never cleaned, with everything inside. A path such as %TEMP%\\tools works too.",
            )
            .small()
            .color(t.weak),
        )
        .wrap(),
    );
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut state.new_protected)
                .hint_text("Folder or file")
                .desired_width((ui.available_width() - 60.0).max(80.0)),
        );
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if ui.button("Add").clicked() || enter {
            state.add_protected();
        }
    });
    if let Some(e) = &state.protect_error {
        ui.add(egui::Label::new(RichText::new(e).small().color(t.red)).wrap());
    }
    ui.add_space(6.0);
    if state.protected.is_empty() {
        ui.label(RichText::new("None yet.").color(t.weak));
        return;
    }
    let mut remove = None;
    egui::ScrollArea::vertical()
        .id_salt("protected_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for entry in state.protected.entries() {
                ui.horizontal(|ui| {
                    if ui.small_button("Remove").clicked() {
                        remove = Some(entry.clone());
                    }
                    ui.add(egui::Label::new(RichText::new(entry).color(t.text)).truncate());
                });
            }
        });
    if let Some(entry) = remove {
        state.remove_protected(&entry);
    }
    if let Ok(path) = protect::file_path() {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("Kept in {}", path.display()))
                .small()
                .color(t.weak),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidize::clean::windows::{StoreReport, Tools};
    use oxidize::clean::{analyse, Options, OrphanItem};

    struct NoTools;

    impl Tools for NoTools {
        fn component_store(&self) -> anyhow::Result<StoreReport> {
            Ok(StoreReport::default())
        }
        fn component_cleanup(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn delivery_cache(&self) -> anyhow::Result<(usize, u64)> {
            Ok((2, 500))
        }
        fn delete_delivery_cache(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn remove_windows_old(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn free_bytes(&self, _path: &std::path::Path) -> Option<u64> {
            None
        }
    }

    fn folder(name: &str, confidence: Confidence) -> OrphanItem {
        OrphanItem {
            path: PathBuf::from(format!(r"C:\Users\Example\AppData\Local\{name}")),
            bytes: 100,
            modified: None,
            confidence,
            reason: "test".into(),
            needs_admin: false,
        }
    }

    /// An analysis of an empty PC with three unclaimed folders, elevated so
    /// the Windows tools count.
    fn analysis() -> Analysis {
        let orphans = || {
            vec![
                folder("Quillmark", Confidence::High),
                folder("Quill Tools", Confidence::Medium),
                folder("Portable", Confidence::Low),
            ]
        };
        analyse(
            &Places::default(),
            &Options {
                protected: &protect::Protected::default(),
                elevated: true,
                now: std::time::SystemTime::now(),
                running: &[],
                recycle_bin_days: clean::RECYCLE_DAYS,
                tools: &NoTools,
                orphans: &orphans,
            },
        )
    }

    fn tab() -> Cleanup {
        Cleanup {
            analysis: None,
            ticked: Vec::new(),
            folders: Vec::new(),
            results: None,
            protected: protect::Protected::default(),
            new_protected: String::new(),
            protect_error: None,
        }
    }

    #[test]
    fn a_new_analysis_ticks_the_safe_set_and_only_high_folders() {
        let mut c = tab();
        c.take_analysis(Places::default(), analysis());
        let choice = c.choice();
        // Nothing else holds anything on an empty PC.
        assert_eq!(choice.categories, [Category::Orphans]);
        assert_eq!(choice.folders.len(), 1);
        assert!(choice.folders[0].ends_with("Quillmark"));
        // Delivery Optimization can be cleaned but is not ticked by itself.
        assert!(!c.ticked.contains(&Category::DeliveryOptimization));
    }

    #[test]
    fn ticks_follow_the_user_and_skip_what_cannot_be_cleaned() {
        let mut c = tab();
        let a = analysis();
        let orphans = a.finding(Category::Orphans).unwrap().clone();
        let temp = a.finding(Category::Temp).unwrap().clone();
        let dopt = a.finding(Category::DeliveryOptimization).unwrap().clone();
        c.take_analysis(Places::default(), a);
        c.set(&orphans, false);
        assert!(c.choice().categories.is_empty());
        assert!(
            c.choice().folders.is_empty(),
            "folders go with their category"
        );
        c.set(&temp, true);
        assert!(
            c.choice().categories.is_empty(),
            "an empty category is never chosen"
        );
        c.set(&dopt, true);
        assert_eq!(c.choice().categories, [Category::DeliveryOptimization]);

        // Ticking the folders again with none ticked takes the high ones.
        c.folders.clear();
        c.set(&orphans, true);
        assert_eq!(c.choice().folders.len(), 1);
        let low = orphans.folders[2].path.clone();
        c.set_folder(&low, true);
        assert_eq!(c.choice().folders.len(), 2);
        c.set_folder(&low, false);
        assert_eq!(c.choice().folders.len(), 1);
    }

    #[test]
    fn the_question_says_what_cannot_be_undone() {
        let a = analysis();
        let mut choice = a.choice(&[Category::Orphans], Confidence::High);
        assert!(confirm_text(&a, &choice, true).contains("can be put back"));
        assert!(confirm_text(&a, &choice, false).contains("deleted for good"));
        choice.categories.push(Category::WindowsOld);
        assert!(confirm_text(&a, &choice, true).contains("no going back"));
    }
}
