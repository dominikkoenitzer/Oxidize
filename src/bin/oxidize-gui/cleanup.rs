//! The "Clean up" tab: analyse, tick, clean, and the protected folders.

use std::path::PathBuf;

use eframe::egui::{self, RichText};

use oxidize::clean::{self, protect, Analysis, Category, Choice, Cleaned, Finding, Places};
use oxidize::model::Confidence;
use oxidize::util;

use super::slate::{self, Slate};
use super::{cell_text, count, fact, primary_button, size_cell, tab_label, Action, Tint};

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
    /// The usage traces, cleared apart from the categories.
    pub slate: Slate,
    /// Which of the two shows: the files or the traces.
    pub view: View,
    /// The protected folders in the panel beside the list.
    pub show_protected: bool,
    /// The category the panel beside the list shows.
    pub focus: Option<Category>,
}

/// The two views of the tab, each with its own one action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    #[default]
    Files,
    Slate,
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
            slate: Slate::default(),
            view: View::Files,
            show_protected: false,
            focus: None,
        }
    }

    /// Take in a new analysis with the safe set ticked.
    pub fn take_analysis(&mut self, places: Places, analysis: Analysis) {
        let choice = analysis.default_choice();
        self.ticked = choice.categories;
        self.folders = choice.folders;
        self.results = None;
        // The panel opens on the first category that holds something.
        self.focus = analysis
            .findings
            .iter()
            .find(|f| f.bytes > 0 || !f.folders.is_empty())
            .or(analysis.findings.first())
            .map(|f| f.category);
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
        self.slate.found = None;
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

/// The head of the tab: what the open view would clean, its one action,
/// and below it the switch between the files and the traces.
pub fn strip(
    ui: &mut egui::Ui,
    t: &Tint,
    state: &mut Cleanup,
    busy: bool,
    dry_run: bool,
    action: &mut Option<Action>,
) {
    head(ui, t, state, busy, dry_run, action);
}

fn head(
    ui: &mut egui::Ui,
    t: &Tint,
    state: &mut Cleanup,
    busy: bool,
    dry_run: bool,
    action: &mut Option<Action>,
) {
    let analysed = state.analysis.is_some() || !state.slate.is_empty();
    let (big, small) = headline(state, busy);
    ui.horizontal(|ui| {
        ui.label(RichText::new(big).size(24.0).color(t.text));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let tall = egui::vec2(0.0, 34.0);
            if !analysed {
                if ui
                    .add_enabled(!busy, primary_button(t, "Analyse this PC").min_size(tall))
                    .on_hover_text("Count what each category holds. Changes nothing.")
                    .clicked()
                {
                    *action = Some(Action::Analyse);
                }
            } else {
                match state.view {
                    View::Files => files_button(ui, t, state, busy, dry_run, action),
                    View::Slate => slate::button(ui, t, &state.slate, busy, dry_run, action),
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("Analyse again").min_size(tall))
                    .on_hover_text("Count again. Changes nothing.")
                    .clicked()
                {
                    *action = Some(Action::Analyse);
                }
            }
            let protected = state.protected.entries().len();
            let label = format!("Protected folders  {protected}");
            if ui
                .add(
                    egui::Button::new(RichText::new(label).color(t.weak))
                        .frame(false)
                        .selected(state.show_protected),
                )
                .on_hover_text("Folders and files Clean up never touches")
                .clicked()
            {
                state.show_protected = !state.show_protected;
            }
        });
    });
    ui.add(egui::Label::new(RichText::new(small).color(t.weak)).wrap());
    if analysed {
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            for (view, label) in [(View::Files, "Files"), (View::Slate, "Clean slate")] {
                if tab_label(ui, t, state.view == view, label).clicked() {
                    state.view = view;
                }
                ui.add_space(8.0);
            }
        });
    } else {
        ui.add_space(16.0);
    }
    ui.add_space(4.0);
    ui.separator();
}

/// The two lines at the top left: a figure, and what it is.
fn headline(state: &Cleanup, busy: bool) -> (String, String) {
    match (state.view, &state.analysis) {
        _ if state.analysis.is_none() && state.slate.is_empty() => {
            if busy {
                (
                    "Analysing...".into(),
                    "Counting what each category holds.".into(),
                )
            } else {
                (
                    "Clean up this PC".into(),
                    "Counts what temporary files, caches and Windows' own stores hold. \
                     Nothing is deleted until you choose."
                        .into(),
                )
            }
        }
        (View::Slate, _) => slate::headline(&state.slate),
        (View::Files, None) => (
            "Analysing...".into(),
            "Counting what each category holds.".into(),
        ),
        (View::Files, Some((_, a))) => {
            let choice = state.choice_in(a);
            let n = choice.categories.len();
            if n == 0 {
                (
                    "Nothing selected".into(),
                    "Tick a category to clean it.".into(),
                )
            } else {
                (
                    util::human_size(a.chosen_bytes(&choice)),
                    format!(
                        "selected in {} of {}",
                        n,
                        count(a.findings.len(), "category", "categories")
                    ),
                )
            }
        }
    }
}

/// The action of the files view: clean what is ticked.
fn files_button(
    ui: &mut egui::Ui,
    t: &Tint,
    state: &Cleanup,
    busy: bool,
    dry_run: bool,
    action: &mut Option<Action>,
) {
    let Some((_, analysis)) = &state.analysis else {
        return;
    };
    let choice = state.choice_in(analysis);
    let bytes = util::human_size(analysis.chosen_bytes(&choice));
    let n = choice.categories.len();
    let label = match (n, dry_run) {
        (0, _) => "Clean".to_string(),
        (_, true) => format!("Preview cleaning {bytes}"),
        (_, false) => format!("Clean {bytes}"),
    };
    if ui
        .add_enabled(
            !busy && n > 0,
            primary_button(t, &label).min_size(egui::vec2(150.0, 34.0)),
        )
        .clicked()
    {
        *action = Some(Action::Clean(choice));
    }
}

/// The tab's main area: the open view.
pub fn view(
    ui: &mut egui::Ui,
    t: &Tint,
    state: &mut Cleanup,
    busy: bool,
    action: &mut Option<Action>,
) {
    egui::ScrollArea::vertical()
        .id_salt("cleanup_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if state.analysis.is_none() && state.slate.is_empty() {
                if !busy {
                    what_it_counts(ui, t);
                }
                return;
            }
            if state.view == View::Slate {
                slate::body(ui, t, &state.slate);
                return;
            }
            if let Some(results) = &state.results {
                show_results(ui, t, results, busy, action);
                ui.add_space(12.0);
                ui.separator();
            }
            // Taken for the frame and put back, so the analysis is not copied.
            let Some((places, analysis)) = state.analysis.take() else {
                return;
            };
            ui.add_space(4.0);
            ui.scope(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for f in &analysis.findings {
                    category_row(ui, t, state, f);
                }
            });
            ui.add_space(16.0);
            state.analysis = Some((places, analysis));
        });
}

/// The panel beside the list: the category in focus, what Clean slate
/// clears, or the protected folders when asked for or before an analysis.
pub fn side(ui: &mut egui::Ui, t: &Tint, state: &mut Cleanup) {
    let analysed = state.analysis.is_some() || !state.slate.is_empty();
    if state.show_protected || !analysed {
        protected_panel(ui, t, state);
        return;
    }
    egui::ScrollArea::vertical()
        .id_salt("cleanup_side")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if state.view == View::Slate {
                slate::about(ui, t);
                return;
            }
            let Some((places, analysis)) = state.analysis.take() else {
                ui.label(RichText::new("Analysing...").color(t.weak));
                return;
            };
            let found = state
                .focus
                .and_then(|c| analysis.findings.iter().find(|f| f.category == c));
            match found {
                Some(f) => category_detail(ui, t, state, f, analysis.elevated),
                None => {
                    ui.label(RichText::new("Pick a category to see what it holds.").color(t.weak));
                }
            }
            state.analysis = Some((places, analysis));
        });
}

/// Before the first analysis: what will be counted, in the order the rows
/// will show.
fn what_it_counts(ui: &mut egui::Ui, t: &Tint) {
    ui.add_space(8.0);
    ui.label(RichText::new("What it looks at").color(t.text));
    ui.add_space(4.0);
    let slate = (
        "Clean slate",
        "recent files, jump lists and histories Windows keeps; the files stay",
    );
    egui::Grid::new("what_it_counts")
        .num_columns(2)
        .min_col_width(240.0)
        .spacing(egui::vec2(24.0, 8.0))
        .show(ui, |ui| {
            let rows = Category::ALL
                .iter()
                .map(|c| (c.title(), c.about()))
                .chain(std::iter::once(slate));
            for (title, about) in rows {
                ui.label(RichText::new(title).color(t.text));
                ui.add(egui::Label::new(RichText::new(about).color(t.weak)).wrap());
                ui.end_row();
            }
        });
    ui.add_space(10.0);
    ui.label(
        RichText::new("Protected folders and anything changed in the last 7 days are left alone.")
            .color(t.weak),
    );
}

/// The size a category row shows: what cleaning it would free. For the
/// folders of removed programs that is the ticked ones, not every folder
/// no program claims.
fn shown_bytes(state: &Cleanup, f: &Finding) -> u64 {
    match f.category {
        Category::Orphans => f
            .folders
            .iter()
            .filter(|o| state.folders.contains(&o.path))
            .map(|o| o.bytes)
            .sum(),
        _ => f.bytes,
    }
}

/// The notes of a category as one line. The one that says the size comes
/// afterwards is left to the size column, which says it already.
fn notes_line(f: &Finding) -> Option<String> {
    let notes: Vec<&str> = f
        .notes
        .iter()
        .map(String::as_str)
        .filter(|n| f.size_known || !n.contains("measured"))
        .collect();
    (!notes.is_empty()).then(|| notes.join("  \u{b7}  "))
}

/// `text` with a capital first letter, for a line that stands alone.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The height of a category's row.
const ROW_HEIGHT: f32 = 34.0;

/// One category on one line, like a program in the table: its tick, its
/// title and its size. A click shows it in the panel beside the list.
fn category_row(ui: &mut egui::Ui, t: &Tint, state: &mut Cleanup, f: &Finding) {
    let focused = state.focus == Some(f.category);
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), ROW_HEIGHT),
        egui::Sense::click(),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            true,
            focused,
            f.category.title(),
        )
    });
    if response.clicked() {
        state.focus = Some(f.category);
    }
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter_at(rect);
    if focused {
        painter.rect_filled(rect, 4.0, t.selected);
        let mark = egui::Rect::from_min_size(rect.left_top(), egui::vec2(3.0, rect.height()))
            .shrink2(egui::vec2(0.0, 7.0));
        painter.rect_filled(mark, 1.5, t.copper);
    } else if response.hovered() {
        painter.rect_filled(rect, 4.0, t.hover);
    }
    let tick = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 22.0, rect.center().y),
        egui::vec2(20.0, 20.0),
    );
    let mut on = state.ticked.contains(&f.category) && f.actionable();
    let mut cell = ui.new_child(egui::UiBuilder::new().max_rect(tick));
    if !f.actionable() {
        cell.disable();
    }
    if cell.add(egui::Checkbox::without_text(&mut on)).changed() {
        state.set(f, on);
    }
    let font = egui::TextStyle::Body.resolve(ui.style());
    let color = if f.actionable() { t.text } else { t.weak };
    let size = egui::Rect::from_min_max(
        egui::pos2(rect.right() - 160.0, rect.top()),
        egui::pos2(rect.right() - 12.0, rect.bottom()),
    );
    let title = egui::Rect::from_min_max(
        egui::pos2(rect.left() + 44.0, rect.top()),
        egui::pos2(size.left() - 16.0, rect.bottom()),
    );
    cell_text(
        &painter,
        title,
        f.category.title(),
        font.clone(),
        color,
        egui::Align::Min,
    );
    let bytes = shown_bytes(state, f);
    if !f.size_known && bytes == 0 {
        cell_text(
            &painter,
            size,
            "measured afterwards",
            font,
            t.weak,
            egui::Align::Max,
        );
    } else if !f.actionable() && bytes == 0 {
        cell_text(
            &painter,
            size,
            "nothing found",
            font,
            t.weak,
            egui::Align::Max,
        );
    } else {
        size_cell(&painter, t, size, Some(bytes), &font);
    }
}

/// The panel for one category: what it is, what it would free, what stays
/// and why, and for the folders of removed programs each folder.
fn category_detail(ui: &mut egui::Ui, t: &Tint, state: &mut Cleanup, f: &Finding, elevated: bool) {
    ui.spacing_mut().item_spacing.y = 6.0;
    ui.label(RichText::new(f.category.title()).size(18.0).color(t.text));
    ui.add(egui::Label::new(RichText::new(f.category.about()).color(t.weak)).wrap());
    ui.add_space(10.0);
    let bytes = shown_bytes(state, f);
    let size = if !f.size_known && bytes == 0 {
        "measured afterwards".to_string()
    } else {
        util::human_size(bytes)
    };
    fact(ui, t, "Would free", &size);
    if f.category == Category::Orphans && !f.folders.is_empty() {
        let all: u64 = f.folders.iter().map(|o| o.bytes).sum();
        fact(
            ui,
            t,
            "Found",
            &format!(
                "{}, {} in all",
                count(f.folders.len(), "folder", "folders"),
                util::human_size(all)
            ),
        );
    }
    let cleaned_by = match f.category {
        Category::ComponentStore | Category::DeliveryOptimization | Category::WindowsOld => {
            "Windows' own tools"
        }
        Category::Orphans => "Oxidize, into a backup first",
        _ => "Oxidize, each file checked again right before it goes",
    };
    fact(ui, t, "Cleaned by", cleaned_by);
    let undo = if f.category.backed_up() {
        "Yes, from the backup"
    } else {
        "No, it is deleted for good"
    };
    fact(ui, t, "Can be undone", undo);
    ui.add_space(10.0);
    let line = |ui: &mut egui::Ui, text: &str, color| {
        ui.add(egui::Label::new(RichText::new(text).color(color)).wrap());
    };
    if let Some(notes) = notes_line(f) {
        let color = if f.category == Category::WindowsOld {
            t.amber
        } else {
            t.weak
        };
        line(ui, &notes, color);
    }
    if let Some(stays) = clean::stays_text(&f.kept) {
        line(
            ui,
            &sentence(&stays),
            if f.needs_admin { t.amber } else { t.weak },
        );
    }
    if f.needs_admin && !elevated {
        line(
            ui,
            "Needs administrator rights: Restart as administrator, then analyse again.",
            t.amber,
        );
    }
    if f.category == Category::Orphans && !f.folders.is_empty() {
        ui.add_space(6.0);
        folder_list(ui, t, state, f);
    }
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
    if let Ok(path) = protect::file_path() {
        ui.add(
            egui::Label::new(
                RichText::new(format!("Kept in {}", path.display()))
                    .small()
                    .color(t.weak),
            )
            .wrap(),
        );
    }
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
                    ui.set_min_height(22.0);
                    // Remove shows on the row under the pointer only, so a
                    // long list reads as a list.
                    let hovered = ui.ui_contains_pointer();
                    let room = ui.available_width() - if hovered { 70.0 } else { 0.0 };
                    ui.allocate_ui_with_layout(
                        egui::vec2(room.max(40.0), 22.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.add(egui::Label::new(RichText::new(entry).color(t.text)).truncate())
                        },
                    );
                    if hovered && ui.small_button("Remove").clicked() {
                        remove = Some(entry.clone());
                    }
                });
            }
        });
    if let Some(entry) = remove {
        state.remove_protected(&entry);
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
        fn running_exes(&self) -> Vec<PathBuf> {
            Vec::new()
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
            slate: Slate::default(),
            view: View::Files,
            show_protected: false,
            focus: None,
        }
    }

    #[test]
    fn a_line_that_stands_alone_starts_with_a_capital() {
        assert_eq!(sentence("stays: 2 changed"), "Stays: 2 changed");
        assert_eq!(sentence(""), "");
    }

    #[test]
    fn the_head_says_what_the_open_view_would_clean() {
        let mut c = tab();
        assert_eq!(headline(&c, false).0, "Clean up this PC");
        assert_eq!(headline(&c, true).0, "Analysing...");
        c.take_analysis(Places::default(), analysis());
        let (_, small) = headline(&c, false);
        assert!(small.starts_with("selected in 1 of "), "{small}");
        c.ticked.clear();
        c.folders.clear();
        assert_eq!(headline(&c, false).0, "Nothing selected");
        // The traces are still being read.
        c.view = View::Slate;
        assert_eq!(headline(&c, false).0, "Analysing...");
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
