//! "Clean slate" on the Clean up tab: the lists Windows keeps of recently
//! used files and programs, shown first and cleared with one button.

use eframe::egui::{self, RichText};

use oxidize::clean::traces::TraceFinding;
use oxidize::clean::{self, traces};
use oxidize::util;

use super::{cell_text, primary_button, Action, Tint};

/// What the section holds between frames.
#[derive(Default)]
pub struct Slate {
    /// The traces as the last analysis found them.
    pub found: Option<Vec<TraceFinding>>,
    /// What the last clearing did.
    pub results: Option<Vec<TraceFinding>>,
}

impl Slate {
    pub fn take_found(&mut self, found: Vec<TraceFinding>) {
        self.found = Some(found);
        self.results = None;
    }

    pub fn take_results(&mut self, results: Vec<TraceFinding>) {
        self.found = None;
        self.results = Some(results);
    }

    pub fn is_empty(&self) -> bool {
        self.found.is_none() && self.results.is_none()
    }
}

/// The question before clearing.
pub fn confirm_text(found: &[TraceFinding]) -> String {
    let (count, _) = traces::total(found);
    format!(
        "Clear {}? The files they point to and pinned items stay. This cannot be undone.",
        items(count)
    )
}

fn items(n: usize) -> String {
    if n == 1 {
        "1 item".to_string()
    } else {
        format!("{n} items")
    }
}

/// The two lines at the top of the tab for this view.
pub fn headline(slate: &Slate) -> (String, String) {
    if let Some(results) = &slate.results {
        let (count, bytes) = traces::total(results);
        return (
            format!("{} cleared", items(count)),
            format!(
                "{} freed. The files themselves stay.",
                util::human_size(bytes)
            ),
        );
    }
    match &slate.found {
        Some(found) if found.iter().any(TraceFinding::actionable) => {
            let (count, _) = traces::total(found);
            (
                items(count),
                "in the lists Windows keeps of what you opened. The files themselves stay.".into(),
            )
        }
        Some(_) => (
            "Nothing to clear".into(),
            "Windows keeps no recent lists right now.".into(),
        ),
        None => (
            "Analysing...".into(),
            "Reading the lists Windows keeps.".into(),
        ),
    }
}

/// The action of this view: clear every trace.
pub fn button(
    ui: &mut egui::Ui,
    t: &Tint,
    slate: &Slate,
    busy: bool,
    dry_run: bool,
    action: &mut Option<Action>,
) {
    let Some(found) = slate.found.as_ref().filter(|_| slate.results.is_none()) else {
        return;
    };
    let (count, _) = traces::total(found);
    let any = found.iter().any(TraceFinding::actionable);
    let label = if dry_run {
        format!("Preview clearing {}", items(count))
    } else {
        format!("Clear {}", items(count))
    };
    if ui
        .add_enabled(
            !busy && any,
            primary_button(t, &label).min_size(egui::vec2(150.0, 34.0)),
        )
        .clicked()
    {
        *action = Some(Action::ClearTraces);
    }
}

/// The view: each trace with what it holds, or what the last clearing did.
pub fn body(ui: &mut egui::Ui, t: &Tint, slate: &Slate) {
    ui.add_space(6.0);
    if let Some(results) = &slate.results {
        show_results(ui, t, results);
    } else if let Some(found) = &slate.found {
        for f in found {
            row(ui, t, f);
        }
        ui.add_space(10.0);
        ui.label(
            RichText::new(
                "A File Explorer window that is open may show old entries until it is closed.",
            )
            .color(t.weak),
        );
    }
    ui.add_space(16.0);
}

/// Where what a trace is starts, past its title.
const TITLE: f32 = 200.0;
/// The room for the count and size at the right.
const AMOUNT: f32 = 220.0;

/// One trace on one line: its title, what it is, and what it holds. Notes
/// and what stays go on a line below.
fn row(ui: &mut egui::Ui, t: &Tint, f: &TraceFinding) {
    let active = f.actionable();
    let strong = if active { t.text } else { t.weak };
    ui.horizontal(|ui| {
        let line = egui::Layout::left_to_right(egui::Align::Center);
        let about = (ui.available_width() - TITLE - AMOUNT - 16.0).max(0.0);
        ui.allocate_ui_with_layout(egui::vec2(TITLE, 24.0), line, |ui| {
            ui.set_min_width(TITLE);
            ui.add(egui::Label::new(RichText::new(f.trace.title()).color(strong)).truncate());
        });
        ui.allocate_ui_with_layout(egui::vec2(about, 24.0), line, |ui| {
            ui.set_min_width(about);
            ui.add(egui::Label::new(RichText::new(f.trace.about()).color(t.weak)).truncate());
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let (cell, _) = ui.allocate_exact_size(egui::vec2(AMOUNT, 20.0), egui::Sense::hover());
            let font = egui::TextStyle::Body.resolve(ui.style());
            let text = if active {
                amount(f)
            } else {
                "nothing found".to_string()
            };
            cell_text(ui.painter(), cell, &text, font, strong, egui::Align::Max);
        });
    });
    let mut extra: Vec<String> = f.notes.clone();
    extra.extend(clean::stays_text(&f.kept));
    if !extra.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(TITLE + ui.spacing().item_spacing.x);
            ui.add(
                egui::Label::new(
                    RichText::new(extra.join("  \u{b7}  "))
                        .small()
                        .color(t.weak),
                )
                .wrap(),
            );
        });
    }
}

/// "12 shortcuts, 3.4 KB", or the size alone where a count says nothing.
fn amount(f: &TraceFinding) -> String {
    let detail = f.detail();
    match (detail.is_empty(), f.bytes) {
        (true, 0) => "some".to_string(),
        (true, b) => util::human_size(b),
        (false, 0) => detail,
        (false, b) => format!("{detail}, {}", util::human_size(b)),
    }
}

fn show_results(ui: &mut egui::Ui, t: &Tint, results: &[TraceFinding]) {
    let (count, bytes) = traces::total(results);
    ui.label(
        RichText::new(format!(
            "{} cleared, {} freed",
            items(count),
            util::human_size(bytes)
        ))
        .size(18.0)
        .color(t.verdigris),
    );
    for f in results
        .iter()
        .filter(|f| f.actionable() || !f.kept.is_empty())
    {
        ui.label(RichText::new(format!("{}: {}", f.trace.title(), amount(f))).color(t.text));
        for note in &f.notes {
            ui.label(RichText::new(note).small().color(t.weak));
        }
        if let Some(stays) = clean::stays_text(&f.kept) {
            let color = if f.failed() { t.red } else { t.weak };
            ui.add(egui::Label::new(RichText::new(stays).small().color(color)).wrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidize::clean::traces::Trace;

    fn finding(trace: Trace, count: usize, bytes: u64, known: bool) -> TraceFinding {
        let mut f = TraceFinding::new(trace);
        f.count = count;
        f.bytes = bytes;
        f.count_known = known;
        f
    }

    #[test]
    fn amounts_say_count_and_size() {
        assert_eq!(
            amount(&finding(Trace::RecentItems, 12, 2048, true)),
            "12 shortcuts, 2.0 KB"
        );
        assert_eq!(amount(&finding(Trace::RunHistory, 1, 0, true)), "1 command");
        assert_eq!(
            amount(&finding(Trace::Thumbnails, 3, 3 << 20, false)),
            "3.0 MB"
        );
        assert_eq!(amount(&finding(Trace::Clipboard, 0, 0, false)), "some");
    }

    #[test]
    fn the_question_counts_the_items() {
        let found = vec![
            finding(Trace::RecentItems, 3, 300, true),
            finding(Trace::Thumbnails, 2, 9000, false),
            finding(Trace::RunHistory, 1, 10, true),
        ];
        let q = confirm_text(&found);
        assert!(q.starts_with("Clear 4 items?"), "{q}");
        assert!(q.contains("stay"));
    }

    #[test]
    fn clearing_replaces_the_preview() {
        let mut s = Slate::default();
        assert!(s.is_empty());
        s.take_found(vec![finding(Trace::RecentItems, 3, 300, true)]);
        assert!(s.found.is_some() && s.results.is_none());
        s.take_results(vec![finding(Trace::RecentItems, 3, 300, true)]);
        assert!(s.found.is_none() && s.results.is_some());
    }
}
