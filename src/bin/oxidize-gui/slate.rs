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

/// The section: the traces, then the button, or what the last clearing did.
pub fn section(
    ui: &mut egui::Ui,
    t: &Tint,
    slate: &Slate,
    busy: bool,
    dry_run: bool,
    action: &mut Option<Action>,
) {
    ui.add_space(14.0);
    ui.label(RichText::new("Clean slate").size(16.0).color(t.text));
    ui.add(
        egui::Label::new(
            RichText::new(
                "Recent files, jump lists and histories Windows keeps. The files themselves stay.",
            )
            .small()
            .color(t.weak),
        )
        .wrap(),
    );
    ui.add_space(4.0);
    if let Some(results) = &slate.results {
        show_results(ui, t, results);
    } else if let Some(found) = &slate.found {
        for f in found {
            row(ui, t, f);
        }
        ui.add_space(12.0);
        let (count, _) = traces::total(found);
        let any = found.iter().any(TraceFinding::actionable);
        let label = if dry_run {
            format!("Preview clearing {}", items(count))
        } else {
            format!("Clear all traces, {}", items(count))
        };
        let full = egui::vec2(ui.available_width().min(380.0), 34.0);
        if ui
            .add_enabled(!busy && any, primary_button(t, &label).min_size(full))
            .clicked()
        {
            *action = Some(Action::ClearTraces);
        }
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "A File Explorer window that is open may show old entries until it is closed.",
            )
            .small()
            .color(t.weak),
        );
    }
    ui.add_space(8.0);
    ui.separator();
}

/// One trace: its title and what it holds, and under it what it is.
fn row(ui: &mut egui::Ui, t: &Tint, f: &TraceFinding) {
    ui.add_space(6.0);
    let active = f.actionable();
    ui.horizontal(|ui| {
        let color = if active { t.text } else { t.weak };
        ui.label(RichText::new(f.trace.title()).color(color));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let (cell, _) = ui.allocate_exact_size(egui::vec2(220.0, 20.0), egui::Sense::hover());
            let font = egui::TextStyle::Body.resolve(ui.style());
            let text = if active {
                amount(f)
            } else {
                "nothing found".to_string()
            };
            let color = if active { t.text } else { t.weak };
            cell_text(ui.painter(), cell, &text, font, color, egui::Align::Max);
        });
    });
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        let line = |ui: &mut egui::Ui, text: &str, color| {
            ui.add(egui::Label::new(RichText::new(text).small().color(color)).wrap());
        };
        line(ui, f.trace.about(), t.weak);
        if !f.notes.is_empty() {
            line(ui, &f.notes.join("  \u{b7}  "), t.weak);
        }
        if let Some(stays) = clean::stays_text(&f.kept) {
            line(ui, &stays, t.weak);
        }
    });
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
