//! Command handlers: wire the engine together and print results. All
//! user-facing text lives here so the lower layers stay quiet.

use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::json;

use crate::backup;
use crate::cli::{
    BackupsArgs, Cli, Commands, LevelOpts, ListArgs, OrphansArgs, RestoreArgs, ScanArgs, SortKey,
    TraceArgs, UninstallArgs,
};
use crate::model::{Confidence, Group, Leftover, Program, ScanReport, ScanTarget};
use crate::safety::{DeletionOutcome, ItemStatus, SafetyContext};
use crate::{hunter, orphans, registry, restore, safety, scanner, term, uninstall, util};

struct Global {
    dry_run: bool,
    yes: bool,
    json: bool,
    no_backup: bool,
}

impl Global {
    fn safety(&self) -> SafetyContext {
        SafetyContext {
            dry_run: self.dry_run,
            make_backups: !self.no_backup,
        }
    }

    /// Ask, unless `-y` was given. JSON mode never prompts.
    fn confirm(&self, question: &str, default_yes: bool) -> bool {
        if self.yes {
            return true;
        }
        if self.json {
            return false;
        }
        term::confirm(question, default_yes)
    }
}

pub fn dispatch(cli: Cli) -> Result<()> {
    let g = Global {
        dry_run: cli.dry_run,
        yes: cli.yes,
        json: cli.json,
        no_backup: cli.no_backup,
    };
    match &cli.command {
        Commands::List(args) => cmd_list(args, &g),
        Commands::Uninstall(args) => cmd_uninstall(args, &g),
        Commands::Scan(args) => cmd_scan(args, &g),
        Commands::Orphans(args) => cmd_orphans(args, &g),
        Commands::Trace(args) => cmd_trace(args, &g),
        Commands::Backups(args) => cmd_backups(args, &g),
        Commands::Restore(args) => cmd_restore(args, &g),
    }
}

// list
// ----

fn cmd_list(args: &ListArgs, g: &Global) -> Result<()> {
    let mut programs = registry::enumerate_installed_programs(args.system);
    if let Some(filter) = &args.filter {
        let needle = filter.to_lowercase();
        programs.retain(|p| {
            p.display_name.to_lowercase().contains(&needle)
                || p.publisher
                    .as_deref()
                    .map(|s| s.to_lowercase().contains(&needle))
                    .unwrap_or(false)
        });
    }
    sort_programs(&mut programs, args.sort);

    if g.json {
        println!("{}", serde_json::to_string_pretty(&programs)?);
        return Ok(());
    }
    if programs.is_empty() {
        term::info("Nothing matched.");
        return Ok(());
    }

    let show_date = matches!(args.sort, SortKey::Date);
    print_program_table(&programs, show_date);
    println!();
    let n = programs.len();
    let word = if n == 1 { "program" } else { "programs" };
    println!("{}", term::dim(&format!("{n} {word}")));
    Ok(())
}

fn sort_programs(programs: &mut [Program], key: SortKey) {
    match key {
        SortKey::Name => programs.sort_by_key(|a| a.display_name.to_lowercase()),
        SortKey::Size => programs.sort_by_key(|a| std::cmp::Reverse(a.size_bytes().unwrap_or(0))),
        SortKey::Date => programs.sort_by(|a, b| {
            b.install_date
                .as_deref()
                .unwrap_or("")
                .cmp(a.install_date.as_deref().unwrap_or(""))
        }),
        // Entries without a publisher sort last, not first.
        SortKey::Publisher => programs.sort_by_key(|p| {
            let name = p.publisher.as_deref().unwrap_or("").to_lowercase();
            (name.is_empty(), name)
        }),
    }
}

fn print_program_table(programs: &[Program], show_date: bool) {
    let name_w = column_width(programs.iter().map(|p| p.display_name.as_str()), 48);
    let ver_w = column_width(
        programs
            .iter()
            .map(|p| p.display_version.as_deref().unwrap_or("")),
        16,
    );
    let pub_w = column_width(
        programs
            .iter()
            .map(|p| p.publisher.as_deref().unwrap_or("")),
        28,
    );

    for p in programs {
        let size = p.size_bytes().map(util::human_size).unwrap_or_default();
        let mut line = format!(
            "{}  {}  {}  {:>9}",
            fit(&p.display_name, name_w),
            term::dim(&fit(p.display_version.as_deref().unwrap_or(""), ver_w)),
            fit(p.publisher.as_deref().unwrap_or(""), pub_w),
            size,
        );
        if show_date {
            line.push_str(&format!("  {}", p.install_date.as_deref().unwrap_or("")));
        }
        println!("{}", line.trim_end());
    }
}

fn column_width<'a>(values: impl Iterator<Item = &'a str>, cap: usize) -> usize {
    values
        .map(|v| v.chars().count())
        .max()
        .unwrap_or(0)
        .min(cap)
}

/// Pad or truncate to exactly `width` characters.
fn fit(s: &str, width: usize) -> String {
    let count = s.chars().count();
    if count <= width {
        format!("{s}{}", " ".repeat(width - count))
    } else if width <= 1 {
        s.chars().take(width).collect()
    } else {
        let mut out: String = s.chars().take(width - 1).collect();
        out.push('~');
        out
    }
}

// scan
// ----

fn cmd_scan(args: &ScanArgs, g: &Global) -> Result<()> {
    let programs = registry::enumerate_installed_programs(true);
    let (target, installed, label) = match resolve_target(&programs, &args.target) {
        Ok(program) => (
            scanner::build_target(program),
            true,
            program.display_name.clone(),
        ),
        Err(Resolve::Ambiguous(msg)) => bail!("{msg}"),
        Err(Resolve::NotFound) => {
            if !g.json {
                println!(
                    "{}",
                    term::dim(&format!(
                        "\"{}\" is not installed, scanning by name",
                        args.target
                    ))
                );
            }
            (
                scanner::name_only_target(&args.target, args.publisher.as_deref()),
                false,
                args.target.clone(),
            )
        }
    };

    let report = scanner::scan(&target, installed);

    if args.remove && installed && !g.dry_run {
        if g.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "report": report, "removal": null }))?
            );
        } else {
            render_report(&report);
        }
        bail!("{label} is still installed. Uninstall it first: oxidize uninstall \"{label}\"");
    }

    if g.json && !args.remove {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if !g.json {
        render_report(&report);
    }

    if args.remove {
        let removal = remove_from_report(&report, &label, &args.levels, g)?;
        if g.json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({ "report": report, "removal": removal_json(&removal) })
                )?
            );
        }
    } else if !report.is_empty() && !report.installed {
        let high = report
            .all()
            .filter(|l| l.confidence == Confidence::High)
            .count();
        print_remove_hint(high, &format!("oxidize scan \"{}\" --remove", args.target));
    }
    Ok(())
}

fn print_remove_hint(high: usize, command: &str) {
    println!();
    if high > 0 {
        println!(
            "{}",
            term::dim(&format!("Remove the high-confidence items: {command}"))
        );
    } else {
        println!(
            "{}",
            term::dim(&format!(
                "Nothing is high confidence. Review the list; {command} --medium removes the medium items too."
            ))
        );
    }
}

// uninstall
// ---------

fn cmd_uninstall(args: &UninstallArgs, g: &Global) -> Result<()> {
    let programs = registry::enumerate_installed_programs(true);
    if let [target] = args.targets.as_slice() {
        let program = resolve_program(&programs, target)?.clone();
        return uninstall_program(&program, args.silent, args.keep, &args.levels, g);
    }
    let batch = plan_batch(&programs, &args.targets, args.silent)?;
    uninstall_batch(&batch, args.keep, &args.levels, g)
}

/// A program of a batch with the command that uninstalls it.
struct Planned {
    program: Program,
    plan: uninstall::UninstallPlan,
}

/// Resolve every name and plan every uninstaller before anything runs. Any
/// name that matches no program or several, and any program without an
/// uninstall command, stops the whole batch. The order is the order of the
/// names; a program named twice runs once.
fn plan_batch(programs: &[Program], targets: &[String], silent: bool) -> Result<Vec<Planned>> {
    let mut planned: Vec<Planned> = Vec::new();
    let mut problems = Vec::new();
    for target in targets {
        let program = match resolve_target(programs, target) {
            Ok(p) => p,
            Err(Resolve::NotFound) => {
                problems.push(format!("no installed program matches \"{target}\""));
                continue;
            }
            Err(Resolve::Ambiguous(msg)) => {
                problems.push(msg);
                continue;
            }
        };
        if planned.iter().any(|b| same_program(&b.program, program)) {
            continue;
        }
        match uninstall::plan(program, silent) {
            Ok(plan) => planned.push(Planned {
                program: program.clone(),
                plan,
            }),
            Err(e) => problems.push(format!("{}: {e:#}", program.display_name)),
        }
    }
    if !problems.is_empty() {
        bail!(
            "nothing was uninstalled. Fix these first:\n{}",
            problems.join("\n")
        );
    }
    Ok(planned)
}

/// The same Uninstall entry: one id can exist in more than one hive or view.
fn same_program(a: &Program, b: &Program) -> bool {
    a.id() == b.id() && a.source == b.source
}

/// Show the whole plan, ask once, then uninstall the programs one after
/// another, each with its own leftover scan, removal and backup.
fn uninstall_batch(batch: &[Planned], keep: bool, levels: &LevelOpts, g: &Global) -> Result<()> {
    // Capture every footprint before the first uninstaller runs: one of them
    // may take a later program along.
    let targets: Vec<ScanTarget> = batch
        .iter()
        .map(|b| scanner::build_target(&b.program))
        .collect();
    let n = batch.len();

    if !g.json {
        let head = if n == 1 {
            "1 program".to_string()
        } else {
            format!("{n} programs, one after another")
        };
        println!("{}", term::bold(&head));
        for (i, b) in batch.iter().enumerate() {
            println!("  {}. {}", i + 1, program_head(&b.program));
            println!("     {}", term::dim(&b.plan.display()));
        }
    }

    let question = if n == 1 {
        "Run the uninstaller?".to_string()
    } else {
        format!("Run {n} uninstallers?")
    };
    if !g.dry_run && !g.confirm(&question, true) {
        if g.json {
            let programs: Vec<_> = batch
                .iter()
                .map(|b| json!({ "program": b.program, "command": b.plan.display(), "cancelled": true }))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "programs": programs,
                    "uninstalled": 0,
                    "failed": 0,
                    "cancelled": true,
                }))?
            );
        } else {
            term::info("Cancelled.");
        }
        return Ok(());
    }

    let mut runs = Vec::with_capacity(n);
    for (i, (b, target)) in batch.iter().zip(&targets).enumerate() {
        if !g.json {
            println!();
            println!(
                "{}",
                term::bold(&format!("[{}/{n}] {}", i + 1, b.program.display_name))
            );
        }
        // One program failing does not stop the others.
        let run = run_uninstall(&b.program, target, &b.plan, keep, levels, g).unwrap_or_else(|e| {
            let error = format!("{e:#}");
            if !g.json {
                term::error(&error);
            }
            ProgramRun::stopped(&b.program, &b.plan, error)
        });
        runs.push(run);
    }

    if g.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&batch_json(&runs, g.dry_run))?
        );
    } else {
        print_batch_summary(&runs, g.dry_run);
    }
    let failed = runs.iter().filter(|r| r.failed(g.dry_run)).count();
    if failed > 0 {
        bail!("{failed} of {n} programs did not uninstall cleanly");
    }
    Ok(())
}

/// A batch as JSON: every program's own result in the order they ran, each
/// with `failed`, then the counts.
fn batch_json(runs: &[ProgramRun], dry_run: bool) -> serde_json::Value {
    let programs: Vec<_> = runs
        .iter()
        .map(|r| {
            let mut entry = r.json.clone();
            entry["failed"] = json!(r.failed(dry_run));
            entry
        })
        .collect();
    json!({
        "programs": programs,
        "uninstalled": runs.iter().filter(|r| r.gone).count(),
        "failed": runs.iter().filter(|r| r.failed(dry_run)).count(),
        "cancelled": false,
    })
}

/// One line per program: its state, its leftovers, its backup.
fn print_batch_summary(runs: &[ProgramRun], dry_run: bool) {
    println!();
    println!("{}", term::bold("Summary"));
    let name_w = column_width(runs.iter().map(|r| r.name.as_str()), 40);
    let state_w = column_width(runs.iter().map(|r| r.state(dry_run)), 16);
    for r in runs {
        let state = fit(r.state(dry_run), state_w);
        let state = if r.failed(dry_run) {
            term::red(&state)
        } else if r.gone {
            term::green(&state)
        } else {
            term::dim(&state)
        };
        let mut line = format!(
            "  {}  {state}  {}",
            fit(&r.name, name_w),
            r.leftovers(dry_run)
        );
        if let Some(name) = r.removal.as_ref().and_then(|o| o.backup_name.as_ref()) {
            line.push_str(&term::dim(&format!("  backup \"{name}\"")));
        }
        println!("{line}");
    }
    println!();
    let n = runs.len();
    if dry_run {
        println!("{}", term::dim("dry run: nothing was changed"));
        return;
    }
    let gone = runs.iter().filter(|r| r.gone).count();
    let failed = runs.iter().filter(|r| r.failed(dry_run)).count();
    let mut parts = vec![format!("{gone} of {n} uninstalled")];
    if failed > 0 {
        parts.push(format!("{failed} failed"));
    }
    println!("{}", parts.join(", "));
    if runs
        .iter()
        .any(|r| r.removal.as_ref().is_some_and(|o| o.backup_name.is_some()))
    {
        println!("{}", term::dim("Undo one: oxidize restore <backup>"));
    }
}

/// Uninstall, then scan and offer to remove the leftovers. Shared with
/// `trace --uninstall`.
fn uninstall_program(
    program: &Program,
    silent: bool,
    keep: bool,
    levels: &LevelOpts,
    g: &Global,
) -> Result<()> {
    // Capture the footprint before the entry disappears.
    let target = scanner::build_target(program);
    let plan = uninstall::plan(program, silent)?;

    if !g.json {
        println!("{}", program_head(program));
        println!("  {}", term::dim(&plan.display()));
    }

    if !g.dry_run && !g.confirm("Run the uninstaller?", true) {
        if g.json {
            let json_out =
                json!({ "program": program, "command": plan.display(), "cancelled": true });
            println!("{}", serde_json::to_string_pretty(&json_out)?);
        } else {
            term::info("Cancelled.");
        }
        return Ok(());
    }

    let run = run_uninstall(program, &target, &plan, keep, levels, g)?;
    if g.json {
        println!("{}", serde_json::to_string_pretty(&run.json)?);
    }
    Ok(())
}

/// The program's name in bold, then its version and publisher.
fn program_head(program: &Program) -> String {
    let mut head = term::bold(&program.display_name);
    let mut extra = Vec::new();
    if let Some(v) = &program.display_version {
        extra.push(v.clone());
    }
    if let Some(p) = &program.publisher {
        extra.push(p.clone());
    }
    if !extra.is_empty() {
        head.push_str(&term::dim(&format!("  {}", extra.join(", "))));
    }
    head
}

/// What one uninstall did, for the JSON output and a batch summary.
struct ProgramRun {
    name: String,
    json: serde_json::Value,
    /// The Uninstall entry is gone afterwards.
    gone: bool,
    /// Leftovers the scan found.
    found: usize,
    removal: Option<DeletionOutcome>,
    /// Why the uninstall stopped, when it did.
    error: Option<String>,
}

impl ProgramRun {
    /// An uninstall that stopped with an error before it finished.
    fn stopped(program: &Program, plan: &uninstall::UninstallPlan, error: String) -> Self {
        ProgramRun {
            name: program.display_name.clone(),
            json: json!({ "program": program, "command": plan.display(), "error": error }),
            gone: false,
            found: 0,
            removal: None,
            error: Some(error),
        }
    }

    /// An error, an entry still registered after its uninstaller, or a
    /// leftover that could not be removed.
    fn failed(&self, dry_run: bool) -> bool {
        self.error.is_some()
            || (!dry_run && !self.gone)
            || self.removal.as_ref().is_some_and(|o| o.failed > 0)
    }

    fn state(&self, dry_run: bool) -> &'static str {
        if self.error.is_some() {
            "failed"
        } else if dry_run {
            "dry run"
        } else if self.gone {
            "uninstalled"
        } else {
            "still registered"
        }
    }

    /// What became of the leftovers, or why the program stopped.
    fn leftovers(&self, dry_run: bool) -> String {
        if let Some(e) = &self.error {
            return e.clone();
        }
        match &self.removal {
            Some(o) if dry_run => format!("{} leftovers would be removed", o.attempted),
            // Removal was offered and declined.
            Some(o) if o.attempted == 0 => format!("{} leftovers kept", self.found),
            Some(o) => {
                let emptied = o.emptied_parents.len() + o.emptied_keys.len();
                let mut parts = vec![format!("{} leftovers removed", o.deleted + emptied)];
                if o.skipped > 0 {
                    parts.push(format!("{} already gone", o.skipped));
                }
                if o.failed > 0 {
                    parts.push(format!("{} failed", o.failed));
                }
                parts.join(", ")
            }
            None if self.found == 0 => "no leftovers".to_string(),
            None if !dry_run && !self.gone => "leftovers not removed".to_string(),
            None => format!("{} leftovers kept", self.found),
        }
    }
}

/// Run a confirmed plan, wait for it, then scan and offer to remove the
/// leftovers. `target` is the footprint captured before anything ran.
fn run_uninstall(
    program: &Program,
    target: &ScanTarget,
    plan: &uninstall::UninstallPlan,
    keep: bool,
    levels: &LevelOpts,
    g: &Global,
) -> Result<ProgramRun> {
    let name = &program.display_name;
    let mut json_out = json!({ "program": program, "command": plan.display() });

    let mut gone = false;
    if g.dry_run {
        if !g.json {
            println!("{}", term::dim("dry run: the uninstaller was not started"));
        }
    } else {
        let status = uninstall::run(plan)?;
        let described = uninstall::describe_exit(status, plan.is_msi);
        if !g.json {
            println!("Uninstaller {described}.");
        }
        if uninstall::still_installed(program) && !plan.is_msi && !g.json {
            println!("{}", term::dim("waiting for the uninstaller to finish"));
        }
        gone = uninstall::wait_for_completion(program, plan, Duration::from_secs(120));
        json_out["uninstaller"] = json!(described);
        json_out["still_installed"] = json!(!gone);
        if !g.json {
            if gone {
                println!("{name} is no longer registered.");
            } else {
                term::warn(&format!(
                    "{name} is still registered. The uninstaller may have been cancelled or is still running."
                ));
            }
        }
    }

    // Still registered means the scan would list the live install.
    let installed = !gone && !g.dry_run;
    let report = scanner::scan(target, installed);
    if !g.json {
        render_report(&report);
    }
    json_out["report"] = json!(report);

    let mut removal = None;
    if !report.is_empty() && !keep {
        if installed {
            if !g.json {
                println!();
                println!(
                    "{}",
                    term::dim("Leftovers are not removed while the program is still registered.")
                );
            }
        } else {
            removal = remove_from_report(&report, name, levels, g)?;
            json_out["removal"] = removal_json(&removal);
        }
    }
    Ok(ProgramRun {
        name: name.clone(),
        json: json_out,
        gone,
        found: report.total(),
        removal,
        error: None,
    })
}

// trace
// -----

fn cmd_trace(args: &TraceArgs, g: &Global) -> Result<()> {
    let programs = registry::enumerate_installed_programs(true);
    let matches = hunter::hunt(&args.query, &programs);

    if g.json && !args.uninstall {
        let arr: Vec<_> = matches
            .iter()
            .map(|m| {
                json!({
                    "id": m.program.id(),
                    "name": m.program.display_name,
                    "publisher": m.program.publisher,
                    "version": m.program.display_version,
                    "score": m.score,
                    "reason": m.reason,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }

    if matches.is_empty() {
        bail!(
            "no installed program matches \"{}\". Try the full path to the .exe or its folder.",
            args.query
        );
    }

    let best = &matches[0];
    if !g.json {
        let mut extra = Vec::new();
        if let Some(p) = &best.program.publisher {
            extra.push(p.clone());
        }
        if let Some(v) = &best.program.display_version {
            extra.push(v.clone());
        }
        println!(
            "{} belongs to {}{}",
            args.query,
            term::bold(&best.program.display_name),
            if extra.is_empty() {
                String::new()
            } else {
                term::dim(&format!("  ({})", extra.join(", ")))
            }
        );
        println!("  {}", term::dim(&best.reason));
        if matches.len() > 1 {
            println!();
            println!("{}", term::dim("also possible"));
            for m in matches.iter().skip(1).take(4) {
                println!("  {}  {}", m.program.display_name, term::dim(&m.reason));
            }
        }
    }

    if args.uninstall {
        if matches.len() >= 2 && matches[1].score == best.score {
            bail!("several programs match equally well; uninstall by name instead");
        }
        // A shared word in a folder name is not enough to uninstall something.
        if best.score < 80 {
            bail!(
                "\"{}\" only matches {} by name; uninstall it by name if that is what you mean",
                args.query,
                best.program.display_name
            );
        }
        if !g.json {
            println!();
        }
        let program = best.program.clone();
        uninstall_program(&program, args.silent, args.keep, &args.levels, g)?;
    } else if !g.json {
        println!();
        println!(
            "{}",
            term::dim(&format!(
                "Uninstall it: oxidize uninstall \"{}\"",
                best.program.display_name
            ))
        );
    }
    Ok(())
}

// orphans
// -------

fn cmd_orphans(args: &OrphansArgs, g: &Global) -> Result<()> {
    let programs = registry::enumerate_installed_programs(true);
    let report = orphans::sweep(&programs);

    if g.json && !args.remove {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if !g.json {
        println!("{}", term::bold("Folders no installed program claims"));
        if report.folders.is_empty() {
            println!("  {}", term::dim("none"));
        }
        for f in &report.folders {
            println!(
                "  {:>9}  {}  {}",
                util::human_size(f.size_bytes),
                term::dim(f.modified.as_deref().unwrap_or("          ")),
                f.path.display()
            );
        }
        if !report.folders.is_empty() {
            let total: u64 = report.folders.iter().map(|f| f.size_bytes).sum();
            println!();
            println!(
                "{}",
                term::dim(&format!(
                    "{} folders, {}. Portable tools and caches show up here too. Check one: oxidize scan <name>",
                    report.folders.len(),
                    util::human_size(total)
                ))
            );
        }

        println!();
        println!("{}", term::bold("References to files that no longer exist"));
        if report.dangling.is_empty() {
            println!("  {}", term::dim("none"));
        } else {
            print_items(&report.dangling, false);
        }
    }

    if args.remove {
        if report.dangling.is_empty() {
            if g.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "report": report, "removal": null }))?
                );
            }
            return Ok(());
        }
        let removal = remove_items(&report.dangling, "orphans", g)?;
        if g.json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({ "report": report, "removal": removal_json(&Some(removal)) })
                )?
            );
        }
    } else if !report.dangling.is_empty() && !g.json {
        println!();
        println!("{}", term::dim("Remove them: oxidize orphans --remove"));
    }
    Ok(())
}

// backups / restore
// -----------------

fn cmd_backups(args: &BackupsArgs, g: &Global) -> Result<()> {
    let all = backup::list_backups()?;

    if args.clear {
        if all.is_empty() {
            return report_deleted(&[], g);
        }
        let total: u64 = all.iter().map(|b| b.size_bytes).sum();
        if !g.dry_run
            && !g.confirm(
                &format!(
                    "Delete all {} backups ({})?",
                    all.len(),
                    util::human_size(total)
                ),
                false,
            )
        {
            return report_cancelled(g);
        }
        let mut done = Vec::new();
        for b in &all {
            if !g.dry_run {
                backup::delete_backup(b)?;
            }
            done.push(b.name.clone());
        }
        return report_deleted(&done, g);
    }

    if let Some(name) = &args.delete {
        let b = backup::find_backup(name)?;
        if !g.dry_run
            && !g.confirm(
                &format!(
                    "Delete backup {} ({})?",
                    b.name,
                    util::human_size(b.size_bytes)
                ),
                false,
            )
        {
            return report_cancelled(g);
        }
        if !g.dry_run {
            backup::delete_backup(&b)?;
        }
        return report_deleted(std::slice::from_ref(&b.name), g);
    }

    if g.json {
        println!("{}", serde_json::to_string_pretty(&all)?);
        return Ok(());
    }
    if all.is_empty() {
        term::info("No backups.");
        return Ok(());
    }
    let name_w = column_width(all.iter().map(|b| b.name.as_str()), 60);
    for b in &all {
        println!(
            "{}  {:>3} items  {:>9}",
            fit(&b.name, name_w),
            b.items,
            util::human_size(b.size_bytes)
        );
    }
    println!();
    println!(
        "{}",
        term::dim(&format!(
            "{} in {}. Undo one: oxidize restore <name>",
            all.len(),
            backup::backups_base()?.display()
        ))
    );
    Ok(())
}

/// Say which backups went, as JSON or as one line each.
fn report_deleted(names: &[String], g: &Global) -> Result<()> {
    report_deleted_or_cancelled(names, false, g)
}

/// The same, for a run that asked and got no answer: a script has to be able
/// to tell "nothing to delete" from "nobody confirmed".
fn report_cancelled(g: &Global) -> Result<()> {
    if !g.json {
        term::info("Cancelled.");
    }
    report_deleted_or_cancelled(&[], true, g)
}

fn report_deleted_or_cancelled(names: &[String], cancelled: bool, g: &Global) -> Result<()> {
    if g.json {
        let key = if g.dry_run { "would_delete" } else { "deleted" };
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ key: names, "cancelled": cancelled }))?
        );
        return Ok(());
    }
    if cancelled {
        return Ok(());
    }
    if names.is_empty() {
        term::info("No backups.");
        return Ok(());
    }
    for name in names {
        if g.dry_run {
            println!("would delete {name}");
        } else {
            println!("deleted {name}");
        }
    }
    Ok(())
}

fn cmd_restore(args: &RestoreArgs, g: &Global) -> Result<()> {
    let info = backup::find_backup(&args.name)?;
    let items = restore::restore(&info, g.dry_run)?;

    if g.json {
        let arr: Vec<_> = items
            .iter()
            .map(|i| {
                json!({
                    "path": i.path,
                    "ok": i.result.is_ok(),
                    "error": i.result.as_ref().err(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "backup": info, "items": arr }))?
        );
        return Ok(());
    }

    println!("{}", term::bold(&format!("Restoring {}", info.name)));
    let mut ok = 0;
    let mut failed = 0;
    for i in &items {
        match &i.result {
            Ok(()) if g.dry_run => println!("  {}  {}", term::dim("would restore"), i.path),
            Ok(()) => {
                ok += 1;
                println!("  {}  {}", term::green("restored"), i.path);
            }
            Err(e) => {
                failed += 1;
                println!("  {}  {}  {}", term::red("failed  "), i.path, term::dim(e));
            }
        }
    }
    println!();
    if g.dry_run {
        println!(
            "{}",
            term::dim(&format!("{} items would be restored", items.len()))
        );
        return Ok(());
    } else {
        let mut parts = vec![format!("{ok} restored")];
        if failed > 0 {
            parts.push(format!("{failed} failed"));
        }
        println!("{}", parts.join(", "));
        if failed == 0 {
            println!(
                "{}",
                term::dim(&format!(
                    "The backup folder is kept. Remove it: oxidize backups --delete \"{}\"",
                    info.name
                ))
            );
        }
        if failed > 0 {
            bail!("{failed} of {} items could not be restored", items.len());
        }
    }
    Ok(())
}

// rendering
// ---------

fn conf_tag(conf: Confidence) -> String {
    match conf {
        Confidence::High => term::green("high"),
        Confidence::Medium => term::yellow("med "),
        Confidence::Low => term::dim("low "),
    }
}

/// Print leftovers, one per line: confidence, path, size, reason.
fn print_items(items: &[Leftover], show_conf: bool) {
    let path_w = items
        .iter()
        .map(|l| l.path.chars().count())
        .max()
        .unwrap_or(0)
        .min(72);
    for l in items {
        let mut line = String::from("  ");
        if show_conf {
            line.push_str(&conf_tag(l.confidence));
            line.push_str("  ");
        }
        let size = match l.size_bytes {
            Some(0) if l.is_empty_dir => "empty".to_string(),
            Some(b) if l.kind.group() == Group::Files => util::human_size(b),
            _ => String::new(),
        };
        let long = l.path.chars().count() > path_w;
        line.push_str(&l.path);
        if long {
            println!("{line}");
            let tail = if show_conf { "        " } else { "    " };
            print_trailer(tail, &size, &l.reason);
        } else {
            line.push_str(&" ".repeat(path_w - l.path.chars().count()));
            print_trailer(&line, &size, &l.reason);
        }
    }
}

fn print_trailer(prefix: &str, size: &str, reason: &str) {
    let mut s = prefix.to_string();
    if !size.is_empty() {
        s.push_str(&format!("  {size:>9}"));
    } else {
        s.push_str(&" ".repeat(11));
    }
    s.push_str("  ");
    s.push_str(&term::dim(reason));
    println!("{}", s.trim_end());
}

fn render_report(report: &ScanReport) {
    println!();
    if report.installed {
        println!(
            "{}  {}",
            term::bold(&format!("Footprint of {}", report.program_name)),
            term::dim("still installed, so these are not leftovers")
        );
    } else {
        println!(
            "{}",
            term::bold(&format!("Leftovers of {}", report.program_name))
        );
    }

    if report.is_empty() {
        println!("  {}", term::dim("nothing found"));
        return;
    }

    for group in Group::ALL {
        let items: Vec<Leftover> = report.group(group).cloned().collect();
        if items.is_empty() {
            continue;
        }
        println!();
        println!("{}", term::dim(group.title()));
        print_items(&items, true);
    }

    println!();
    let reclaim = report.reclaimable_bytes();
    let mut summary = format!("{} items", report.total());
    if reclaim > 0 {
        summary.push_str(&format!(", {} in files", util::human_size(reclaim)));
    }
    println!("{}", term::dim(&summary));
}

// removal
// -------

fn remove_from_report(
    report: &ScanReport,
    label: &str,
    levels: &LevelOpts,
    g: &Global,
) -> Result<Option<DeletionOutcome>> {
    let threshold = levels.threshold();
    let selected: Vec<Leftover> = report
        .all()
        .filter(|l| l.confidence <= threshold)
        .cloned()
        .collect();
    if selected.is_empty() {
        if !g.json {
            println!();
            println!("Nothing at {} to remove.", levels.describe());
        }
        return Ok(None);
    }
    remove_items(&selected, label, g).map(Some)
}

fn remove_items(selected: &[Leftover], label: &str, g: &Global) -> Result<DeletionOutcome> {
    let ctx = g.safety();

    if !g.json && safety::needs_elevation(selected) && !safety::is_elevated() {
        term::warn(
            "some items need administrator rights; run from an elevated terminal or add --elevate",
        );
    }

    if ctx.dry_run {
        if !g.json {
            println!();
            println!(
                "{}",
                term::dim(&format!(
                    "dry run: {} items would be removed",
                    selected.len()
                ))
            );
        }
        return safety::remove_leftovers(selected, label, &ctx);
    }

    if !g.json {
        println!();
    }
    let question = if ctx.make_backups {
        format!(
            "Remove {} items? Backups are kept for restore.",
            selected.len()
        )
    } else {
        format!("Remove {} items permanently?", selected.len())
    };
    // Enter means yes while a backup is kept, and no when it is not.
    if !g.confirm(&question, ctx.make_backups) {
        if !g.json {
            term::info("Skipped.");
        }
        return Ok(DeletionOutcome::default());
    }

    let outcome = safety::remove_leftovers(selected, label, &ctx)?;
    if !g.json {
        print_outcome(&outcome);
    }
    Ok(outcome)
}

fn print_outcome(outcome: &DeletionOutcome) {
    for item in &outcome.items {
        match &item.status {
            ItemStatus::Removed => println!("  {}  {}", term::green("removed"), item.path),
            ItemStatus::AlreadyGone => println!("  {}  {}", term::dim("gone   "), item.path),
            ItemStatus::Failed(e) => println!(
                "  {}  {}  {}",
                term::red("failed "),
                item.path,
                term::dim(e)
            ),
        }
    }
    for p in &outcome.emptied_parents {
        println!(
            "  {}  {}  {}",
            term::green("removed"),
            p.display(),
            term::dim("emptied folder")
        );
    }
    for k in &outcome.emptied_keys {
        println!(
            "  {}  {}  {}",
            term::green("removed"),
            k,
            term::dim("emptied key")
        );
    }
    println!();
    let emptied = outcome.emptied_parents.len() + outcome.emptied_keys.len();
    let mut parts = vec![format!("{} removed", outcome.deleted + emptied)];
    if outcome.skipped > 0 {
        parts.push(format!("{} already gone", outcome.skipped));
    }
    if outcome.failed > 0 {
        parts.push(format!("{} failed", outcome.failed));
    }
    println!("{}", parts.join(", "));
    if outcome.failed > 0 && !safety::is_elevated() {
        println!(
            "{}",
            term::dim("Failures are usually missing administrator rights. Re-run with --elevate.")
        );
    }
    if let Some(name) = &outcome.backup_name {
        println!(
            "{}",
            term::dim(&format!("Undo: oxidize restore \"{name}\""))
        );
    }
}

fn removal_json(outcome: &Option<DeletionOutcome>) -> serde_json::Value {
    match outcome {
        None => json!(null),
        Some(o) => json!({
            "attempted": o.attempted,
            "removed": o.deleted,
            "already_gone": o.skipped,
            "failed": o.failed,
            "backup": o.backup_name,
            "items": o.items.iter().map(|i| json!({
                "path": i.path,
                "status": match &i.status {
                    ItemStatus::Removed => "removed",
                    ItemStatus::AlreadyGone => "gone",
                    ItemStatus::Failed(_) => "failed",
                },
                "error": match &i.status { ItemStatus::Failed(e) => Some(e.as_str()), _ => None },
            })).collect::<Vec<_>>(),
        }),
    }
}

// program resolution
// ------------------

enum Resolve {
    NotFound,
    Ambiguous(String),
}

/// Exact id, then exact name, then a unique substring of the name.
fn resolve_target<'a>(
    programs: &'a [Program],
    target: &str,
) -> std::result::Result<&'a Program, Resolve> {
    if let Some(p) = programs
        .iter()
        .find(|p| p.id().eq_ignore_ascii_case(target))
    {
        return Ok(p);
    }
    let exact: Vec<&Program> = programs
        .iter()
        .filter(|p| p.display_name.eq_ignore_ascii_case(target))
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0]);
    }

    let needle = target.to_lowercase();
    let subs: Vec<&Program> = programs
        .iter()
        .filter(|p| p.display_name.to_lowercase().contains(&needle))
        .collect();
    match subs.len() {
        0 => Err(Resolve::NotFound),
        1 => Ok(subs[0]),
        n => {
            let listing = subs
                .iter()
                .take(12)
                .map(|p| format!("  {}  {}", p.display_name, term::dim(p.id())))
                .collect::<Vec<_>>()
                .join("\n");
            let more = if n > 12 {
                format!("\n  and {} more", n - 12)
            } else {
                String::new()
            };
            Err(Resolve::Ambiguous(format!(
                "\"{target}\" matches {n} programs:\n{listing}{more}\nUse a longer name or the id on the right."
            )))
        }
    }
}

fn resolve_program<'a>(programs: &'a [Program], target: &str) -> Result<&'a Program> {
    match resolve_target(programs, target) {
        Ok(p) => Ok(p),
        Err(Resolve::NotFound) => bail!("no installed program matches \"{target}\""),
        Err(Resolve::Ambiguous(msg)) => bail!("{msg}"),
    }
}
