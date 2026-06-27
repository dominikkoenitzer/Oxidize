//! Command handlers: they wire the registry/scanner/uninstall/safety modules
//! together and render results. All user-facing text and table formatting lives
//! here so the lower layers stay UI-free and testable.

use anyhow::{bail, Result};

use crate::cli::{Cli, Commands, HunterArgs, LeftoverOpts, ListArgs, ScanArgs, SortKey, UninstallArgs};
use crate::model::{Confidence, Hive, Leftover, Program, ScanReport};
use crate::safety::SafetyContext;
use crate::{hunter, registry, safety, scanner, term, uninstall, util};

/// The global flags, gathered once and passed to each handler.
struct Global {
    dry_run: bool,
    yes: bool,
    json: bool,
    no_backup: bool,
    #[allow(dead_code)]
    verbose: u8,
}

impl Global {
    fn safety(&self) -> SafetyContext {
        SafetyContext {
            dry_run: self.dry_run,
            make_backups: !self.no_backup,
        }
    }
}

/// Entry point called from `main`.
pub fn dispatch(cli: Cli) -> Result<()> {
    let g = Global {
        dry_run: cli.dry_run,
        yes: cli.yes,
        json: cli.json,
        no_backup: cli.no_backup,
        verbose: cli.verbose,
    };
    match &cli.command {
        Commands::List(args) => cmd_list(args, &g),
        Commands::Uninstall(args) => cmd_uninstall(args, &g),
        Commands::Scan(args) => cmd_scan(args, &g),
        Commands::Hunter(args) => cmd_hunter(args, &g),
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn cmd_list(args: &ListArgs, g: &Global) -> Result<()> {
    let mut programs = registry::enumerate_installed_programs(args.all);

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
        term::info("No installed programs matched.");
        return Ok(());
    }

    let refs: Vec<&Program> = programs.iter().collect();
    print_program_table(&refs);
    println!();
    term::info(&format!(
        "{} program(s){}.",
        programs.len(),
        if args.all { " (including system components)" } else { "" }
    ));
    Ok(())
}

fn sort_programs(programs: &mut [Program], key: SortKey) {
    match key {
        SortKey::Name => programs.sort_by_key(|a| a.display_name.to_lowercase()),
        SortKey::Size => programs.sort_by(|a, b| {
            b.size_bytes().unwrap_or(0).cmp(&a.size_bytes().unwrap_or(0))
        }),
        SortKey::Date => programs.sort_by(|a, b| {
            b.install_date
                .as_deref()
                .unwrap_or("")
                .cmp(a.install_date.as_deref().unwrap_or(""))
        }),
        SortKey::Publisher => programs.sort_by(|a, b| {
            a.publisher
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .cmp(&b.publisher.as_deref().unwrap_or("").to_lowercase())
        }),
    }
}

fn print_program_table(programs: &[&Program]) {
    let header = format!(
        "{:<38}  {:<12}  {:<22}  {:>9}  {:<10}  {:<11}",
        "NAME", "VERSION", "PUBLISHER", "SIZE", "INSTALLED", "SOURCE"
    );
    println!("{}", term::bold(&header));
    for p in programs {
        let size = p
            .size_bytes()
            .map(util::human_size)
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<38}  {:<12}  {:<22}  {:>9}  {:<10}  {:<11}",
            fit(&p.display_name, 38),
            fit(p.display_version.as_deref().unwrap_or("-"), 12),
            fit(p.publisher.as_deref().unwrap_or("-"), 22),
            fit(&size, 9),
            fit(p.install_date.as_deref().unwrap_or("-"), 10),
            p.source.label(),
        );
    }
}

/// Truncate a string to at most `width` characters, adding an ellipsis.
fn fit(s: &str, width: usize) -> String {
    let count = s.chars().count();
    if count <= width {
        s.to_string()
    } else {
        let take = width.saturating_sub(1);
        let mut out: String = s.chars().take(take).collect();
        out.push('\u{2026}');
        out
    }
}

// ---------------------------------------------------------------------------
// uninstall / scan (shared core)
// ---------------------------------------------------------------------------

fn cmd_uninstall(args: &UninstallArgs, g: &Global) -> Result<()> {
    let programs = registry::enumerate_installed_programs(true);
    let program = resolve_target(&programs, &args.target)?.clone();
    uninstall_program(&program, args.silent, args.scan, args.remove, &args.leftovers, g)
}

fn cmd_scan(args: &ScanArgs, g: &Global) -> Result<()> {
    let programs = registry::enumerate_installed_programs(true);
    let program = resolve_target(&programs, &args.target)?.clone();
    let target = scanner::build_target(&program);

    if !g.dry_run && args.remove && program.source.hive == Hive::LocalMachine {
        safety::warn_if_not_elevated();
    }

    let report = scanner::scan(&target);
    render_report(&report, g)?;

    if args.remove {
        remove_from_report(&report, &program.display_name, &args.leftovers, g)?;
    } else if report.total() > 0 && !g.json {
        term::info("Re-run with --remove to delete the leftovers above.");
    }
    Ok(())
}

/// Run a program's uninstaller, then optionally scan/remove leftovers. Shared by
/// `uninstall` and `hunter --uninstall`.
fn uninstall_program(
    program: &Program,
    silent: bool,
    do_scan: bool,
    do_remove: bool,
    opts: &LeftoverOpts,
    g: &Global,
) -> Result<()> {
    // Snapshot the footprint BEFORE running the uninstaller, so we can still
    // recognise leftovers after the program's own entry is gone.
    let target = scanner::build_target(program);

    let plan = uninstall::plan(program, silent)?;

    println!("{}", term::bold(&format!("Uninstall: {}", program.display_name)));
    if let Some(v) = &program.display_version {
        println!("  version:   {v}");
    }
    if let Some(p) = &program.publisher {
        println!("  publisher: {p}");
    }
    println!("  source:    {} ({})", program.source.label(), plan.source);
    println!("  command:   {}", plan.display());

    let safety_ctx = g.safety();
    if safety_ctx.dry_run {
        term::info("[dry-run] the uninstaller would run now; nothing was changed.");
    } else {
        if program.source.hive == Hive::LocalMachine {
            safety::warn_if_not_elevated();
        }
        if !g.yes
            && !term::confirm(
                &format!("Run the uninstaller for \"{}\"?", program.display_name),
                true,
            )
        {
            term::info("Cancelled.");
            return Ok(());
        }
        match uninstall::run(&plan) {
            Ok(status) => {
                term::info(&format!(
                    "Uninstaller {}.",
                    uninstall::describe_exit(status, plan.is_msi)
                ));
                if uninstall::still_installed(program) {
                    term::warn(
                        "The program is still registered — the uninstaller may have been \
                         cancelled, or may still be finishing in the background.",
                    );
                } else {
                    term::success("Removed from the installed-programs list.");
                }
            }
            Err(e) => term::error(&format!("{e:#}")),
        }
    }

    if do_scan || do_remove {
        if safety_ctx.dry_run {
            term::info(
                "[dry-run] the scan below reflects the CURRENT state (the program was not \
                 actually uninstalled).",
            );
        }
        let report = scanner::scan(&target);
        render_report(&report, g)?;
        if do_remove {
            remove_from_report(&report, &program.display_name, opts, g)?;
        } else if report.total() > 0 && !g.json {
            term::info("Re-run with --remove to delete the leftovers above.");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// hunter
// ---------------------------------------------------------------------------

fn cmd_hunter(args: &HunterArgs, g: &Global) -> Result<()> {
    let programs = registry::enumerate_installed_programs(true);
    let matches = hunter::hunt(&args.query, &programs);

    if g.json {
        let arr: Vec<_> = matches
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.program.id(),
                    "display_name": m.program.display_name,
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
        term::warn(&format!(
            "No installed program could be traced from \"{}\".",
            args.query
        ));
        term::info("Try the full path to the program's .exe, or its install folder.");
        return Ok(());
    }

    println!("{}", term::bold(&format!("Traced \"{}\" to:", args.query)));
    for (i, m) in matches.iter().take(5).enumerate() {
        println!(
            "  {}. {} {} {}",
            i + 1,
            term::bold(&m.program.display_name),
            term::dim(&format!("[{}]", m.program.id())),
            term::dim(&format!("(score {})", m.score)),
        );
        println!("       {}", term::dim(&m.reason));
    }

    if args.uninstall {
        let best = &matches[0];
        if matches.len() >= 2 && matches[1].score == best.score {
            bail!(
                "Several programs match equally well; uninstall by name with \
                 `oxidize uninstall <name>` instead."
            );
        }
        println!();
        let program = best.program.clone();
        uninstall_program(&program, args.silent, args.scan, args.remove, &args.leftovers, g)?;
    } else {
        println!();
        term::info(
            "Re-run with --uninstall to remove the top match (add --scan/--remove to clean \
             leftovers).",
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// shared rendering / removal
// ---------------------------------------------------------------------------

fn render_report(report: &ScanReport, g: &Global) -> Result<()> {
    if g.json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!();
    println!(
        "{}",
        term::bold(&format!("Leftover scan for \"{}\"", report.program_name))
    );
    print_group("Registry leftovers", &report.registry);
    print_group("Files & folders", &report.filesystem);

    println!();
    if report.is_empty() {
        term::success("No leftovers found — looks like a clean uninstall.");
    } else {
        let reclaim = report.reclaimable_bytes();
        let reclaim_note = if reclaim > 0 {
            format!(", ~{} reclaimable", util::human_size(reclaim))
        } else {
            String::new()
        };
        term::info(&format!(
            "{} registry item(s), {} filesystem item(s){reclaim_note}.",
            report.registry.len(),
            report.filesystem.len()
        ));
    }
    Ok(())
}

fn print_group(title: &str, items: &[Leftover]) {
    println!();
    println!("{} ({})", term::bold(title), items.len());
    if items.is_empty() {
        println!("  {}", term::dim("(none)"));
        return;
    }
    for it in items {
        let size = it
            .size_bytes
            .map(|b| format!(" [{}]", util::human_size(b)))
            .unwrap_or_default();
        let empty = if it.is_empty_dir { " (empty)" } else { "" };
        println!("  {} {}{size}{empty}", conf_tag(it.confidence), it.path);
        println!("       {}", term::dim(&it.reason));
    }
}

fn conf_tag(conf: Confidence) -> String {
    match conf {
        Confidence::High => term::bold_green("[HIGH]"),
        Confidence::Medium => term::yellow("[MED ]"),
        Confidence::Low => term::dim("[LOW ]"),
    }
}

fn remove_from_report(
    report: &ScanReport,
    label: &str,
    opts: &LeftoverOpts,
    g: &Global,
) -> Result<()> {
    let threshold = opts.threshold();
    let selected: Vec<Leftover> = report
        .all()
        .filter(|l| l.confidence <= threshold)
        .cloned()
        .collect();

    let scope = if opts.include_all {
        "high, medium and low"
    } else if opts.include_medium {
        "high and medium"
    } else {
        "high"
    };

    if selected.is_empty() {
        term::info(&format!(
            "No {scope}-confidence leftovers to remove."
        ));
        return Ok(());
    }

    println!();
    term::info(&format!(
        "Selected {} leftover(s) ({scope}-confidence) for removal.",
        selected.len()
    ));

    let safety_ctx = g.safety();
    if !safety_ctx.dry_run
        && !g.yes
        && !term::confirm("Remove the selected leftovers?", false)
    {
        term::info("Skipped removal.");
        return Ok(());
    }

    let outcome = safety::remove_leftovers(&selected, label, &safety_ctx)?;
    print_outcome(&outcome, &safety_ctx);
    Ok(())
}

fn print_outcome(outcome: &safety::DeletionOutcome, safety_ctx: &SafetyContext) {
    println!();
    if safety_ctx.dry_run {
        term::info(&format!(
            "[dry-run] {} item(s) would be removed. Run again without --dry-run to apply.",
            outcome.attempted
        ));
        return;
    }

    let mut parts = vec![format!("{} removed", outcome.deleted)];
    if outcome.skipped > 0 {
        parts.push(format!("{} already gone", outcome.skipped));
    }
    if outcome.failed > 0 {
        parts.push(format!("{} failed", outcome.failed));
    }
    term::info(&parts.join(", "));

    if let Some(dir) = &outcome.backup_dir {
        term::info(&format!("Backups & quarantined files: {}", dir.display()));
    }
    if outcome.failed > 0 {
        term::warn("Some removals failed — likely missing Administrator rights. Re-run elevated.");
    }
}

// ---------------------------------------------------------------------------
// program resolution
// ---------------------------------------------------------------------------

/// Resolve a user-supplied target to exactly one program: by exact id, then
/// exact name, then unique case-insensitive substring of the display name.
fn resolve_target<'a>(programs: &'a [Program], target: &str) -> Result<&'a Program> {
    if let Some(p) = programs.iter().find(|p| p.id().eq_ignore_ascii_case(target)) {
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
        0 => bail!("no installed program matches \"{target}\""),
        1 => Ok(subs[0]),
        _ => {
            let listing = subs
                .iter()
                .take(12)
                .map(|p| format!("  - {} [{}]", p.display_name, p.id()))
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "\"{target}\" matches {} programs:\n{listing}\nBe more specific, or pass the exact id in brackets.",
                subs.len()
            )
        }
    }
}
