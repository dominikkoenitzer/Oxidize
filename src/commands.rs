//! Command handlers: wire the engine together and print results. All
//! user-facing text lives here so the lower layers stay quiet.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::json;

use crate::backup;
use crate::clean::traces::{self, TraceFinding};
use crate::clean::{self, Analysis, Category, Choice, Cleaned, Finding};
use crate::cli::{
    BackupsArgs, CleanArgs, Cli, Commands, LevelOpts, ListArgs, OrphansArgs, ProtectArgs,
    RestoreArgs, ScanArgs, SortKey, TraceArgs, UninstallArgs,
};
use crate::exit::{self, Failure};
use crate::model::{
    Confidence, Group, Leftover, Package, Program, ScanReport, ScanTarget, SignatureKind,
};
use crate::packages::{
    self, package_guard, PackageStore, Refusal, RemovalOutcome, WindowsPackageStore,
};
use crate::safety::{DeletionOutcome, ItemOutcome, ItemStatus, SafetyContext};
use crate::{
    complete, hunter, orphans, registry, restore, safety, scanner, system, term, uninstall, util,
};

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
        Commands::Clean(args) => cmd_clean(args, &g),
        Commands::Protect(args) => cmd_protect(args, &g),
        Commands::Mcp => {
            mcp_takes_no_run_flags(&g)?;
            crate::mcp::serve()
        }
    }
}

/// `oxidize mcp` serves until the assistant goes away, and its removals are
/// planned, shown and backed up one by one. A `--dry-run` it ignored would
/// let an assistant remove for real on a server started to try things out,
/// so the flags that steer a single run are refused instead.
fn mcp_takes_no_run_flags(g: &Global) -> Result<()> {
    let given: Vec<&str> = [
        (g.dry_run, "--dry-run"),
        (g.yes, "--yes"),
        (g.no_backup, "--no-backup"),
    ]
    .into_iter()
    .filter_map(|(on, flag)| on.then_some(flag))
    .collect();
    if given.is_empty() {
        return Ok(());
    }
    Err(Failure::usage(format!(
        "oxidize mcp does not take {}: the assistant previews with plan_removal, \
         and every plan it applies is asked for and backed up",
        given.join(" or ")
    ))
    .into())
}

// list
// ----

fn cmd_list(args: &ListArgs, g: &Global) -> Result<()> {
    let programs = if args.store {
        Vec::new()
    } else {
        registry::enumerate_installed_programs(args.system)
    };
    let rows = list_rows(programs, WindowsPackageStore.list(), args)?;

    if g.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        term::info("Nothing matched.");
        return Ok(());
    }

    let show_date = matches!(args.sort, SortKey::Date);
    print_list(&rows, show_date);
    println!();
    println!("{}", term::dim(&list_footer(&rows)));
    Ok(())
}

/// The rows `list` shows: `programs` as read with `args.system`, the Store
/// apps unless Windows could not list them, filtered and sorted.
pub(crate) fn list_rows(
    programs: Vec<Program>,
    packages: Result<Vec<Package>>,
    args: &ListArgs,
) -> Result<Vec<Listed>> {
    let mut rows: Vec<Listed> = Vec::new();
    if !args.store {
        rows.extend(programs.into_iter().map(Listed::Program));
    }
    match packages {
        Ok(packages) => rows.extend(store_rows(&packages, args.system)),
        Err(e) if args.store => return Err(e),
        // The programs are still worth listing.
        Err(e) => term::warn(&format!("Store apps left out: {e:#}")),
    }
    if let Some(filter) = &args.filter {
        let needle = filter.to_lowercase();
        rows.retain(|r| r.matches(&needle));
    }
    sort_rows(&mut rows, args.sort);
    Ok(rows)
}

/// One entry of `list`: a program from the registry or a Store app. As JSON
/// it is the program or package with a `kind` in front.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(crate) enum Listed {
    Program(Program),
    Store {
        #[serde(flatten)]
        package: Package,
        /// Why the guard keeps the app, `None` when it may go.
        protected: Option<Refusal>,
    },
}

impl Listed {
    fn name(&self) -> &str {
        match self {
            Listed::Program(p) => &p.display_name,
            Listed::Store { package, .. } => &package.display_name,
        }
    }

    fn version(&self) -> &str {
        match self {
            Listed::Program(p) => p.display_version.as_deref().unwrap_or(""),
            Listed::Store { package, .. } => &package.version,
        }
    }

    fn publisher(&self) -> &str {
        match self {
            Listed::Program(p) => p.publisher.as_deref(),
            Listed::Store { package, .. } => package.publisher.as_deref(),
        }
        .unwrap_or("")
    }

    fn size_bytes(&self) -> Option<u64> {
        match self {
            Listed::Program(p) => p.size_bytes(),
            Listed::Store { .. } => None,
        }
    }

    fn date(&self) -> &str {
        match self {
            Listed::Program(p) => p.install_date.as_deref(),
            Listed::Store { package, .. } => package.installed_date.as_deref(),
        }
        .unwrap_or("")
    }

    /// Where the entry comes from, when that is not the registry.
    fn source(&self) -> &'static str {
        match self {
            Listed::Program(_) => "",
            Listed::Store { .. } => "store",
        }
    }

    /// `needle` is lower-cased. A Store app also answers to its identity name.
    fn matches(&self, needle: &str) -> bool {
        let identity = match self {
            Listed::Program(_) => "",
            Listed::Store { package, .. } => &package.name,
        };
        [self.name(), self.publisher(), identity]
            .iter()
            .any(|s| s.to_lowercase().contains(needle))
    }
}

/// The Store apps `list` shows, each with the guard's verdict. The guard sees
/// every package, so one that a hidden Windows package needs is still kept.
/// Packages signed as part of Windows show only with `system`.
fn store_rows(packages: &[Package], system: bool) -> Vec<Listed> {
    packages
        .iter()
        .filter(|p| system || p.signature != SignatureKind::System)
        .map(|p| Listed::Store {
            package: p.clone(),
            protected: package_guard(p, packages).err(),
        })
        .collect()
}

fn sort_rows(rows: &mut [Listed], key: SortKey) {
    match key {
        SortKey::Name => rows.sort_by_key(|r| r.name().to_lowercase()),
        SortKey::Size => rows.sort_by_key(|r| std::cmp::Reverse(r.size_bytes().unwrap_or(0))),
        SortKey::Date => rows.sort_by(|a, b| b.date().cmp(a.date())),
        // Entries without a publisher sort last, not first.
        SortKey::Publisher => rows.sort_by_key(|r| {
            let name = r.publisher().to_lowercase();
            (name.is_empty(), name)
        }),
    }
}

fn print_list(rows: &[Listed], show_date: bool) {
    let name_w = column_width(rows.iter().map(Listed::name), 48);
    let ver_w = column_width(rows.iter().map(Listed::version), 16);
    let pub_w = column_width(rows.iter().map(Listed::publisher), 28);
    let source_w = column_width(rows.iter().map(Listed::source), 5);
    // Store apps have no size; a list of only them drops the empty column.
    let show_size = rows.iter().any(|r| matches!(r, Listed::Program(_)));

    for r in rows {
        let mut line = format!(
            "{}  {}  {}",
            fit(r.name(), name_w),
            term::dim(&fit(r.version(), ver_w)),
            fit(r.publisher(), pub_w),
        );
        if show_size {
            let size = r.size_bytes().map(util::human_size).unwrap_or_default();
            line.push_str(&format!("  {size:>9}"));
        }
        if source_w > 0 {
            line.push_str(&format!("  {}", fit(r.source(), source_w)));
        }
        if show_date {
            line.push_str(&format!("  {}", fit(r.date(), 10)));
        }
        if let Listed::Store {
            protected: Some(reason),
            ..
        } = r
        {
            line.push_str(&term::dim(&format!("  protected: {reason}")));
        }
        println!("{}", line.trim_end());
    }
}

/// `12 programs`, or `12 programs, 30 Store apps (18 protected)`.
fn list_footer(rows: &[Listed]) -> String {
    let apps = rows.iter().filter(|r| !r.source().is_empty()).count();
    let programs = rows.len() - apps;
    let protected = rows
        .iter()
        .filter(|r| {
            matches!(
                r,
                Listed::Store {
                    protected: Some(_),
                    ..
                }
            )
        })
        .count();
    let mut parts = Vec::new();
    if programs > 0 {
        let word = if programs == 1 { "program" } else { "programs" };
        parts.push(format!("{programs} {word}"));
    }
    if apps > 0 {
        let word = if apps == 1 { "Store app" } else { "Store apps" };
        let mut part = format!("{apps} {word}");
        if protected > 0 {
            part.push_str(&format!(" ({protected} protected)"));
        }
        parts.push(part);
    }
    parts.join(", ")
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
    // Nothing changes before the scan, so one reading serves every step.
    let snap = scanner::Snapshot::with_programs(programs.clone());
    let installed = scan_subject(
        &programs,
        || WindowsPackageStore.list().unwrap_or_default(),
        &args.target,
    )?;
    let (target, label) = match installed {
        Some(program) => (
            scanner::build_target_with(program, &snap),
            program.display_name.clone(),
        ),
        None => {
            let hint = match &args.publisher {
                Some(_) => None,
                None => scanner::publisher_hint(&args.target),
            };
            if !g.json {
                println!(
                    "{}",
                    term::dim(&format!(
                        "\"{}\" is not installed, scanning by name",
                        args.target
                    ))
                );
                if let Some((publisher, source)) = &hint {
                    let from = match source {
                        scanner::PublisherSource::Backup => "an earlier removal",
                        scanner::PublisherSource::CachedName => "the names Windows cached",
                    };
                    println!(
                        "{}",
                        term::dim(&format!("publisher {publisher}, from {from}"))
                    );
                }
            }
            let publisher = args.publisher.clone().or_else(|| hint.map(|(p, _)| p));
            (
                scanner::name_only_target(&args.target, publisher.as_deref()),
                args.target.clone(),
            )
        }
    };
    let installed = installed.is_some();

    let report = scanner::scan_with(&target, installed, &snap);

    if args.remove && installed && !g.dry_run {
        if g.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "report": report, "removal": null }))?
            );
        } else {
            render_report(&report);
        }
        let message = format!(
            "{label} is still installed. Uninstall it first: oxidize uninstall \"{label}\""
        );
        return Err(Failure::new("error", exit::ERROR, message, g.json).into());
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
        let selected = selected_leftovers(&report, &args.levels).len();
        removal_verdict(selected, removal.as_ref(), g)?;
    } else if !report.is_empty() && !report.installed {
        let high = report
            .all()
            .filter(|l| l.confidence == Confidence::High)
            .count();
        print_remove_hint(high, &format!("oxidize scan \"{}\" --remove", args.target));
    }
    Ok(())
}

/// What `scan` looks for: the installed program `name` resolves to, or
/// `None` when nothing installed answers to it and the scan goes by name. A
/// name only a Store app answers to is refused; `packages` is asked for the
/// apps only then.
pub(crate) fn scan_subject<'a>(
    programs: &'a [Program],
    packages: impl FnOnce() -> Vec<Package>,
    name: &str,
) -> Result<Option<&'a Program>> {
    match resolve_target(programs, name) {
        Ok(program) => Ok(Some(program)),
        Err(Resolve::Ambiguous(msg)) => Err(Failure::ambiguous(msg).into()),
        Err(Resolve::NotFound) => {
            if let Some(app) = store_app_named(&packages(), name) {
                bail!("{}", store_app_refusal(name, app));
            }
            Ok(None)
        }
    }
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
    // Nobody is there to click through an uninstaller's pages.
    let silent = args.silent || g.yes || g.json;
    let how = How {
        silent,
        keep: args.keep,
        use_uninstaller: args.use_uninstaller,
    };
    let programs = registry::enumerate_installed_programs(true);
    let env = StoreEnv::windows();
    let packages = installed_store_apps(env.store, g);
    if let [target] = args.targets.as_slice() {
        return match resolve_any(&programs, &packages, target) {
            Ok(Resolved::Program(program)) => {
                let program = program.clone();
                uninstall_program(&program, &how, &args.levels, g)
            }
            Ok(Resolved::Store(app)) => {
                if let Err(reason) = package_guard(app, &packages) {
                    bail!("{}", kept(app, &reason));
                }
                uninstall_package(&env, app, args.keep, &args.levels, g)
            }
            Err(resolve) => Err(resolve.into_failure(target).into()),
        };
    }
    let batch = plan_batch(&programs, &packages, &args.targets, silent)?;
    uninstall_batch(&env, &batch, &how, &args.levels, g)
}

/// How `uninstall` goes about a program.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct How {
    pub silent: bool,
    /// Show the leftovers but remove nothing.
    pub keep: bool,
    /// Run the vendor's uninstaller even when Oxidize could do without it.
    pub use_uninstaller: bool,
}

/// A program of a batch with the command that uninstalls it.
#[derive(Debug)]
pub(crate) struct Planned {
    pub program: Program,
    pub plan: uninstall::UninstallPlan,
}

/// One entry of a batch: a program and its uninstaller, or a Store app the
/// guard lets go.
#[derive(Debug)]
pub(crate) enum Step {
    Program(Planned),
    Store(Package),
}

impl Step {
    fn name(&self) -> &str {
        match self {
            Step::Program(b) => &b.program.display_name,
            Step::Store(app) => &app.display_name,
        }
    }
}

/// Resolve every name and plan every step before anything runs. Any name
/// that matches nothing or several, any program without an uninstall
/// command and any Store app the guard keeps stops the whole batch. The
/// order is the order of the names; a program or app named twice runs once.
pub(crate) fn plan_batch(
    programs: &[Program],
    packages: &[Package],
    targets: &[String],
    silent: bool,
) -> Result<Vec<Step>> {
    let mut planned: Vec<Step> = Vec::new();
    let mut problems = Vec::new();
    let mut code = None;
    for target in targets {
        match resolve_any(programs, packages, target) {
            Ok(Resolved::Program(program)) => {
                let seen = planned
                    .iter()
                    .any(|s| matches!(s, Step::Program(b) if same_program(&b.program, program)));
                if seen {
                    continue;
                }
                match uninstall::plan(program, silent) {
                    Ok(plan) => planned.push(Step::Program(Planned {
                        program: program.clone(),
                        plan,
                    })),
                    Err(e) => problems.push(format!("{}: {e:#}", program.display_name)),
                }
            }
            Ok(Resolved::Store(app)) => {
                let seen = planned.iter().any(
                    |s| matches!(s, Step::Store(a) if a.family_name.eq_ignore_ascii_case(&app.family_name)),
                );
                if seen {
                    continue;
                }
                match package_guard(app, packages) {
                    Ok(()) => planned.push(Step::Store(app.clone())),
                    Err(reason) => problems.push(kept(app, &reason)),
                }
            }
            Err(resolve) => {
                let failure = resolve.into_failure(target);
                code = code.or(Some(failure.code));
                problems.push(failure.message);
            }
        }
    }
    if !problems.is_empty() {
        let message = format!(
            "nothing was uninstalled. Fix these first:\n{}",
            problems.join("\n")
        );
        return Err(match code {
            Some(code) => Failure::new(code, exit::ERROR, message, false).into(),
            None => anyhow::anyhow!(message),
        });
    }
    Ok(planned)
}

/// Why the guard keeps a Store app, as one line.
fn kept(app: &Package, reason: &Refusal) -> String {
    format!("{} stays: {reason}", app.display_name)
}

/// `2 programs`, `1 Store app`, `2 programs and 1 Store app`.
fn kinds(programs: usize, apps: usize) -> String {
    let program = format!(
        "{programs} {}",
        if programs == 1 { "program" } else { "programs" }
    );
    let app = format!(
        "{apps} {}",
        if apps == 1 { "Store app" } else { "Store apps" }
    );
    match (programs, apps) {
        (_, 0) => program,
        (0, _) => app,
        _ => format!("{program} and {app}"),
    }
}

/// The same Uninstall entry: one id can exist in more than one hive or view.
pub(crate) fn same_program(a: &Program, b: &Program) -> bool {
    a.id() == b.id() && a.source == b.source
}

/// Show the whole plan, ask once, then uninstall the programs and remove the
/// Store apps one after another, each with its own leftover scan, removal
/// and backup.
fn uninstall_batch(
    env: &StoreEnv,
    batch: &[Step],
    how: &How,
    levels: &LevelOpts,
    g: &Global,
) -> Result<()> {
    let keep = how.keep;
    // Capture every footprint before the first uninstaller runs: one of them
    // may take a later program along.
    let targets: Vec<Option<ScanTarget>> = batch
        .iter()
        .map(|s| match s {
            Step::Program(b) => Some(scanner::build_target(&b.program)),
            Step::Store(_) => None,
        })
        .collect();
    let n = batch.len();
    let apps = batch.iter().filter(|s| matches!(s, Step::Store(_))).count();
    let programs = n - apps;

    if !g.json {
        let head = if n == 1 {
            kinds(programs, apps)
        } else {
            format!("{}, one after another", kinds(programs, apps))
        };
        println!("{}", term::bold(&head));
        for (i, step) in batch.iter().enumerate() {
            match step {
                Step::Program(b) => {
                    println!("  {}. {}", i + 1, program_head(&b.program));
                    println!("     {}", term::dim(&b.plan.display()));
                }
                Step::Store(app) => {
                    println!("  {}. {}", i + 1, package_head(app));
                    println!("     {}", term::dim(&package_command(app)));
                }
            }
        }
        if apps > 0 {
            println!();
            println!("{STORE_APP_WARNING}");
        }
    }

    let question = match (programs, apps) {
        (1, 0) => "Run the uninstaller?".to_string(),
        (_, 0) => format!("Run {programs} uninstallers?"),
        (0, 1) => "Remove the Store app?".to_string(),
        (0, _) => format!("Remove {apps} Store apps?"),
        _ => format!(
            "Run {} and remove {}?",
            if programs == 1 {
                "1 uninstaller".to_string()
            } else {
                format!("{programs} uninstallers")
            },
            kinds(0, apps)
        ),
    };
    // A Store app's removal has no backup, so Enter means no.
    if !g.dry_run && !g.confirm(&question, apps == 0) {
        if g.json {
            let programs: Vec<_> = batch
                .iter()
                .map(|s| match s {
                    Step::Program(b) => json!({ "kind": "program", "program": b.program, "command": b.plan.display(), "cancelled": true }),
                    Step::Store(app) => json!({ "kind": "store", "program": app, "command": package_command(app), "cancelled": true }),
                })
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
        return Err(Failure::cancelled("Cancelled.", true).into());
    }

    let mut runs = Vec::with_capacity(n);
    for (i, (step, target)) in batch.iter().zip(targets).enumerate() {
        if !g.json {
            println!();
            println!(
                "{}",
                term::bold(&format!("[{}/{n}] {}", i + 1, step.name()))
            );
        }
        let failed = |e: anyhow::Error| {
            let error = format!("{e:#}");
            if !g.json {
                term::error(&error);
            }
            error
        };
        // One failing does not stop the others.
        let run = match step {
            Step::Program(b) => {
                let target = target.unwrap_or_else(|| scanner::build_target(&b.program));
                // An earlier uninstaller may have taken this one along; its
                // own would then fail or run on a half-removed install.
                let already_gone = !g.dry_run && !uninstall::still_installed(&b.program);
                run_uninstall(
                    &b.program,
                    &target,
                    &b.plan,
                    already_gone,
                    None,
                    how,
                    levels,
                    g,
                )
                .unwrap_or_else(|e| ProgramRun::stopped(&b.program, &b.plan, failed(e)))
            }
            Step::Store(app) => {
                // A lookup that fails counts as registered: the removal then
                // says what is wrong.
                let already_gone =
                    !g.dry_run && !env.store.is_registered(&app.family_name).unwrap_or(true);
                run_package(env, app, already_gone, keep, levels, g)
                    .unwrap_or_else(|e| ProgramRun::stopped_package(app, failed(e)))
            }
        };
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
    let failed: Vec<&ProgramRun> = runs.iter().filter(|r| r.failed(g.dry_run)).collect();
    if let Some(first) = failed.first() {
        // The batch exits like the first run that failed.
        let first = first.failure(g.json);
        let message = format!(
            "{} of {} did not uninstall cleanly",
            failed.len(),
            kinds(programs, apps)
        );
        return Err(Failure::new(first.code, first.exit, message, g.json).into());
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
fn uninstall_program(program: &Program, how: &How, levels: &LevelOpts, g: &Global) -> Result<()> {
    // Capture the footprint before the entry disappears.
    // One reading of the machine for the target and the first scan.
    let snap = scanner::Snapshot::new();
    let target = scanner::build_target_with(program, &snap);
    let plan = uninstall::plan(program, how.silent)?;

    if !g.json {
        println!("{}", program_head(program));
        println!("  {}", term::dim(&plan.display()));
    }

    let question = if how.keep {
        "Run the uninstaller?"
    } else {
        "Remove it completely? Running copies are closed first."
    };
    if !g.dry_run && !g.confirm(question, true) {
        if g.json {
            let json_out = json!({ "kind": "program", "program": program, "command": plan.display(), "cancelled": true });
            println!("{}", serde_json::to_string_pretty(&json_out)?);
        } else {
            term::info("Cancelled.");
        }
        return Err(Failure::cancelled("Cancelled.", true).into());
    }

    let run = run_uninstall(program, &target, &plan, false, Some(snap), how, levels, g)?;
    if g.json {
        println!("{}", serde_json::to_string_pretty(&run.json)?);
    }
    if run.json["cancelled"] == json!(true) {
        return Err(Failure::cancelled("Cancelled.", true).into());
    }
    if run.failed(g.dry_run) {
        return Err(run.failure(g.json).into());
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
    /// Items at the chosen level the second scan still found.
    left: usize,
}

impl ProgramRun {
    /// An uninstall that stopped with an error before it finished.
    fn stopped(program: &Program, plan: &uninstall::UninstallPlan, error: String) -> Self {
        ProgramRun {
            name: program.display_name.clone(),
            json: json!({ "kind": "program", "program": program, "command": plan.display(), "error": error }),
            gone: false,
            found: 0,
            removal: None,
            error: Some(error),
            left: 0,
        }
    }

    /// A Store app whose removal stopped with an error.
    fn stopped_package(app: &Package, error: String) -> Self {
        ProgramRun {
            name: app.display_name.clone(),
            json: json!({ "kind": "store", "program": app, "command": package_command(app), "error": error }),
            gone: false,
            found: 0,
            removal: None,
            error: Some(error),
            left: 0,
        }
    }

    /// An error, an entry still registered after its uninstaller, a
    /// leftover that could not be removed or one the second scan still found.
    fn failed(&self, dry_run: bool) -> bool {
        self.error.is_some()
            || (!dry_run && !self.gone)
            || self.removal.as_ref().is_some_and(|o| o.failed > 0)
            || (!dry_run && self.left > 0)
    }

    /// One line on why a run counts as failed.
    fn why_failed(&self) -> String {
        if let Some(e) = &self.error {
            return e.clone();
        }
        if !self.gone {
            return format!("{} is still installed", self.name);
        }
        let failed = self.removal.as_ref().map_or(0, |o| o.failed);
        if failed > 0 {
            return format!("{failed} items of {} could not be removed", self.name);
        }
        format!("{} items of {} are still there", self.left, self.name)
    }

    /// [`Self::why_failed`] as a typed error: still installed (exit 3), an
    /// incomplete removal (exit 4), or a plain error.
    fn failure(&self, reported: bool) -> Failure {
        let why = self.why_failed();
        if self.error.is_some() {
            Failure::new("error", exit::ERROR, why, reported)
        } else if !self.gone {
            Failure::still_installed(why, reported)
        } else {
            Failure::incomplete(why, reported)
        }
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

/// Run a confirmed plan the complete way: close what runs from the
/// program's folders, run its uninstaller only when Oxidize cannot do without
/// it, remove the leftovers at `levels` and scan again. `target` is the
/// footprint captured before anything ran, `snap` the reading of the
/// machine it was built from, when that is still current.
#[allow(clippy::too_many_arguments)]
fn run_uninstall(
    program: &Program,
    target: &ScanTarget,
    plan: &uninstall::UninstallPlan,
    already_gone: bool,
    snap: Option<scanner::Snapshot>,
    how: &How,
    levels: &LevelOpts,
    g: &Global,
) -> Result<ProgramRun> {
    if how.keep {
        return run_uninstall_keep(program, target, plan, already_gone, g);
    }
    let name = &program.display_name;
    let level = levels.threshold();
    // An uninstaller someone clicks through gets the time it needs.
    let wait = if plan.unattended || g.yes || g.json {
        complete::VENDOR_WAIT
    } else {
        Duration::from_secs(120)
    };
    let pc = CliPc {
        g,
        wait,
        first: std::cell::RefCell::new(snap),
    };
    let opts = complete::Options {
        level,
        dry_run: g.dry_run,
        use_uninstaller: how.use_uninstaller,
    };
    let out = complete::remove_completely(&pc, program, target, plan, &opts);
    let v = &out.verdict;

    let mut json_out = complete_json(program, plan, &out, level, g.dry_run);
    let cancelled = out
        .removal
        .as_ref()
        .is_some_and(|o| declined(out.selected.len(), o, g.dry_run));
    if cancelled {
        json_out["cancelled"] = json!(true);
    }

    if !g.json {
        print_complete(name, &out, g.dry_run);
    }
    Ok(ProgramRun {
        name: name.clone(),
        json: json_out,
        gone: !g.dry_run && !v.still_installed,
        found: out.report.total(),
        removal: out.removal.clone(),
        error: out.error.clone(),
        left: v.remaining.len(),
    })
}

/// A complete removal as JSON. Stable fields for scripts: `nothing_left`,
/// `still_installed`, `remaining`, `below_level`, `closed`, `uninstaller`,
/// `uninstaller_step`, `removal`, `seconds`; a dry run has `would_close` and
/// `would_remove` instead.
fn complete_json(
    program: &Program,
    plan: &uninstall::UninstallPlan,
    out: &complete::Outcome,
    level: Confidence,
    dry_run: bool,
) -> serde_json::Value {
    let v = &out.verdict;
    let mut json_out = json!({
        "kind": "program",
        "program": program,
        "command": plan.display(),
        "uninstaller_step": out.vendor,
        "level": level.label(),
        "report": out.report,
        "seconds": (out.seconds * 10.0).round() / 10.0,
    });
    if dry_run {
        json_out["would_close"] = json!(out.would_close);
        json_out["would_remove"] = json!(out.selected);
    } else {
        json_out["closed"] = json!(out.closed);
        json_out["uninstaller"] = match (&out.vendor, &out.uninstaller) {
            (complete::VendorStep::Skip { reason }, _) => json!(format!("skipped, {reason}")),
            (_, Some(how)) => json!(how),
            (_, None) => json!(null),
        };
        json_out["still_installed"] = json!(v.still_installed);
        json_out["remaining"] = json!(v.remaining);
        json_out["below_level"] = json!(v.below_level);
        json_out["kept"] = json!(v.kept);
        json_out["nothing_left"] = json!(out.complete());
    }
    if out.removal.is_some() {
        json_out["removal"] = removal_json(&out.removal);
    }
    if let Some(e) = &out.error {
        json_out["error"] = json!(e);
    }
    json_out
}

/// The end of a complete removal in words.
fn print_complete(name: &str, out: &complete::Outcome, dry_run: bool) {
    let v = &out.verdict;
    if dry_run {
        if !out.would_close.is_empty() {
            println!();
            println!("{}", term::dim("would close"));
            for p in &out.would_close {
                println!("  {}", p.exe.display());
            }
        }
        return;
    }
    for c in out
        .closed
        .iter()
        .filter(|c| c.how == complete::CloseHow::Failed)
    {
        term::warn(&format!(
            "could not close {}: {}",
            c.exe,
            c.error.as_deref().unwrap_or("unknown error")
        ));
    }
    if let Some(e) = &out.error {
        term::error(e);
    }
    println!();
    if out.complete() {
        println!(
            "{}  {}",
            term::green("Nothing left."),
            term::dim(&format!("{:.1} s", out.seconds))
        );
    } else if v.still_installed {
        term::warn(&format!(
            "{name} is still registered. The uninstaller may have been cancelled or is still running."
        ));
    }
    if !v.remaining.is_empty() {
        println!("{}", term::bold("Still there"));
        print_items(&v.remaining, true);
    }
    if v.below_level > 0 {
        println!(
            "{}",
            term::dim(&format!(
                "{} lower-confidence items were kept; add --medium or --all to include them",
                v.below_level
            ))
        );
    }
    if let Some(backup) = out.removal.as_ref().and_then(|o| o.backup_name.as_ref()) {
        println!(
            "{}",
            term::dim(&format!("Undo: oxidize restore \"{backup}\""))
        );
    }
}

/// This PC for the command line: says what it does as it goes and asks
/// before it removes anything, unless told yes.
struct CliPc<'a> {
    g: &'a Global,
    wait: Duration,
    /// The reading the target was built from, for the first scan only:
    /// later scans must see what the removal changed.
    first: std::cell::RefCell<Option<scanner::Snapshot>>,
}

impl complete::Pc for CliPc<'_> {
    fn scan(&self, target: &ScanTarget, installed: bool) -> ScanReport {
        match self.first.borrow_mut().take() {
            Some(snap) => scanner::scan_with(target, installed, &snap),
            None => scanner::scan(target, installed),
        }
    }

    fn still_installed(&self, program: &Program) -> bool {
        uninstall::still_installed(program)
    }

    fn running(&self) -> Vec<complete::Running> {
        system::running_processes()
    }

    fn close(&self, procs: &[complete::Running]) -> Vec<complete::Closed> {
        if !self.g.json {
            let n = procs.len();
            println!(
                "Closing {n} running {}.",
                if n == 1 { "process" } else { "processes" }
            );
        }
        system::close_processes(procs, complete::CLOSE_GRACE)
    }

    fn run_uninstaller(&self, plan: &uninstall::UninstallPlan) -> Result<uninstall::Ran> {
        use std::process::Stdio;
        // Someone clicking through it gets all the time they need; one that
        // runs on its own is not waited for longer than the flow allows.
        let attended = !plan.unattended && !self.g.yes && !self.g.json;
        let status = if attended {
            Some(uninstall::run(plan)?)
        } else if self.g.json {
            // With --json our output is the result; the uninstaller gets none.
            uninstall::run_for(plan, Stdio::null(), Stdio::null(), self.wait)?
        } else {
            uninstall::run_for(plan, Stdio::inherit(), Stdio::inherit(), self.wait)?
        };
        let ran = uninstall::Ran::of(status, plan.is_msi, || {
            format!("was still running after {} s", self.wait.as_secs())
        });
        if !self.g.json {
            println!("Uninstaller {}.", ran.said);
        }
        Ok(ran)
    }

    fn wait_until_gone(&self, program: &Program, plan: &uninstall::UninstallPlan) -> bool {
        if !self.g.json && !plan.is_msi && uninstall::still_installed(program) {
            println!("{}", term::dim("waiting for the uninstaller to finish"));
        }
        let gone = uninstall::wait_for_completion(program, plan, self.wait);
        if !self.g.json && gone {
            println!("{} is no longer registered.", program.display_name);
        }
        gone
    }

    fn remove(&self, items: &[Leftover], label: &str) -> Result<DeletionOutcome> {
        if !self.g.json {
            render_report(&ScanReport {
                program_name: label.to_string(),
                installed: false,
                items: items.to_vec(),
            });
        }
        if self.g.dry_run {
            // The list above already says what would go and why.
            let outcome = safety::remove_leftovers(items, label, &self.g.safety())?;
            if !self.g.json {
                println!();
                println!(
                    "{}",
                    term::dim(&format!("dry run: {} items would be removed", items.len()))
                );
            }
            return Ok(outcome);
        }
        remove_items(items, label, self.g)
    }

    fn remove_more(
        &self,
        items: &[Leftover],
        label: &str,
        earlier: &DeletionOutcome,
    ) -> Result<DeletionOutcome> {
        // The removal was agreed to already; these are Windows' records of
        // what it took, which only show once it is gone.
        if !self.g.json {
            println!();
            println!("{}", term::dim("found once the files were gone"));
            render_report(&ScanReport {
                program_name: label.to_string(),
                installed: false,
                items: items.to_vec(),
            });
        }
        let outcome = safety::remove_leftovers_into(
            items,
            label,
            &self.g.safety(),
            earlier.backup_dir.as_deref(),
        )?;
        if !self.g.json {
            print_outcome(&outcome);
        }
        Ok(outcome)
    }

    fn machine_dirs(&self) -> Vec<PathBuf> {
        complete::machine_dirs()
    }

    fn decided(&self, vendor: &complete::VendorStep) {
        if self.g.json || self.g.dry_run {
            if !self.g.json {
                let line = match vendor {
                    complete::VendorStep::Run { .. } => "dry run: the uninstaller would run",
                    complete::VendorStep::Skip { .. } => {
                        "dry run: the uninstaller would be skipped"
                    }
                };
                println!("{}", term::dim(line));
            }
            return;
        }
        match vendor {
            complete::VendorStep::Skip { reason } => {
                println!("{}", term::dim(&format!("Uninstaller skipped: {reason}.")));
            }
            complete::VendorStep::Run { silent, .. } => {
                if !silent {
                    println!(
                        "{}",
                        term::dim("The uninstaller may ask questions in its own window.")
                    );
                }
            }
        }
    }
}

/// `--keep`: run a confirmed plan, wait for it, then scan and show the
/// leftovers without removing them. A program that is `already_gone` goes
/// straight to its leftovers.
fn run_uninstall_keep(
    program: &Program,
    target: &ScanTarget,
    plan: &uninstall::UninstallPlan,
    already_gone: bool,
    g: &Global,
) -> Result<ProgramRun> {
    let name = &program.display_name;
    let mut json_out = json!({ "kind": "program", "program": program, "command": plan.display() });

    let mut gone = false;
    if g.dry_run {
        if !g.json {
            println!("{}", term::dim("dry run: the uninstaller was not started"));
        }
    } else if already_gone {
        if !g.json {
            println!("{name} is no longer registered, so its uninstaller was not started.");
        }
        gone = true;
        json_out["uninstaller"] = json!("not started, no longer registered");
        json_out["still_installed"] = json!(false);
    } else {
        // With --json our output is the result; the uninstaller gets none.
        let ran = if g.json {
            let null = std::process::Stdio::null;
            let status = uninstall::run_for(plan, null(), null(), complete::VENDOR_WAIT)?;
            uninstall::Ran::of(status, plan.is_msi, || {
                format!(
                    "was still running after {} s",
                    complete::VENDOR_WAIT.as_secs()
                )
            })
        } else {
            uninstall::Ran {
                said: uninstall::describe_exit(uninstall::run(plan)?, plan.is_msi),
                ended: true,
            }
        };
        if !g.json {
            println!("Uninstaller {}.", ran.said);
        }
        if uninstall::still_installed(program) && !plan.is_msi && !g.json {
            println!("{}", term::dim("waiting for the uninstaller to finish"));
        }
        gone = ran.gone(|| uninstall::wait_for_completion(program, plan, Duration::from_secs(120)));
        json_out["uninstaller"] = json!(ran.said);
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

    Ok(ProgramRun {
        name: name.clone(),
        json: json_out,
        gone,
        found: report.total(),
        removal: None,
        error: None,
        left: 0,
    })
}

/// Said before any Store app is removed, whatever the flags.
pub(crate) const STORE_APP_WARNING: &str =
    "Removing a Store app deletes its data with it; reinstalling means the Store. \
     The removal itself cannot be backed up, only the leftovers found after it.";

/// What removing a Store app works with: the package store, the folder the
/// apps keep their data in, the scan by name for everything else, and the
/// processes the app runs.
struct StoreEnv<'a> {
    store: &'a dyn PackageStore,
    /// `%LOCALAPPDATA%`, whose `Packages` folder holds the apps' data.
    local_appdata: Option<PathBuf>,
    scan_by_name: fn(&ScanTarget) -> Vec<Leftover>,
    /// Every running process with a known image.
    running: &'a dyn Fn() -> Vec<complete::Running>,
    /// Does the process have a window it can be asked to close through?
    has_window: &'a dyn Fn(u32) -> bool,
    /// Close these processes: their windows first, then end them.
    close: &'a dyn Fn(&[complete::Running]) -> Vec<complete::Closed>,
}

impl StoreEnv<'static> {
    fn windows() -> Self {
        StoreEnv {
            store: &WindowsPackageStore,
            local_appdata: scanner::env_dir("LOCALAPPDATA"),
            scan_by_name: |target| scanner::scan(target, false).items,
            running: &system::running_processes,
            has_window: &system::has_window,
            close: &close_with_grace,
        }
    }
}

fn close_with_grace(procs: &[complete::Running]) -> Vec<complete::Closed> {
    system::close_processes(procs, complete::CLOSE_GRACE)
}

/// Close what runs from a Store app's folder before Windows removes it, the
/// way a program is closed before its uninstaller: windows are asked first,
/// a helper without a window is ended. Without this Windows ends them all.
fn close_app(env: &StoreEnv, app: &Package, g: &Global) -> Vec<complete::Closed> {
    let picked = complete::app_processes(&(env.running)(), app, std::process::id());
    if picked.is_empty() {
        return Vec::new();
    }
    if !g.json {
        let n = picked.len();
        println!(
            "Closing {n} running {}.",
            if n == 1 { "process" } else { "processes" }
        );
    }
    let closed = (env.close)(&picked);
    if !g.json {
        for c in &closed {
            match c.how {
                complete::CloseHow::Failed => term::warn(&format!(
                    "could not close {}: {}",
                    c.exe,
                    c.error.as_deref().unwrap_or("unknown error")
                )),
                _ if c.windowless => println!(
                    "{}",
                    term::dim(&format!("ended {}, it has no window", c.exe))
                ),
                _ => {}
            }
        }
    }
    closed
}

/// The Store apps `uninstall` resolves names against. When Windows cannot
/// list them the programs still resolve, and the warning says why no app
/// does.
fn installed_store_apps(store: &dyn PackageStore, g: &Global) -> Vec<Package> {
    store.list().unwrap_or_else(|e| {
        if !g.json {
            term::warn(&format!("Store apps left out: {e:#}"));
        }
        Vec::new()
    })
}

/// The app's name in bold, then its version and publisher.
fn package_head(app: &Package) -> String {
    let mut extra = vec![app.version.clone()];
    if let Some(p) = &app.publisher {
        extra.push(p.clone());
    }
    extra.push("Store app".to_string());
    format!(
        "{}{}",
        term::bold(&app.display_name),
        term::dim(&format!("  {}", extra.join(", ")))
    )
}

/// What removing the app does, in the place a program shows its uninstaller.
pub(crate) fn package_command(app: &Package) -> String {
    format!("remove package {} for this user", app.full_name)
}

/// Remove one Store app, then scan and offer to remove its leftovers.
fn uninstall_package(
    env: &StoreEnv,
    app: &Package,
    keep: bool,
    levels: &LevelOpts,
    g: &Global,
) -> Result<()> {
    if !g.json {
        println!("{}", package_head(app));
        println!("  {}", term::dim(&package_command(app)));
        println!();
        println!("{STORE_APP_WARNING}");
    }

    // No backup of the removal, so Enter means no.
    if !g.dry_run && !g.confirm("Remove the Store app?", false) {
        if g.json {
            let json_out = json!({ "kind": "store", "program": app, "command": package_command(app), "cancelled": true });
            println!("{}", serde_json::to_string_pretty(&json_out)?);
        } else {
            term::info("Cancelled.");
        }
        return Err(Failure::cancelled("Cancelled.", true).into());
    }

    let run = match run_package(env, app, false, keep, levels, g) {
        Ok(run) => run,
        Err(e) => {
            if g.json {
                let stopped = ProgramRun::stopped_package(app, format!("{e:#}"));
                println!("{}", serde_json::to_string_pretty(&stopped.json)?);
                return Err(exit::reported(e));
            }
            return Err(e);
        }
    };
    if g.json {
        println!("{}", serde_json::to_string_pretty(&run.json)?);
    }
    if !g.dry_run && !run.gone {
        let message = format!("{} is still registered", app.display_name);
        return Err(Failure::still_installed(message, g.json).into());
    }
    if run.failed(g.dry_run) {
        return Err(run.failure(g.json).into());
    }
    Ok(())
}

/// Remove a confirmed Store app, then scan for and offer to remove what it
/// left. An app that is `already_gone` goes straight to its leftovers.
fn run_package(
    env: &StoreEnv,
    app: &Package,
    already_gone: bool,
    keep: bool,
    levels: &LevelOpts,
    g: &Global,
) -> Result<ProgramRun> {
    let name = &app.display_name;
    let mut json_out = json!({ "kind": "store", "program": app, "command": package_command(app) });

    let mut gone = false;
    if g.dry_run {
        let would_close = complete::app_processes(&(env.running)(), app, std::process::id());
        // A helper without a window cannot be asked, so it would be ended.
        let would_end: Vec<&complete::Running> = would_close
            .iter()
            .filter(|p| !(env.has_window)(p.pid))
            .collect();
        if !g.json {
            if !would_close.is_empty() {
                println!("{}", term::dim("would close"));
                for p in &would_close {
                    let ended = would_end.iter().any(|e| e.pid == p.pid);
                    let note = if ended {
                        ", no window, so it is ended"
                    } else {
                        ""
                    };
                    println!("  {}{note}", p.exe.display());
                }
            }
            println!(
                "{}",
                term::dim(
                    "dry run: the app was not removed; Windows deletes its data folder with it"
                )
            );
        }
        json_out["would_end"] = json!(would_end);
        json_out["would_close"] = json!(would_close);
    } else if already_gone {
        if !g.json {
            println!("{name} is no longer registered, so it was not removed again.");
        }
        gone = true;
        json_out["uninstaller"] = json!("not started, no longer registered");
        json_out["still_installed"] = json!(false);
    } else {
        let mut closed = Vec::new();
        let removed = remove_package(env.store, app, &mut || closed = close_app(env, app, g));
        json_out["closed"] = json!(closed);
        gone = removed? == RemovalOutcome::Removed;
        json_out["uninstaller"] = json!("removed by Windows");
        json_out["still_installed"] = json!(!gone);
        if !g.json {
            if gone {
                println!("{name} is no longer registered.");
            } else {
                term::warn(&format!(
                    "{name} is still registered, although Windows reported it removed."
                ));
            }
        }
        if gone {
            let comes_back = may_come_back(env.store, app);
            json_out["may_come_back"] = json!(comes_back);
            if comes_back && !g.json {
                println!(
                    "{}",
                    term::dim(
                        "Windows may bring this app back for new accounts or after a feature update."
                    )
                );
            }
        }
    }

    // Still registered means its data folder is still in use.
    let installed = !gone && !g.dry_run;
    let report = if installed {
        if !g.json {
            println!();
            println!(
                "{}",
                term::dim("Leftovers are not looked for while the app is still registered.")
            );
        }
        ScanReport {
            program_name: name.clone(),
            installed: true,
            items: Vec::new(),
        }
    } else {
        // A dry run leaves the data folder out: Windows deletes it with the
        // app, so it is a leftover only if it outlives the removal.
        let local = if g.dry_run {
            None
        } else {
            env.local_appdata.as_deref()
        };
        let report = store_app_leftovers(app, local, env.scan_by_name);
        if !g.json {
            render_report(&report);
        }
        report
    };
    json_out["report"] = json!(report);

    let mut removal = None;
    if !installed && !report.is_empty() && !keep {
        removal = remove_from_report(&report, name, levels, g)?;
        json_out["removal"] = removal_json(&removal);
    }
    Ok(ProgramRun {
        name: name.clone(),
        json: json_out,
        gone,
        found: report.total(),
        removal,
        error: None,
        left: 0,
    })
}

/// What a removed Store app leaves: its data folder under `local_appdata`
/// when that is given, then what a scan by its names finds.
pub(crate) fn store_app_leftovers(
    app: &Package,
    local_appdata: Option<&std::path::Path>,
    scan_by_name: impl Fn(&ScanTarget) -> Vec<Leftover>,
) -> ScanReport {
    let target = packages::scan_target(app);
    ScanReport {
        program_name: app.display_name.clone(),
        installed: false,
        items: packages::leftovers(app, local_appdata, scan_by_name(&target)),
    }
}

/// Remove a Store app after asking the guard once more against a fresh
/// listing: a refused app never reaches the removal, and `before` runs only
/// for one that may go.
pub(crate) fn remove_package(
    store: &dyn PackageStore,
    app: &Package,
    before: &mut dyn FnMut(),
) -> Result<RemovalOutcome> {
    let installed = store.list()?;
    if let Err(reason) = package_guard(app, &installed) {
        bail!("{}", kept(app, &reason));
    }
    // Only an app that may go is closed.
    before();
    store.remove(app)
}

/// Whether Windows may bring a removed app back: it is provisioned for new
/// accounts. Reading that can need administrator rights; when it cannot be
/// read, an app Microsoft publishes counts as one that may.
fn may_come_back(store: &dyn PackageStore, app: &Package) -> bool {
    store.is_provisioned(&app.family_name).unwrap_or_else(|_| {
        app.family_name
            .to_ascii_lowercase()
            .ends_with("_8wekyb3d8bbwe")
    })
}

// trace
// -----

fn cmd_trace(args: &TraceArgs, g: &Global) -> Result<()> {
    let programs = registry::enumerate_installed_programs(true);
    let matches = hunter::hunt(&args.query, &programs);

    if g.json && !args.uninstall {
        println!("{}", serde_json::to_string_pretty(&trace_json(&matches))?);
        return Ok(());
    }

    if matches.is_empty() {
        return Err(Failure::not_found(format!(
            "no installed program matches \"{}\". Try the full path to the .exe or its folder.",
            args.query
        ))
        .into());
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
            return Err(Failure::ambiguous(
                "several programs match equally well; uninstall by name instead",
            )
            .into());
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
        let how = How {
            silent: args.silent || g.yes || g.json,
            keep: args.keep,
            use_uninstaller: false,
        };
        uninstall_program(&program, &how, &args.levels, g)?;
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

/// The programs `trace` found, best first, as `trace --json` prints them.
pub(crate) fn trace_json(matches: &[hunter::HunterMatch]) -> serde_json::Value {
    matches
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
        .collect()
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
                    &json!({ "report": report, "removal": removal_json(&Some(removal.clone())) })
                )?
            );
        }
        removal_verdict(report.dangling.len(), Some(&removal), g)?;
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
        let items = match b.restored {
            Some(_) => "restored ".to_string(),
            None => format!("{:>3} items", b.items),
        };
        println!(
            "{}  {items}  {:>9}",
            fit(&b.name, name_w),
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
/// Exits with [`exit::CANCELLED`].
fn report_cancelled(g: &Global) -> Result<()> {
    if !g.json {
        term::info("Cancelled.");
    }
    report_deleted_or_cancelled(&[], true, g)?;
    Err(Failure::cancelled("Cancelled.", true).into())
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

/// Whether a restore goes ahead. A dry run never asks. Enter means yes,
/// since a restore puts things back. `--json` cannot ask, so it needs
/// `--yes`.
fn restore_goes_ahead(dry_run: bool, yes: bool, json: bool, ask: impl FnOnce() -> bool) -> bool {
    if dry_run || yes {
        return true;
    }
    if json {
        return false;
    }
    ask()
}

fn cmd_restore(args: &RestoreArgs, g: &Global) -> Result<()> {
    let info = backup::find_backup(&args.name)?;
    let question = format!("Restore {} items from {}?", info.items, info.name);
    if !restore_goes_ahead(g.dry_run, g.yes, g.json, || term::confirm(&question, true)) {
        if g.json {
            return Err(Failure::cancelled(
                "nothing was restored; add --yes to restore with --json",
                false,
            )
            .into());
        }
        term::info("Cancelled.");
        return Err(Failure::cancelled("Cancelled.", true).into());
    }
    let items = restore::restore(&info, g.dry_run)?;
    let failed = items.iter().filter(|i| i.result.is_err()).count();
    let incomplete = || {
        Failure::incomplete(
            format!("{failed} of {} items could not be restored", items.len()),
            g.json,
        )
    };

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
        if failed > 0 && !g.dry_run {
            return Err(incomplete().into());
        }
        return Ok(());
    }

    println!("{}", term::bold(&format!("Restoring {}", info.name)));
    let mut ok = 0;
    for i in &items {
        match &i.result {
            Ok(()) if g.dry_run => println!("  {}  {}", term::dim("would restore"), i.path),
            Ok(()) => {
                ok += 1;
                println!("  {}  {}", term::green("restored"), i.path);
            }
            Err(e) => {
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
            return Err(incomplete().into());
        }
    }
    Ok(())
}

// clean
// -----

fn cmd_clean(args: &CleanArgs, g: &Global) -> Result<()> {
    if args.traces {
        return cmd_clean_traces(g);
    }
    let protected = clean::protect::load()?;
    if !g.json {
        term::info("Analysing...");
    }
    let (places, analysis) = clean::analyse_this_pc(&protected, args.recycle_bin_days);
    let named = args.named();
    let choice = if named.is_empty() {
        analysis.default_choice()
    } else {
        analysis.choice(&named, args.levels.threshold())
    };
    let run = g.yes && !g.dry_run;

    if g.json && !run {
        println!(
            "{}",
            serde_json::to_string_pretty(&clean_plan_json(&analysis, &choice))?
        );
        return Ok(());
    }
    if !g.json {
        print_clean_analysis(&analysis, &choice, &named);
    }
    if !run {
        if !g.json {
            print_clean_hints(&analysis, &choice, g.dry_run);
        }
        return Ok(());
    }

    if choice.categories.is_empty() {
        if g.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "cleaned": [],
                    "freed": 0,
                    "summary": clean::Summary::default(),
                }))?
            );
        } else {
            println!();
            println!("Nothing chosen can be cleaned.");
        }
        return Ok(());
    }
    if !g.json {
        println!();
        term::info("Cleaning...");
    }
    let done = clean::clean_this_pc(&places, &analysis, &choice, &protected, !g.no_backup);
    let freed: u64 = done.iter().map(|c| c.freed).sum();
    if g.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "cleaned": done,
                "freed": freed,
                "summary": clean::cleaned_summary(&done),
            }))?
        );
    } else {
        print_cleaned(&done, freed);
    }
    let failed = done.iter().filter(|c| c.failed()).count();
    if failed > 0 {
        let message = format!("{failed} of {} categories did not clean fully", done.len());
        return Err(Failure::incomplete(message, true).into());
    }
    Ok(())
}

/// `oxidize clean --traces`: show the usage traces, or clear them with
/// `--yes`.
fn cmd_clean_traces(g: &Global) -> Result<()> {
    let protected = clean::protect::load()?;
    let places = traces::TracePlaces::this_pc();
    let shell = traces::shell_for(&places);
    let run = g.yes && !g.dry_run;
    if !run {
        let found = traces::analyse(&places, &protected, shell.as_ref());
        let (count, bytes) = traces::total(&found);
        if g.json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({ "traces": found, "count": count, "bytes": bytes })
                )?
            );
            return Ok(());
        }
        println!();
        for f in &found {
            print_trace(f);
        }
        println!();
        let line = if g.dry_run {
            format!("dry run: {count} items would be cleared")
        } else if found.iter().any(TraceFinding::actionable) {
            format!("{count} items. Clear them: add --yes")
        } else {
            "Nothing to clear.".to_string()
        };
        println!("{}", term::dim(&line));
        println!(
            "{}",
            term::dim("The files they point to stay, and so do pinned items.")
        );
        return Ok(());
    }
    if !g.json {
        term::info("Clearing...");
    }
    let done = traces::clear(&places, &protected, shell.as_ref());
    let (count, bytes) = traces::total(&done);
    if g.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({ "cleared": done, "count": count, "bytes": bytes })
            )?
        );
    } else {
        println!();
        for f in &done {
            print_trace(f);
        }
        println!();
        println!("{count} items cleared, {} freed", util::human_size(bytes));
    }
    let failed = done.iter().filter(|f| f.failed()).count();
    if failed > 0 {
        let message = format!("{failed} of {} lists did not clear fully", done.len());
        return Err(Failure::incomplete(message, true).into());
    }
    Ok(())
}

/// One trace: its size, title and count, then what stays and why.
fn print_trace(f: &TraceFinding) {
    let size = if f.bytes == 0 {
        "-".to_string()
    } else {
        util::human_size(f.bytes)
    };
    let detail = if f.actionable() {
        f.detail()
    } else {
        "nothing found".to_string()
    };
    if detail.is_empty() {
        println!("  {size:>9}  {}", f.trace.title());
    } else {
        println!("  {size:>9}  {}  {}", f.trace.title(), term::dim(&detail));
    }
    for note in &f.notes {
        println!("{INDENT}{}", term::dim(note));
    }
    if let Some(stays) = clean::stays_text(&f.kept) {
        println!("{INDENT}{}", term::dim(&stays));
    }
}

/// The analysis as `--json` prints it without `--yes`.
pub(crate) fn clean_plan_json(analysis: &Analysis, choice: &Choice) -> serde_json::Value {
    json!({
        "analysis": analysis,
        "chosen": choice.categories,
        "chosen_folders": choice.folders,
        "chosen_bytes": analysis.chosen_bytes(choice),
        "summary": analysis.summary(),
    })
}

fn print_clean_analysis(analysis: &Analysis, choice: &Choice, named: &[Category]) {
    let (chosen, rest): (Vec<&Finding>, Vec<&Finding>) = analysis
        .findings
        .iter()
        .partition(|f| choice.categories.contains(&f.category));
    println!();
    println!("{}", term::bold("Chosen"));
    if chosen.is_empty() {
        println!("  {}", term::dim("nothing"));
    }
    for f in &chosen {
        print_finding(f, Some(choice));
    }
    println!();
    println!("{}", term::bold("Not chosen"));
    for f in &rest {
        print_finding(f, None);
        let why = if named.contains(&f.category) {
            "nothing to clean here now".to_string()
        } else {
            format!("add --{}", f.category.id())
        };
        println!("{INDENT}{}", term::dim(&why));
    }
}

/// Where the lines under a category start, below its title.
const INDENT: &str = "             ";

/// One category: what would go, then what stays and why.
fn print_finding(f: &Finding, choice: Option<&Choice>) {
    let bytes = match choice {
        Some(c) if f.category == Category::Orphans => f
            .folders
            .iter()
            .filter(|o| c.folders.contains(&o.path))
            .map(|o| o.bytes)
            .sum(),
        _ => f.bytes,
    };
    let size = if (!f.size_known || !f.actionable()) && bytes == 0 {
        "-".to_string()
    } else {
        util::human_size(bytes)
    };
    println!(
        "  {size:>9}  {}  {}",
        f.category.title(),
        term::dim(&finding_detail(f, choice))
    );
    for note in &f.notes {
        println!("{INDENT}{}", term::dim(note));
    }
    if let Some(stays) = clean::stays_text(&f.kept) {
        println!("{INDENT}{}", term::dim(&stays));
    }
    if let Some(c) = choice {
        for o in f.folders.iter().filter(|o| c.folders.contains(&o.path)) {
            println!(
                "{INDENT}{}  {}  {}",
                conf_tag(o.confidence),
                o.path.display(),
                term::dim(&format!("{}, {}", util::human_size(o.bytes), o.reason))
            );
        }
    }
}

fn finding_detail(f: &Finding, choice: Option<&Choice>) -> String {
    if !f.actionable() && f.kept.is_empty() && f.notes.is_empty() {
        return "nothing found".to_string();
    }
    let n = f.count;
    let plural = |one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    match f.category {
        Category::Temp | Category::CrashDumps | Category::BrowserCache => plural("file", "files"),
        Category::DeliveryOptimization if f.actionable() => plural("file", "files"),
        Category::RecycleBin => plural("item", "items"),
        Category::Orphans => match choice {
            Some(c) => format!("{} of {n} folders", c.folders.len()),
            None => plural("folder", "folders"),
        },
        Category::WindowsOld if f.actionable() => "1 folder".to_string(),
        _ => String::new(),
    }
}

fn print_clean_hints(analysis: &Analysis, choice: &Choice, dry_run: bool) {
    println!();
    let bytes = util::human_size(analysis.chosen_bytes(choice));
    let n = choice.categories.len();
    let categories = if n == 1 { "category" } else { "categories" };
    if dry_run {
        println!(
            "{}",
            term::dim(&format!(
                "dry run: {bytes} in {n} {categories} would be cleaned"
            ))
        );
    } else if n > 0 {
        println!(
            "{}",
            term::dim(&format!(
                "{bytes} in {n} {categories}. Clean them: add --yes"
            ))
        );
    }
    if !analysis.elevated && analysis.findings.iter().any(|f| f.needs_admin) {
        println!(
            "{}",
            term::dim("Some of it needs administrator rights. Add --elevate to include it.")
        );
    }
    if let Ok(path) = clean::protect::file_path() {
        let line = if analysis.protected.is_empty() {
            format!("Folders listed in {} are never cleaned.", path.display())
        } else {
            format!(
                "{} protected folders in {} are never cleaned.",
                analysis.protected.len(),
                path.display()
            )
        };
        println!("{}", term::dim(&line));
    }
}

fn print_cleaned(done: &[Cleaned], freed: u64) {
    println!();
    for c in done {
        println!(
            "  {:>9}  {}  {}",
            util::human_size(c.freed),
            c.category.title(),
            term::dim(&format!("{} removed", c.removed))
        );
        for note in &c.notes {
            println!("{INDENT}{}", term::dim(note));
        }
        if let Some(stays) = clean::stays_text(&c.kept) {
            println!("{INDENT}{}", term::dim(&stays));
        }
    }
    println!();
    println!("{} freed", util::human_size(freed));
    for name in done.iter().filter_map(|c| c.backup.as_deref()) {
        println!(
            "{}",
            term::dim(&format!("Undo: oxidize restore \"{name}\""))
        );
    }
}

// protect
// -------

/// `oxidize protect`: the protected list, or with `--check` whether one
/// path is on it.
fn cmd_protect(args: &ProtectArgs, g: &Global) -> Result<()> {
    let file = clean::protect::file_path()?;
    let list = clean::protect::load_from(&file)?;
    let Some(path) = &args.check else {
        if g.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "file": file, "entries": list.entries() }))?
            );
        } else if list.is_empty() {
            println!("Nothing is protected yet.");
            println!(
                "{}",
                term::dim(&format!(
                    "Folders listed in {} are never cleaned.",
                    file.display()
                ))
            );
        } else {
            for e in list.entries() {
                println!("  {e}");
            }
            println!();
            println!(
                "{}",
                term::dim(&format!(
                    "{} protected, listed in {}",
                    list.entries().len(),
                    file.display()
                ))
            );
        }
        return Ok(());
    };
    if path.trim().is_empty() {
        return Err(Failure::usage("give a path to check").into());
    }
    let answer = protect_check(&list, path);
    if g.json {
        println!("{}", serde_json::to_string_pretty(&answer)?);
        return Ok(());
    }
    match &answer.by {
        Some(by) => println!("protected: {path}  {}", term::dim(&format!("by {by}"))),
        None => println!("not protected: {path}"),
    }
    if !answer.holds.is_empty() {
        println!(
            "{}",
            term::dim("It holds these, so it is never removed as a whole:")
        );
        for e in &answer.holds {
            println!("  {e}");
        }
    }
    Ok(())
}

/// The answer of `protect --check`, as `--json` prints it.
#[derive(Debug, Serialize)]
struct ProtectCheck {
    /// The path as given.
    path: String,
    /// The full path as compared: variables expanded, real name, lower case.
    resolved: String,
    protected: bool,
    /// The entry, as written, that covers it.
    by: Option<String>,
    /// Entries inside it, which keep it from being removed as a whole.
    holds: Vec<String>,
}

/// Check `path` against `list`, with `%VAR%` expanded and a relative path
/// taken from the current folder.
fn protect_check(list: &clean::protect::Protected, path: &str) -> ProtectCheck {
    let expanded = PathBuf::from(util::expand_env_vars(path));
    let full = std::path::absolute(&expanded).unwrap_or(expanded);
    let by = list.covered_by(&full).map(str::to_string);
    ProtectCheck {
        path: path.to_string(),
        resolved: clean::protect::key_of(&full),
        protected: by.is_some(),
        by,
        holds: list.inside(&full).into_iter().map(str::to_string).collect(),
    }
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
    let selected = selected_leftovers(report, levels);
    if selected.is_empty() {
        if !g.json {
            println!();
            println!("Nothing at {} to remove.", levels.describe());
        }
        return Ok(None);
    }
    remove_items(&selected, label, g).map(Some)
}

/// The leftovers a removal at `levels` acts on.
pub(crate) fn selected_leftovers(report: &ScanReport, levels: &LevelOpts) -> Vec<Leftover> {
    let threshold = levels.threshold();
    report
        .all()
        .filter(|l| l.confidence <= threshold)
        .cloned()
        .collect()
}

/// The exit code of a removal of `selected` items that already printed its
/// result: 5 when the question was answered no, 4 when an item failed.
fn removal_verdict(selected: usize, removal: Option<&DeletionOutcome>, g: &Global) -> Result<()> {
    let Some(o) = removal else {
        return Ok(());
    };
    if declined(selected, o, g.dry_run) {
        return Err(Failure::cancelled("Cancelled.", true).into());
    }
    if o.failed > 0 {
        let message = format!("{} of {} items could not be removed", o.failed, o.attempted);
        return Err(Failure::incomplete(message, g.json).into());
    }
    Ok(())
}

/// Items were selected and none was tried: the question was answered no.
fn declined(selected: usize, o: &DeletionOutcome, dry_run: bool) -> bool {
    !dry_run && selected > 0 && o.attempted == 0
}

fn remove_items(selected: &[Leftover], label: &str, g: &Global) -> Result<DeletionOutcome> {
    let ctx = g.safety();

    if !g.json && safety::needs_elevation(selected) && !safety::is_elevated() {
        term::warn(
            "some items need administrator rights; run from an elevated terminal or add --elevate",
        );
    }

    if ctx.dry_run {
        let outcome = safety::remove_leftovers(selected, label, &ctx)?;
        if !g.json {
            println!();
            for item in &outcome.items {
                println!("{}", item_line(item));
            }
            println!();
            println!(
                "{}",
                term::dim(&format!(
                    "dry run: {} items would be removed",
                    selected.len()
                ))
            );
        }
        return Ok(outcome);
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

/// One item of a removal as a line of output.
fn item_line(item: &ItemOutcome) -> String {
    match &item.status {
        ItemStatus::Removed => format!("  {}  {}", term::green("removed"), item.path),
        ItemStatus::RemovedAfterRestart => format!(
            "  {}  {}  {}",
            term::green("marked "),
            item.path,
            term::dim("goes at the next restart")
        ),
        ItemStatus::AlreadyGone => format!("  {}  {}", term::dim("gone   "), item.path),
        ItemStatus::Failed(e) => format!(
            "  {}  {}  {}",
            term::red("failed "),
            item.path,
            term::dim(e)
        ),
        ItemStatus::WouldRemove => format!("  {}  {}", term::dim("would remove"), item.path),
    }
}

fn print_outcome(outcome: &DeletionOutcome) {
    for item in &outcome.items {
        println!("{}", item_line(item));
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
    if outcome.dry_run {
        println!("{} would be removed", outcome.attempted);
        return;
    }
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

pub(crate) fn removal_json(outcome: &Option<DeletionOutcome>) -> serde_json::Value {
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
                    ItemStatus::RemovedAfterRestart => "removed_after_restart",
                    ItemStatus::AlreadyGone => "gone",
                    ItemStatus::Failed(_) => "failed",
                    ItemStatus::WouldRemove => "would_remove",
                },
                "error": match &i.status { ItemStatus::Failed(e) => Some(e.as_str()), _ => None },
            })).collect::<Vec<_>>(),
        }),
    }
}

// program resolution
// ------------------

pub(crate) enum Resolve {
    NotFound,
    Ambiguous(String),
}

impl Resolve {
    /// The typed error for a name `uninstall` cannot act on.
    pub(crate) fn into_failure(self, target: &str) -> Failure {
        match self {
            Resolve::NotFound => Failure::not_found(not_found(target)),
            Resolve::Ambiguous(msg) => Failure::ambiguous(msg),
        }
    }
}

/// A name `uninstall` acts on: a program or a Store app.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Resolved<'a> {
    Program(&'a Program),
    Store(&'a Package),
}

/// Exact id, then exact name, then a unique substring of the name.
fn resolve_target<'a>(
    programs: &'a [Program],
    target: &str,
) -> std::result::Result<&'a Program, Resolve> {
    match resolve_any(programs, &[], target)? {
        Resolved::Program(p) => Ok(p),
        // Only reached with Store apps to choose from.
        Resolved::Store(_) => Err(Resolve::NotFound),
    }
}

/// Programs and Store apps side by side: an exact id (a program's registry
/// id; an app's family, full or identity name), then an exact name, then a
/// unique part of a name. A name both kinds answer to equally well is
/// ambiguous; neither wins. Store apps signed as part of Windows answer only
/// to their exact id or name.
pub(crate) fn resolve_any<'a>(
    programs: &'a [Program],
    packages: &'a [Package],
    target: &str,
) -> std::result::Result<Resolved<'a>, Resolve> {
    // Every name contains the empty one, so it would answer to everything.
    if target.trim().is_empty() {
        return Err(Resolve::Ambiguous(
            "give a name; an empty one would match everything".to_string(),
        ));
    }
    let program_id = programs
        .iter()
        .find(|p| p.id().eq_ignore_ascii_case(target));
    let app_id = packages.iter().find(|a| {
        [&a.family_name, &a.full_name, &a.name]
            .iter()
            .any(|id| id.eq_ignore_ascii_case(target))
    });
    match (program_id, app_id) {
        (Some(p), None) => return Ok(Resolved::Program(p)),
        (None, Some(a)) => return Ok(Resolved::Store(a)),
        (Some(p), Some(a)) => return Err(ambiguous(target, &[p], &[a])),
        (None, None) => {}
    }

    let exact: Vec<&Program> = programs
        .iter()
        .filter(|p| p.display_name.eq_ignore_ascii_case(target))
        .collect();
    let exact_apps: Vec<&Package> = packages
        .iter()
        .filter(|a| a.display_name.eq_ignore_ascii_case(target))
        .collect();
    match (exact.as_slice(), exact_apps.as_slice()) {
        ([p], []) => return Ok(Resolved::Program(p)),
        ([], [a]) => return Ok(Resolved::Store(a)),
        _ => {}
    }

    let needle = target.to_lowercase();
    let subs: Vec<&Program> = programs
        .iter()
        .filter(|p| p.display_name.to_lowercase().contains(&needle))
        .collect();
    let sub_apps: Vec<&Package> = packages
        .iter()
        .filter(|a| {
            a.signature != SignatureKind::System
                && [&a.display_name, &a.name]
                    .iter()
                    .any(|s| s.to_lowercase().contains(&needle))
        })
        .collect();
    match (subs.as_slice(), sub_apps.as_slice()) {
        ([], []) => Err(Resolve::NotFound),
        ([p], []) => Ok(Resolved::Program(p)),
        ([], [a]) => Ok(Resolved::Store(a)),
        _ => Err(ambiguous(target, &subs, &sub_apps)),
    }
}

/// Every candidate for a name, each with the id that picks it.
fn ambiguous(target: &str, programs: &[&Program], apps: &[&Package]) -> Resolve {
    let n = programs.len() + apps.len();
    let listing = programs
        .iter()
        .map(|p| format!("  {}  {}", p.display_name, term::dim(p.id())))
        .chain(apps.iter().map(|a| {
            format!(
                "  {} (Store app)  {}",
                a.display_name,
                term::dim(&a.family_name)
            )
        }))
        .take(12)
        .collect::<Vec<_>>()
        .join("\n");
    let more = if n > 12 {
        format!("\n  and {} more", n - 12)
    } else {
        String::new()
    };
    Resolve::Ambiguous(format!(
        "\"{target}\" matches {}:\n{listing}{more}\nUse a longer name or the id on the right.",
        kinds(programs.len(), apps.len())
    ))
}

/// Why `uninstall` cannot act on a name.
fn not_found(target: &str) -> String {
    format!("no installed program or Store app matches \"{target}\"")
}

/// `scan` looks for a program's leftovers; a Store app's are found when
/// `uninstall` removes it, so a name only an app answers to stops `scan`.
fn store_app_refusal(target: &str, app: &Package) -> String {
    format!(
        "\"{target}\" is the Store app {}. Its leftovers are found when it is removed: oxidize uninstall \"{}\"",
        app.display_name, app.family_name
    )
}

/// The Store app a name points to: its family, full or identity name, or a
/// part of the name Windows shows.
fn store_app_named<'a>(packages: &'a [Package], target: &str) -> Option<&'a Package> {
    let needle = target.to_lowercase();
    packages.iter().find(|p| {
        [&p.family_name, &p.full_name, &p.name]
            .iter()
            .any(|id| id.eq_ignore_ascii_case(target))
            || p.display_name.to_lowercase().contains(&needle)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hive, LeftoverKind, RegistrySource, RegistryView};
    use crate::packages::fake::{package, FakePackageStore};
    use crate::safety::ItemOutcome;
    use clap::Parser;

    #[test]
    fn the_mcp_server_refuses_the_flags_of_a_single_run() {
        for flags in [
            &["--dry-run"][..],
            &["--yes"],
            &["--no-backup"],
            &["--dry-run", "--yes"],
        ] {
            let mut argv = vec!["oxidize"];
            argv.extend_from_slice(flags);
            argv.push("mcp");
            let cli = Cli::try_parse_from(&argv).unwrap();
            let g = Global {
                dry_run: cli.dry_run,
                yes: cli.yes,
                json: cli.json,
                no_backup: cli.no_backup,
            };
            let err = mcp_takes_no_run_flags(&g).unwrap_err();
            let out = exit::outcome(&err);
            assert_eq!((out.code, out.exit), ("usage", exit::USAGE), "{flags:?}");
            for flag in flags {
                assert!(err.to_string().contains(flag), "{err}");
            }
        }
        let plain = Global {
            dry_run: false,
            yes: false,
            json: true,
            no_backup: false,
        };
        assert!(mcp_takes_no_run_flags(&plain).is_ok());
    }

    #[test]
    fn a_protect_check_expands_variables_and_reads_relative_paths_from_here() {
        let base = std::env::temp_dir().join("oxidize_protect_check_test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join(r"keep\inner")).unwrap();
        std::env::set_var("OXIDIZE_CHECK_TEST", &base);
        let list = clean::protect::Protected::new([r"%OXIDIZE_CHECK_TEST%\keep".to_string()]);

        let inside = protect_check(&list, r"%OXIDIZE_CHECK_TEST%\keep\inner");
        assert!(inside.protected);
        assert_eq!(inside.by.as_deref(), Some(r"%OXIDIZE_CHECK_TEST%\keep"));
        assert_eq!(
            inside.resolved,
            clean::protect::key_of(&base.join(r"keep\inner"))
        );
        let beside = protect_check(&list, r"%OXIDIZE_CHECK_TEST%\keeper");
        assert!(!beside.protected && beside.by.is_none());
        let above = protect_check(&list, r"%OXIDIZE_CHECK_TEST%");
        assert!(!above.protected);
        assert_eq!(above.holds, [r"%OXIDIZE_CHECK_TEST%\keep"]);

        // Relative to the current folder, as a shell would mean it.
        let relative = std::env::current_dir()
            .unwrap()
            .join("keep")
            .display()
            .to_string();
        let here = clean::protect::Protected::new([relative]);
        assert!(protect_check(&here, r"keep\x").protected);
        assert!(!protect_check(&here, "x").protected);

        let v = serde_json::to_value(&inside).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["by", "holds", "path", "protected", "resolved"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    fn program(name: &str, key: &str, uninstall: Option<&str>) -> Program {
        Program {
            registry_key: key.to_string(),
            source: RegistrySource::new(Hive::LocalMachine, RegistryView::Native64),
            display_name: name.to_string(),
            display_version: None,
            publisher: None,
            install_date: None,
            install_location: None,
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: uninstall.map(str::to_string),
            quiet_uninstall_string: None,
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    fn installed() -> Vec<Program> {
        vec![
            program(
                "Brave",
                "BraveSoftware Brave-Browser",
                Some(r#""C:\Brave\setup.exe" --uninstall"#),
            ),
            program(
                "VLC media player",
                "VLC media player",
                Some(r"C:\VLC\uninstall.exe"),
            ),
            program(
                "7-Zip 24.08 (x64)",
                "7-Zip",
                Some(r"C:\7-Zip\Uninstall.exe"),
            ),
            program("Frobnic Editor", "FrobEdit", Some(r"C:\Frob\unins000.exe")),
            program("Frobnic Viewer", "FrobView", Some(r"C:\Frob\unins001.exe")),
            program("Driver Pack", "DriverPack", None),
        ]
    }

    fn names(targets: &[&str]) -> Vec<String> {
        targets.iter().map(|t| t.to_string()).collect()
    }

    fn planned_names(batch: &[Step]) -> Vec<&str> {
        batch.iter().map(Step::name).collect()
    }

    fn plan_of(step: &Step) -> &uninstall::UninstallPlan {
        match step {
            Step::Program(b) => &b.plan,
            Step::Store(app) => panic!("{} is a Store app", app.display_name),
        }
    }

    #[test]
    fn several_names_are_parsed_and_one_is_required() {
        let cli = Cli::try_parse_from(["oxidize", "uninstall", "brave", "vlc", "7zip", "-y"])
            .expect("several names parse");
        assert!(cli.yes);
        match cli.command {
            Commands::Uninstall(args) => assert_eq!(args.targets, ["brave", "vlc", "7zip"]),
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(Cli::try_parse_from(["oxidize", "uninstall"]).is_err());
    }

    #[test]
    fn a_batch_runs_in_the_order_of_the_names() {
        let programs = installed();
        let batch = plan_batch(&programs, &[], &names(&["7-zip", "brave", "vlc"]), false).unwrap();
        assert_eq!(
            planned_names(&batch),
            ["7-Zip 24.08 (x64)", "Brave", "VLC media player"]
        );
        assert_eq!(
            plan_of(&batch[1]).argv,
            [r"C:\Brave\setup.exe", "--uninstall"]
        );
    }

    #[test]
    fn names_resolve_by_id_exact_name_or_unique_part() {
        let programs = installed();
        let batch = plan_batch(
            &programs,
            &[],
            &names(&["FrobView", "frobnic editor", "media"]),
            false,
        )
        .unwrap();
        assert_eq!(
            planned_names(&batch),
            ["Frobnic Viewer", "Frobnic Editor", "VLC media player"]
        );
    }

    #[test]
    fn a_name_that_matches_nothing_stops_the_whole_batch() {
        let programs = installed();
        let err = plan_batch(&programs, &[], &names(&["brave", "nosuchapp"]), false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.starts_with("nothing was uninstalled"), "{msg}");
        assert!(
            msg.contains("no installed program or Store app matches \"nosuchapp\""),
            "{msg}"
        );
        assert!(!msg.contains("Brave"), "{msg}");
    }

    #[test]
    fn an_ambiguous_name_lists_its_candidates_and_stops_the_batch() {
        let programs = installed();
        let err = plan_batch(&programs, &[], &names(&["vlc", "frobnic"]), false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("\"frobnic\" matches 2 programs"), "{msg}");
        assert!(msg.contains("Frobnic Editor"), "{msg}");
        assert!(msg.contains("Frobnic Viewer"), "{msg}");
    }

    #[test]
    fn every_problem_is_listed_at_once_in_the_order_given() {
        let programs = installed();
        let err = plan_batch(
            &programs,
            &[],
            &names(&["nosuchapp", "vlc", "frobnic", "driver"]),
            false,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        let missing = msg.find("\"nosuchapp\"").expect("missing name listed");
        let ambiguous = msg
            .find("\"frobnic\" matches")
            .expect("ambiguous name listed");
        let no_command = msg
            .find("Driver Pack: no uninstall command")
            .expect("program without an uninstaller listed");
        assert!(missing < ambiguous && ambiguous < no_command, "{msg}");
    }

    #[test]
    fn a_program_named_twice_runs_once() {
        let programs = installed();
        let batch = plan_batch(
            &programs,
            &[],
            &names(&["brave", "vlc", "Brave", "BraveSoftware Brave-Browser"]),
            false,
        )
        .unwrap();
        assert_eq!(planned_names(&batch), ["Brave", "VLC media player"]);
    }

    #[test]
    fn the_same_id_in_another_hive_is_another_program() {
        let machine = program("Tool", "Tool", Some(r"C:\Tool\uninstall.exe"));
        let mut user = machine.clone();
        user.source = RegistrySource::new(Hive::CurrentUser, RegistryView::Native64);
        assert!(same_program(&machine, &machine.clone()));
        assert!(!same_program(&machine, &user));
    }

    #[test]
    fn silent_is_planned_per_program() {
        let mut programs = installed();
        programs[0].quiet_uninstall_string =
            Some(r#""C:\Brave\setup.exe" --uninstall --force-uninstall"#.to_string());
        let batch = plan_batch(&programs, &[], &names(&["brave", "vlc"]), true).unwrap();
        assert_eq!(plan_of(&batch[0]).source, "QuietUninstallString");
        assert_eq!(
            plan_of(&batch[0]).argv.last().map(String::as_str),
            Some("--force-uninstall")
        );
        // No quiet variant: the normal command, and the plan says so.
        assert_eq!(
            plan_of(&batch[1]).source,
            "UninstallString, no quiet variant"
        );

        let loud = plan_batch(&programs, &[], &names(&["brave"]), false).unwrap();
        assert_eq!(plan_of(&loud[0]).source, "UninstallString");
    }

    fn run(name: &str, gone: bool, found: usize, removal: Option<DeletionOutcome>) -> ProgramRun {
        let p = program(name, name, Some(r"C:\x\uninstall.exe"));
        ProgramRun {
            name: name.to_string(),
            json: json!({ "program": p, "command": r"C:\x\uninstall.exe" }),
            gone,
            found,
            removal,
            error: None,
            left: 0,
        }
    }

    fn removed(deleted: usize, failed: usize, backup: Option<&str>) -> DeletionOutcome {
        DeletionOutcome {
            attempted: deleted + failed,
            deleted,
            failed,
            backup_name: backup.map(str::to_string),
            items: (0..deleted + failed)
                .map(|i| ItemOutcome {
                    path: format!(r"C:\x\{i}"),
                    kind: LeftoverKind::File,
                    status: if i < deleted {
                        ItemStatus::Removed
                    } else {
                        ItemStatus::Failed("denied".to_string())
                    },
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_program_fails_when_it_stays_registered_stops_or_keeps_a_failed_leftover() {
        assert!(!run("A", true, 3, Some(removed(3, 0, Some("b")))).failed(false));
        assert!(run("A", false, 0, None).failed(false));
        assert!(run("A", true, 3, Some(removed(2, 1, Some("b")))).failed(false));
        let plan = uninstall::plan(&program("A", "A", Some("x.exe")), false).unwrap();
        let stopped = ProgramRun::stopped(&program("A", "A", None), &plan, "boom".into());
        assert!(stopped.failed(false));
        assert_eq!(stopped.state(false), "failed");
        assert_eq!(stopped.leftovers(false), "boom");
        assert_eq!(stopped.json["error"], "boom");
        assert_eq!(stopped.json["kind"], "program");
        // A dry run never ran anything, so still registered is expected.
        assert!(!run("A", false, 3, None).failed(true));
    }

    #[test]
    fn the_summary_says_what_became_of_the_leftovers() {
        assert_eq!(
            run("A", true, 3, Some(removed(2, 1, None))).leftovers(false),
            "2 leftovers removed, 1 failed"
        );
        assert_eq!(run("A", true, 0, None).leftovers(false), "no leftovers");
        assert_eq!(
            run("A", false, 4, None).leftovers(false),
            "leftovers not removed"
        );
        // Offered and declined, or --keep.
        assert_eq!(
            run("A", true, 4, Some(DeletionOutcome::default())).leftovers(false),
            "4 leftovers kept"
        );
        assert_eq!(run("A", true, 4, None).leftovers(false), "4 leftovers kept");
        let preview = DeletionOutcome {
            attempted: 5,
            ..Default::default()
        };
        assert_eq!(
            run("A", false, 5, Some(preview)).leftovers(true),
            "5 leftovers would be removed"
        );
        assert_eq!(run("A", false, 0, None).state(false), "still registered");
        assert_eq!(run("A", true, 0, None).state(false), "uninstalled");
        assert_eq!(run("A", false, 0, None).state(true), "dry run");
    }

    #[test]
    fn a_batch_as_json_lists_each_program_in_order_with_counts() {
        let runs = [
            run(
                "Brave",
                true,
                3,
                Some(removed(3, 0, Some("2026-09-29 120000 Brave"))),
            ),
            run("VLC media player", false, 2, None),
            run("7-Zip", true, 0, None),
        ];
        let v = batch_json(&runs, false);
        let programs = v["programs"].as_array().expect("programs is an array");
        let order: Vec<&str> = programs
            .iter()
            .map(|p| p["program"]["display_name"].as_str().unwrap())
            .collect();
        assert_eq!(order, ["Brave", "VLC media player", "7-Zip"]);
        // Each entry is the single-program object, plus whether it failed.
        for p in programs {
            assert!(p["command"].is_string());
            assert!(p["failed"].is_boolean());
        }
        assert_eq!(programs[0]["failed"], false);
        assert_eq!(programs[1]["failed"], true);
        assert_eq!(v["uninstalled"], 2);
        assert_eq!(v["failed"], 1);
        assert_eq!(v["cancelled"], false);
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["cancelled", "failed", "programs", "uninstalled"]);
    }

    fn store_apps() -> Vec<Package> {
        vec![
            package("Microsoft.WindowsCalculator", "Windows Calculator"),
            package("Vendor.Brave", "Brave"),
        ]
    }

    fn resolved_app<'a>(programs: &'a [Program], apps: &'a [Package], target: &str) -> &'a str {
        match resolve_any(programs, apps, target) {
            Ok(Resolved::Store(app)) => &app.family_name,
            Ok(Resolved::Program(p)) => panic!("{target} resolved to the program {}", p.id()),
            Err(Resolve::NotFound) => panic!("{target} matched nothing"),
            Err(Resolve::Ambiguous(msg)) => panic!("{msg}"),
        }
    }

    #[test]
    fn a_store_app_resolves_by_family_full_identity_or_shown_name() {
        let programs = installed();
        let apps = store_apps();
        let family = "Microsoft.WindowsCalculator_8wekyb3d8bbwe";
        for target in [
            "calculator",
            "Windows Calculator",
            family,
            "microsoft.windowscalculator_8wekyb3d8bbwe",
            "Microsoft.WindowsCalculator_1.2.3.0_x64__8wekyb3d8bbwe",
            "Microsoft.WindowsCalculator",
        ] {
            assert_eq!(resolved_app(&programs, &apps, target), family, "{target}");
        }
    }

    #[test]
    fn a_name_both_kinds_answer_to_lists_both_with_their_ids() {
        let programs = installed();
        let apps = store_apps();
        // A blank name never answers to anything, not even by name alone.
        for blank in ["", "  "] {
            let Err(Resolve::Ambiguous(msg)) = resolve_any(&programs, &apps, blank) else {
                panic!("{blank:?} must be refused");
            };
            assert!(msg.contains("empty one"), "{msg}");
        }
        let Err(Resolve::Ambiguous(msg)) = resolve_any(&programs, &apps, "brave") else {
            panic!("brave is both a program and a Store app");
        };
        assert!(
            msg.starts_with("\"brave\" matches 1 program and 1 Store app:"),
            "{msg}"
        );
        assert!(msg.contains("Brave  BraveSoftware Brave-Browser"), "{msg}");
        assert!(
            msg.contains("Brave (Store app)  Vendor.Brave_8wekyb3d8bbwe"),
            "{msg}"
        );
        // Either id picks one.
        assert!(matches!(
            resolve_any(&programs, &apps, "BraveSoftware Brave-Browser"),
            Ok(Resolved::Program(p)) if p.display_name == "Brave"
        ));
        assert_eq!(
            resolved_app(&programs, &apps, "Vendor.Brave_8wekyb3d8bbwe"),
            "Vendor.Brave_8wekyb3d8bbwe"
        );
        // In a batch the ambiguity stops everything.
        let err = plan_batch(&programs, &apps, &names(&["vlc", "brave"]), false).unwrap_err();
        assert!(
            format!("{err:#}").contains("\"brave\" matches 1 program and 1 Store app"),
            "{err:#}"
        );
    }

    #[test]
    fn an_exact_name_beats_a_part_of_another_kinds_name() {
        let programs = installed();
        let apps = vec![package("Vendor.Player", "VLC media player Remote")];
        assert!(matches!(
            resolve_any(&programs, &apps, "vlc media player"),
            Ok(Resolved::Program(p)) if p.display_name == "VLC media player"
        ));
        assert!(matches!(
            resolve_any(&programs, &apps, "vlc"),
            Err(Resolve::Ambiguous(_))
        ));
    }

    #[test]
    fn a_windows_signed_app_answers_only_to_its_exact_name() {
        let mut shell = package("Vendor.Shell", "Shell Helper");
        shell.signature = SignatureKind::System;
        let apps = vec![shell];
        assert!(matches!(
            resolve_any(&[], &apps, "helper"),
            Err(Resolve::NotFound)
        ));
        assert!(matches!(
            resolve_any(&[], &apps, "shell helper"),
            Ok(Resolved::Store(_))
        ));
    }

    #[test]
    fn a_batch_mixes_programs_and_store_apps_in_the_order_given() {
        let programs = installed();
        let apps = store_apps();
        let batch = plan_batch(
            &programs,
            &apps,
            &names(&["vlc", "calculator", "7-zip", "Windows Calculator"]),
            false,
        )
        .unwrap();
        assert_eq!(
            planned_names(&batch),
            [
                "VLC media player",
                "Windows Calculator",
                "7-Zip 24.08 (x64)"
            ]
        );
        assert!(matches!(&batch[1], Step::Store(app) if app.name == "Microsoft.WindowsCalculator"));
        assert_eq!(plan_of(&batch[2]).argv, [r"C:\7-Zip\Uninstall.exe"]);
    }

    #[test]
    fn a_store_app_the_guard_keeps_stops_the_whole_batch() {
        let programs = installed();
        let engine = package("Vendor.Engine", "Engine");
        let mut studio = package("Vendor.Studio", "Studio");
        studio.dependencies = vec![engine.family_name.clone()];
        let apps = vec![
            engine,
            studio,
            package("Microsoft.WindowsStore", "Microsoft Store"),
        ];
        let err = plan_batch(
            &programs,
            &apps,
            &names(&["vlc", "engine", "microsoft store", "nosuchapp"]),
            false,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.starts_with("nothing was uninstalled"), "{msg}");
        assert!(msg.contains("Engine stays: Studio depends on it"), "{msg}");
        assert!(
            msg.contains("Microsoft Store stays: a Windows component Oxidize keeps"),
            "{msg}"
        );
        assert!(
            msg.contains("no installed program or Store app matches \"nosuchapp\""),
            "{msg}"
        );
        // The dependent itself may go.
        let batch = plan_batch(&programs, &apps, &names(&["studio"]), false).unwrap();
        assert_eq!(planned_names(&batch), ["Studio"]);
    }

    #[test]
    fn scanning_a_store_app_points_to_uninstall() {
        let apps = store_apps();
        let app =
            store_app_named(&apps, "calculator").expect("the app answers to part of its name");
        assert_eq!(
            store_app_refusal("calculator", app),
            "\"calculator\" is the Store app Windows Calculator. Its leftovers are found when it is removed: oxidize uninstall \"Microsoft.WindowsCalculator_8wekyb3d8bbwe\""
        );
    }

    fn outcome(dry_run: bool) -> complete::Outcome {
        let folder = Leftover::fs(
            LeftoverKind::Directory,
            PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer"),
            Confidence::High,
            "named after the program",
            Some(10),
            false,
        );
        complete::Outcome {
            closed: if dry_run {
                Vec::new()
            } else {
                vec![complete::Closed {
                    pid: 100,
                    exe: r"C:\Users\me\AppData\Local\ExamplePlayer\player.exe".to_string(),
                    how: complete::CloseHow::Ended,
                    error: None,
                    windowless: false,
                }]
            },
            would_close: if dry_run {
                vec![complete::Running {
                    pid: 100,
                    exe: PathBuf::from(r"C:\Users\me\AppData\Local\ExamplePlayer\player.exe"),
                }]
            } else {
                Vec::new()
            },
            vendor: complete::VendorStep::Skip {
                reason: "installed for this user only".to_string(),
            },
            uninstaller: None,
            report: ScanReport {
                program_name: "Example Player".to_string(),
                installed: false,
                items: vec![folder.clone()],
            },
            selected: vec![folder],
            removal: (!dry_run).then(|| removed(1, 0, Some("2026-10-10 150000 Example Player"))),
            verdict: complete::Verdict {
                nothing_left: !dry_run,
                still_installed: dry_run,
                remaining: Vec::new(),
                below_level: 2,
                kept: Vec::new(),
            },
            error: None,
            seconds: 1.234,
        }
    }

    #[test]
    fn a_complete_removal_as_json_says_nothing_is_left() {
        let p = program(
            "Example Player",
            "example-player",
            Some(r"C:\x\uninstall.exe"),
        );
        let plan = uninstall::plan(&p, true).unwrap();
        let j = complete_json(&p, &plan, &outcome(false), Confidence::High, false);
        assert_eq!(j["nothing_left"], true);
        assert_eq!(j["still_installed"], false);
        assert_eq!(j["remaining"], json!([]));
        assert_eq!(j["below_level"], 2);
        assert_eq!(j["closed"][0]["how"], "ended");
        assert_eq!(j["uninstaller_step"]["action"], "skip");
        assert_eq!(j["uninstaller"], "skipped, installed for this user only");
        assert_eq!(j["removal"]["backup"], "2026-10-10 150000 Example Player");
        assert_eq!(j["level"], "high");
        assert_eq!(j["seconds"], 1.2);
        assert!(j.get("would_remove").is_none());
    }

    #[test]
    fn a_dry_run_as_json_lists_every_item_it_would_remove() {
        let p = program(
            "Example Player",
            "example-player",
            Some(r"C:\x\uninstall.exe"),
        );
        let plan = uninstall::plan(&p, true).unwrap();
        let j = complete_json(&p, &plan, &outcome(true), Confidence::High, true);
        assert_eq!(
            j["would_remove"][0]["path"],
            r"C:\Users\me\AppData\Local\ExamplePlayer"
        );
        assert_eq!(j["would_remove"][0]["confidence"], "High");
        assert_eq!(j["would_close"][0]["pid"], 100);
        assert!(j.get("nothing_left").is_none());
        assert!(j.get("closed").is_none());
    }

    #[test]
    fn a_removal_answered_no_is_a_cancel_and_a_failed_item_is_incomplete() {
        let g = Global {
            dry_run: false,
            yes: false,
            json: true,
            no_backup: false,
        };
        let no = DeletionOutcome::default();
        assert!(declined(3, &no, false));
        assert!(!declined(0, &no, false), "nothing selected, nothing asked");
        assert!(!declined(3, &no, true), "a dry run asks nothing");
        let code = |r: Result<()>| r.err().map(|e| exit::outcome(&e).exit);
        assert_eq!(
            code(removal_verdict(3, Some(&no), &g)),
            Some(exit::CANCELLED)
        );
        let failed = removed(2, 1, Some("b"));
        assert_eq!(
            code(removal_verdict(3, Some(&failed), &g)),
            Some(exit::INCOMPLETE)
        );
        assert_eq!(
            code(removal_verdict(3, Some(&removed(3, 0, Some("b"))), &g)),
            None
        );
        assert_eq!(code(removal_verdict(0, None, &g)), None);
    }

    #[test]
    fn something_left_after_the_second_scan_fails_the_run() {
        let mut r = run("Example Player", true, 3, Some(removed(3, 0, Some("b"))));
        assert!(!r.failed(false));
        r.left = 1;
        assert!(r.failed(false));
        assert_eq!(r.why_failed(), "1 items of Example Player are still there");
        // A dry run removes nothing, so nothing left over counts against it.
        assert!(!r.failed(true));
    }

    #[test]
    fn a_failed_run_exits_with_what_went_wrong() {
        let still = run("Example Player", false, 0, None).failure(true);
        assert_eq!(
            (still.code, still.exit),
            ("still_installed", exit::STILL_INSTALLED)
        );
        assert!(still.reported);

        let partly = run("Example Player", true, 3, Some(removed(2, 1, Some("b")))).failure(false);
        assert_eq!((partly.code, partly.exit), ("incomplete", exit::INCOMPLETE));
        assert_eq!(
            partly.message,
            "1 items of Example Player could not be removed"
        );
        assert!(!partly.reported);

        let mut left = run("Example Player", true, 3, Some(removed(3, 0, Some("b"))));
        left.left = 2;
        assert_eq!(left.failure(true).exit, exit::INCOMPLETE);

        let mut stopped = run("Example Player", false, 0, None);
        stopped.error = Some("no uninstaller".into());
        let f = stopped.failure(true);
        assert_eq!(
            (f.code, f.exit, f.message.as_str()),
            ("error", exit::ERROR, "no uninstaller")
        );
    }

    /// Answers yes to everything and prints JSON, so nothing waits on a prompt.
    fn unattended(dry_run: bool, no_backup: bool) -> Global {
        Global {
            dry_run,
            yes: true,
            json: true,
            no_backup,
        }
    }

    /// The fake store, a folder standing in for `%LOCALAPPDATA%` and a scan
    /// by name that finds one folder by the app's name.
    fn fake_env(store: &FakePackageStore, local_appdata: Option<PathBuf>) -> StoreEnv<'_> {
        StoreEnv {
            store,
            local_appdata,
            scan_by_name: |target| {
                vec![Leftover::fs(
                    crate::model::LeftoverKind::Directory,
                    PathBuf::from(format!(
                        r"C:\Users\x\AppData\Roaming\{}",
                        target.display_name
                    )),
                    Confidence::High,
                    "name match",
                    Some(0),
                    true,
                )]
            },
            running: &nothing_runs,
            has_window: &|_| true,
            close: &nothing_closes,
        }
    }

    fn nothing_runs() -> Vec<complete::Running> {
        Vec::new()
    }

    fn nothing_closes(_: &[complete::Running]) -> Vec<complete::Closed> {
        Vec::new()
    }

    /// The app's own process, a helper of its own without a window, and a
    /// process of another program.
    fn notes_running() -> Vec<complete::Running> {
        [
            (100, r"C:\Program Files\WindowsApps\Vendor.Notes\Notes.exe"),
            (
                101,
                r"C:\Program Files\WindowsApps\Vendor.Notes\sync\NotesSync.exe",
            ),
            (200, r"C:\Program Files\Other\other.exe"),
        ]
        .into_iter()
        .map(|(pid, exe)| complete::Running {
            pid,
            exe: PathBuf::from(exe),
        })
        .collect()
    }

    #[test]
    fn a_store_app_is_closed_before_windows_removes_it() {
        let notes = package("Vendor.Notes", "Notes");
        let store = FakePackageStore::new(notes_and_paint());
        // The pids asked to close, and how many removals had run by then.
        let asked = std::cell::RefCell::new(Vec::new());
        let close = |procs: &[complete::Running]| {
            let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
            asked
                .borrow_mut()
                .push((pids, store.removed.borrow().len()));
            procs
                .iter()
                .map(|p| complete::Closed {
                    pid: p.pid,
                    exe: p.exe.display().to_string(),
                    how: complete::CloseHow::Closed,
                    error: None,
                    windowless: p.pid == 101,
                })
                .collect()
        };
        let env = StoreEnv {
            scan_by_name: |_| Vec::new(),
            running: &notes_running,
            close: &close,
            ..fake_env(&store, None)
        };
        let run = run_package(
            &env,
            &notes,
            false,
            false,
            &LevelOpts::default(),
            &unattended(false, true),
        )
        .unwrap();
        assert_eq!(*asked.borrow(), [(vec![100, 101], 0)]);
        assert_eq!(store.removed.borrow().len(), 1);
        let closed = &run.json["closed"];
        assert_eq!(closed[0]["pid"], 100);
        assert!(closed[0].get("windowless").is_none(), "{closed}");
        assert_eq!(closed[1]["windowless"], true, "{closed}");
    }

    #[test]
    fn a_dry_run_names_what_it_would_close_and_closes_nothing() {
        let notes = package("Vendor.Notes", "Notes");
        let store = FakePackageStore::new(notes_and_paint());
        let env = StoreEnv {
            scan_by_name: |_| Vec::new(),
            running: &notes_running,
            has_window: &|pid| pid == 100,
            close: &|_| panic!("a dry run closes nothing"),
            ..fake_env(&store, None)
        };
        let run = run_package(
            &env,
            &notes,
            false,
            false,
            &LevelOpts::default(),
            &unattended(true, true),
        )
        .unwrap();
        assert!(store.removed.borrow().is_empty());
        let pids = |key: &str| -> Vec<u64> {
            run.json[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["pid"].as_u64().unwrap())
                .collect()
        };
        assert_eq!(pids("would_close"), [100, 101]);
        // The helper has no window to be asked through.
        assert_eq!(pids("would_end"), [101]);
    }

    /// A stand-in LocalAppData, removed when the test ends, passed or failed.
    struct LocalAppData(PathBuf);

    impl Drop for LocalAppData {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn local_appdata(tag: &str) -> LocalAppData {
        let dir = std::env::temp_dir().join(format!(
            "oxidize_store_uninstall_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Packages")).unwrap();
        LocalAppData(dir)
    }

    fn notes_and_paint() -> Vec<Package> {
        vec![
            package("Vendor.Notes", "Notes"),
            package("Vendor.Paint", "Paint"),
        ]
    }

    #[test]
    fn a_dry_run_never_removes_a_store_app() {
        let store = FakePackageStore::new(notes_and_paint());
        let env = fake_env(&store, None);
        let batch: Vec<Step> = notes_and_paint().into_iter().map(Step::Store).collect();
        let levels = LevelOpts::default();
        uninstall_batch(
            &env,
            &batch,
            &How::default(),
            &levels,
            &unattended(true, false),
        )
        .unwrap();
        uninstall_package(
            &env,
            &notes_and_paint()[0],
            false,
            &levels,
            &unattended(true, false),
        )
        .unwrap();
        assert!(store.removed.borrow().is_empty());
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn a_refused_store_app_never_reaches_the_removal() {
        let engine = package("Vendor.Engine", "Engine");
        let mut studio = package("Vendor.Studio", "Studio");
        studio.dependencies = vec![engine.family_name.clone()];
        let windows_store = package("Microsoft.WindowsStore", "Microsoft Store");
        let store = FakePackageStore::new(vec![engine.clone(), studio, windows_store.clone()]);
        let env = fake_env(&store, None);

        for app in [&engine, &windows_store] {
            let err = remove_package(&store, app, &mut || panic!("closed")).unwrap_err();
            assert!(format!("{err:#}").contains(" stays: "), "{err:#}");
        }
        // Even a batch that skipped planning stops at the removal.
        let batch = vec![Step::Store(engine), Step::Store(windows_store)];
        let err = uninstall_batch(
            &env,
            &batch,
            &How {
                keep: true,
                ..How::default()
            },
            &LevelOpts::default(),
            &unattended(false, false),
        )
        .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "2 of 2 Store apps did not uninstall cleanly"
        );
        assert!(store.removed.borrow().is_empty());
    }

    #[test]
    fn a_failed_removal_fails_the_run_and_the_batch() {
        let mut store = FakePackageStore::new(notes_and_paint());
        store.fail_with = Some("0x80073CFA, removal failed".to_string());
        let env = fake_env(&store, None);
        let g = unattended(false, false);
        let levels = LevelOpts::default();
        let notes = package("Vendor.Notes", "Notes");

        let Err(err) = run_package(&env, &notes, false, true, &levels, &g) else {
            panic!("the removal fails");
        };
        assert!(format!("{err:#}").contains("0x80073CFA"), "{err:#}");
        let stopped = ProgramRun::stopped_package(&notes, format!("{err:#}"));
        assert!(stopped.failed(false));
        assert_eq!(stopped.json["kind"], "store");
        assert_eq!(stopped.json["program"]["family_name"], notes.family_name);

        let batch: Vec<Step> = notes_and_paint().into_iter().map(Step::Store).collect();
        let keep = How {
            keep: true,
            ..How::default()
        };
        let err = uninstall_batch(&env, &batch, &keep, &levels, &g).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "2 of 2 Store apps did not uninstall cleanly"
        );
        assert!(uninstall_package(&env, &notes, true, &levels, &g).is_err());
        // Each app was tried once per run and none is gone.
        assert_eq!(store.removed.borrow().len(), 4);
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn an_app_windows_keeps_registered_is_a_failed_run() {
        let mut store = FakePackageStore::new(notes_and_paint());
        store.keeps_registered = true;
        let env = fake_env(&store, None);
        let g = unattended(false, false);
        let notes = package("Vendor.Notes", "Notes");
        let run = run_package(&env, &notes, false, false, &LevelOpts::default(), &g).unwrap();
        assert!(!run.gone);
        assert!(run.failed(false));
        assert_eq!(run.json["still_installed"], true);
        // Its data is still in use, so nothing is looked for or removed.
        assert_eq!(run.found, 0);
        assert!(run.removal.is_none());
        let err = uninstall_package(&env, &notes, false, &LevelOpts::default(), &g).unwrap_err();
        assert_eq!(format!("{err:#}"), "Notes is still registered");
        assert_eq!(exit::outcome(&err).exit, exit::STILL_INSTALLED);
    }

    #[test]
    fn a_removed_app_leads_to_its_leftovers() {
        let local = local_appdata("leftovers");
        let notes = package("Vendor.Notes", "Notes");
        let folder = local.0.join("Packages").join(&notes.family_name);
        std::fs::create_dir_all(folder.join("LocalState")).unwrap();
        std::fs::write(folder.join("LocalState").join("notes.db"), b"data").unwrap();
        let mut store = FakePackageStore::new(notes_and_paint());
        store.provisioned = vec![notes.family_name.clone()];
        let env = fake_env(&store, Some(local.0.clone()));

        let run = run_package(
            &env,
            &notes,
            false,
            true,
            &LevelOpts::default(),
            &unattended(false, false),
        )
        .unwrap();
        assert_eq!(*store.removed.borrow(), [notes.full_name.as_str()]);
        assert!(run.gone && !run.failed(false));
        let items = run.json["report"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["path"], folder.display().to_string());
        assert_eq!(items[0]["confidence"], "High");
        assert_eq!(items[1]["path"], r"C:\Users\x\AppData\Roaming\Notes");
        assert_eq!(items[1]["confidence"], "Medium");
        assert_eq!(run.json["may_come_back"], true);
        assert_eq!(run.leftovers(false), "2 leftovers kept");
        assert!(folder.exists(), "--keep leaves the folder");
    }

    #[test]
    fn the_data_folder_goes_through_the_leftover_removal() {
        let local = local_appdata("removal");
        let notes = package("Vendor.Notes", "Notes");
        let folder = local.0.join("Packages").join(&notes.family_name);
        std::fs::create_dir_all(folder.join("LocalState")).unwrap();
        let store = FakePackageStore::new(notes_and_paint());
        let env = StoreEnv {
            scan_by_name: |_| Vec::new(),
            ..fake_env(&store, Some(local.0.clone()))
        };
        // High only, and no backup so the test leaves nothing behind.
        let run = run_package(
            &env,
            &notes,
            false,
            false,
            &LevelOpts::default(),
            &unattended(false, true),
        )
        .unwrap();
        assert!(!folder.exists());
        assert_eq!(run.json["removal"]["removed"], 1);
        assert_eq!(
            run.json["removal"]["items"][0]["path"],
            folder.display().to_string()
        );
        assert!(!run.failed(false));
    }

    #[test]
    fn a_store_run_as_json_is_a_program_run_with_its_kind() {
        let store = FakePackageStore::new(notes_and_paint());
        let env = fake_env(&store, None);
        let notes = package("Vendor.Notes", "Notes");
        let run = run_package(
            &env,
            &notes,
            false,
            true,
            &LevelOpts::default(),
            &unattended(false, false),
        )
        .unwrap();
        let mut keys: Vec<&str> = run
            .json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "closed",
                "command",
                "kind",
                "may_come_back",
                "program",
                "report",
                "still_installed",
                "uninstaller"
            ]
        );
        assert_eq!(run.json["kind"], "store");
        assert_eq!(run.json["program"]["family_name"], notes.family_name);
        assert_eq!(
            run.json["command"],
            "remove package Vendor.Notes_1.2.3.0_x64__8wekyb3d8bbwe for this user"
        );

        // In a batch it sits next to the programs, with the same counts.
        let v = batch_json(&[run, self::run("VLC media player", true, 0, None)], false);
        let entries = v["programs"].as_array().unwrap();
        assert_eq!(entries[0]["kind"], "store");
        assert_eq!(entries[0]["failed"], false);
        assert_eq!(v["uninstalled"], 2);
        assert_eq!(v["failed"], 0);
    }

    #[test]
    fn an_app_already_gone_is_not_removed_again() {
        let store = FakePackageStore::new(Vec::new());
        let env = fake_env(&store, None);
        let notes = package("Vendor.Notes", "Notes");
        let run = run_package(
            &env,
            &notes,
            true,
            true,
            &LevelOpts::default(),
            &unattended(false, false),
        )
        .unwrap();
        assert!(run.gone);
        assert!(store.removed.borrow().is_empty());
        assert_eq!(run.json["uninstaller"], "not started, no longer registered");
    }

    #[test]
    fn counts_name_both_kinds() {
        assert_eq!(kinds(1, 0), "1 program");
        assert_eq!(kinds(3, 0), "3 programs");
        assert_eq!(kinds(0, 1), "1 Store app");
        assert_eq!(kinds(2, 2), "2 programs and 2 Store apps");
    }

    fn row_names(rows: &[Listed]) -> Vec<&str> {
        rows.iter().map(Listed::name).collect()
    }

    #[test]
    fn a_listed_program_keeps_its_json_and_gains_a_kind_in_front() {
        let p = program("Brave", "BraveSoftware Brave-Browser", Some("x.exe"));
        let before = serde_json::to_string_pretty(&p).unwrap();
        let listed = serde_json::to_string_pretty(&Listed::Program(p)).unwrap();
        assert!(
            listed.starts_with("{\n  \"kind\": \"program\",\n"),
            "{listed}"
        );
        assert_eq!(listed.replacen("\n  \"kind\": \"program\",", "", 1), before);
    }

    #[test]
    fn a_listed_store_app_says_what_it_is_and_why_it_stays() {
        let engine = package("Vendor.Engine", "Engine");
        let mut studio = package("Vendor.Studio", "Studio");
        studio.dependencies = vec![engine.family_name.clone()];
        let rows = store_rows(
            &FakePackageStore::new(vec![engine, studio]).list().unwrap(),
            false,
        );
        let v = serde_json::to_value(&rows).unwrap();
        assert_eq!(v[0]["kind"], "store");
        assert_eq!(v[0]["family_name"], "Vendor.Engine_8wekyb3d8bbwe");
        assert_eq!(v[0]["protected"], "Studio depends on it");
        assert_eq!(v[1]["signature"], "store");
        assert!(v[1]["protected"].is_null());
        let mut keys: Vec<&str> = v[1]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "dependencies",
                "display_name",
                "family_name",
                "full_name",
                "installed_date",
                "installed_path",
                "is_bundle",
                "is_framework",
                "is_resource",
                "is_sparse",
                "kind",
                "name",
                "protected",
                "publisher",
                "signature",
                "version",
            ]
        );
    }

    #[test]
    fn windows_own_packages_show_only_with_system_yet_always_count_for_the_guard() {
        let engine = package("Vendor.Engine", "Engine");
        let mut shell = package("Vendor.Shell", "Shell");
        shell.signature = SignatureKind::System;
        shell.dependencies = vec![engine.family_name.clone()];
        let store = FakePackageStore::new(vec![engine, shell]);

        let shown = store_rows(&store.list().unwrap(), false);
        assert_eq!(row_names(&shown), ["Engine"]);
        assert!(matches!(
            &shown[0],
            Listed::Store { protected: Some(Refusal::RequiredBy(by)), .. } if by == "Shell"
        ));

        let all = store_rows(&store.list().unwrap(), true);
        assert_eq!(row_names(&all), ["Engine", "Shell"]);
        assert!(matches!(
            &all[1],
            Listed::Store {
                protected: Some(Refusal::System),
                ..
            }
        ));
    }

    #[test]
    fn programs_and_store_apps_sort_filter_and_count_together() {
        let mut rows = vec![Listed::Program(program("Zed", "Zed", None))];
        rows.extend(store_rows(
            &FakePackageStore::new(vec![
                package("Vendor.Notes", "Notes"),
                package("Microsoft.WindowsStore", "Microsoft Store"),
            ])
            .list()
            .unwrap(),
            false,
        ));
        rows.push(Listed::Program(program("brave", "brave", None)));
        sort_rows(&mut rows, SortKey::Name);
        assert_eq!(
            row_names(&rows),
            ["brave", "Microsoft Store", "Notes", "Zed"]
        );
        assert_eq!(rows[2].source(), "store");
        assert_eq!(rows[3].source(), "");
        assert_eq!(list_footer(&rows), "2 programs, 2 Store apps (1 protected)");

        // A Store app also answers to its identity name.
        rows.retain(|r| r.matches("vendor.notes"));
        assert_eq!(row_names(&rows), ["Notes"]);
        assert_eq!(list_footer(&rows), "1 Store app");
    }

    #[test]
    fn a_dry_run_lists_every_item_it_would_remove() {
        let dir = std::env::temp_dir().join("oxidize_dry_run_list_test");
        let selected = vec![
            Leftover::fs(
                LeftoverKind::Directory,
                dir.join("Example Player"),
                Confidence::High,
                "install folder",
                None,
                false,
            ),
            Leftover::reg_value(
                Hive::CurrentUser,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "Example Player",
                Confidence::Medium,
                "autostart",
            ),
        ];
        let ctx = SafetyContext {
            dry_run: true,
            make_backups: true,
        };
        let outcome = safety::remove_leftovers(&selected, "Example Player", &ctx).unwrap();
        assert_eq!(outcome.items.len(), selected.len());
        assert!(outcome.backup_name.is_none());
        for (item, leftover) in outcome.items.iter().zip(&selected) {
            assert_eq!(item.path, leftover.path);
            assert!(matches!(item.status, ItemStatus::WouldRemove));
            assert!(item_line(item).contains(&leftover.path));
            assert!(item_line(item).contains("would remove"));
        }
        let json = removal_json(&Some(outcome));
        let items = json["items"].as_array().unwrap();
        assert_eq!(items.len(), selected.len());
        for (item, leftover) in items.iter().zip(&selected) {
            assert_eq!(item["path"], leftover.path.as_str());
            assert_eq!(item["status"], "would_remove");
        }
        // Nothing was gone before: a dry run counts every item as attempted only.
        assert_eq!(json["attempted"], selected.len());
        assert_eq!(json["already_gone"], 0);
        assert_eq!(json["removed"], 0);
    }

    #[test]
    fn a_service_only_marked_for_deletion_goes_at_the_next_restart() {
        let item = ItemOutcome {
            path: "Vendor Update Service".to_string(),
            kind: LeftoverKind::Service,
            status: ItemStatus::RemovedAfterRestart,
        };
        assert!(item_line(&item).contains("Vendor Update Service"));
        assert!(item_line(&item).contains("goes at the next restart"));
        let outcome = DeletionOutcome {
            attempted: 1,
            deleted: 1,
            items: vec![item],
            ..Default::default()
        };
        let json = removal_json(&Some(outcome));
        assert_eq!(json["items"][0]["status"], "removed_after_restart");
        assert_eq!(json["removed"], 1);
    }

    #[test]
    fn a_restore_asks_unless_told_not_to() {
        let never = || -> bool { panic!("asked") };
        // dry run, yes
        assert!(restore_goes_ahead(true, false, false, never));
        assert!(restore_goes_ahead(true, false, true, never));
        assert!(restore_goes_ahead(false, true, false, never));
        assert!(restore_goes_ahead(false, true, true, never));
        // --json cannot ask
        assert!(!restore_goes_ahead(false, false, true, never));
        // otherwise the answer decides
        assert!(restore_goes_ahead(false, false, false, || true));
        assert!(!restore_goes_ahead(false, false, false, || false));
    }

    #[test]
    fn a_name_that_resolves_to_nothing_or_several_is_typed() {
        let f = Resolve::NotFound.into_failure("Example Player");
        assert_eq!((f.code, f.exit), ("not_found", exit::ERROR));
        assert_eq!(f.message, not_found("Example Player"));
        let f = Resolve::Ambiguous("two match".into()).into_failure("Example");
        assert_eq!((f.code, f.message.as_str()), ("ambiguous", "two match"));
    }

    #[test]
    fn a_batch_with_an_unknown_name_fails_as_not_found() {
        let programs = vec![program("Example Player", "ExamplePlayer", Some("u.exe"))];
        let targets = vec!["Example Player".to_string(), "Nothing Here".to_string()];
        let err = plan_batch(&programs, &[], &targets, false).unwrap_err();
        let o = exit::outcome(&err);
        assert_eq!((o.code, o.exit), ("not_found", exit::ERROR));
        assert!(o.message.starts_with("nothing was uninstalled"));
    }
}
