//! Command handlers: wire the engine together and print results. All
//! user-facing text lives here so the lower layers stay quiet.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::json;

use crate::backup;
use crate::cli::{
    BackupsArgs, Cli, Commands, LevelOpts, ListArgs, OrphansArgs, RestoreArgs, ScanArgs, SortKey,
    TraceArgs, UninstallArgs,
};
use crate::model::{
    Confidence, Group, Leftover, Package, Program, ScanReport, ScanTarget, SignatureKind,
};
use crate::packages::{
    self, package_guard, PackageStore, Refusal, RemovalOutcome, WindowsPackageStore,
};
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
    let mut rows: Vec<Listed> = Vec::new();
    if !args.store {
        rows.extend(
            registry::enumerate_installed_programs(args.system)
                .into_iter()
                .map(Listed::Program),
        );
    }
    match store_rows(&WindowsPackageStore, args.system) {
        Ok(apps) => rows.extend(apps),
        Err(e) if args.store => return Err(e),
        // The programs are still worth listing.
        Err(e) => term::warn(&format!("Store apps left out: {e:#}")),
    }
    if let Some(filter) = &args.filter {
        let needle = filter.to_lowercase();
        rows.retain(|r| r.matches(&needle));
    }
    sort_rows(&mut rows, args.sort);

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

/// One entry of `list`: a program from the registry or a Store app. As JSON
/// it is the program or package with a `kind` in front.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Listed {
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
fn store_rows(store: &dyn PackageStore, system: bool) -> Result<Vec<Listed>> {
    let packages = store.list()?;
    Ok(packages
        .iter()
        .filter(|p| system || p.signature != SignatureKind::System)
        .map(|p| Listed::Store {
            package: p.clone(),
            protected: package_guard(p, &packages).err(),
        })
        .collect())
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
    let (target, installed, label) = match resolve_target(&programs, &args.target) {
        Ok(program) => (
            scanner::build_target(program),
            true,
            program.display_name.clone(),
        ),
        Err(Resolve::Ambiguous(msg)) => bail!("{msg}"),
        Err(Resolve::NotFound) => {
            let packages = WindowsPackageStore.list().unwrap_or_default();
            if let Some(app) = store_app_named(&packages, &args.target) {
                bail!("{}", store_app_refusal(&args.target, app));
            }
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
    let env = StoreEnv::windows();
    let packages = installed_store_apps(env.store, g);
    if let [target] = args.targets.as_slice() {
        return match resolve_any(&programs, &packages, target) {
            Ok(Resolved::Program(program)) => {
                let program = program.clone();
                uninstall_program(&program, args.silent, args.keep, &args.levels, g)
            }
            Ok(Resolved::Store(app)) => {
                if let Err(reason) = package_guard(app, &packages) {
                    bail!("{}", kept(app, &reason));
                }
                uninstall_package(&env, app, args.keep, &args.levels, g)
            }
            Err(Resolve::NotFound) => bail!("{}", not_found(target)),
            Err(Resolve::Ambiguous(msg)) => bail!("{msg}"),
        };
    }
    let batch = plan_batch(&programs, &packages, &args.targets, args.silent)?;
    uninstall_batch(&env, &batch, args.keep, &args.levels, g)
}

/// A program of a batch with the command that uninstalls it.
#[derive(Debug)]
struct Planned {
    program: Program,
    plan: uninstall::UninstallPlan,
}

/// One entry of a batch: a program and its uninstaller, or a Store app the
/// guard lets go.
#[derive(Debug)]
enum Step {
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
fn plan_batch(
    programs: &[Program],
    packages: &[Package],
    targets: &[String],
    silent: bool,
) -> Result<Vec<Step>> {
    let mut planned: Vec<Step> = Vec::new();
    let mut problems = Vec::new();
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
            Err(Resolve::NotFound) => problems.push(not_found(target)),
            Err(Resolve::Ambiguous(msg)) => problems.push(msg),
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
fn same_program(a: &Program, b: &Program) -> bool {
    a.id() == b.id() && a.source == b.source
}

/// Show the whole plan, ask once, then uninstall the programs and remove the
/// Store apps one after another, each with its own leftover scan, removal
/// and backup.
fn uninstall_batch(
    env: &StoreEnv,
    batch: &[Step],
    keep: bool,
    levels: &LevelOpts,
    g: &Global,
) -> Result<()> {
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
        return Ok(());
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
                run_uninstall(&b.program, &target, &b.plan, already_gone, keep, levels, g)
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
    let failed = runs.iter().filter(|r| r.failed(g.dry_run)).count();
    if failed > 0 {
        bail!(
            "{failed} of {} did not uninstall cleanly",
            kinds(programs, apps)
        );
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
            let json_out = json!({ "kind": "program", "program": program, "command": plan.display(), "cancelled": true });
            println!("{}", serde_json::to_string_pretty(&json_out)?);
        } else {
            term::info("Cancelled.");
        }
        return Ok(());
    }

    let run = run_uninstall(program, &target, &plan, false, keep, levels, g)?;
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
            json: json!({ "kind": "program", "program": program, "command": plan.display(), "error": error }),
            gone: false,
            found: 0,
            removal: None,
            error: Some(error),
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
/// leftovers. `target` is the footprint captured before anything ran. A
/// program that is `already_gone` goes straight to its leftovers.
fn run_uninstall(
    program: &Program,
    target: &ScanTarget,
    plan: &uninstall::UninstallPlan,
    already_gone: bool,
    keep: bool,
    levels: &LevelOpts,
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

/// Said before any Store app is removed, whatever the flags.
const STORE_APP_WARNING: &str =
    "Removing a Store app deletes its data with it; reinstalling means the Store. \
     The removal itself cannot be backed up, only the leftovers found after it.";

/// What removing a Store app works with: the package store, the folder the
/// apps keep their data in, and the scan by name for everything else.
struct StoreEnv<'a> {
    store: &'a dyn PackageStore,
    /// `%LOCALAPPDATA%`, whose `Packages` folder holds the apps' data.
    local_appdata: Option<PathBuf>,
    scan_by_name: fn(&ScanTarget) -> Vec<Leftover>,
}

impl StoreEnv<'static> {
    fn windows() -> Self {
        StoreEnv {
            store: &WindowsPackageStore,
            local_appdata: scanner::env_dir("LOCALAPPDATA"),
            scan_by_name: |target| scanner::scan(target, false).items,
        }
    }
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
fn package_command(app: &Package) -> String {
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
        return Ok(());
    }

    let run = match run_package(env, app, false, keep, levels, g) {
        Ok(run) => run,
        Err(e) => {
            if g.json {
                let stopped = ProgramRun::stopped_package(app, format!("{e:#}"));
                println!("{}", serde_json::to_string_pretty(&stopped.json)?);
            }
            return Err(e);
        }
    };
    if g.json {
        println!("{}", serde_json::to_string_pretty(&run.json)?);
    }
    if !g.dry_run && !run.gone {
        bail!("{} is still registered", app.display_name);
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
        if !g.json {
            println!(
                "{}",
                term::dim(
                    "dry run: the app was not removed; Windows deletes its data folder with it"
                )
            );
        }
    } else if already_gone {
        if !g.json {
            println!("{name} is no longer registered, so it was not removed again.");
        }
        gone = true;
        json_out["uninstaller"] = json!("not started, no longer registered");
        json_out["still_installed"] = json!(false);
    } else {
        gone = remove_package(env.store, app)? == RemovalOutcome::Removed;
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
        let target = scanner::name_target(name, app.publisher.as_deref());
        let report = ScanReport {
            program_name: name.clone(),
            installed: false,
            items: packages::leftovers(app, local, (env.scan_by_name)(&target)),
        };
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
    })
}

/// Remove a Store app after asking the guard once more against a fresh
/// listing: a refused app never reaches the removal.
fn remove_package(store: &dyn PackageStore, app: &Package) -> Result<RemovalOutcome> {
    let installed = store.list()?;
    if let Err(reason) = package_guard(app, &installed) {
        bail!("{}", kept(app, &reason));
    }
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

/// A name `uninstall` acts on: a program or a Store app.
#[derive(Debug, Clone, Copy)]
enum Resolved<'a> {
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
fn resolve_any<'a>(
    programs: &'a [Program],
    packages: &'a [Package],
    target: &str,
) -> std::result::Result<Resolved<'a>, Resolve> {
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
        }
    }

    fn local_appdata(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oxidize_store_uninstall_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Packages")).unwrap();
        dir
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
        uninstall_batch(&env, &batch, false, &levels, &unattended(true, false)).unwrap();
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
            let err = remove_package(&store, app).unwrap_err();
            assert!(format!("{err:#}").contains(" stays: "), "{err:#}");
        }
        // Even a batch that skipped planning stops at the removal.
        let batch = vec![Step::Store(engine), Step::Store(windows_store)];
        let err = uninstall_batch(
            &env,
            &batch,
            true,
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
        let err = uninstall_batch(&env, &batch, true, &levels, &g).unwrap_err();
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
    }

    #[test]
    fn a_removed_app_leads_to_its_leftovers() {
        let local = local_appdata("leftovers");
        let notes = package("Vendor.Notes", "Notes");
        let folder = local.join("Packages").join(&notes.family_name);
        std::fs::create_dir_all(folder.join("LocalState")).unwrap();
        std::fs::write(folder.join("LocalState").join("notes.db"), b"data").unwrap();
        let mut store = FakePackageStore::new(notes_and_paint());
        store.provisioned = vec![notes.family_name.clone()];
        let env = fake_env(&store, Some(local.clone()));

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
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn the_data_folder_goes_through_the_leftover_removal() {
        let local = local_appdata("removal");
        let notes = package("Vendor.Notes", "Notes");
        let folder = local.join("Packages").join(&notes.family_name);
        std::fs::create_dir_all(folder.join("LocalState")).unwrap();
        let store = FakePackageStore::new(notes_and_paint());
        let env = StoreEnv {
            scan_by_name: |_| Vec::new(),
            ..fake_env(&store, Some(local.clone()))
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
        let _ = std::fs::remove_dir_all(&local);
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
        let rows = store_rows(&FakePackageStore::new(vec![engine, studio]), false).unwrap();
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

        let shown = store_rows(&store, false).unwrap();
        assert_eq!(row_names(&shown), ["Engine"]);
        assert!(matches!(
            &shown[0],
            Listed::Store { protected: Some(Refusal::RequiredBy(by)), .. } if by == "Shell"
        ));

        let all = store_rows(&store, true).unwrap();
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
        rows.extend(
            store_rows(
                &FakePackageStore::new(vec![
                    package("Vendor.Notes", "Notes"),
                    package("Microsoft.WindowsStore", "Microsoft Store"),
                ]),
                false,
            )
            .unwrap(),
        );
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
}
