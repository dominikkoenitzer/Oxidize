//! `oxidize mcp`: a local MCP server on stdin and stdout, so an AI assistant
//! can look at installed programs and their leftovers and remove one the
//! user agreed to.
//!
//! Every tool only reads, except `apply_removal_plan`. `plan_removal` keeps
//! each plan it returns under an id while the server runs, and
//! `apply_removal_plan` carries out one such plan, exactly as shown, once,
//! with a backup of every item it removes. The client asks the user before
//! each tool call.
//!
//! The machine is reached through two traits: [`Inspect`] reads, [`Remove`]
//! changes, and only `apply_removal_plan` holds the second.

mod machine;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::backup::BackupInfo;
use crate::cli::{LevelOpts, ListArgs, SortKey};
use crate::commands::{self, Planned, Resolved, Step};
use crate::complete::{self, Closed, Running, VendorStep};
use crate::hunter::HunterMatch;
use crate::model::{Confidence, Group, Leftover, Package, Program, ScanReport, ScanTarget};
use crate::orphans::OrphanReport;
use crate::safety::{self, DeletionOutcome, ItemStatus};
use crate::uninstall::UninstallPlan;

pub use machine::{Remover, ThisPc};

/// Everything the server reads. Nothing here changes the machine.
pub trait Inspect: Send + Sync {
    /// Programs from the Uninstall keys; `system` adds hidden components.
    fn programs(&self, system: bool) -> Vec<Program>;
    fn store_apps(&self) -> Result<Vec<Package>>;
    /// What a scan for an installed program looks for.
    fn target(&self, program: &Program) -> ScanTarget;
    /// What a scan by name looks for.
    fn target_by_name(&self, name: &str, publisher: Option<&str>) -> ScanTarget;
    fn scan(&self, target: &ScanTarget, installed: bool) -> ScanReport;
    fn orphans(&self, programs: &[Program]) -> OrphanReport;
    fn trace(&self, query: &str, programs: &[Program]) -> Vec<HunterMatch>;
    fn backups(&self) -> Result<Vec<BackupInfo>>;
    fn backups_folder(&self) -> Option<PathBuf>;
    fn local_appdata(&self) -> Option<PathBuf>;
    fn is_elevated(&self) -> bool;
    /// Every running process with a known image.
    fn running(&self) -> Vec<Running>;
    /// The machine-wide folders, which need administrator rights.
    fn machine_dirs(&self) -> Vec<PathBuf>;
}

/// The one way the server changes anything: carrying out an approved plan.
/// There is no removal without a backup here.
pub trait Remove: Send + Sync {
    /// Run a program's uninstaller and wait for it; says how it ended.
    fn uninstall(&self, plan: &UninstallPlan) -> Result<String>;
    /// Wait for the program to leave the Uninstall list; true once it has.
    fn wait_until_gone(&self, program: &Program, plan: &UninstallPlan) -> bool;
    /// Remove a Store app; true once Windows no longer lists it.
    fn remove_app(&self, app: &Package) -> Result<bool>;
    /// Close these processes: their windows first, then end them.
    fn close(&self, procs: &[Running]) -> Vec<Closed>;
    /// Remove leftovers, each one backed up first.
    fn remove_items(&self, items: &[Leftover], label: &str) -> Result<DeletionOutcome>;
}

/// Said to the assistant when it connects.
const INSTRUCTIONS: &str = "Oxidize finds the Windows programs and Store apps installed on this PC \
and what they leave behind. Every tool only reads, except apply_removal_plan. To remove a program, \
call plan_removal, show the user the plan, and call apply_removal_plan with its plan_id only once the \
user agrees. A plan is carried out exactly as shown and only once; every item it removes is backed \
up first, and the result names the backup and the command that restores it.";

// Tool arguments
// --------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ListParams {
    /// Only programs and Store apps whose name or publisher contains this text.
    #[serde(default)]
    pub filter: Option<String>,
    /// Include hidden system components and the Store apps that are part of Windows.
    #[serde(default)]
    pub system: bool,
    /// Only Store apps.
    #[serde(default)]
    pub store: bool,
    /// Sort order. Size and date sort largest and newest first.
    #[serde(default)]
    pub sort: Sort,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Sort {
    #[default]
    Name,
    Size,
    Date,
    Publisher,
}

impl From<Sort> for SortKey {
    fn from(sort: Sort) -> Self {
        match sort {
            Sort::Name => SortKey::Name,
            Sort::Size => SortKey::Size,
            Sort::Date => SortKey::Date,
            Sort::Publisher => SortKey::Publisher,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanParams {
    /// Program name, a unique part of it, or its registry id. A program that
    /// is no longer installed is scanned by name.
    pub program: String,
    /// Publisher, to tell vendor folders apart when scanning by name.
    #[serde(default)]
    pub publisher: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TraceParams {
    /// Path to an .exe or a folder, or the name of a running process.
    pub query: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanParams {
    /// Programs or Store apps to remove: a name, a unique part of it, or an
    /// id, in the order they should go. A name nothing installed answers to
    /// plans the removal of its leftovers.
    pub programs: Vec<String>,
    /// Use each program's unattended uninstall switches where it has them.
    #[serde(default)]
    pub silent: bool,
    /// Which leftovers to remove: high (the default), medium (high and
    /// medium) or all.
    #[serde(default)]
    pub level: Level,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    #[default]
    High,
    Medium,
    All,
}

impl Level {
    fn opts(self) -> LevelOpts {
        LevelOpts {
            medium: self == Level::Medium,
            all: self == Level::All,
        }
    }

    /// The lowest confidence this level removes.
    fn confidence(self) -> Confidence {
        match self {
            Level::High => Confidence::High,
            Level::Medium => Confidence::Medium,
            Level::All => Confidence::Low,
        }
    }

    /// The command-line flag that picks this level.
    fn flag(self) -> &'static str {
        match self {
            Level::High => "",
            Level::Medium => " --medium",
            Level::All => " --all",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyParams {
    /// The plan_id plan_removal returned in this session.
    pub plan_id: String,
}

// Reading
// -------

fn list_programs(m: &dyn Inspect, p: ListParams) -> Result<Value> {
    let args = ListArgs {
        filter: p.filter,
        system: p.system,
        store: p.store,
        sort: p.sort.into(),
    };
    let programs = if args.store {
        Vec::new()
    } else {
        m.programs(args.system)
    };
    let rows = commands::list_rows(programs, m.store_apps(), &args)?;
    Ok(json!({ "programs": rows }))
}

fn scan_leftovers(m: &dyn Inspect, p: ScanParams) -> Result<Value> {
    let programs = m.programs(true);
    let installed =
        commands::scan_subject(&programs, || m.store_apps().unwrap_or_default(), &p.program)?;
    let report = match installed {
        Some(program) => m.scan(&m.target(program), true),
        None => m.scan(&m.target_by_name(&p.program, p.publisher.as_deref()), false),
    };
    Ok(serde_json::to_value(report)?)
}

fn find_orphans(m: &dyn Inspect) -> Result<Value> {
    let programs = m.programs(true);
    Ok(serde_json::to_value(m.orphans(&programs))?)
}

fn trace(m: &dyn Inspect, p: TraceParams) -> Result<Value> {
    let programs = m.programs(true);
    let matches = m.trace(&p.query, &programs);
    Ok(json!({ "matches": commands::trace_json(&matches) }))
}

fn list_backups(m: &dyn Inspect) -> Result<Value> {
    Ok(json!({
        "folder": m.backups_folder(),
        "backups": m.backups()?,
        "restore_command": "oxidize restore \"<name>\"",
    }))
}

// Plans
// -----

/// One entry of a removal plan, with what carrying it out needs.
#[derive(Debug, Clone)]
enum PlanStep {
    /// Close what runs from the program's folders, run its uninstaller
    /// unless `vendor` skips it, then remove the leftovers listed.
    Program {
        program: Box<Program>,
        uninstaller: UninstallPlan,
        vendor: VendorStep,
        target: ScanTarget,
        leftovers: Vec<Leftover>,
    },
    /// Remove the Store app, then the leftovers listed.
    Store {
        app: Package,
        leftovers: Vec<Leftover>,
    },
    /// Nothing installed answers to the name: remove the leftovers listed.
    Leftovers {
        name: String,
        target: ScanTarget,
        leftovers: Vec<Leftover>,
    },
}

impl PlanStep {
    fn name(&self) -> &str {
        match self {
            PlanStep::Program { program, .. } => &program.display_name,
            PlanStep::Store { app, .. } => &app.display_name,
            PlanStep::Leftovers { name, .. } => name,
        }
    }

    fn leftovers(&self) -> &[Leftover] {
        match self {
            PlanStep::Program { leftovers, .. }
            | PlanStep::Store { leftovers, .. }
            | PlanStep::Leftovers { leftovers, .. } => leftovers,
        }
    }
}

#[derive(Debug, Clone)]
struct RemovalPlan {
    steps: Vec<PlanStep>,
    level: Level,
    /// The commands that do the same from a terminal.
    commands: Vec<String>,
}

/// Resolve every name and list what removing it takes, the way
/// `oxidize uninstall` plans a batch: any name that matches several, any
/// program without an uninstaller and any Store app Windows needs stops the
/// whole plan. Leftovers are what a scan finds now, at the level asked for.
fn make_plan(m: &dyn Inspect, p: &PlanParams) -> Result<RemovalPlan> {
    if p.programs.is_empty() {
        bail!("name at least one program");
    }
    let programs = m.programs(true);
    let packages = m.store_apps().unwrap_or_default();
    let levels = p.level.opts();
    // A name nothing installed answers to plans its leftovers, like
    // `oxidize scan --remove`; every other name goes through the batch plan.
    let (gone, installed): (Vec<String>, Vec<String>) =
        p.programs.iter().cloned().partition(|name| {
            matches!(
                commands::resolve_any(&programs, &packages, name),
                Err(commands::Resolve::NotFound)
            ) && matches!(
                commands::scan_subject(&programs, || packages.clone(), name),
                Ok(None)
            )
        });

    let mut steps = Vec::new();
    if !installed.is_empty() {
        let machine_dirs = m.machine_dirs();
        for step in commands::plan_batch(&programs, &packages, &installed, p.silent)? {
            steps.push(match step {
                Step::Program(Planned { program, plan }) => {
                    let target = m.target(&program);
                    // Scanned as if gone, so its own uninstall entry is listed.
                    let report = m.scan(&target, false);
                    let leftovers = commands::selected_leftovers(&report, &levels);
                    let vendor = vendor_step(
                        &program,
                        &plan,
                        &target,
                        &report.items,
                        &leftovers,
                        &machine_dirs,
                    );
                    PlanStep::Program {
                        leftovers,
                        program: Box::new(program),
                        uninstaller: plan,
                        vendor,
                        target,
                    }
                }
                Step::Store(app) => {
                    // Windows deletes the data folder with the app.
                    let report =
                        commands::store_app_leftovers(&app, None, |t| m.scan(t, false).items);
                    PlanStep::Store {
                        leftovers: commands::selected_leftovers(&report, &levels),
                        app,
                    }
                }
            });
        }
    }
    for name in gone {
        let target = m.target_by_name(&name, None);
        let report = m.scan(&target, false);
        if report.is_empty() {
            bail!("no installed program or Store app matches \"{name}\", and nothing by that name was found");
        }
        steps.push(PlanStep::Leftovers {
            leftovers: commands::selected_leftovers(&report, &levels),
            name,
            target,
        });
    }
    let commands = user_commands(&steps, &programs, &packages, p.silent, p.level);
    Ok(RemovalPlan {
        steps,
        level: p.level,
        commands,
    })
}

/// The program's own uninstall entry, as a leftover.
fn own_entry(program: &Program) -> Leftover {
    Leftover::reg_key(
        program.source.hive,
        format!(
            "{}\\{}",
            program.source.view.uninstall_base(),
            program.registry_key
        ),
        Confidence::High,
        "orphaned uninstall entry",
    )
}

/// Whether the program's uninstaller runs. Skipping it needs the program's
/// own uninstall entry among the leftovers, or it would stay registered.
fn vendor_step(
    program: &Program,
    plan: &UninstallPlan,
    target: &ScanTarget,
    footprint: &[Leftover],
    leftovers: &[Leftover],
    machine_dirs: &[PathBuf],
) -> VendorStep {
    let step = complete::vendor_step(program, plan, target, footprint, machine_dirs);
    let entry = own_entry(program).path;
    if step.runs()
        || leftovers
            .iter()
            .any(|l| l.path.eq_ignore_ascii_case(&entry))
    {
        return step;
    }
    VendorStep::Run {
        silent: complete::runs_silently(program, plan),
        reason: "its uninstall entry was not found".to_string(),
    }
}

/// Whether the program is still in the Uninstall list.
fn registered(m: &dyn Inspect, program: &Program) -> bool {
    m.programs(true)
        .iter()
        .any(|p| commands::same_program(p, program))
}

/// Close the processes that run from a step's folders. Returns what was
/// closed; nothing when no folder of its own is known.
fn close_running(
    m: &dyn Inspect,
    r: &dyn Remove,
    target: &ScanTarget,
    planned: &[Leftover],
) -> Vec<Closed> {
    let dirs = complete::owned_dirs(target, planned);
    if dirs.is_empty() {
        return Vec::new();
    }
    let picked = complete::processes_in(&m.running(), &dirs, std::process::id());
    if picked.is_empty() {
        return Vec::new();
    }
    r.close(&picked)
}

/// The commands a user would run for the same plan.
fn user_commands(
    steps: &[PlanStep],
    programs: &[Program],
    packages: &[Package],
    silent: bool,
    level: Level,
) -> Vec<String> {
    let flags = format!("{}{}", if silent { " --silent" } else { "" }, level.flag());
    let names: Vec<String> = steps
        .iter()
        .filter(|s| !matches!(s, PlanStep::Leftovers { .. }))
        .map(|s| cli_name(s, programs, packages))
        .collect();
    let mut out = Vec::new();
    if !names.is_empty() {
        out.push(format!("oxidize uninstall {}{flags}", names.join(" ")));
    }
    for step in steps {
        if let PlanStep::Leftovers { name, .. } = step {
            out.push(scan_remove_command(name, level));
        }
    }
    out
}

/// The step's name as a command argument, or its id when the name would
/// pick something else.
fn cli_name(step: &PlanStep, programs: &[Program], packages: &[Package]) -> String {
    let name = step.name();
    let same = match (commands::resolve_any(programs, packages, name), step) {
        (Ok(Resolved::Program(p)), PlanStep::Program { program, .. }) => {
            commands::same_program(p, program)
        }
        (Ok(Resolved::Store(a)), PlanStep::Store { app, .. }) => a.family_name == app.family_name,
        _ => false,
    };
    let arg = match step {
        _ if same => name,
        PlanStep::Program { program, .. } => program.id(),
        PlanStep::Store { app, .. } => &app.family_name,
        PlanStep::Leftovers { name, .. } => name,
    };
    format!("\"{arg}\"")
}

fn scan_remove_command(name: &str, level: Level) -> String {
    format!("oxidize scan \"{name}\" --remove{}", level.flag())
}

/// Bytes in the files and folders among `items`.
fn file_bytes(items: &[Leftover]) -> u64 {
    items
        .iter()
        .filter(|l| l.kind.group() == Group::Files)
        .filter_map(|l| l.size_bytes)
        .sum()
}

fn plan_json(id: &str, plan: &RemovalPlan, m: &dyn Inspect) -> Value {
    let steps: Vec<Value> = plan
        .steps
        .iter()
        .map(|step| {
            let leftovers = step.leftovers();
            let mut out = match step {
                PlanStep::Program {
                    program,
                    uninstaller,
                    vendor,
                    ..
                } => json!({
                    "kind": "program",
                    "name": program.display_name,
                    "id": program.id(),
                    "uninstaller": uninstaller.display(),
                    "uninstaller_source": uninstaller.source,
                    "uninstaller_step": vendor,
                }),
                PlanStep::Store { app, .. } => json!({
                    "kind": "store",
                    "name": app.display_name,
                    "id": app.family_name,
                    "uninstaller": commands::package_command(app),
                    "warning": commands::STORE_APP_WARNING,
                }),
                PlanStep::Leftovers { name, .. } => json!({
                    "kind": "leftovers",
                    "name": name,
                    "uninstaller": null,
                }),
            };
            out["leftovers"] = json!(leftovers);
            out["bytes"] = json!(file_bytes(leftovers));
            out["needs_admin"] = json!(safety::needs_elevation(leftovers));
            out
        })
        .collect();
    let all: Vec<Leftover> = plan
        .steps
        .iter()
        .flat_map(|s| s.leftovers().iter().cloned())
        .collect();
    json!({
        "plan_id": id,
        "steps": steps,
        "leftovers": all.len(),
        "bytes": file_bytes(&all),
        "needs_admin": safety::needs_elevation(&all),
        "elevated": m.is_elevated(),
        "backup_folder": m.backups_folder(),
        "how": "Running copies of each program are closed first. A program installed for this user \
    only, with nothing machine-wide, is removed by Oxidize alone, its uninstall entry included; any \
    other uninstaller runs in turn and Oxidize waits up to two minutes for it to finish. Then exactly \
    the leftovers listed are removed, each one backed up first. Nothing else is touched.",
        "apply": "apply_removal_plan with this plan_id, once the user agrees",
        "commands": plan.commands,
    })
}

/// Plans made in this session, each until it is applied.
#[derive(Default)]
struct Plans {
    made: u64,
    open: HashMap<String, RemovalPlan>,
}

impl Plans {
    fn keep(&mut self, plan: RemovalPlan) -> String {
        self.made += 1;
        let salt = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let id = format!("plan-{}-{salt:08x}", self.made);
        self.open.insert(id.clone(), plan);
        id
    }

    fn take(&mut self, id: &str) -> Option<RemovalPlan> {
        self.open.remove(id)
    }
}

// Applying
// --------

/// Carry out a plan, step after step. One step failing does not stop the
/// next. Only the leftovers the plan listed are removed; what a scan finds
/// afterwards is reported, not touched.
fn apply(m: &dyn Inspect, r: &dyn Remove, id: &str, plan: &RemovalPlan) -> Value {
    let elevated = m.is_elevated();
    let steps: Vec<Value> = plan
        .steps
        .iter()
        .map(|step| apply_step(m, r, step, plan.level, elevated))
        .collect();
    let backups: Vec<&Value> = steps
        .iter()
        .filter_map(|s| s.get("backup"))
        .filter(|b| !b.is_null())
        .collect();
    let failed = steps.iter().filter(|s| s["failed"] == json!(true)).count();
    json!({
        "plan_id": id,
        "steps": steps,
        "failed": failed,
        "backups": backups,
    })
}

fn apply_step(
    m: &dyn Inspect,
    r: &dyn Remove,
    step: &PlanStep,
    level: Level,
    elevated: bool,
) -> Value {
    let name = step.name().to_string();
    let mut out = json!({ "name": name });
    let gone = match step {
        PlanStep::Program {
            program,
            uninstaller,
            vendor,
            target,
            leftovers,
        } => {
            out["kind"] = json!("program");
            out["closed"] = json!(close_running(m, r, target, leftovers));
            if !registered(m, program) {
                out["uninstaller"] = json!("not started, no longer registered");
                Ok(true)
            } else if let VendorStep::Skip { reason } = vendor {
                // The uninstall entry goes with the leftovers.
                out["uninstaller"] = json!(format!("not started, {reason}"));
                Ok(true)
            } else {
                r.uninstall(uninstaller).map(|described| {
                    out["uninstaller"] = json!(described);
                    r.wait_until_gone(program, uninstaller)
                })
            }
        }
        PlanStep::Store { app, .. } => {
            out["kind"] = json!("store");
            let registered = m
                .store_apps()
                .map(|apps| apps.iter().any(|a| a.family_name == app.family_name))
                // Unknown counts as registered: the removal says what is wrong.
                .unwrap_or(true);
            if !registered {
                out["uninstaller"] = json!("not started, no longer registered");
                Ok(true)
            } else {
                out["uninstaller"] = json!("removed by Windows");
                r.remove_app(app)
            }
        }
        PlanStep::Leftovers {
            target, leftovers, ..
        } => {
            out["kind"] = json!("leftovers");
            let programs = m.programs(true);
            match commands::scan_subject(&programs, Vec::new, &name) {
                Ok(None) => {
                    out["closed"] = json!(close_running(m, r, target, leftovers));
                    Ok(true)
                }
                Ok(Some(_)) => Err(anyhow!("{name} is installed now. Plan its removal again.")),
                Err(e) => Err(e.context(format!(
                    "{name} now answers to an installed program, so nothing was removed. Plan again"
                ))),
            }
        }
    };
    let gone = match gone {
        Ok(gone) => gone,
        Err(e) => {
            out["error"] = json!(format!("{e:#}"));
            out["failed"] = json!(true);
            return out;
        }
    };
    if !gone {
        out["still_installed"] = json!(true);
        out["error"] = json!(format!(
            "{name} is still registered. The uninstaller may have been cancelled or is still running, so its leftovers were not removed."
        ));
        out["failed"] = json!(true);
        return out;
    }

    let planned = step.leftovers();
    let mut failed = match r.remove_items(planned, &name) {
        Ok(outcome) => {
            let failed = outcome.failed > 0;
            let failed_items: Vec<Leftover> = planned
                .iter()
                .filter(|l| {
                    outcome
                        .items
                        .iter()
                        .any(|i| i.path == l.path && matches!(i.status, ItemStatus::Failed(_)))
                })
                .cloned()
                .collect();
            if !elevated && safety::needs_elevation(&failed_items) {
                out["needs_admin"] = json!(true);
                out["admin_command"] =
                    json!(format!("{} --elevate", scan_remove_command(&name, level)));
            }
            if let Some(backup) = &outcome.backup_name {
                out["backup"] = json!(backup);
                out["restore_command"] = json!(format!("oxidize restore \"{backup}\""));
            }
            out["removal"] = commands::removal_json(&Some(outcome));
            failed
        }
        Err(e) => {
            out["error"] = json!(format!("{e:#}"));
            true
        }
    };

    // A skipped uninstaller left the entry to the removal; see that it went.
    let installed = match step {
        PlanStep::Program { program, .. } => registered(m, program),
        _ => false,
    };
    out["still_installed"] = json!(installed);
    if installed {
        if out["error"].is_null() {
            out["error"] = json!(format!("{name} is still registered."));
        }
        failed = true;
    }

    // What a fresh scan still finds: anything the plan did not list, and
    // anything that could not go.
    let after = match step {
        PlanStep::Program { target, .. } | PlanStep::Leftovers { target, .. } => {
            m.scan(target, installed)
        }
        PlanStep::Store { app, .. } => {
            commands::store_app_leftovers(app, m.local_appdata().as_deref(), |t| {
                m.scan(t, false).items
            })
        }
    };
    let verdict = complete::verdict(installed, &after, level.confidence());
    out["remaining"] = json!(after.items);
    out["nothing_left"] = json!(verdict.nothing_left);
    out["failed"] = json!(failed);
    out
}

// The server
// ----------

#[derive(Clone)]
pub struct Server {
    inspect: Arc<dyn Inspect>,
    remove: Arc<dyn Remove>,
    plans: Arc<Mutex<Plans>>,
    /// Held while a plan is carried out, so two never run at once.
    applying: Arc<Mutex<()>>,
    tool_router: ToolRouter<Self>,
}

/// Run a tool off the protocol's thread: scans can take seconds and an
/// uninstaller minutes. An error becomes a tool error the assistant reads.
async fn blocking<F>(work: F) -> CallToolResult
where
    F: FnOnce() -> Result<Value> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => CallToolResult::structured(value),
        Ok(Err(e)) => CallToolResult::error(vec![ContentBlock::text(format!("{e:#}"))]),
        Err(e) => CallToolResult::error(vec![ContentBlock::text(format!("the tool stopped: {e}"))]),
    }
}

#[tool_router(router = tool_router)]
impl Server {
    pub fn new(inspect: Arc<dyn Inspect>, remove: Arc<dyn Remove>) -> Self {
        Server {
            inspect,
            remove,
            plans: Arc::default(),
            applying: Arc::default(),
            tool_router: Self::tool_router(),
        }
    }

    /// List installed programs and Store apps: name, version, publisher,
    /// size, install date and registry id. Store apps say whether Windows
    /// needs them. Reads only.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn list_programs(&self, Parameters(p): Parameters<ListParams>) -> CallToolResult {
        let m = Arc::clone(&self.inspect);
        blocking(move || list_programs(&*m, p)).await
    }

    /// Find what a program leaves behind: folders, files, registry keys and
    /// values, services, scheduled tasks, firewall rules and PATH entries,
    /// each with a confidence (High, Medium, Low) and the reason it was
    /// matched. For an installed program this is its current footprint;
    /// for one already gone, its leftovers. Reads only.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn scan_leftovers(&self, Parameters(p): Parameters<ScanParams>) -> CallToolResult {
        let m = Arc::clone(&self.inspect);
        blocking(move || scan_leftovers(&*m, p)).await
    }

    /// Find folders no installed program claims, and PATH entries,
    /// autostart values, services and tasks that point to files that no
    /// longer exist. Reads only.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn find_orphans(&self) -> CallToolResult {
        let m = Arc::clone(&self.inspect);
        blocking(move || find_orphans(&*m)).await
    }

    /// Find the installed program behind a path or a running process, best
    /// match first, with a score and the reason. Reads only.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn trace(&self, Parameters(p): Parameters<TraceParams>) -> CallToolResult {
        let m = Arc::clone(&self.inspect);
        blocking(move || trace(&*m, p)).await
    }

    /// List the backups earlier removals made, newest first, with the
    /// command that restores one. Reads only.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn list_backups(&self) -> CallToolResult {
        let m = Arc::clone(&self.inspect);
        blocking(move || list_backups(&*m)).await
    }

    /// Plan the removal of programs or Store apps: the uninstaller each one
    /// runs, then exactly which leftovers go (kind, path, size, confidence,
    /// reason), whether administrator rights are needed, and where the
    /// backups go. Changes nothing. Returns a plan_id; show the plan to the
    /// user, and once they agree, apply_removal_plan carries it out.
    #[tool(annotations(read_only_hint = true, open_world_hint = false))]
    async fn plan_removal(&self, Parameters(p): Parameters<PlanParams>) -> CallToolResult {
        let m = Arc::clone(&self.inspect);
        let plans = Arc::clone(&self.plans);
        blocking(move || {
            let plan = make_plan(&*m, &p)?;
            let id = plans
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .keep(plan.clone());
            Ok(plan_json(&id, &plan, &*m))
        })
        .await
    }

    /// Carry out a plan from plan_removal in this session, exactly as it
    /// was shown and only once: close what runs from each program's
    /// folders, run each uninstaller the plan keeps, then remove the
    /// leftovers it listed, each one backed up first. Returns what was
    /// closed and removed, what was not and why, what a fresh scan still
    /// finds and whether nothing at the plan's level is left, and the
    /// backup with the command that restores it. Call it only after the
    /// user agreed to that plan.
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn apply_removal_plan(&self, Parameters(p): Parameters<ApplyParams>) -> CallToolResult {
        let m = Arc::clone(&self.inspect);
        let r = Arc::clone(&self.remove);
        let plans = Arc::clone(&self.plans);
        let applying = Arc::clone(&self.applying);
        blocking(move || {
            let _one_at_a_time = applying.lock().unwrap_or_else(|e| e.into_inner());
            let plan = plans
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(&p.plan_id)
                .ok_or_else(|| {
                    anyhow!(
                        "no open plan \"{}\" in this session. Make one with plan_removal; a plan is applied only once.",
                        p.plan_id
                    )
                })?;
            Ok(apply(&*m, &*r, &p.plan_id, &plan))
        })
        .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("oxidize", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

/// `oxidize mcp`: serve this PC on stdin and stdout until the client leaves.
/// Stdout carries only the protocol; anything else goes to stderr.
pub fn serve() -> Result<()> {
    crate::term::init(true);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let server = Server::new(Arc::new(ThisPc), Arc::new(Remover));
        let running = server
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|e| anyhow!("the MCP client did not connect: {e}"))?;
        running.waiting().await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use clap::Parser;
    use tokio::io::{
        AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf,
    };

    use crate::cli::Cli;
    use crate::model::{Confidence, Hive, LeftoverKind, RegistrySource, RegistryView};
    use crate::orphans::OrphanFolder;
    use crate::packages::fake::package;
    use crate::safety::ItemOutcome;
    use crate::scanner;

    fn program(name: &str, key: &str) -> Program {
        Program {
            registry_key: key.to_string(),
            source: RegistrySource::new(Hive::CurrentUser, RegistryView::Native64),
            display_name: name.to_string(),
            display_version: Some("1.0".to_string()),
            publisher: None,
            install_date: None,
            install_location: None,
            display_icon: None,
            estimated_size_kb: None,
            uninstall_string: Some(format!(r"C:\Apps\{key}\uninstall.exe")),
            quiet_uninstall_string: Some(format!(r"C:\Apps\{key}\uninstall.exe /S")),
            url_info_about: None,
            is_windows_installer: false,
            is_system_component: false,
        }
    }

    fn folder(path: &str, confidence: Confidence, bytes: u64) -> Leftover {
        Leftover::fs(
            LeftoverKind::Directory,
            PathBuf::from(path),
            confidence,
            "named after the program",
            Some(bytes),
            false,
        )
    }

    /// A PC in memory. What it lists and finds is fixed, less what the
    /// recorder it watches removed; nothing reaches Windows.
    struct FakePc {
        programs: Vec<Program>,
        apps: Vec<Package>,
        found: HashMap<String, Vec<Leftover>>,
        seen: Option<Arc<Recorder>>,
    }

    impl FakePc {
        fn done(&self, call: &str) -> bool {
            self.seen
                .as_ref()
                .is_some_and(|r| r.calls().iter().any(|c| c == call))
        }

        /// Removed, unless it is machine-wide and the recorder refused it.
        fn removed(&self, item: &Leftover) -> bool {
            item.hive != Some(Hive::LocalMachine) && self.done(&format!("remove {}", item.path))
        }
    }

    fn pc() -> FakePc {
        let mut found = HashMap::new();
        found.insert(
            "Example Player".to_string(),
            vec![
                folder(
                    r"C:\Users\me\AppData\Local\ExamplePlayer",
                    Confidence::High,
                    900,
                ),
                Leftover::reg_key(
                    Hive::CurrentUser,
                    r"Software\Example Studio",
                    Confidence::High,
                    "the vendor's key",
                ),
                folder(
                    r"C:\Users\me\AppData\Local\Temp\ExamplePlayer",
                    Confidence::Medium,
                    50,
                ),
            ],
        );
        found.insert(
            "OldGame".to_string(),
            vec![folder(r"C:\Games\OldGame", Confidence::High, 70)],
        );
        found.insert(
            "Game Service".to_string(),
            vec![
                Leftover::reg_key(
                    Hive::LocalMachine,
                    r"SOFTWARE\Game Service",
                    Confidence::High,
                    "the program's own key",
                ),
                folder(r"C:\Program Files\Game Service", Confidence::High, 30),
            ],
        );
        FakePc {
            programs: vec![
                program("Example Player", "example-player"),
                program("Paper Browser", "PaperSoft Paper-Browser"),
                program("Game Service", "game-service"),
            ],
            apps: vec![package("Vendor.Notes", "Notes")],
            found,
            seen: None,
        }
    }

    impl Inspect for FakePc {
        fn programs(&self, _system: bool) -> Vec<Program> {
            self.programs
                .iter()
                .filter(|p| !self.done(&format!("wait {}", p.display_name)))
                .filter(|p| !self.removed(&own_entry(p)))
                .cloned()
                .collect()
        }
        fn store_apps(&self) -> Result<Vec<Package>> {
            Ok(self.apps.clone())
        }
        fn target(&self, program: &Program) -> ScanTarget {
            let mut t = scanner::name_target(&program.display_name, program.publisher.as_deref());
            t.registry = Some((program.registry_key.clone(), program.source));
            t
        }
        fn target_by_name(&self, name: &str, publisher: Option<&str>) -> ScanTarget {
            scanner::name_target(name, publisher)
        }
        fn scan(&self, target: &ScanTarget, installed: bool) -> ScanReport {
            let mut items: Vec<Leftover> = self
                .found
                .get(&target.display_name)
                .into_iter()
                .flatten()
                .filter(|l| !self.removed(l))
                .cloned()
                .collect();
            // Like the engine: a scan as if gone lists the program's own entry.
            if let (false, Some((key, _))) = (installed, &target.registry) {
                if let Some(p) = self.programs(true).iter().find(|p| &p.registry_key == key) {
                    items.push(own_entry(p));
                }
            }
            ScanReport {
                program_name: target.display_name.clone(),
                installed,
                items,
            }
        }
        fn orphans(&self, _programs: &[Program]) -> OrphanReport {
            OrphanReport {
                folders: vec![OrphanFolder {
                    path: PathBuf::from(r"C:\Users\me\AppData\Roaming\OldTool"),
                    size_bytes: 2048,
                    modified: Some("2026-01-02".to_string()),
                }],
                dangling: Vec::new(),
            }
        }
        fn trace(&self, query: &str, programs: &[Program]) -> Vec<HunterMatch> {
            programs
                .iter()
                .filter(|p| query.contains(p.id()))
                .map(|p| HunterMatch {
                    program: p.clone(),
                    score: 90,
                    reason: "runs from its install folder".to_string(),
                })
                .collect()
        }
        fn backups(&self) -> Result<Vec<BackupInfo>> {
            Ok(Vec::new())
        }
        fn backups_folder(&self) -> Option<PathBuf> {
            Some(PathBuf::from(r"C:\Users\me\AppData\Local\Oxidize\backups"))
        }
        fn local_appdata(&self) -> Option<PathBuf> {
            None
        }
        fn is_elevated(&self) -> bool {
            false
        }
        fn running(&self) -> Vec<Running> {
            [
                (100, r"C:\Users\me\AppData\Local\ExamplePlayer\player.exe"),
                (200, r"C:\Users\me\AppData\Local\Other\player.exe"),
                (300, r"C:\Games\OldGame\game.exe"),
                (400, r"C:\Program Files\Game Service\service.exe"),
            ]
            .into_iter()
            .map(|(pid, exe)| Running {
                pid,
                exe: PathBuf::from(exe),
            })
            .collect()
        }
        fn machine_dirs(&self) -> Vec<PathBuf> {
            vec![
                PathBuf::from(r"C:\Program Files"),
                PathBuf::from(r"C:\ProgramData"),
            ]
        }
    }

    /// Writes down what it is asked to do and does none of it. A machine-wide
    /// item fails as it would without administrator rights.
    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<String>>,
    }

    impl Recorder {
        fn log(&self, call: String) {
            self.calls.lock().unwrap().push(call);
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Remove for Recorder {
        fn uninstall(&self, plan: &UninstallPlan) -> Result<String> {
            self.log(format!("uninstall {}", plan.display()));
            Ok("exited with code 0".to_string())
        }
        fn wait_until_gone(&self, program: &Program, _plan: &UninstallPlan) -> bool {
            self.log(format!("wait {}", program.display_name));
            true
        }
        fn remove_app(&self, app: &Package) -> Result<bool> {
            self.log(format!("remove app {}", app.family_name));
            Ok(true)
        }
        fn close(&self, procs: &[Running]) -> Vec<Closed> {
            let pids: Vec<String> = procs.iter().map(|p| p.pid.to_string()).collect();
            self.log(format!("close {}", pids.join(",")));
            procs
                .iter()
                .map(|p| Closed {
                    pid: p.pid,
                    exe: p.exe.display().to_string(),
                    how: complete::CloseHow::Closed,
                    error: None,
                })
                .collect()
        }
        fn remove_items(&self, items: &[Leftover], label: &str) -> Result<DeletionOutcome> {
            for l in items {
                self.log(format!("remove {}", l.path));
            }
            let denied = |l: &Leftover| l.hive == Some(Hive::LocalMachine);
            let failed = items.iter().filter(|l| denied(l)).count();
            Ok(DeletionOutcome {
                attempted: items.len(),
                deleted: items.len() - failed,
                failed,
                backup_name: Some(format!("2026-10-10_150000_{label}")),
                items: items
                    .iter()
                    .map(|l| ItemOutcome {
                        path: l.path.clone(),
                        kind: l.kind,
                        status: if denied(l) {
                            ItemStatus::Failed("access denied".to_string())
                        } else {
                            ItemStatus::Removed
                        },
                    })
                    .collect(),
                ..DeletionOutcome::default()
            })
        }
    }

    /// A client on the other end of an in-memory stdio pipe.
    struct Session {
        write: WriteHalf<DuplexStream>,
        lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
        server: tokio::task::JoinHandle<()>,
        next_id: u64,
    }

    impl Session {
        async fn open(server: Server) -> (Session, Value) {
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            let server = tokio::spawn(async move {
                if let Ok(running) = server.serve(theirs).await {
                    let _ = running.waiting().await;
                }
            });
            let (read, write) = tokio::io::split(ours);
            let mut session = Session {
                write,
                lines: BufReader::new(read).lines(),
                server,
                next_id: 0,
            };
            let init = session
                .request(
                    "initialize",
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": { "name": "test", "version": "1" },
                    }),
                )
                .await;
            session
                .send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
                .await;
            (session, init)
        }

        async fn send(&mut self, message: Value) {
            let line = format!("{message}\n");
            self.write.write_all(line.as_bytes()).await.unwrap();
        }

        /// Send a request and return the whole answer to it.
        async fn request(&mut self, method: &str, params: Value) -> Value {
            self.next_id += 1;
            let id = self.next_id;
            self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
                .await;
            loop {
                let line = tokio::time::timeout(Duration::from_secs(20), self.lines.next_line())
                    .await
                    .expect("an answer in time")
                    .unwrap()
                    .expect("the server is still there");
                let answer: Value = serde_json::from_str(&line).expect("one JSON message a line");
                if answer["id"] == json!(id) {
                    return answer;
                }
            }
        }

        /// Call a tool and return its result.
        async fn call(&mut self, tool: &str, arguments: Value) -> Value {
            let answer = self
                .request(
                    "tools/call",
                    json!({ "name": tool, "arguments": arguments }),
                )
                .await;
            assert!(answer.get("error").is_none(), "{answer}");
            answer["result"].clone()
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn server_on(mut pc: FakePc) -> (Server, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());
        pc.seen = Some(Arc::clone(&recorder));
        let remove: Arc<dyn Remove> = recorder.clone();
        (Server::new(Arc::new(pc), remove), recorder)
    }

    fn plan_id(plan: &Value) -> Value {
        let id = plan["structuredContent"]["plan_id"].clone();
        assert!(id.is_string(), "{plan}");
        id
    }

    #[tokio::test]
    async fn the_handshake_names_the_server_and_offers_tools() {
        let (server, _) = server_on(pc());
        let (_session, init) = Session::open(server).await;
        let result = &init["result"];
        assert_eq!(result["protocolVersion"], "2025-11-25", "{init}");
        assert_eq!(result["serverInfo"]["name"], "oxidize");
        assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(result["capabilities"]["tools"].is_object(), "{init}");
        assert!(result["instructions"]
            .as_str()
            .unwrap()
            .contains("apply_removal_plan"));
    }

    #[tokio::test]
    async fn tools_are_listed_with_their_arguments_and_hints() {
        let (server, _) = server_on(pc());
        let (mut session, _) = Session::open(server).await;
        let answer = session.request("tools/list", json!({})).await;
        let tools = answer["result"]["tools"]
            .as_array()
            .expect("a list")
            .clone();
        let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "apply_removal_plan",
                "find_orphans",
                "list_backups",
                "list_programs",
                "plan_removal",
                "scan_leftovers",
                "trace",
            ]
        );
        for tool in &tools {
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert!(!tool["description"].as_str().unwrap().is_empty());
            let read_only = tool["annotations"]["readOnlyHint"] == json!(true);
            assert_eq!(read_only, tool["name"] != "apply_removal_plan", "{tool}");
        }
        let plan = tools.iter().find(|t| t["name"] == "plan_removal").unwrap();
        assert_eq!(plan["inputSchema"]["required"], json!(["programs"]));
        let apply = tools
            .iter()
            .find(|t| t["name"] == "apply_removal_plan")
            .unwrap();
        assert_eq!(apply["annotations"]["destructiveHint"], true);
        assert_eq!(apply["inputSchema"]["required"], json!(["plan_id"]));
    }

    #[tokio::test]
    async fn reading_tools_answer_with_the_command_lines_json_and_change_nothing() {
        let (server, recorder) = server_on(pc());
        let (mut session, _) = Session::open(server).await;

        let list = session
            .call("list_programs", json!({ "filter": "player" }))
            .await;
        let rows = list["structuredContent"]["programs"].as_array().unwrap();
        let names: Vec<&str> = rows
            .iter()
            .map(|r| r["display_name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Example Player"]);
        assert_eq!(rows[0]["kind"], "program");
        // The text is the same JSON, for clients that read only text.
        let text: Value =
            serde_json::from_str(list["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, list["structuredContent"]);

        let apps = session
            .call("list_programs", json!({ "store": true }))
            .await;
        assert_eq!(apps["structuredContent"]["programs"][0]["kind"], "store");

        let scan = session
            .call("scan_leftovers", json!({ "program": "Example" }))
            .await;
        let report = &scan["structuredContent"];
        assert_eq!(report["program_name"], "Example Player");
        assert_eq!(report["installed"], true);
        assert_eq!(report["items"][0]["confidence"], "High");
        assert_eq!(report["items"][0]["reason"], "named after the program");
        assert_eq!(report["items"][2]["confidence"], "Medium");

        let gone = session
            .call("scan_leftovers", json!({ "program": "OldGame" }))
            .await;
        assert_eq!(gone["structuredContent"]["installed"], false);

        let orphans = session.call("find_orphans", json!({})).await;
        assert_eq!(
            orphans["structuredContent"]["folders"][0]["size_bytes"],
            2048
        );

        let traced = session
            .call(
                "trace",
                json!({ "query": r"C:\Apps\example-player\player.exe" }),
            )
            .await;
        assert_eq!(
            traced["structuredContent"]["matches"][0]["name"],
            "Example Player"
        );

        let backups = session.call("list_backups", json!({})).await;
        assert_eq!(backups["structuredContent"]["backups"], json!([]));

        let plan = session
            .call("plan_removal", json!({ "programs": ["Example"] }))
            .await;
        plan_id(&plan);

        assert!(recorder.calls().is_empty(), "{:?}", recorder.calls());
    }

    #[tokio::test]
    async fn an_unclear_name_is_a_tool_error_the_assistant_can_read() {
        let (server, recorder) = server_on(pc());
        let (mut session, _) = Session::open(server).await;
        let result = session
            .call("plan_removal", json!({ "programs": ["r"] }))
            .await;
        assert_eq!(result["isError"], true, "{result}");
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("Example Player") && text.contains("Paper Browser"),
            "{text}"
        );
        assert!(recorder.calls().is_empty());
    }

    #[tokio::test]
    async fn a_plan_lists_exactly_what_goes_and_the_command_that_does_the_same() {
        let (server, _) = server_on(pc());
        let (mut session, _) = Session::open(server).await;
        let result = session
            .call(
                "plan_removal",
                json!({ "programs": ["Example", "OldGame"], "silent": true }),
            )
            .await;
        let plan = &result["structuredContent"];
        let steps = plan["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 2, "{plan}");
        assert_eq!(steps[0]["kind"], "program");
        assert_eq!(
            steps[0]["uninstaller"],
            r"C:\Apps\example-player\uninstall.exe /S"
        );
        // Installed for this user only with nothing machine-wide: Oxidize
        // removes it alone, its uninstall entry included.
        assert_eq!(
            steps[0]["uninstaller_step"],
            json!({
                "action": "skip",
                "reason": "installed for this user only; Oxidize removes all of it"
            })
        );
        // High only by default: the Medium temp folder stays.
        let paths: Vec<&str> = steps[0]["leftovers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                r"C:\Users\me\AppData\Local\ExamplePlayer",
                r"HKCU\Software\Example Studio",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\example-player",
            ]
        );
        assert_eq!(steps[0]["bytes"], 900);
        assert_eq!(steps[1]["kind"], "leftovers");
        assert_eq!(
            plan["commands"],
            json!([
                "oxidize uninstall \"Example Player\" --silent",
                "oxidize scan \"OldGame\" --remove"
            ])
        );
        assert_eq!(plan["leftovers"], 4);
        assert_eq!(plan["bytes"], 970);
        assert!(plan["how"].as_str().unwrap().starts_with("Running copies"));
        assert_eq!(plan["needs_admin"], false);
        assert_eq!(
            plan["backup_folder"],
            r"C:\Users\me\AppData\Local\Oxidize\backups"
        );

        let medium = session
            .call(
                "plan_removal",
                json!({ "programs": ["Example"], "level": "medium" }),
            )
            .await;
        assert_eq!(medium["structuredContent"]["leftovers"], 4);
        assert_eq!(
            medium["structuredContent"]["commands"],
            json!(["oxidize uninstall \"Example Player\" --medium"])
        );
    }

    #[tokio::test]
    async fn applying_a_plan_does_exactly_what_it_showed_once() {
        let (server, recorder) = server_on(pc());
        let (mut session, _) = Session::open(server).await;
        let plan = session
            .call("plan_removal", json!({ "programs": ["Example"] }))
            .await;
        let id = plan_id(&plan);
        assert!(recorder.calls().is_empty());

        let done = session
            .call("apply_removal_plan", json!({ "plan_id": id }))
            .await;
        assert_ne!(done["isError"], true, "{done}");
        // What runs from its folder closes first; its uninstaller is skipped
        // and the entry goes with the leftovers.
        assert_eq!(
            recorder.calls(),
            [
                "close 100",
                r"remove C:\Users\me\AppData\Local\ExamplePlayer",
                r"remove HKCU\Software\Example Studio",
                r"remove HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\example-player",
            ]
        );
        let step = &done["structuredContent"]["steps"][0];
        assert_eq!(step["still_installed"], false, "{step}");
        assert_eq!(step["failed"], false, "{step}");
        assert!(step["uninstaller"]
            .as_str()
            .unwrap()
            .starts_with("not started, installed for this user only"));
        assert_eq!(
            step["closed"],
            json!([{ "pid": 100, "exe": r"C:\Users\me\AppData\Local\ExamplePlayer\player.exe", "how": "closed" }])
        );
        assert_eq!(step["removal"]["removed"], 3);
        assert_eq!(step["backup"], "2026-10-10_150000_Example Player");
        assert_eq!(
            step["restore_command"],
            "oxidize restore \"2026-10-10_150000_Example Player\""
        );
        // The rescan finds only the Medium folder, below the plan's level.
        let left: Vec<&str> = step["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["path"].as_str().unwrap())
            .collect();
        assert_eq!(left, [r"C:\Users\me\AppData\Local\Temp\ExamplePlayer"]);
        assert_eq!(step["nothing_left"], true, "{step}");

        let again = session
            .call("apply_removal_plan", json!({ "plan_id": id }))
            .await;
        assert_eq!(again["isError"], true, "{again}");
        assert_eq!(recorder.calls().len(), 4, "a plan runs once");
    }

    #[tokio::test]
    async fn an_item_that_needs_administrator_rights_comes_back_with_the_command_for_it() {
        let (server, _) = server_on(pc());
        let (mut session, _) = Session::open(server).await;
        let plan = session
            .call("plan_removal", json!({ "programs": ["Game Service"] }))
            .await;
        assert_eq!(plan["structuredContent"]["needs_admin"], true, "{plan}");
        let id = plan_id(&plan);

        let done = session
            .call("apply_removal_plan", json!({ "plan_id": id }))
            .await;
        let result = &done["structuredContent"];
        assert_eq!(result["failed"], 1, "{done}");
        let step = &result["steps"][0];
        assert_eq!(step["failed"], true);
        assert_eq!(step["removal"]["items"][0]["status"], "failed");
        assert_eq!(step["removal"]["items"][0]["error"], "access denied");
        assert_eq!(step["needs_admin"], true);
        assert_eq!(
            step["admin_command"],
            "oxidize scan \"Game Service\" --remove --elevate"
        );
    }

    #[tokio::test]
    async fn only_a_plan_made_in_this_session_can_be_applied() {
        let (first, _) = server_on(pc());
        let (mut planning, _) = Session::open(first).await;
        let plan = planning
            .call("plan_removal", json!({ "programs": ["Paper Browser"] }))
            .await;
        let id = plan_id(&plan);

        let (second, recorder) = server_on(pc());
        let (mut other, _) = Session::open(second).await;
        for plan_id in [id, json!("plan-1"), json!("")] {
            let result = other
                .call("apply_removal_plan", json!({ "plan_id": plan_id }))
                .await;
            assert_eq!(result["isError"], true, "{result}");
        }
        assert!(recorder.calls().is_empty());
    }

    #[tokio::test]
    async fn a_store_app_and_leftovers_by_name_take_the_same_path() {
        let (server, recorder) = server_on(pc());
        let (mut session, _) = Session::open(server).await;
        let plan = session
            .call("plan_removal", json!({ "programs": ["Notes", "OldGame"] }))
            .await;
        assert_eq!(plan["structuredContent"]["steps"][0]["kind"], "store");
        assert_eq!(
            plan["structuredContent"]["commands"],
            json!([
                "oxidize uninstall \"Notes\"",
                "oxidize scan \"OldGame\" --remove"
            ])
        );
        let id = plan_id(&plan);
        session
            .call("apply_removal_plan", json!({ "plan_id": id }))
            .await;
        assert_eq!(
            recorder.calls(),
            [
                "remove app Vendor.Notes_8wekyb3d8bbwe",
                "close 300",
                r"remove C:\Games\OldGame",
            ]
        );
    }

    #[tokio::test]
    async fn a_machine_wide_program_runs_its_uninstaller_once_its_processes_closed() {
        let (server, recorder) = server_on(pc());
        let (mut session, _) = Session::open(server).await;
        let plan = session
            .call("plan_removal", json!({ "programs": ["Game Service"] }))
            .await;
        let planned = &plan["structuredContent"]["steps"][0];
        assert_eq!(
            planned["uninstaller_step"],
            // Planned without `silent`, so the recorded quiet command is not used.
            json!({ "action": "run", "silent": false, "reason": "owns something machine-wide" }),
            "{planned}"
        );
        let id = plan_id(&plan);
        let done = session
            .call("apply_removal_plan", json!({ "plan_id": id }))
            .await;
        assert_eq!(
            recorder.calls(),
            [
                "close 400",
                r"uninstall C:\Apps\game-service\uninstall.exe",
                "wait Game Service",
                r"remove HKLM\SOFTWARE\Game Service",
                r"remove C:\Program Files\Game Service",
                r"remove HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\game-service",
            ]
        );
        let step = &done["structuredContent"]["steps"][0];
        assert_eq!(step["still_installed"], false, "{step}");
        // The machine key needed administrator rights and stayed.
        assert_eq!(step["nothing_left"], false, "{step}");
        assert_eq!(step["remaining"][0]["path"], r"HKLM\SOFTWARE\Game Service");
    }

    #[tokio::test]
    async fn a_process_outside_the_programs_folders_is_never_closed() {
        let (server, recorder) = server_on(pc());
        let (mut session, _) = Session::open(server).await;
        let plan = session
            .call(
                "plan_removal",
                json!({ "programs": ["Example", "Paper Browser", "OldGame"], "level": "all" }),
            )
            .await;
        let id = plan_id(&plan);
        session
            .call("apply_removal_plan", json!({ "plan_id": id }))
            .await;
        let closed: Vec<String> = recorder
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("close"))
            .collect();
        assert_eq!(closed, ["close 100", "close 300"]);
    }

    /// The command line each tool does the work of.
    const MIRRORS: &[(&str, &str)] = &[
        ("list_programs", "list --json"),
        ("scan_leftovers", "scan Thing --json"),
        ("find_orphans", "orphans --json"),
        ("trace", "trace thing.exe --json"),
        ("list_backups", "backups --json"),
        ("plan_removal", "uninstall Thing --dry-run --json"),
        ("apply_removal_plan", "uninstall Thing --yes --json"),
    ];

    #[test]
    fn every_tool_but_one_mirrors_a_command_line_that_changes_nothing() {
        let mut tools: Vec<String> = Server::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        tools.sort_unstable();
        let mut mirrored: Vec<String> = MIRRORS.iter().map(|(t, _)| t.to_string()).collect();
        mirrored.sort_unstable();
        assert_eq!(tools, mirrored, "every tool says what it mirrors");

        let changing: Vec<&str> = MIRRORS
            .iter()
            .filter(|(_, args)| {
                let cli = Cli::try_parse_from(std::iter::once("oxidize").chain(args.split(' ')))
                    .unwrap_or_else(|e| panic!("{args}: {e}"));
                if !cli.changes_nothing() {
                    assert!(!cli.no_backup && !cli.elevate, "{args}");
                }
                !cli.changes_nothing()
            })
            .map(|(tool, _)| *tool)
            .collect();
        assert_eq!(changing, ["apply_removal_plan"]);
    }

    /// Engine calls that change the machine.
    const ENGINE_CHANGES: &[&str] = &[
        "remove_leftovers",
        "close_processes",
        "TerminateProcess",
        "uninstall::run",
        "remove_package",
        "restore::",
        "delete_backup",
        "relaunch_elevated",
        "delete_service",
        "delete_task",
        "remove_path_entry",
        "delete_key_tree",
        "delete_value",
        "import_registry_file",
        "Command::new",
        "fs::remove",
        "fs::write",
    ];

    #[test]
    fn only_the_remover_reaches_the_engines_removal_and_it_always_backs_up() {
        let source = include_str!("mcp.rs");
        let server = &source[..source.find("#[cfg(test)]").unwrap()];
        for call in ENGINE_CHANGES {
            assert!(!server.contains(call), "the server calls {call}");
        }
        assert_eq!(
            server.matches("self.remove").count(),
            1,
            "only apply_removal_plan holds the remover"
        );

        let machine = include_str!("mcp/machine.rs");
        let (reads, removes) = machine.split_once("impl Remove for Remover").unwrap();
        for call in ENGINE_CHANGES {
            assert!(!reads.contains(call), "the reading side calls {call}");
        }
        assert!(removes.contains("make_backups: true"));
        assert!(!machine.contains("make_backups: false"));
    }
}
