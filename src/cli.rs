//! Command-line definition (clap derive).

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

use crate::model::Confidence;

/// Uninstall Windows programs and remove what they leave behind.
#[derive(Parser, Debug)]
#[command(name = "oxidize", version, about, long_about = None, propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Show what would happen, change nothing.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Answer yes to every prompt.
    #[arg(short = 'y', long = "yes", global = true)]
    pub yes: bool,

    /// Print JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Plain output without colour.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Delete without backups. Removals become permanent.
    #[arg(long, global = true)]
    pub no_backup: bool,

    /// Relaunch as administrator (UAC prompt) first.
    #[arg(long, global = true)]
    pub elevate: bool,

    /// File the elevated run writes its stdout to. `--elevate` sets it.
    #[arg(long, hide = true, value_name = "PATH")]
    pub result_file: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List installed programs and Store apps.
    List(ListArgs),
    /// Uninstall programs or Store apps, then remove their leftovers.
    Uninstall(UninstallArgs),
    /// Find a program's leftovers. Works for programs that are already gone.
    Scan(ScanArgs),
    /// Find folders, PATH entries, services and tasks no program owns.
    Orphans(OrphansArgs),
    /// Find the program behind a running process or an executable.
    Trace(TraceArgs),
    /// List backups made by earlier removals.
    Backups(BackupsArgs),
    /// Put back everything a backup holds.
    Restore(RestoreArgs),
    /// Clean temporary files, crash dumps, caches and folders of removed
    /// programs.
    ///
    /// Shows what it would clean and changes nothing; --yes cleans it.
    /// --traces clears the lists of recently used files and programs
    /// instead.
    Clean(CleanArgs),
    /// Show the folders and files `clean` never touches, or check a path
    /// against them.
    Protect(ProtectArgs),
    /// Serve Oxidize to an AI assistant over MCP on stdin and stdout.
    Mcp,
}

impl Cli {
    /// Whether this command line only reads: it uninstalls, removes,
    /// deletes, restores and elevates nothing. `mcp` does not count, since
    /// one of its tools carries out a removal plan.
    pub fn changes_nothing(&self) -> bool {
        if self.elevate {
            return false;
        }
        match &self.command {
            Commands::List(_) => true,
            Commands::Uninstall(_) => self.dry_run,
            Commands::Scan(args) => !args.remove || self.dry_run,
            Commands::Orphans(args) => !args.remove || self.dry_run,
            Commands::Trace(args) => !args.uninstall || self.dry_run,
            Commands::Backups(args) => (args.delete.is_none() && !args.clear) || self.dry_run,
            Commands::Restore(_) => self.dry_run,
            Commands::Clean(_) => !self.yes || self.dry_run,
            Commands::Protect(_) => true,
            Commands::Mcp => false,
        }
    }
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Only programs and apps whose name or publisher contains this text.
    pub filter: Option<String>,

    /// Include hidden system components and the Store apps that are part of
    /// Windows.
    #[arg(long)]
    pub system: bool,

    /// Only Store apps.
    #[arg(long)]
    pub store: bool,

    #[arg(long, value_enum, default_value_t = SortKey::Name)]
    pub sort: SortKey,
}

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Program or Store app name, a unique part of it, or its id (registry
    /// id or package family name). Several run one after another, and only
    /// once every name matches exactly one program or app.
    #[arg(value_name = "PROGRAM", required = true, num_args = 1.., value_parser = named)]
    pub targets: Vec<String>,

    /// Use the program's unattended uninstall switches where it has them.
    #[arg(long)]
    pub silent: bool,

    /// Show leftovers afterwards but do not remove them.
    #[arg(long)]
    pub keep: bool,

    /// Always run the program's own uninstaller, also when Oxidize can
    /// remove a program installed for this user alone.
    #[arg(long)]
    pub use_uninstaller: bool,

    #[command(flatten)]
    pub levels: LevelOpts,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Program name, a unique part of it, or its registry id. A program that
    /// is no longer installed is scanned by name.
    #[arg(value_name = "PROGRAM", value_parser = named)]
    pub target: String,

    /// Publisher, to tell vendor folders apart when scanning by name.
    #[arg(long, value_parser = named)]
    pub publisher: Option<String>,

    /// Remove what was found, after confirmation.
    #[arg(long)]
    pub remove: bool,

    #[command(flatten)]
    pub levels: LevelOpts,
}

#[derive(Args, Debug)]
pub struct OrphansArgs {
    /// Remove PATH entries, autostart values, services and tasks that point
    /// to files that no longer exist. Folders are listed only.
    #[arg(long)]
    pub remove: bool,
}

#[derive(Args, Debug)]
pub struct TraceArgs {
    /// Path to an .exe or folder, or the name of a running process.
    #[arg(value_name = "EXE_OR_PROCESS", value_parser = named)]
    pub query: String,

    /// Uninstall the program found, then remove its leftovers.
    #[arg(long)]
    pub uninstall: bool,

    /// With --uninstall: use unattended switches where available.
    #[arg(long)]
    pub silent: bool,

    /// With --uninstall: show leftovers but do not remove them.
    #[arg(long)]
    pub keep: bool,

    #[command(flatten)]
    pub levels: LevelOpts,
}

#[derive(Args, Debug)]
pub struct BackupsArgs {
    /// Delete one backup by name.
    #[arg(long, value_name = "NAME")]
    pub delete: Option<String>,

    /// Delete every backup.
    #[arg(long, conflicts_with = "delete")]
    pub clear: bool,
}

#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// Backup name as shown by `oxidize backups`.
    #[arg(value_parser = named)]
    pub name: String,
}

/// A name to look something up by. An empty one is refused: as a part of a
/// name it would match every program.
fn named(s: &str) -> Result<String, String> {
    if s.trim().is_empty() {
        Err("give a name; an empty one would match everything".to_string())
    } else {
        Ok(s.to_string())
    }
}

/// Without a category flag the safe set is chosen: temporary files, crash
/// dumps, browser caches, and folders of removed programs at high
/// confidence.
#[derive(Args, Debug)]
pub struct CleanArgs {
    /// Temporary files not changed for 7 days, yours and Windows' own.
    #[arg(long)]
    pub temp: bool,

    /// Crash dumps and queued error reports.
    #[arg(long)]
    pub crash_dumps: bool,

    /// Recycle Bin items deleted at least --recycle-bin-days ago.
    #[arg(long)]
    pub recycle_bin: bool,

    /// Caches of the browsers that are not running. Never cookies, history,
    /// sessions or logins.
    #[arg(long)]
    pub browser_cache: bool,

    /// Superseded Windows components, through DISM. Needs administrator
    /// rights and can take several minutes.
    #[arg(long)]
    pub component_store: bool,

    /// The Delivery Optimization cache, through Windows' own cmdlet. Needs
    /// administrator rights.
    #[arg(long)]
    pub delivery_optimization: bool,

    /// The previous Windows installation (Windows.old), through Disk
    /// Cleanup. Afterwards there is no going back to that Windows.
    #[arg(long)]
    pub windows_old: bool,

    /// Folders of removed programs, moved into a backup. High confidence
    /// only, unless --medium or --all.
    #[arg(long)]
    pub orphans: bool,

    /// Clear usage traces instead, and nothing else: recent items, jump
    /// lists, Run, search and Open and Save history, program launch counts,
    /// the thumbnail cache and the clipboard history. The files they point
    /// to stay; so do pinned items.
    #[arg(long, conflicts_with_all = [
        "temp", "crash_dumps", "recycle_bin", "browser_cache", "component_store",
        "delivery_optimization", "windows_old", "orphans",
    ])]
    pub traces: bool,

    /// How many days ago a Recycle Bin item has to have been deleted.
    #[arg(long, value_name = "DAYS", default_value_t = crate::clean::RECYCLE_DAYS)]
    pub recycle_bin_days: u64,

    #[command(flatten)]
    pub levels: LevelOpts,
}

impl CleanArgs {
    /// The categories named on the command line.
    pub fn named(&self) -> Vec<crate::clean::Category> {
        use crate::clean::Category;
        [
            (self.temp, Category::Temp),
            (self.crash_dumps, Category::CrashDumps),
            (self.recycle_bin, Category::RecycleBin),
            (self.browser_cache, Category::BrowserCache),
            (self.component_store, Category::ComponentStore),
            (self.delivery_optimization, Category::DeliveryOptimization),
            (self.windows_old, Category::WindowsOld),
            (self.orphans, Category::Orphans),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, c)| c)
        .collect()
    }
}

#[derive(Args, Debug)]
pub struct ProtectArgs {
    /// Say whether this path is protected: listed itself, or inside a
    /// listed folder. %VAR% references are expanded.
    #[arg(long, value_name = "PATH")]
    pub check: Option<String>,
}

/// Which confidence levels a removal acts on. High is always included.
#[derive(Args, Debug, Clone, Copy, Default)]
pub struct LevelOpts {
    /// Also remove medium-confidence items.
    #[arg(long)]
    pub medium: bool,

    /// Remove everything found, low-confidence items included.
    #[arg(long)]
    pub all: bool,

    /// The lowest confidence to remove. `medium` is `--medium`, `low` is
    /// `--all`.
    #[arg(long, value_enum, value_name = "LEVEL", conflicts_with_all = ["medium", "all"])]
    pub level: Option<Level>,
}

/// A confidence level as `--level` takes it.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    High,
    Medium,
    #[value(alias = "all")]
    Low,
}

impl LevelOpts {
    pub fn threshold(&self) -> Confidence {
        match self.level {
            Some(Level::High) => Confidence::High,
            Some(Level::Medium) => Confidence::Medium,
            Some(Level::Low) => Confidence::Low,
            None if self.all => Confidence::Low,
            None if self.medium => Confidence::Medium,
            None => Confidence::High,
        }
    }

    pub fn describe(&self) -> &'static str {
        match self.threshold() {
            Confidence::Low => "all",
            Confidence::Medium => "high and medium confidence",
            Confidence::High => "high confidence",
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum SortKey {
    Name,
    Size,
    Date,
    Publisher,
}

/// Whether `--json` or `--yes` alone means an elevated run asks nothing, so
/// `--elevate` can bring its stdout back. [`Cli::never_asks`] adds the
/// commands that never ask; any other run keeps its own window, where its
/// questions can be answered.
pub fn captures_elevated_output(json: bool, yes: bool) -> bool {
    json || yes
}

impl Cli {
    /// Whether this command line never asks a question, so an elevated run
    /// of it has nothing to wait for in its own window.
    pub fn never_asks(&self) -> bool {
        captures_elevated_output(self.json, self.yes) || matches!(self.command, Commands::Clean(_))
    }
}

/// What `oxidize` does when it is started without arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareStart {
    /// Started from a terminal: print the help, as always.
    Help,
    /// Double-clicked, with the window app next to it: open that instead.
    OpenWindow,
    /// Double-clicked, no window app next to it: print the help and keep the
    /// console open until Enter.
    HelpAndWait,
}

/// Decides what a start without arguments does. `console_processes` is the
/// number of processes attached to the console. Windows gives a program
/// double-clicked in Explorer a console of its own, so the count is 1; a
/// terminal's shell makes it 2 or more. 0 means there is no console.
pub fn bare_start(console_processes: u32, window_app_present: bool) -> BareStart {
    match (console_processes, window_app_present) {
        (1, true) => BareStart::OpenWindow,
        (1, false) => BareStart::HelpAndWait,
        _ => BareStart::Help,
    }
}

/// Handles a start without arguments. Returns only when the usual argument
/// parsing should go on and print the help.
pub fn handle_bare_start() {
    let window_app = std::env::current_exe()
        .ok()
        .map(|exe| exe.with_file_name("oxidize-gui.exe"))
        .filter(|path| path.is_file());
    match bare_start(console_process_count(), window_app.is_some()) {
        BareStart::Help => {}
        BareStart::OpenWindow => {
            if let Some(path) = window_app {
                let started = std::process::Command::new(path)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                if started.is_ok() {
                    std::process::exit(0);
                }
            }
            help_and_wait();
        }
        BareStart::HelpAndWait => help_and_wait(),
    }
}

fn help_and_wait() -> ! {
    use std::io::Write;

    let _ = Cli::command().print_help();
    println!();
    println!("Open a terminal and run oxidize with one of the commands above.");
    println!("oxidize-gui.exe is the same tool as a window.");
    print!("Press Enter to close.");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    std::process::exit(0);
}

#[cfg(windows)]
fn console_process_count() -> u32 {
    use windows::Win32::System::Console::GetConsoleProcessList;
    let mut ids = [0u32; 8];
    unsafe { GetConsoleProcessList(&mut ids) }
}

#[cfg(not(windows))]
fn console_process_count() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_name_is_refused() {
        use clap::Parser;
        for args in [
            &["oxidize", "scan", ""][..],
            &["oxidize", "scan", "  "],
            &["oxidize", "uninstall", "Example", ""],
            &["oxidize", "trace", ""],
            &["oxidize", "restore", ""],
            &["oxidize", "scan", "Example", "--publisher", ""],
        ] {
            let err = Cli::try_parse_from(args).unwrap_err();
            assert!(err.to_string().contains("empty one"), "{args:?}: {err}");
        }
        assert!(Cli::try_parse_from(["oxidize", "scan", "Example"]).is_ok());
    }

    #[test]
    fn own_console_opens_the_window_app_when_it_is_there() {
        assert_eq!(bare_start(1, true), BareStart::OpenWindow);
    }

    #[test]
    fn own_console_without_the_window_app_waits_after_the_help() {
        assert_eq!(bare_start(1, false), BareStart::HelpAndWait);
    }

    #[test]
    fn a_terminal_gets_the_help_as_before() {
        for count in [2, 3, 8] {
            assert_eq!(bare_start(count, true), BareStart::Help);
            assert_eq!(bare_start(count, false), BareStart::Help);
        }
    }

    fn parse(args: &str) -> Cli {
        Cli::try_parse_from(std::iter::once("oxidize").chain(args.split(' ')))
            .unwrap_or_else(|e| panic!("{args}: {e}"))
    }

    #[test]
    fn only_command_lines_that_read_change_nothing() {
        for args in [
            "list --json",
            "scan Thing --json",
            "orphans",
            "trace thing.exe",
            "backups",
            "uninstall Thing --dry-run",
            "scan Thing --remove --dry-run",
            "restore name --dry-run",
            "clean",
            "clean --json --recycle-bin --windows-old",
            "clean --yes --dry-run",
        ] {
            assert!(parse(args).changes_nothing(), "{args}");
        }
        for args in [
            "uninstall Thing",
            "uninstall Thing --yes --json",
            "scan Thing --remove",
            "orphans --remove",
            "trace thing.exe --uninstall",
            "backups --delete name",
            "backups --clear",
            "restore name",
            "list --elevate",
            "clean --yes",
            "clean --orphans --all -y --json",
            "mcp",
        ] {
            assert!(!parse(args).changes_nothing(), "{args}");
        }
    }

    fn levels(args: &str) -> LevelOpts {
        match parse(args).command {
            Commands::Uninstall(a) => a.levels,
            Commands::Scan(a) => a.levels,
            Commands::Trace(a) => a.levels,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn level_is_the_long_form_of_medium_and_all() {
        for (args, threshold) in [
            ("uninstall Thing", Confidence::High),
            ("uninstall Thing --level high", Confidence::High),
            ("uninstall Thing --medium", Confidence::Medium),
            ("uninstall Thing --level medium", Confidence::Medium),
            ("scan Thing --remove --level medium", Confidence::Medium),
            ("uninstall Thing --all", Confidence::Low),
            ("uninstall Thing --level low", Confidence::Low),
            ("trace thing.exe --uninstall --level all", Confidence::Low),
        ] {
            assert_eq!(levels(args).threshold(), threshold, "{args}");
        }
        assert_eq!(
            levels("uninstall Thing --level medium").describe(),
            levels("uninstall Thing --medium").describe()
        );
    }

    #[test]
    fn level_does_not_mix_with_medium_or_all() {
        for args in [
            "uninstall Thing --level low --medium",
            "uninstall Thing --level high --all",
            "uninstall Thing --level none",
        ] {
            let parsed = Cli::try_parse_from(std::iter::once("oxidize").chain(args.split(' ')));
            assert!(parsed.is_err(), "{args}");
        }
    }

    #[test]
    fn the_result_file_is_hidden_and_comes_before_the_command() {
        let path = r"C:\Users\Example User\AppData\Local\Temp\oxidize-elevated-1-2.out";
        let cli = Cli::try_parse_from([
            "oxidize",
            "--result-file",
            path,
            "uninstall",
            "Example Player",
            "--json",
        ])
        .unwrap();
        assert_eq!(cli.result_file.as_deref(), Some(std::path::Path::new(path)));
        assert!(cli.json);
        assert!(Cli::try_parse_from(["oxidize", "list"])
            .unwrap()
            .result_file
            .is_none());
        let help = Cli::command().render_long_help().to_string();
        assert!(!help.contains("result-file"), "{help}");
        assert!(help.contains("--elevate"));
    }

    #[test]
    fn elevated_output_comes_back_only_when_nothing_is_asked() {
        assert!(captures_elevated_output(true, false));
        assert!(captures_elevated_output(false, true));
        assert!(!captures_elevated_output(false, false));
    }

    #[test]
    fn clean_takes_its_categories_and_never_asks() {
        use crate::clean::Category;
        let Commands::Clean(a) = parse("clean").command else {
            panic!("not clean");
        };
        assert!(a.named().is_empty());
        assert_eq!(a.recycle_bin_days, 30);
        assert_eq!(a.levels.threshold(), Confidence::High);
        let cli = parse("clean --recycle-bin --recycle-bin-days 90 --orphans --medium");
        assert!(cli.never_asks());
        let Commands::Clean(a) = cli.command else {
            panic!("not clean");
        };
        assert_eq!(a.named(), [Category::RecycleBin, Category::Orphans]);
        assert_eq!(a.recycle_bin_days, 90);
        assert_eq!(a.levels.threshold(), Confidence::Medium);
        assert!(!parse("orphans").never_asks());
    }

    #[test]
    fn clean_traces_stands_alone() {
        let Commands::Clean(a) = parse("clean --traces").command else {
            panic!("not clean");
        };
        assert!(a.traces);
        assert!(a.named().is_empty());
        assert!(parse("clean --traces").changes_nothing());
        assert!(!parse("clean --traces --yes").changes_nothing());
        for other in ["--temp", "--orphans", "--browser-cache", "--recycle-bin"] {
            let args = ["oxidize", "clean", "--traces", other];
            assert!(Cli::try_parse_from(args).is_err(), "{other}");
        }
    }

    #[test]
    fn no_console_gets_the_help() {
        assert_eq!(bare_start(0, true), BareStart::Help);
        assert_eq!(bare_start(0, false), BareStart::Help);
    }
}
