//! Command-line definition (clap derive).

use clap::{Args, Parser, Subcommand, ValueEnum};

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
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List installed programs.
    List(ListArgs),
    /// Uninstall a program, then remove its leftovers.
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
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Only programs whose name or publisher contains this text.
    pub filter: Option<String>,

    /// Include hidden system components.
    #[arg(long)]
    pub system: bool,

    #[arg(long, value_enum, default_value_t = SortKey::Name)]
    pub sort: SortKey,
}

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Program name, a unique part of it, or its registry id.
    #[arg(value_name = "PROGRAM")]
    pub target: String,

    /// Use the program's unattended uninstall switches where it has them.
    #[arg(long)]
    pub silent: bool,

    /// Show leftovers afterwards but do not remove them.
    #[arg(long)]
    pub keep: bool,

    #[command(flatten)]
    pub levels: LevelOpts,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Program name, a unique part of it, or its registry id. A program that
    /// is no longer installed is scanned by name.
    #[arg(value_name = "PROGRAM")]
    pub target: String,

    /// Publisher, to tell vendor folders apart when scanning by name.
    #[arg(long)]
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
    #[arg(value_name = "EXE_OR_PROCESS")]
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
    pub name: String,
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
}

impl LevelOpts {
    pub fn threshold(&self) -> Confidence {
        if self.all {
            Confidence::Low
        } else if self.medium {
            Confidence::Medium
        } else {
            Confidence::High
        }
    }

    pub fn describe(&self) -> &'static str {
        if self.all {
            "all"
        } else if self.medium {
            "high and medium confidence"
        } else {
            "high confidence"
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
