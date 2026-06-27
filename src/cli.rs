//! Command-line interface definition (clap derive).

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::model::Confidence;

/// Oxidize — a thorough Windows uninstaller.
///
/// Runs a program's own uninstaller, then finds and removes the registry and
/// filesystem leftovers it leaves behind. Always backs up registry keys (to
/// `.reg`) and quarantines files before deleting; supports `--dry-run`.
#[derive(Parser, Debug)]
#[command(name = "oxidize", version, about, long_about = None, propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Show what would happen without changing anything.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Assume "yes" to all confirmation prompts.
    #[arg(short = 'y', long = "yes", global = true)]
    pub yes: bool,

    /// Emit machine-readable JSON instead of formatted text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable coloured output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Do NOT back up registry keys / quarantine files before deleting
    /// (dangerous; deletions become irreversible).
    #[arg(long, global = true)]
    pub no_backup: bool,

    /// Relaunch with Administrator rights (UAC prompt) before running.
    #[arg(long, global = true)]
    pub elevate: bool,

    /// Increase verbosity (-v, -vv).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List installed programs (read-only).
    List(ListArgs),
    /// Run a program's uninstaller, then optionally scan/remove leftovers.
    Uninstall(UninstallArgs),
    /// Scan for a program's leftovers, and optionally remove them.
    Scan(ScanArgs),
    /// Trace a running process / executable back to its installed program.
    Hunter(HunterArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Only show programs whose name or publisher contains this text.
    pub filter: Option<String>,

    /// Include hidden system components.
    #[arg(long)]
    pub all: bool,

    /// Sort order.
    #[arg(long, value_enum, default_value_t = SortKey::Name)]
    pub sort: SortKey,
}

#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Program display name (or unique substring) or registry id.
    #[arg(value_name = "NAME_OR_ID")]
    pub target: String,

    /// Run the uninstaller unattended/silently where the program supports it.
    #[arg(long)]
    pub silent: bool,

    /// After uninstalling, scan for leftovers.
    #[arg(long)]
    pub scan: bool,

    /// After scanning, remove the leftovers (implies --scan).
    #[arg(long)]
    pub remove: bool,

    #[command(flatten)]
    pub leftovers: LeftoverOpts,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Program display name (or unique substring) or registry id.
    #[arg(value_name = "NAME_OR_ID")]
    pub target: String,

    /// Remove the discovered leftovers (after confirmation).
    #[arg(long)]
    pub remove: bool,

    #[command(flatten)]
    pub leftovers: LeftoverOpts,
}

#[derive(Args, Debug)]
pub struct HunterArgs {
    /// Path to an .exe or folder, or the name of a running process.
    #[arg(value_name = "EXE_PATH_OR_PROCESS")]
    pub query: String,

    /// If a program is identified, run its uninstaller.
    #[arg(long)]
    pub uninstall: bool,

    /// Uninstall silently (with --uninstall).
    #[arg(long)]
    pub silent: bool,

    /// Scan for leftovers after uninstalling (with --uninstall).
    #[arg(long)]
    pub scan: bool,

    /// Remove leftovers after scanning (with --uninstall; implies --scan).
    #[arg(long)]
    pub remove: bool,

    #[command(flatten)]
    pub leftovers: LeftoverOpts,
}

/// Which confidence levels a removal acts on.
#[derive(Args, Debug, Clone, Copy)]
pub struct LeftoverOpts {
    /// Also act on medium-confidence leftovers (default: high-confidence only).
    #[arg(long)]
    pub include_medium: bool,

    /// Act on all leftovers, including low-confidence ones (implies
    /// --include-medium).
    #[arg(long)]
    pub include_all: bool,
}

impl LeftoverOpts {
    /// The lowest confidence to act on. Because `Confidence` orders
    /// `High < Medium < Low`, "act on items whose confidence `<=` this" yields
    /// the expected nested behaviour.
    pub fn threshold(&self) -> Confidence {
        if self.include_all {
            Confidence::Low
        } else if self.include_medium {
            Confidence::Medium
        } else {
            Confidence::High
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
