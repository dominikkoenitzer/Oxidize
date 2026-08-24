//! The `oxidize` command-line front-end.
//!
//! Windows' built-in uninstaller tends to leave junk behind: orphaned registry
//! keys, leftover files, empty folders under AppData, ProgramData and Program
//! Files. Oxidize runs the program's own uninstaller first, then scans for
//! whatever survived and removes it, after asking and after taking a backup.
//!
//! The engine itself lives in `lib.rs`; this binary is a thin CLI over it.
//! `bin/oxidize-gui.rs` is the graphical front-end.

use clap::Parser;

use oxidize::cli::Cli;
use oxidize::{commands, safety, term};

fn main() {
    let cli = Cli::parse();

    // Disable colour when emitting JSON so the output stays machine-readable.
    term::init(cli.no_color || cli.json);

    // Optional self-elevation: relaunch via a UAC prompt, then exit this
    // (non-elevated) instance.
    if cli.elevate && !safety::is_elevated() {
        match safety::relaunch_elevated() {
            Ok(()) => {
                term::info("Relaunching with Administrator rights (a new window will open)…");
                std::process::exit(0);
            }
            Err(e) => {
                term::error(&format!("{e:#}"));
                std::process::exit(1);
            }
        }
    }

    if let Err(e) = commands::dispatch(cli) {
        term::error(&format!("{e:#}"));
        std::process::exit(1);
    }
}
