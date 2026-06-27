//! `oxidize` — the command-line front-end for the Oxidize uninstaller.
//!
//! Windows' built-in uninstaller frequently leaves junk behind: orphaned
//! registry keys, leftover files, and empty folders under AppData/ProgramData/
//! Program Files. Oxidize runs a program's *own* uninstaller and then scans for
//! and (with confirmation, and after backing things up) removes what survived.
//!
//! The engine lives in the `oxidize` library (`lib.rs`); this binary is a thin
//! CLI on top of it. The graphical front-end is `bin/oxidize-gui.rs`.

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
