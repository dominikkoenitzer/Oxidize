//! The `oxidize` command line. The engine lives in the library; this is a thin
//! front-end over it. `bin/oxidize-gui.rs` is the window.

use clap::Parser;

use oxidize::cli::Cli;
use oxidize::{commands, safety, term};

fn main() {
    let cli = Cli::parse();
    term::init(cli.no_color || cli.json);

    if cli.elevate && !safety::is_elevated() {
        match safety::relaunch_elevated() {
            Ok(()) => {
                term::info("Relaunching as administrator in a new window.");
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
