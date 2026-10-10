//! The `oxidize` command line. The engine lives in the library; this is a thin
//! front-end over it. `bin/oxidize-gui.rs` is the window.

use std::io::Write;

use clap::Parser;

use oxidize::cli::Cli;
use oxidize::{commands, exit, safety, term};

fn main() {
    if std::env::args_os().len() <= 1 {
        oxidize::cli::handle_bare_start();
    }
    let cli = Cli::parse();
    term::init(cli.no_color || cli.json);
    let json = cli.json;

    if cli.elevate && !safety::is_elevated() {
        let relaunched = safety::relaunch_elevated().map(|()| {
            let note = "Relaunching as administrator in a new window.";
            if json {
                eprintln!("{note}");
            } else {
                term::info(note);
            }
            exit::DONE
        });
        finish(relaunched, json);
    }

    finish(commands::dispatch(cli).map(|()| exit::DONE), json);
}

/// Print what is left to print and exit. With `--json` an error is one
/// object on stdout, unless the command already printed its result.
fn finish(result: anyhow::Result<i32>, json: bool) -> ! {
    let code = match result {
        Ok(code) => code,
        Err(e) => {
            let o = exit::outcome(&e);
            if !o.reported {
                if json {
                    let doc = exit::error_json(o.code, &o.message);
                    println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
                } else {
                    term::error(&o.message);
                }
            }
            o.exit
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}
