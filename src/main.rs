//! The `oxidize` command line. The engine lives in the library; this is a thin
//! front-end over it. `bin/oxidize-gui.rs` is the window.

use std::io::Write;

use clap::Parser;

use oxidize::cli::{self, Cli};
use oxidize::exit::{self, Failure};
use oxidize::{commands, safety, term};

fn main() {
    if std::env::args_os().len() <= 1 {
        cli::handle_bare_start();
    }
    let cli = Cli::parse();
    if let Some(path) = &cli.result_file {
        // Started by --elevate: the result goes back to the run that waits.
        if let Err(e) = safety::send_stdout_to(path) {
            term::warn(&format!("{e:#}"));
        }
    }
    term::init(cli.no_color || cli.json);
    let json = cli.json;

    if cli.elevate && !safety::is_elevated() {
        finish(elevate(&cli), json);
    }

    finish(commands::dispatch(cli).map(|()| exit::DONE), json);
}

/// Run the command line again as administrator, wait for it, and pass on
/// its exit code and, when it asks nothing, its output.
fn elevate(cli: &Cli) -> anyhow::Result<i32> {
    let note = "Relaunching as administrator in a new window.";
    if cli.json {
        eprintln!("{note}");
    } else {
        term::info(note);
    }
    let _ = std::io::stdout().flush();

    let file = if cli::captures_elevated_output(cli.json, cli.yes) {
        Some(safety::new_result_file()?)
    } else {
        None
    };
    let code = safety::run_elevated(file.as_deref());
    let output = file.map(|path| {
        let bytes = std::fs::read(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        bytes
    });
    let code = code?;
    if let Some(bytes) = output {
        if cli.json && code != exit::DONE && bytes.iter().all(u8::is_ascii_whitespace) {
            let message =
                format!("the elevated run ended with exit code {code} and printed nothing");
            return Err(Failure::new("error", code, message, false).into());
        }
        std::io::stdout().write_all(&bytes)?;
    }
    Ok(code)
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
