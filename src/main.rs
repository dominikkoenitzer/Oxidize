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
        // Without a way back the run would change things nobody hears of.
        if let Err(e) = safety::send_output_to(path) {
            finish(Err(e), cli.json);
        }
    }
    term::init(cli.no_color || cli.json);
    let json = cli.json;

    if cli.elevate && !safety::is_elevated() {
        finish(elevate(&cli), json);
    }

    // A panic still ends in one JSON document and a non-zero exit code.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        commands::dispatch(cli).map(|()| exit::DONE)
    }))
    .unwrap_or_else(|panic| {
        let what = panic
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown".to_string());
        Err(anyhow::anyhow!("internal error: {what}"))
    });
    finish(result, json);
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
    let output = file.map(|path| (take(&path), take(&safety::error_file(&path))));
    let code = code?;
    if let Some((out, err)) = output {
        let _ = std::io::stderr().write_all(&err);
        if cli.json && out.iter().all(u8::is_ascii_whitespace) {
            let message =
                format!("the elevated run ended with exit code {code} and printed nothing");
            return Err(Failure::new("error", code, message, false).into());
        }
        std::io::stdout().write_all(&out)?;
    }
    Ok(code)
}

/// Read a file the elevated run wrote, then delete it.
fn take(path: &std::path::Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_default();
    let _ = std::fs::remove_file(path);
    bytes
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
