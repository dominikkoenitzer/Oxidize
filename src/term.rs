//! Terminal output helpers: ANSI colour (with a global on/off switch), enabling
//! virtual-terminal processing on the Windows console, and an interactive
//! yes/no prompt.
//!
//! Colour is disabled automatically when stdout is not a terminal, when the
//! `NO_COLOR` environment variable is set, or when the caller passes
//! `--no-color`, so piping `oxidize list` into a file yields clean text.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);

/// Initialise terminal output. Call once at startup. `force_off` corresponds to
/// `--no-color`.
pub fn init(force_off: bool) {
    let enabled = !force_off
        && std::env::var_os("NO_COLOR").is_none()
        && io::stdout().is_terminal();
    if enabled {
        enable_virtual_terminal();
    }
    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

fn color_on() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
}

/// Wrap `text` in an SGR colour code when colour is enabled.
fn paint(text: &str, code: &str) -> String {
    if color_on() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn bold(text: &str) -> String {
    paint(text, "1")
}
pub fn dim(text: &str) -> String {
    paint(text, "2")
}
pub fn yellow(text: &str) -> String {
    paint(text, "33")
}
pub fn cyan(text: &str) -> String {
    paint(text, "36")
}
pub fn bold_red(text: &str) -> String {
    paint(text, "1;31")
}
pub fn bold_green(text: &str) -> String {
    paint(text, "1;32")
}
pub fn bold_yellow(text: &str) -> String {
    paint(text, "1;33")
}

/// Print a labelled informational line, e.g. `[i] message`.
pub fn info(msg: &str) {
    println!("{} {msg}", cyan("[i]"));
}

/// Print a labelled warning line to stderr.
pub fn warn(msg: &str) {
    eprintln!("{} {msg}", bold_yellow("[!]"));
}

/// Print a labelled error line to stderr.
pub fn error(msg: &str) {
    eprintln!("{} {msg}", bold_red("[x]"));
}

/// Print a labelled success line.
pub fn success(msg: &str) {
    println!("{} {msg}", bold_green("[\u{2713}]"));
}

/// Ask a yes/no question on the terminal. Returns `default_yes` on empty input
/// or when stdin is not interactive.
pub fn confirm(question: &str, default_yes: bool) -> bool {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{question} {hint} ");
    let _ = io::stdout().flush();

    if !io::stdin().is_terminal() {
        // Non-interactive: don't block on a read that will never come.
        println!();
        return default_yes;
    }

    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return default_yes;
    }
    match line.trim().to_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    }
}

/// Turn on ANSI escape sequence interpretation for the current console so that
/// colour works on older `conhost` hosts (Windows Terminal already supports it).
#[cfg(windows)]
fn enable_virtual_terminal() {
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) else {
            return;
        };
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(handle, &mut mode).is_ok() {
            let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

#[cfg(not(windows))]
fn enable_virtual_terminal() {}
