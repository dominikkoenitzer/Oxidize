//! Terminal output: colour with a global switch, VT enabling on older
//! consoles, and a yes/no prompt.
//!
//! Colour is off when stdout is not a terminal, when `NO_COLOR` is set, or
//! with `--no-color`, so piped output is plain text.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn init(force_off: bool) {
    let enabled =
        !force_off && std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal();
    if enabled {
        enable_virtual_terminal();
    }
    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

fn color_on() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
}

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
pub fn red(text: &str) -> String {
    paint(text, "31")
}
pub fn green(text: &str) -> String {
    paint(text, "32")
}
pub fn yellow(text: &str) -> String {
    paint(text, "33")
}

/// A plain line on stdout.
pub fn info(msg: &str) {
    println!("{msg}");
}

/// `warning: ...` on stderr.
pub fn warn(msg: &str) {
    eprintln!("{} {msg}", yellow("warning:"));
}

/// `error: ...` on stderr.
pub fn error(msg: &str) {
    eprintln!("{} {msg}", red("error:"));
}

/// Ask a yes/no question. Empty input picks the default. When stdin is not a
/// terminal nobody can answer, so the answer is no; `-y` exists for scripts.
pub fn confirm(question: &str, default_yes: bool) -> bool {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    if !io::stdin().is_terminal() {
        return false;
    }
    print!("{question} {hint} ");
    let _ = io::stdout().flush();

    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    match line.trim().to_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    }
}

/// Turn on ANSI escape handling so colour works on `conhost` too.
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
