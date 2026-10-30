//! Terminal output: colour with a global switch, VT enabling on older
//! consoles, and a yes/no prompt.
//!
//! stdout and stderr each have colour only while they are a terminal
//! themselves, and neither has it when `NO_COLOR` is set or with
//! `--no-color`, so piped or redirected output is plain text.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);
static ERR_COLOR_ENABLED: AtomicBool = AtomicBool::new(false);

/// Colour on or off for stdout and for stderr.
#[derive(Debug, PartialEq, Eq)]
struct Colors {
    out: bool,
    err: bool,
}

fn colors(force_off: bool, no_color: bool, out_terminal: bool, err_terminal: bool) -> Colors {
    let allowed = !force_off && !no_color;
    Colors {
        out: allowed && out_terminal,
        err: allowed && err_terminal,
    }
}

pub fn init(force_off: bool) {
    let colors = colors(
        force_off,
        std::env::var_os("NO_COLOR").is_some(),
        io::stdout().is_terminal(),
        io::stderr().is_terminal(),
    );
    if colors.out {
        enable_virtual_terminal(Stream::Out);
    }
    if colors.err {
        enable_virtual_terminal(Stream::Err);
    }
    COLOR_ENABLED.store(colors.out, Ordering::Relaxed);
    ERR_COLOR_ENABLED.store(colors.err, Ordering::Relaxed);
}

fn color_on() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
}

fn paint(text: &str, code: &str) -> String {
    paint_if(color_on(), text, code)
}

/// For text bound for stderr, which has its own switch.
fn paint_err(text: &str, code: &str) -> String {
    paint_if(ERR_COLOR_ENABLED.load(Ordering::Relaxed), text, code)
}

fn paint_if(on: bool, text: &str, code: &str) -> String {
    if on {
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
    eprintln!("{} {msg}", paint_err("warning:", "33"));
}

/// `error: ...` on stderr.
pub fn error(msg: &str) {
    eprintln!("{} {msg}", paint_err("error:", "31"));
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

enum Stream {
    Out,
    Err,
}

/// Turn on ANSI escape handling for one stream's console so colour works
/// on `conhost` too.
#[cfg(windows)]
fn enable_virtual_terminal(stream: Stream) {
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };
    let which = match stream {
        Stream::Out => STD_OUTPUT_HANDLE,
        Stream::Err => STD_ERROR_HANDLE,
    };
    unsafe {
        let Ok(handle) = GetStdHandle(which) else {
            return;
        };
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(handle, &mut mode).is_ok() {
            let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

#[cfg(not(windows))]
fn enable_virtual_terminal(_stream: Stream) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redirected_stderr_is_plain_while_stdout_is_a_terminal() {
        assert_eq!(
            colors(false, false, true, false),
            Colors {
                out: true,
                err: false
            }
        );
    }

    #[test]
    fn a_console_stderr_keeps_colour_while_stdout_is_redirected() {
        assert_eq!(
            colors(false, false, false, true),
            Colors {
                out: false,
                err: true
            }
        );
    }

    #[test]
    fn no_color_and_the_flag_turn_off_both_streams() {
        let off = Colors {
            out: false,
            err: false,
        };
        assert_eq!(colors(true, false, true, true), off);
        assert_eq!(colors(false, true, true, true), off);
    }

    #[test]
    fn stdout_follows_its_own_terminal_as_before() {
        assert!(colors(false, false, true, true).out);
        assert!(!colors(false, false, false, false).out);
    }

    #[test]
    fn only_a_stream_with_colour_gets_escape_codes() {
        assert_eq!(paint_if(true, "error:", "31"), "\x1b[31merror:\x1b[0m");
        assert_eq!(paint_if(false, "error:", "31"), "error:");
    }
}
