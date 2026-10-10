//! Exit codes and the typed failure behind them.
//!
//! A command returns a [`Failure`] through `anyhow` when a script needs to
//! tell the outcome apart; `main` maps it to the exit code and, with
//! `--json`, to one error object on stdout. Any other error exits with
//! [`ERROR`] and code `"error"`.

use std::fmt;

/// Everything went as asked.
pub const DONE: i32 = 0;
/// Any other error.
pub const ERROR: i32 = 1;
/// The command line did not parse. Clap exits with it on its own.
pub const USAGE: i32 = 2;
/// The program is still installed after its uninstall.
pub const STILL_INSTALLED: i32 = 3;
/// The removal is incomplete: an item failed or something is left.
pub const INCOMPLETE: i32 = 4;
/// A prompt was answered no, or `--json` ran without `--yes`.
pub const CANCELLED: i32 = 5;

/// An error with a stable code and exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Short snake_case name, the `code` of the JSON error object.
    pub code: &'static str,
    /// Process exit code.
    pub exit: i32,
    /// The human message, unchanged from the text output.
    pub message: String,
    /// The command already told the user, as JSON or as text. `main` then
    /// prints nothing and only exits with `exit`.
    pub reported: bool,
}

impl Failure {
    pub fn new(code: &'static str, exit: i32, message: impl Into<String>, reported: bool) -> Self {
        Failure {
            code,
            exit,
            message: message.into(),
            reported,
        }
    }

    /// Nothing installed, and no backup, answers to a name.
    pub fn not_found(message: impl Into<String>) -> Self {
        Failure::new("not_found", ERROR, message, false)
    }

    /// Several programs, apps or backups answer to a name equally well.
    pub fn ambiguous(message: impl Into<String>) -> Self {
        Failure::new("ambiguous", ERROR, message, false)
    }

    /// The step needs administrator rights.
    pub fn needs_admin(message: impl Into<String>) -> Self {
        Failure::new("needs_admin", ERROR, message, false)
    }

    pub fn still_installed(message: impl Into<String>, reported: bool) -> Self {
        Failure::new("still_installed", STILL_INSTALLED, message, reported)
    }

    pub fn incomplete(message: impl Into<String>, reported: bool) -> Self {
        Failure::new("incomplete", INCOMPLETE, message, reported)
    }

    pub fn cancelled(message: impl Into<String>, reported: bool) -> Self {
        Failure::new("cancelled", CANCELLED, message, reported)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// How `main` ends a run that returned an error: exit code, JSON code,
/// message, and whether anything is left to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub exit: i32,
    pub code: &'static str,
    pub message: String,
    pub reported: bool,
}

/// Read the [`Failure`] out of an error, wherever it sits in the chain. The
/// message is the whole chain, as `error:` has always shown it.
pub fn outcome(err: &anyhow::Error) -> Outcome {
    let message = format!("{err:#}");
    match err.chain().find_map(|e| e.downcast_ref::<Failure>()) {
        Some(f) => Outcome {
            exit: f.exit,
            code: f.code,
            message,
            reported: f.reported,
        },
        None => Outcome {
            exit: ERROR,
            code: "error",
            message,
            reported: false,
        },
    }
}

/// The same error, marked as already reported. Its code and exit code stay.
pub fn reported(err: anyhow::Error) -> anyhow::Error {
    let o = outcome(&err);
    Failure::new(o.code, o.exit, o.message, true).into()
}

/// The error object `--json` prints on stdout.
pub fn error_json(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn each_failure_has_its_exit_code() {
        let cases = [
            (Failure::not_found("x"), "not_found", ERROR),
            (Failure::ambiguous("x"), "ambiguous", ERROR),
            (Failure::needs_admin("x"), "needs_admin", ERROR),
            (
                Failure::still_installed("x", false),
                "still_installed",
                STILL_INSTALLED,
            ),
            (Failure::incomplete("x", true), "incomplete", INCOMPLETE),
            (Failure::cancelled("x", false), "cancelled", CANCELLED),
        ];
        for (failure, code, exit) in cases {
            assert_eq!(failure.code, code);
            assert_eq!(failure.exit, exit);
        }
        assert_eq!(
            [DONE, ERROR, USAGE, STILL_INSTALLED, INCOMPLETE, CANCELLED],
            [0, 1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn a_failure_survives_anyhow_and_context() {
        let err: anyhow::Error = Failure::cancelled("Cancelled.", true).into();
        let o = outcome(&err);
        assert_eq!((o.exit, o.code, o.reported), (CANCELLED, "cancelled", true));
        assert_eq!(o.message, "Cancelled.");

        let wrapped = Err::<(), _>(anyhow::Error::from(Failure::not_found("no backup")))
            .context("restoring")
            .unwrap_err();
        let o = outcome(&wrapped);
        assert_eq!((o.exit, o.code), (ERROR, "not_found"));
        assert_eq!(o.message, "restoring: no backup");
    }

    #[test]
    fn a_reported_error_keeps_its_codes() {
        let o = outcome(&reported(Failure::not_found("gone").into()));
        assert_eq!((o.exit, o.code, o.reported), (ERROR, "not_found", true));
        let o = outcome(&reported(anyhow::anyhow!("disk full")));
        assert_eq!((o.exit, o.code, o.reported), (ERROR, "error", true));
        assert_eq!(o.message, "disk full");
    }

    #[test]
    fn any_other_error_is_a_plain_error() {
        let o = outcome(&anyhow::anyhow!("disk full"));
        assert_eq!(o.exit, ERROR);
        assert_eq!(o.code, "error");
        assert_eq!(o.message, "disk full");
        assert!(!o.reported);
    }

    #[test]
    fn the_json_error_has_a_code_and_a_message() {
        let value = error_json("not_found", "no backup matches \"x\"");
        assert_eq!(
            value,
            serde_json::json!({
                "error": { "code": "not_found", "message": "no backup matches \"x\"" }
            })
        );
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 1);
        assert_eq!(object["error"].as_object().unwrap().len(), 2);
    }
}
