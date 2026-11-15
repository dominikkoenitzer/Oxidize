// The real program writing to a pipe whose reader has gone, as after `oxidize list | head -n 5`.
use std::process::{Command, Stdio};

/// Runs oxidize with `args` and closes the read end of its stdout before it writes anything.
/// Returns the exit code and what it wrote on stderr.
fn run_unread(args: &[&str]) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oxidize"))
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    let code = output
        .status
        .code()
        .expect("oxidize ended with an exit code");
    (code, String::from_utf8_lossy(&output.stderr).into_owned())
}

#[test]
fn a_list_whose_reader_has_gone_ends_quietly_with_exit_code_0() {
    for args in [&["list"][..], &["list", "--json"]] {
        let (code, stderr) = run_unread(args);
        assert!(!stderr.contains("panicked"), "{args:?} panicked: {stderr}");
        assert!(!stderr.contains("os error"), "{args:?} said: {stderr}");
        assert_eq!(code, 0, "{args:?} said: {stderr}");
    }
}

#[test]
fn an_error_whose_reader_has_gone_keeps_its_own_exit_code() {
    // A usage error with --json is one document on stdout, written after the command is done.
    let (code, stderr) = run_unread(&["mcp", "--dry-run", "--json"]);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert_eq!(code, 2, "{stderr}");
}
