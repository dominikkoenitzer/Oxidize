# Contributing to Oxidize

Oxidize is a Windows-only Rust project.

## Getting set up

```powershell
# Requires the stable Rust toolchain with the MSVC target + VS Build Tools.
rustup default stable
cargo build
cargo test
cargo clippy --all-targets
```

The codebase is split into a shared engine library (`src/lib.rs`) and two thin
front-ends: `src/main.rs` (CLI, `oxidize-cli`) and `src/bin/oxidize-gui.rs`
(GUI). See the module map at the top of `src/main.rs`.

## Ground rules

- **Safety first.** This tool deletes registry keys and files. Anything
  destructive must go through `safety::remove_leftovers`, support `--dry-run`,
  and be backed up first (`.reg` export / file quarantine). Please don't add a
  delete path that bypasses that.
- **Test the risky logic.** The matcher, command-line parser, and backup
  validation have unit tests — add to them when you change behaviour, and prefer
  testing in a throwaway VM.
- Keep `cargo clippy --all-targets -- -D warnings` clean; run `cargo fmt`.
- Match the surrounding style and keep comments where intent isn't obvious.

## Reporting bugs / ideas

Bug reports and ideas via issues are welcome — include your Windows version,
what you ran, and what happened (redact anything sensitive from registry
paths). To use Oxidize or contribute code, please open an issue to arrange
permission first, since the project is all-rights-reserved.
