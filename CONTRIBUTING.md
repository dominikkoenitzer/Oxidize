# Contributing

Oxidize is a Windows-only Rust project.

```
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

The engine is the library in `src/lib.rs`. `src/main.rs` is the command line,
`src/bin/oxidize-gui.rs` the window.

Rules:

- Anything destructive goes through `safety::remove_leftovers`, honours
  `--dry-run` and is backed up first. Do not add another delete path.
- The matcher, the command-line parser and the backup validation have unit
  tests. Extend them when you change behaviour, and try changes in a
  throwaway VM.
- Keep clippy and rustfmt clean.

Bug reports are welcome as issues. Include the Windows version, the command
you ran and what happened. Redact anything sensitive from registry paths.
