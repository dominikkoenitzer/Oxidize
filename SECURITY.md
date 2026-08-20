# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public GitHub issue for anything security-sensitive.

- Preferred: open a [private security advisory](https://github.com/dominikkoenitzer/Oxidize/security/advisories/new) on this repository.
- Alternatively: email **dominik.koenitzer@gmail.com** with the details.

Please include:

- a description of the issue and its impact,
- the program you were uninstalling and the exact command line,
- the `--json` output or the console log if you still have it, and
- your Windows version.

## What to expect

- An acknowledgement of your report, typically within a few days.
- An assessment and, where applicable, a fix in the next release.
- Credit for the report if you would like it, once the issue is resolved.

## Scope

Oxidize deletes registry keys and files, and it asks to run **as Administrator** to do it. That makes correctness and safety the same thing here: a bug that removes the wrong thing is a security bug, not a papercut.

The reports that matter most:

- **Anything deleted that should not have been.** Every destructive action passes through a single choke point (`remove_leftovers` in `src/safety.rs`), and `is_protected_path` / `path_within_shared_dir` in `src/scanner.rs` are what stand between a match and a Windows directory or a folder shared with another program. A path that gets past them is the highest-severity bug in this repository.
- **A deletion that is not reversible.** Registry keys are exported with `reg.exe export` and the file is validated (BOM, header, non-empty) *before* the key is touched; files are moved into quarantine rather than destroyed. Any path that deletes without a verified backup, or that silently loses the quarantine, is in scope.
- **`--dry-run` that is not dry.** It must show and never touch.
- **Elevation problems** — an unnecessary elevation, a privilege that outlives its use, or a way to get Oxidize to run something else elevated.
- **Anything influenced by the uninstalled program.** Uninstall strings, display names and install locations come from the registry and are attacker-controlled if the program was malicious; command injection or a path escape through one of those values is in scope.

Out of scope: a leftover Oxidize fails to *find*. That is a coverage gap — open a normal issue with the program name.
