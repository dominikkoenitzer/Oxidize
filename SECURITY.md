# Security Policy

## Reporting a vulnerability

Report security issues privately. Please don't open a public issue for anything
security-sensitive. Use a
[private security advisory](https://github.com/dominikkoenitzer/Oxidize/security/advisories/new)
on this repository.

Include what happened and what it affects, the program you were uninstalling and
the exact command line, the `--json` output or the console log if you still have
it, and your Windows version.

I answer as soon as I can, usually within a few days, and fix what needs fixing
in the next release. Say so if you want credit once it is resolved.

## Scope

Oxidize deletes registry keys and files and asks for administrator rights to do
it, so correctness and safety are the same question here. If it removes the
wrong thing, that is a security issue and I would rather hear about it that way.

What matters most:

- Anything deleted that should not have been. Every destructive action goes
  through one choke point, `remove_leftovers` in `src/safety.rs`, and
  `is_protected_path` and `path_within_shared_dir` in `src/scanner.rs` are what
  stand between a match and a Windows directory or a folder shared with another
  program. A path that gets past them is the worst bug this repository can have.
- A deletion that cannot be undone. Registry keys are exported with
  `reg.exe export` and the file is checked for its BOM, its header and the key
  it should contain before anything is touched; files are moved to quarantine
  instead of deleted. Anything that deletes without a verified backup, or loses
  the quarantine, is in scope.
- A `--dry-run` that is not dry. It shows and never touches.
- Elevation problems: an elevation that was not needed, a privilege that
  outlives its use, or a way to make Oxidize run something else elevated.
- Anything the uninstalled program controls. Uninstall strings, display names
  and install locations come out of the registry, so a malicious program picks
  them. Command injection or a path escape through one of those is in scope.

Out of scope: a leftover Oxidize does not find. That is a coverage gap, so open
a normal issue with the program name.
