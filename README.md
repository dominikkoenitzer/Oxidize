# Oxidize

Uninstall Windows programs and remove what they leave behind.

Windows' own uninstall leaves things around: registry keys, folders under
AppData and ProgramData, services, scheduled tasks, firewall rules, PATH
entries that point nowhere. Oxidize runs a program's own uninstaller, then
finds those leftovers and removes them. Everything removed is backed up first
and can be put back with one command.

```
oxidize list                     installed programs
oxidize uninstall <program>      uninstall, then remove the leftovers
oxidize scan <program>           leftovers of a program, installed or not
oxidize orphans                  folders and references nothing owns anymore
oxidize trace <exe or process>   which program does this belong to
oxidize backups                  what earlier removals backed up
oxidize restore <backup>         put a backup back
```

`oxidize-gui.exe` is the same engine as a window.

## Install

Download `oxidize-<version>-windows-x64.zip` from the latest release, check it
against the `.sha256` file next to it, and unpack `oxidize.exe` and
`oxidize-gui.exe` into a folder on your PATH. Or build it yourself:

```
cargo build --release
```

Windows only. Rust 1.95 or newer with the MSVC toolchain.

## Using it

Names can be partial. `oxidize uninstall brave` is enough if only one program
matches.

```
oxidize uninstall brave
oxidize scan "Google Chrome"          works after the program is gone
oxidize scan Docker --remove
oxidize orphans --remove              drops PATH entries, autostart values, services
                                      and tasks whose files no longer exist
```

`oxidize uninstall brave vlc 7zip` uninstalls several programs one after
another. Every name has to match exactly one program before anything runs;
otherwise nothing runs and the unclear names are listed with their candidates.
The plan is shown once, each program then gets its own leftover scan, removal
and backup, and a summary follows. The exit code is 1 if any program failed.
With `--json` a batch prints `{"programs": [...], "uninstalled", "failed",
"cancelled"}`; a single name keeps the single-program shape.

A program Windows no longer lists is scanned by name alone, and a vendor folder
is only recognised as one when you name the publisher:
`oxidize scan Chrome --publisher "Google LLC"`.

`oxidize list` shows Store apps next to programs, marked `store`;
`oxidize list --store` shows only them, and `--system` adds the ones that are
part of Windows. An app Oxidize would never remove, such as the Store itself, a
runtime or the package of a normal program, is marked `protected` with the
reason. With `--json` every entry gains a `kind`, `program` or `store`.

Every leftover has a confidence. `--remove` takes the high-confidence ones;
`--medium` adds the plausible ones, `--all` takes everything listed.

| flag | |
|---|---|
| `--dry-run` | show what would happen, change nothing |
| `-y` | answer yes to every prompt |
| `--json` | machine-readable output |
| `--elevate` | relaunch as administrator |
| `--no-backup` | delete permanently instead of quarantining |

## What gets checked

Registry keys and values under `SOFTWARE` in HKCU and HKLM, both 32- and
64-bit views, App Paths and autostart entries. Folders under Program Files,
ProgramData, AppData, the Start Menu, Startup and the Desktop. Services,
scheduled tasks, firewall rules and PATH entries. Windows' own locations are
never touched, and a vendor folder that also holds other products is never
removed as a whole. One that held nothing but the program, folder or key, goes
with it.

Store apps are listed but not removed yet.

## Backups

Removals go to `%LOCALAPPDATA%\Oxidize\backups\<date> <program>\`. Registry
keys are exported to `.reg` files and validated before anything is deleted.
Files and folders are moved there, not deleted. Task definitions are copied.
A manifest records every step, and `oxidize restore` replays it in reverse.

## Building and testing

```
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The engine is a library (`src/lib.rs`); `src/main.rs` and
`src/bin/oxidize-gui.rs` are the two front-ends. Nothing deletes anything
except `safety::remove_leftovers`.

## License

MIT.
