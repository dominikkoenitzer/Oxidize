# Oxidize

Oxidize uninstalls Windows programs and removes what they leave behind.

[Download Oxidize](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize-gui.exe), then double-click it.

The file is not signed, so Windows may say "Windows protected your PC"; click More info, then Run anyway.

There is nothing to install. The command-line version and a zip with both are
under [Other ways to install](#other-ways-to-install).

## What it does

Windows' own uninstall leaves things around: registry keys, folders under
AppData and ProgramData, services, scheduled tasks, firewall rules, PATH
entries that point nowhere. Oxidize closes whatever still runs from the
program's folders, runs its uninstaller when one is needed, then finds those
leftovers and removes them. A second scan ends the run with `Nothing left.` or
a list of what is still there and why. Everything removed is backed up first
and can be put back with one command.

In the window, select a program and click Remove completely; Undo puts back
what was removed. From a terminal it is one command:

```
oxidize uninstall "Example Player" --yes
```

```
oxidize list                     installed programs and Store apps
oxidize uninstall <program>      uninstall, then remove the leftovers
oxidize scan <program>           leftovers of a program, installed or not
oxidize orphans                  folders and references nothing owns anymore
oxidize trace <exe or process>   which program does this belong to
oxidize backups                  what earlier removals backed up
oxidize restore <backup>         put a backup back
oxidize mcp                      let an AI assistant use Oxidize
```

`oxidize-gui.exe` is the same engine as a window. The full command-line
reference is [further down](#command-line-reference).

## Use it with an AI assistant

`oxidize mcp` runs an MCP (Model Context Protocol) server for an assistant on
your PC. It talks to the assistant over stdin and stdout, nothing else, and
runs only while the assistant has it open. Add it to the assistant's MCP
settings with the full path to `oxidize.exe`:

```json
{
  "mcpServers": {
    "oxidize": {
      "command": "C:\\Tools\\oxidize.exe",
      "args": ["mcp"]
    }
  }
}
```

`list_programs`, `scan_leftovers`, `find_orphans`, `trace` and `list_backups`
only read. To remove a program the assistant first calls `plan_removal`, which
changes nothing either: it returns the uninstaller and whether it runs at all,
every leftover that would go with its path, size, confidence and reason,
whether administrator rights are needed, and where the backup goes.
`apply_removal_plan` carries out a plan made in the same session, exactly as
shown and only once, after closing copies of the program still running from
its folders. Your assistant asks you before it calls a tool, unless you told it
to stop asking for this one, so nothing is removed until you agree to that
step.

Every removed item is backed up the same way as from the command line, and
there is no way to skip it. The result says what was removed, what was not and
why, what a fresh scan still finds, and the `oxidize restore` command that puts
the removed items back. The assistant cannot restore or delete backups, remove
anything that was not in a plan, or start Oxidize as administrator. Items that
need administrator rights are reported with the command that removes them as
administrator, for you to run. Every plan also lists the commands that do the
same from a terminal, for example `oxidize uninstall "Example Player"`, if you
would rather run the removal yourself.

Scripts can use the command line directly: every command takes `--json`, and
stdout then holds exactly one JSON document. See [JSON output](#json-output).

## Your data, updates and removal

Oxidize stores nothing but its backups. Each removal gets a folder
`%LOCALAPPDATA%\Oxidize\backups\<date and time> <program>\`. Registry keys are
exported to `.reg` files and validated before anything is deleted. Files and
folders are moved there, not deleted. Task definitions are copied. A manifest
records every step, and `oxidize restore` replays it in reverse.

`oxidize backups` lists the backups, newest first. With `--json` each entry's
`id` is its folder name, and `oxidize restore <id>` takes it as an exact
match; a part of the name or of the program's name works too when only one
backup matches it. `restore` asks first, Enter means yes; `-y` skips the
question. `oxidize backups --delete <name>` deletes one backup and
`oxidize backups --clear` deletes them all.

To update, download the file again and replace the old one. Every release uses
the same file names, so the links here always get the latest version.

To remove Oxidize, delete `oxidize-gui.exe` and `oxidize.exe`, then the folder
`%LOCALAPPDATA%\Oxidize` once you no longer need the backups in it. If you
added a folder to your PATH for `oxidize.exe`, remove that entry too.

## Other ways to install

Oxidize runs on Windows only and has no installer. Each release has three files:

| file | |
|---|---|
| [`oxidize-gui.exe`](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize-gui.exe) | the window app |
| [`oxidize.exe`](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize.exe) | the command line |
| [`oxidize-windows-x64.zip`](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize-windows-x64.zip) | both in one zip |

To type `oxidize` in any terminal, `oxidize.exe` has to be in a folder on your
PATH. Make a folder such as `C:\Tools` and move `oxidize.exe` into it. Search
Windows for "Edit environment variables for your account", select `Path`,
click Edit, then New, type `C:\Tools` and close both windows with OK. Terminals
you open after that find it.

You can also skip PATH and run it from the folder you saved it to. Open a
terminal there (right-click an empty spot in the folder, then Open in Terminal)
and start it with its path:

```
.\oxidize.exe list
```

Double-clicking `oxidize.exe` in Explorer opens the window app when
`oxidize-gui.exe` is in the same folder. Otherwise it shows the help and waits
for Enter.

Each file has a `.sha256` file next to it in the release, for example
`oxidize-gui.exe.sha256`. To check a download, save both into the same folder,
open a terminal there and run:

```
Get-FileHash .\oxidize-gui.exe -Algorithm SHA256
```

The hash it prints has to match the one in `oxidize-gui.exe.sha256`; upper or
lower case does not matter. This line compares them for you and prints `True`
when they match:

```
(Get-FileHash .\oxidize-gui.exe -Algorithm SHA256).Hash -eq (Get-Content .\oxidize-gui.exe.sha256).Split(' ')[0]
```

## Command-line reference

Names can be partial. `oxidize uninstall player` is enough if only one program
matches.

```
oxidize uninstall "Example Player"
oxidize scan "Example Player"         works after the program is gone
oxidize scan "Example Player" --remove
oxidize orphans --remove              drops PATH entries, autostart values, services
                                      and tasks whose files no longer exist
```

`oxidize scan <program> --remove` is for leftovers of a program that is
already gone; while it is still installed, use `oxidize uninstall`.

`oxidize uninstall <program> --yes` removes a program completely in one go.
Whatever runs from its folders is closed first: each process is asked to close
its windows and ended if it is still running three seconds later. Nothing that
runs from anywhere else is touched. A program installed for your user alone,
with no service, firewall rule or machine-wide file or key, is then removed by
Oxidize itself, uninstall entry included, without starting its own
uninstaller. Any other program runs its uninstaller first, silently where it
supports that. Every high-confidence leftover goes next, with a backup
(`--medium` adds the plausible ones), and a second scan ends the run with
`Nothing left.` or a list of what is still there and why. `--use-uninstaller`
always runs the program's own uninstaller, `--keep` removes no leftovers, and
`--dry-run` lists every process it would close and every item it would remove.

`oxidize uninstall "Example Player" "Example Editor"` uninstalls several
programs one after another. Every name has to match exactly one program before
anything runs; otherwise nothing runs and the unclear names are listed with
their candidates. The plan is shown once, each program then gets its own
leftover scan, removal and backup, and a summary follows. If any program
failed, the batch exits with the code of the first one that did.

A program Windows no longer lists is scanned by name alone, and a vendor folder
is only recognised as one when you name the publisher:
`oxidize scan "Example Player" --publisher "Example Corp"`.

`oxidize list` shows Store apps next to programs, marked `store`;
`oxidize list --store` shows only them, and `--system` adds the ones that are
part of Windows. An app Oxidize would never remove, such as the Store itself, a
runtime or the package of a normal program, is marked `protected` with the
reason.

Every leftover has a confidence. `--remove` takes the high-confidence ones;
`--medium` adds the plausible ones, `--all` takes everything listed. The same as
one flag: `--level high`, `--level medium` or `--level low`.

| flag | |
|---|---|
| `--dry-run` | show what would happen, change nothing |
| `-y`, `--yes` | answer yes to every prompt |
| `--json` | machine-readable output |
| `--no-color` | plain output without colour |
| `--elevate` | relaunch as administrator |
| `--no-backup` | delete permanently instead of quarantining |

`--dry-run` lists every item a removal would take. `--elevate` waits for the
elevated run and exits with its code. With `--json` or `-y` it also prints that
run's output; otherwise the run keeps its own window for its questions.

### Exit codes

| code | |
|---|---|
| 0 | done |
| 1 | error |
| 2 | the command line did not parse |
| 3 | the program is still installed after its uninstall |
| 4 | the removal is incomplete: an item failed or something is left |
| 5 | cancelled: a question was answered no, or `--json` ran without `-y` |

### JSON output

With `--json`, a run that fails before it has a result prints one object
instead: `{"error": {"code": "not_found", "message": "..."}}`. The codes are
`error`, `not_found`, `ambiguous`, `still_installed`, `incomplete` and
`cancelled`. A run that already printed its result only sets the exit code,
so stdout always holds one JSON document. A command that would ask a question
needs `-y` as well; without it the answer is no.

`oxidize uninstall <program> --yes --json` prints `nothing_left`,
`still_installed`, `remaining` (what the second scan still found, with
reasons), `below_level`, `closed` (the processes it closed), `uninstaller`,
`uninstaller_step`, `removal` (with the `backup` name) and `seconds`. A dry
run has `would_close` and `would_remove` instead. With several names a batch
prints `{"programs": [...], "uninstalled", "failed", "cancelled"}`; a single
name keeps the single-program shape. `oxidize scan <program> --json` prints
`program_name`, `installed` and `items`. In `oxidize list --json` every entry
has a `kind`, `program` or `store`.

### What gets checked

Registry keys and values under `SOFTWARE` in HKCU and HKLM, both 32- and
64-bit views, App Paths and autostart entries. Folders under Program Files,
ProgramData, AppData, the Start Menu, Startup and the Desktop. Services,
scheduled tasks, firewall rules and PATH entries. Link types (`name://`
links, also the ones a browser hands to the program), file types and
open-with entries whose command runs from the program's folder, shortcuts
that lead into it whatever they are called, its folders in your temp folder,
other uninstall entries left pointing into it, and the vendor's own key in
your registry when nothing else of theirs is installed. Windows' own locations
are never touched, and a vendor folder that also holds other products is never
removed as a whole. One that held nothing but the program, folder or key, goes
with it.

`oxidize uninstall` also removes Store apps, by name or family name, alone or
in a batch with programs. Windows removes the app for the current user only,
and its data with it; reinstalling means the Store. That removal cannot be
backed up. A data folder left in `%LOCALAPPDATA%\Packages` afterwards is a
high-confidence leftover, name matches elsewhere are medium at most, and both
are backed up like any other leftover. A protected app is never removed, and
Windows may bring back an app it installs for every new account.

## Build from source

You need Git, Rust 1.95 or newer and the Visual Studio Build Tools with the
Windows SDK. The Build Tools provide the MSVC linker; the SDK provides
`rc.exe`, which `build.rs` needs to embed the icon. On a fresh PC, install them
from PowerShell:

```
winget install --id Git.Git -e
winget install --id Rustlang.Rustup -e
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100"
```

Open a new terminal so PATH picks up the new tools, then build:

```
rustup default stable
git clone https://github.com/dominikkoenitzer/Oxidize.git
cd Oxidize
cargo build --release --locked
```

The programs end up in `target\release\oxidize.exe` and
`target\release\oxidize-gui.exe`. Both are self-contained: the C runtime is
linked in, so they run on any Windows PC without installing a runtime.

Once you have the clone, `scripts\setup.ps1` does the checking for you. It
looks for rustup, cargo, the MSVC build tools and the Windows SDK and prints
the winget command for anything missing; it installs nothing itself. When
nothing is missing it runs `cargo build --release --locked`. From the
repository root:

```
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

Before you send a change, run what CI runs:

```
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

The engine is a library (`src/lib.rs`); `src/main.rs` and
`src/bin/oxidize-gui.rs` are the two front-ends. Leftovers are only ever
deleted through `safety::remove_leftovers`; the one other destructive call is
the Store-app removal in `packages.rs`, which Windows carries out and which
runs only after the guard allows it. The MCP server in `src/mcp.rs` reads
through one trait and removes through another, `Remove`, implemented in
`src/mcp/machine.rs`, which only `apply_removal_plan` holds.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as
described in [SECURITY.md](SECURITY.md). Changes are listed in
[CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
