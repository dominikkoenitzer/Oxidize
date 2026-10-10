# Oxidize

Uninstall Windows programs and remove what they leave behind.

[Download Oxidize](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize-gui.exe), then double-click it.

The file is not signed, so Windows may show "Windows protected your PC". Click
More info, then Run anyway.

The command-line version is
[oxidize.exe](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize.exe),
or get [a zip with both](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize-windows-x64.zip).
It runs from a terminal, for example `.\oxidize.exe list` in the folder you
saved it to.

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
oxidize mcp                      let an AI assistant use Oxidize
```

`oxidize-gui.exe` is the same engine as a window.

## Install

Oxidize runs on Windows only and has no installer. Every release uses the same
file names, so these links always get the latest version:

| file | |
|---|---|
| [`oxidize-gui.exe`](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize-gui.exe) | the window app |
| [`oxidize.exe`](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize.exe) | the command line |
| [`oxidize-windows-x64.zip`](https://github.com/dominikkoenitzer/Oxidize/releases/latest/download/oxidize-windows-x64.zip) | both in one zip |

The window app runs from wherever you save it. Double-click it; if Windows
warns that it does not know the file, click More info, then Run anyway.

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

`oxidize uninstall` also removes Store apps, by name or family name, alone or
in a batch with programs. Windows removes the app for the current user only,
and its data with it; reinstalling means the Store. That removal cannot be
backed up. A data folder left in `%LOCALAPPDATA%\Packages` afterwards is a
high-confidence leftover, name matches elsewhere are medium at most, and both
are backed up like any other leftover. A protected app is never removed, and
Windows may bring back an app it installs for every new account.

## Backups

Removals go to `%LOCALAPPDATA%\Oxidize\backups\<date> <program>\`. Registry
keys are exported to `.reg` files and validated before anything is deleted.
Files and folders are moved there, not deleted. Task definitions are copied.
A manifest records every step, and `oxidize restore` replays it in reverse.

## Use it with an AI assistant

`oxidize mcp` lets an assistant that speaks MCP (the Model Context Protocol)
use Oxidize on your PC. Add it to the assistant's MCP settings with the full
path to `oxidize.exe`:

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

The assistant can then list programs and Store apps, scan for a program's
leftovers, find orphans, trace an exe or a running process to its program and
list your backups. None of that changes anything.

To remove a program it first asks for a plan, which changes nothing either:
the uninstaller and whether it runs at all, every leftover that would go with
its path, size, confidence and reason, whether administrator rights are needed,
and where the backup goes. Only applying that plan removes anything, and only a
plan made in the same session, exactly as shown and once. Copies of the program
still running from its folders are closed first. Your assistant asks you before
it calls a tool, unless you told it to stop asking for this one, so nothing is
removed until you agree to that step.

Every removed item is backed up the same way as from the command line, and
there is no way to skip it. The result says what was removed, what was not and
why, what a fresh scan still finds, and the `oxidize restore` command that puts
the removed items back. The assistant cannot restore or delete backups, remove
anything that was not in a plan, or start Oxidize as administrator. Items that
need administrator rights are reported with the command that removes them as
administrator, for you to run.

Every plan also lists the commands that do the same from a terminal, for
example `oxidize uninstall "Example Player"`, if you would rather run the
removal yourself.

The server runs only while the assistant has it open and talks to it over
stdin and stdout, nothing else.

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
through one trait and removes through another, `Remove` in
`src/mcp/machine.rs`, which only `apply_removal_plan` holds.

## License

MIT.
