# Command-line reference

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

`oxidize clean` only shows what it would clean; `--yes` cleans it. Without a
category flag it takes the safe set, with one or more it takes exactly those.
`--orphans` takes high-confidence folders, `--medium` and `--all` widen it as
for leftovers, and `--delete-dead` deletes the proven dead ones outright. `--elevate` brings back the elevated run's output, because
`clean` never asks a question.

`oxidize uninstall <program> --yes` removes a program completely in one go.
Whatever runs from its folders is closed first: each process is asked to close
its windows. One without a window that runs from the program's own install
folder cannot be asked, so the plan names it before the question, and once
you confirm it is ended by its process id. Any other process still running
three seconds later stops the run before anything is uninstalled or removed,
and the error names it. Nothing that runs from
anywhere else is touched. A program installed for your user alone,
with no service, firewall rule or machine-wide file or key, is then removed by
Oxidize itself, uninstall entry included, without starting its own
uninstaller. Any other program runs its uninstaller first, silently where it
supports that. Every high-confidence leftover goes next, backed up first with
`--backup` (`--medium` adds the plausible ones), and a second scan ends the run with
`Nothing left.` or a list of what is still there and why. `--use-uninstaller`
always runs the program's own uninstaller, `--keep` removes no leftovers, and
`--dry-run` lists every process it would close and every item it would remove.

`oxidize uninstall "Example Player" "Example Editor"` uninstalls several
programs one after another. Every name has to match exactly one program before
anything runs; otherwise nothing runs and the unclear names are listed with
their candidates. The plan is shown once, each program then gets its own
leftover scan and removal, and its own backup with `--backup`, and a summary
follows. If any program
failed, the batch exits with the code of the first one that did.

A program Windows no longer lists is scanned by name alone. Its publisher,
which tells vendor folders and the vendor's files Windows remembers apart,
comes from the uninstall entry an earlier removal backed up, or else from
the company Windows cached for the program's files; the scan says which.
Name it yourself when neither knows:
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
| `--backup` | keep a backup of what is removed, so `oxidize restore` can put it back |

Without `--backup` a removal is permanent, and a dry run says so.
`--no-backup` is still accepted and changes nothing.

`--dry-run` lists every item a removal would take. `--elevate` waits for the
elevated run and exits with its code. It also prints that run's output for
`list`, `protect` and `clean`, which never ask a question, and for any command
with `--json` or `-y`; otherwise the run keeps its own window for its questions.

## Exit codes

| code | |
|---|---|
| 0 | done |
| 1 | error |
| 2 | the command line did not parse, or asked a command for what it does not do |
| 3 | the program is still installed after its uninstall |
| 4 | the removal is incomplete: an item failed or something is left |
| 5 | cancelled: a question was answered no, or `--json` ran without `-y` |

## JSON output

With `--json`, a run that fails before it has a result prints one object
instead: `{"error": {"code": "not_found", "message": "..."}}`. The codes are
`error`, `not_found`, `ambiguous`, `usage`, `still_installed`, `incomplete`
and `cancelled`. A run that already printed its result only sets the exit code,
so stdout always holds one JSON document. A command that would ask a question
needs `-y` as well; without it the answer is no.

`oxidize uninstall <program> --yes --json` prints `nothing_left`,
`still_installed`, `remaining` (what the second scan still found, with
reasons), `below_level` and `kept` (the items below the chosen level, with
reasons), `closed` (the processes it closed), `uninstaller`,
`uninstaller_step`, `removal` (with the `backup` name, and `permanent`, true
when no backup was kept) and `seconds`. A dry
run has `would_close` and `would_remove` instead. With several names a batch
prints `{"programs": [...], "uninstalled", "failed", "cancelled"}`; a single
name keeps the single-program shape. `oxidize scan <program> --json` prints
`program_name`, `installed` and `items`. In `oxidize list --json` every entry
has a `kind`, `program` or `store`.

`oxidize clean --json` prints `backup` (whether the folders of removed
programs would go into one), `analysis` (each category in `findings` with
`bytes`, `count`, `kept`, `notes`, `needs_admin` and `preselected`, and the
`folders` of removed programs with their confidence), `chosen`,
`chosen_folders` and `chosen_bytes`. Each `kept` entry has a `code`
(`recent`, `recently_deleted`, `in_use`, `protected`, `repository`,
`access_denied`, `unreadable`, `needs_admin`, `running`, `failed`), the
`reason` in words, a
`count` and `bytes`. With `--yes` it prints `cleaned`, one entry per category
with `freed`, `removed`, `kept`, `backup` and `notes`, and the total `freed`;
a category that did not clean fully exits with 4. Both carry a `summary` to
compare runs by: `bytes`, `count` and `protected` (the `count` and `bytes`
the protected list kept), in total and per category id under `categories`.
Before a cleaning it counts what each category holds, after it what went.
A protected folder is never entered, so it counts as one item of 0 bytes.
`oxidize clean --traces --json` prints `traces`, one entry per trace with `trace`, `count`, `bytes`,
`count_known`, `kept` and `notes`, and the totals `count` and `bytes`; with
`--yes` the entries are in `cleared`. A jump list kept for its pinned items
has the code `pinned`.

`oxidize protect --check <path> --json` prints `path` as given, `resolved`
(the full path as compared: variables expanded, its real name, lower case),
`protected`, `by` (the entry as written that covers it, or `null`) and
`holds`, the entries inside it, which keep it from being removed as a whole.
Without `--check` it prints the list's `file` and its `entries`.

## What gets checked

Registry keys and values under `SOFTWARE` in HKCU and HKLM, both 32- and
64-bit views, App Paths and autostart entries. Folders under Program Files,
ProgramData, AppData, the Start Menu, Startup and the Desktop. Services,
scheduled tasks, firewall rules and PATH entries. Link types (`name://`
links, also the ones a browser hands to the program), file types and
open-with entries whose command runs from the program's folder, shortcuts
that lead into it whatever they are called, its folders in your temp folder,
other uninstall entries left pointing into it, and the vendor's own key in
your registry when nothing else of theirs is installed, Store apps included.
Windows' own locations are never touched, and a vendor folder that also holds
other products is never removed as a whole. One that held nothing but the
program, folder or key, goes with it.

`oxidize uninstall` also removes Store apps, by name or family name, alone or
in a batch with programs. Windows removes the app for the current user only,
and its data with it; reinstalling means the Store. That removal cannot be
backed up. What runs from the app's folder is closed first, as for a program,
and one that stays, a helper without a window too, stops the removal. A data folder left in
`%LOCALAPPDATA%\Packages` afterwards is a high-confidence leftover, name
matches elsewhere are medium at most, and both go like any other leftover,
into a backup with `--backup`. A protected app is never removed, and Windows may bring back an app
it installs for every new account.
