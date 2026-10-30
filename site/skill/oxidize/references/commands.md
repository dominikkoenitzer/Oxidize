# Command reference

`oxidize <command> [arguments] [flags]`. `oxidize --help` and `oxidize <command> --help` print the same, `oxidize --version` the version.

## Global flags

These work with every command, before or after it.

| flag | effect |
|---|---|
| `--dry-run` | Show what would happen, change nothing. No question is asked. |
| `-y`, `--yes` | Answer yes to every question. |
| `--json` | Print one JSON document on stdout instead of text. Never asks; without `-y` every question counts as no. |
| `--no-color` | Plain text without colour. `--json` implies it. |
| `--no-backup` | Delete without a backup. Removals become permanent. |
| `--elevate` | Run the same command again as administrator, after a Windows prompt, in a new window. Oxidize waits for it and exits with its exit code. It also prints that run's stdout and stderr for `list`, `protect` and `clean`, which never ask a question, and for any command with `--json` or `-y`; otherwise the run keeps its own window for its questions and its output stays there. A declined prompt exits with 5. Without effect when Oxidize already runs as administrator. |

## Confidence levels

Every leftover has a confidence: `High`, `Medium` or `Low`. Removal takes High only. These flags widen it, on `uninstall`, `scan` and `trace`:

| flag | removes |
|---|---|
| (none), `--level high` | High |
| `--medium`, `--level medium` | High and Medium |
| `--all`, `--level low` | High, Medium and Low |

`--level all` is the same as `--level low`. `--level` cannot be combined with `--medium` or `--all`.

## list

`oxidize list [FILTER] [--system] [--store] [--sort name|size|date|publisher]`

Lists installed programs and Store apps. Reads only.

- `FILTER`: only entries whose name or publisher contains this text, case-insensitive.
- `--system`: also hidden system components and the Store apps that are part of Windows.
- `--store`: only Store apps.
- `--sort`: `name` (default), `size`, `date` or `publisher`.

## uninstall

`oxidize uninstall PROGRAM... [--silent] [--keep] [--use-uninstaller] [--medium | --all | --level LEVEL]`

Removes each program completely: closes what runs from its folders, runs its own uninstaller when one is needed, removes the leftovers at the chosen level with a backup, then scans again.

- `PROGRAM`: a name, a unique part of it, or its id: the `registry_key` of a program or the `family_name` of a Store app. Matching tries the exact id, then the exact name, then a unique part of the name.
- Several names run one after another. Every name must match exactly one program before anything runs; otherwise nothing runs and the unclear names are listed with their candidates.
- Closing: a process whose executable lies in the program's install folder, or in a folder the scan gives the program at High confidence, is asked to close its windows. Nothing is ended by force: one still running three seconds later, or one without a window to be asked through, stops the run with an error before the uninstaller or any removal. Processes in the Windows folder, Oxidize itself and the processes that started it are never closed.
- The uninstaller is skipped when the program is registered for the current user only, has a folder of its own, is not a Windows Installer product, and owns nothing machine-wide: no service, firewall rule, or key, value or PATH entry in HKLM, and no file under Program Files, ProgramData or the Public folder. Oxidize then removes all of it itself, the uninstall entry included. Every other program runs its uninstaller first.
- `--use-uninstaller`: always run the program's own uninstaller.
- `--silent`: use the program's unattended uninstall switches where it has them. For Windows Installer products this adds `/qn /norestart`, for an uninstaller named `unins000.exe` (or another number) without a recorded quiet command `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`. A program without either runs its normal uninstall command. `-y` and `--json` imply `--silent`.
- Waiting: with `-y`, `--json` or unattended switches, Oxidize waits up to 60 seconds for the uninstaller to end and up to 60 more for the program to leave the list. Otherwise it waits until the uninstaller ends, then up to two minutes for the program to leave the list.
- `--keep`: run the uninstaller, then show the leftovers and remove nothing. Nothing is closed, and the uninstaller always runs. A Store app is still removed by Windows with `--keep`, so what runs from its folder is still closed first.
- Questions: "Remove it completely? Running copies are asked to close first." (with `--keep`: "Run the uninstaller?"; with several names: "Run N uninstallers?"), then "Remove N items? Backups are kept for restore." For a Store app: "Remove the Store app?", which defaults to no.
- After an uninstaller, leftovers are removed only once the program has left the list.
- Some of Windows' records of a removed file, such as the history of a shortcut, only show once the file is gone. New high-confidence items in the second scan go without another question in one more pass, into the same backup, and a last scan follows. There is never a third pass.
- The last scan ends the run with `Nothing left.` or a list of what is still there and why. Items below the chosen level are counted as kept.
- `--dry-run`: lists every process it would close and every item it would remove, and says whether the uninstaller would run. Nothing is closed, started or removed.
- A Store app guarded as `protected` in `list` is refused. Removing a Store app cannot be backed up; its leftovers found afterwards are. What runs from the app's install folder is closed first, as for a program; one that stays stops the removal. A helper with no window is named in `would_stay` (dry run) or with `"windowless": true` in `closed`.

## scan

`oxidize scan PROGRAM [--publisher TEXT] [--remove] [--medium | --all | --level LEVEL]`

Finds a program's leftovers. Reads only unless `--remove` is given.

- `PROGRAM`: a name, a unique part of it, or its registry id. A program that is not installed is scanned by name.
- `--publisher`: the publisher, so vendor folders are recognised when scanning by name. Without it, the publisher comes from the uninstall entry a backup of an earlier removal holds, or from the company Windows cached for files it shows under the program's name; the text output says which.
- `--remove`: remove what was found at the chosen level, after a question. Refused while the program is still installed, except with `--dry-run`.
- A name that only matches a Store app is refused; use `uninstall` for those.

## orphans

`oxidize orphans [--remove]`

Lists folders no installed program claims, and PATH entries, autostart values, services and tasks that point to files that no longer exist. Reads only unless `--remove` is given.

- `--remove`: remove the dangling references, after a question. The folders are listed only and never removed by this command.

## trace

`oxidize trace EXE_OR_PROCESS [--uninstall] [--silent] [--keep] [--medium | --all | --level LEVEL]`

Finds the program behind a running process or an executable.

- `EXE_OR_PROCESS`: a path to an `.exe` or a folder, or the name of a running process.
- `--uninstall`: remove the best match completely, as `uninstall` does. Refused when two programs match equally well or the best score is below 80.
- `--silent`, `--keep`: as for `uninstall`, with `--uninstall` only.

## backups

`oxidize backups [--delete NAME | --clear]`

Lists the backups of earlier removals, newest first. Reads only unless a delete flag is given.

- `--delete NAME`: delete one backup, after a question that defaults to no. `NAME` is matched as for `restore`.
- `--clear`: delete every backup, after a question that defaults to no. A backup that cannot be deleted stays, and the others still go.
- Only folders inside the backups folder are ever deleted.

## restore

`oxidize restore NAME`

Puts back everything a backup holds, in reverse order of removal, after the question "Restore N items from NAME?", which defaults to yes. `-y` skips it; with `--json` it needs `-y`, or nothing is restored.

- `NAME`: the backup's `id` or name as shown by `oxidize backups`, which matches exactly, or a part of it or of the program name that matches exactly one backup. Case does not matter. A part that matches several backups is refused.
- With `--dry-run` it asks nothing, checks that the saved copies are still in the backup and restores nothing.
- Files and folders: an item fails with `already exists` if something is at its old path. Restoring the same backup twice is harmless.
- Registry values are written over what is there. Registry keys are merged with `reg import`. Tasks replace a task of the same name. PATH entries go back at their old position unless already present.
- The backup folder is kept afterwards.

## clean

`oxidize clean [--temp] [--crash-dumps [--dump PATH]... [--skip-dumps-of PROGRAM]...] [--recycle-bin] [--browser-cache] [--component-store] [--delivery-optimization] [--windows-old] [--orphans [--delete-dead]] [--build-output] [--recycle-bin-days DAYS] [--medium | --all | --level LEVEL]`

Counts what each category holds, from the files themselves, and what stays and why. Reads only unless `--yes` is given; then it cleans and reports per category what was freed and what stayed. It never asks a question, so `--elevate` always brings the elevated run's output back.

- Without a category flag the safe set is chosen: `--temp`, `--crash-dumps`, `--browser-cache`, and `--orphans` at high confidence. With flags, exactly those.
- `--temp`: files neither written nor created for 7 days, in the user's temp folder and in Windows' own (`%SystemRoot%\Temp`, administrator only). A file another program holds open stays. A git repository (a folder with a `.git` folder or file, or a bare repository) is never entered and stays whole however old, counted in `kept` with the code `repository`.
- `--crash-dumps`: `.dmp` files in `%LOCALAPPDATA%\CrashDumps`, `%SystemRoot%\Minidump`, `%SystemRoot%\LiveKernelReports` and `MEMORY.DMP`, and the queued and archived error reports under `Microsoft\Windows\WER`. The machine-wide ones need administrator rights. The plan lists each dump under `dumps`: a dump file, or an error report's folder, with the program it belongs to where its name says it.
- `--dump PATH`, with `--crash-dumps`: clean only this dump, a path as `dumps` lists it. Give it once for each dump. A path that is not among the dumps found is named in `notes`.
- `--skip-dumps-of PROGRAM`, with `--crash-dumps`: leave the dumps of this program, by its file name with or without `.exe`, in any case. Give it once for each program. What either flag leaves stays, counted in `kept` with the code `left_out`.
- `--recycle-bin`: items in the user's Recycle Bin on every fixed drive deleted at least `--recycle-bin-days` ago (30 by default). Never chosen by itself.
- `--browser-cache`: only the folders `Cache`, `Code Cache`, `GPUCache`, `DawnCache`, `DawnGraphiteCache`, `DawnWebGPUCache` and `Media Cache` of each Chromium profile (Chrome, Edge, Brave, Vivaldi, Chromium and their beta channels), the shared shader caches beside them, and `cache2`, `startupCache` and `jumpListCache` of Firefox profiles. A browser that is running is skipped.
- `--component-store`: runs `dism /Online /English /Cleanup-Image /StartComponentCleanup`, never `/ResetBase`. Administrator only. The space freed is measured on the drive afterwards.
- `--delivery-optimization`: runs `Delete-DeliveryOptimizationCache -Force`. Administrator only.
- `--windows-old`: removes `Windows.old` through Disk Cleanup's previous-installations handler. Administrator only, never chosen by itself, and the previous Windows cannot come back afterwards.
- `--orphans`: folders no installed program claims, under the roots `orphans` reads. A folder named like a program Oxidize or Windows Installer removed is High by the leftover rules, a looser match Medium, every other Low. They are moved into a backup like leftovers. A backup on the same drive frees nothing until it is deleted.
- `--delete-dead`, with `--orphans`: delete the chosen folders that are proven dead outright, without a backup, so their space comes back at once. Proven dead: High, no file in it changed for 30 days (written or created) or held open by a program, nothing running from it, no git repository in it or above it, and all of it readable and on the disk: a cloud placeholder or another file whose data may live elsewhere keeps it from being proven. The plan marks each folder with `proven_dead` and lists the ones that would go outright in `chosen_outright`. Each is checked again right before it goes, and goes whole or not at all; one that came alive goes into the backup instead, and the run's `notes` say how many. A folder Windows keeps from the user's reach is not proven dead without administrator rights. Without `--delete-dead` no folder is proven dead, and `proven_dead` is false.
- `--build-output`: folders a build or package tool marked as its cache with a `CACHEDIR.TAG` file that starts with the Cache Directory Tagging signature, with a project file beside it (`Cargo.toml`, `package.json`, `pyproject.toml`, `CMakeLists.txt`, `build.gradle`, `go.mod` or a `.csproj` file) or ignored by git in its checkout, found up to six folders deep in the user's profile and never in the temp folders, with nothing in them changed for 30 days. Never chosen by itself, and deleted without a backup: the tool makes them again. One in a git checkout goes only while `git status` shows no changed, staged or untracked file there (`uncommitted` in `kept`); with administrator rights git is not run, since a checkout's own settings can start programs, and such a folder stays (`checkout_unknown`). A git repository inside one keeps it (`repository`), and so does a program running from it or a file in it that is open (`in_use`). A cloud placeholder or another file whose data may live elsewhere keeps it too (`unreadable`). Each folder is checked again right before it goes, and goes whole or not at all. The plan lists them under `build_folders`. A tagged folder with neither a project file nor git ignoring it is not listed at all; with administrator rights git is not asked, so only the project file counts. Build output is looked for only with this flag; without it the finding is empty and has `skipped` set.
- Folders and files listed in `%LOCALAPPDATA%\Oxidize\protected.txt` are never cleaned, with everything inside them; a folder that holds one is never removed as a whole.
- `--no-backup` deletes all the chosen folders of removed programs for good, proven dead or not. Nothing else the command cleans is backed up.
- With `--json`, the plan and the run both carry `summary`: `bytes`, `count` and `protected` (`count` and `bytes` the protected list kept), in total and per category id under `categories`. A protected folder is never entered, so it counts as one item of 0 bytes. Compare two runs by it.

## protect

`oxidize protect [--check PATH]`

Reads only. Without `--check` it prints the protected list; with `--json`, its `file` and `entries`. A line of the file that is not a full path once `%VAR%` references are expanded, or that names a whole drive, protects nothing and is not among the entries.

- `--check PATH`: whether `PATH` is listed itself or lies inside a listed folder. `%VAR%` references are expanded and a relative path is taken from the current folder. The comparison is by the full real name, so a folder reached through a junction answers by either name, and `C:\Tools\wt` is not covered by `C:\Tools\wt-old`.
- `--json` prints `path`, `resolved` (the full path as compared, lower case), `protected`, `by` (the entry as written that covers it, or `null`) and `holds` (entries inside it; such a folder is cleaned but never removed as a whole). The exit code is 0 either way.

## Backup folder

`%LOCALAPPDATA%\Oxidize\backups\<YYYY-MM-DD HHMMSS> <program>\`, in local time. A second backup in the same second gets ` (2)`, ` (3)` and so on.

| removed item | what the backup keeps |
|---|---|
| registry key | a `.reg` export under `registry\`, checked before the key is deleted; if the check fails, the key stays |
| registry value, firewall rule | the value and its type, in `manifest.json` |
| file, folder | the item itself, moved to `files\<drive letter>\<rest of the path>` |
| scheduled task | its XML definition, copied to `tasks\` |
| service | its registry key as a `.reg` export; the service is then stopped and deleted |
| PATH entry | the entry and its position, in `manifest.json` |

`manifest.json` records every step; `restore` replays it. If the backup folder cannot be created, nothing is removed.

## Where it looks

Registry keys and values under `SOFTWARE` in HKCU and HKLM, in both the 32- and 64-bit views, App Paths and autostart entries. Folders under Program Files, ProgramData, AppData, the Start Menu, Startup and the Desktop. Services, scheduled tasks, firewall rules and PATH entries. Link types (`name://` links) and file types whose command runs from the program's folder, open-with entries, shortcuts that lead into the program's folder whatever they are called, its folders in the user's temp folder, other uninstall entries left pointing into it, and the vendor's own key under `HKCU\Software` when nothing else of the vendor's is installed. A vendor folder or key that held nothing but the program goes with it.

## What it never removes

- Drive roots, the Windows folder and everything under it.
- The scanned roots themselves (Program Files, ProgramData, AppData, the Start Menu, Startup, the Desktop), the user profile, the Users folder, the Public folder, Documents and `%LOCALAPPDATA%\Packages`.
- A vendor folder that also holds other products.
- Scheduled tasks under `\Microsoft`.
- Store apps that are part of Windows, frameworks, resource packages, bundles, packages that belong to a normal program, apps other apps depend on, and the ones on its keep list: the Store, its helpers, Windows components and app runtimes. `list` shows these as `protected` with the reason.
