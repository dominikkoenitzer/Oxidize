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
| `--elevate` | Run the same command again as administrator, after a Windows prompt, in a new window. Oxidize waits for it and exits with its exit code. With `--json` or `-y` it also prints that run's stdout and stderr; otherwise the run keeps its own window for its questions and its output stays there. A declined prompt exits with 5. Without effect when Oxidize already runs as administrator. |

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
- Closing: a process whose executable lies in the program's install folder, or in a folder the scan gives the program at High confidence, is asked to close its windows. One still running three seconds later, or one without a window, is ended. Processes in the Windows folder, Oxidize itself and the processes that started it are never closed.
- The uninstaller is skipped when the program is registered for the current user only, has a folder of its own, is not a Windows Installer product, and owns nothing machine-wide: no service, firewall rule, or key, value or PATH entry in HKLM, and no file under Program Files, ProgramData or the Public folder. Oxidize then removes all of it itself, the uninstall entry included. Every other program runs its uninstaller first.
- `--use-uninstaller`: always run the program's own uninstaller.
- `--silent`: use the program's unattended uninstall switches where it has them. For Windows Installer products this adds `/qn /norestart`, for an uninstaller named `unins000.exe` (or another number) without a recorded quiet command `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`. A program without either runs its normal uninstall command. `-y` and `--json` imply `--silent`.
- Waiting: with `-y`, `--json` or unattended switches, Oxidize waits up to 60 seconds for the uninstaller to end and up to 60 more for the program to leave the list. Otherwise it waits until the uninstaller ends, then up to two minutes for the program to leave the list.
- `--keep`: run the uninstaller, then show the leftovers and remove nothing. Nothing is closed, and the uninstaller always runs.
- Questions: "Remove it completely? Running copies are closed first." (with `--keep`: "Run the uninstaller?"; with several names: "Run N uninstallers?"), then "Remove N items? Backups are kept for restore." For a Store app: "Remove the Store app?", which defaults to no.
- After an uninstaller, leftovers are removed only once the program has left the list.
- Some of Windows' records of a removed file, such as the history of a shortcut, only show once the file is gone. New high-confidence items in the second scan go without another question in one more pass, into the same backup, and a last scan follows. There is never a third pass.
- The last scan ends the run with `Nothing left.` or a list of what is still there and why. Items below the chosen level are counted as kept.
- `--dry-run`: lists every process it would close and every item it would remove, and says whether the uninstaller would run. Nothing is closed, started or removed.
- A Store app guarded as `protected` in `list` is refused. Removing a Store app cannot be backed up; its leftovers found afterwards are. Nothing is closed before a Store app is removed.

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
- `--clear`: delete every backup, after a question that defaults to no.
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

`oxidize clean [--temp] [--crash-dumps] [--recycle-bin] [--browser-cache] [--component-store] [--delivery-optimization] [--windows-old] [--orphans] [--recycle-bin-days DAYS] [--medium | --all | --level LEVEL]`

Counts what each category holds, from the files themselves, and what stays and why. Reads only unless `--yes` is given; then it cleans and reports per category what was freed and what stayed. It never asks a question, so `--elevate` always brings the elevated run's output back.

- Without a category flag the safe set is chosen: `--temp`, `--crash-dumps`, `--browser-cache`, and `--orphans` at high confidence. With flags, exactly those.
- `--temp`: files neither written nor created for 7 days, in the user's temp folder and in Windows' own (`%SystemRoot%\Temp`, administrator only). A file another program holds open stays.
- `--crash-dumps`: `.dmp` files in `%LOCALAPPDATA%\CrashDumps`, `%SystemRoot%\Minidump`, `%SystemRoot%\LiveKernelReports` and `MEMORY.DMP`, and the queued and archived error reports under `Microsoft\Windows\WER`. The machine-wide ones need administrator rights.
- `--recycle-bin`: items in the user's Recycle Bin on every fixed drive deleted at least `--recycle-bin-days` ago (30 by default). Never chosen by itself.
- `--browser-cache`: only the folders `Cache`, `Code Cache`, `GPUCache`, `DawnCache`, `DawnGraphiteCache`, `DawnWebGPUCache` and `Media Cache` of each Chromium profile (Chrome, Edge, Brave, Vivaldi, Chromium and their beta channels), the shared shader caches beside them, and `cache2`, `startupCache` and `jumpListCache` of Firefox profiles. A browser that is running is skipped.
- `--component-store`: runs `dism /Online /English /Cleanup-Image /StartComponentCleanup`, never `/ResetBase`. Administrator only. The space freed is measured on the drive afterwards.
- `--delivery-optimization`: runs `Delete-DeliveryOptimizationCache -Force`. Administrator only.
- `--windows-old`: removes `Windows.old` through Disk Cleanup's previous-installations handler. Administrator only, never chosen by itself, and the previous Windows cannot come back afterwards.
- `--orphans`: folders no installed program claims, under the roots `orphans` reads. A folder named like a program Oxidize or Windows Installer removed is High by the leftover rules, a looser match Medium, every other Low. They are moved into a backup like leftovers.
- Folders and files listed in `%LOCALAPPDATA%\Oxidize\protected.txt` are never cleaned, with everything inside them; a folder that holds one is never removed as a whole.
- `--no-backup` deletes the folders of removed programs for good. Nothing else the command cleans is backed up.

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
