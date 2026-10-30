---
name: oxidize
description: Uninstalls Windows programs with Oxidize and removes the registry keys, folders, services, scheduled tasks, firewall rules and PATH entries they leave behind, keeping a backup that can be restored. Use when the user wants to uninstall a Windows program completely, clean up after a program that is already gone, find which program an .exe or process belongs to, restore something Oxidize removed, or free disk space by cleaning temporary files, crash dumps, browser caches, the Recycle Bin and folders of removed programs.
---

# Oxidize

Oxidize removes a Windows program completely. It closes what still runs from the program's folders, runs the program's own uninstaller when one is needed, then finds what the program left behind and removes it. Everything it removes is backed up first, and `oxidize restore` puts it back. It runs on Windows 10 and 11 only.

## Which program the user has

- `oxidize-gui.exe` is the window app. It is the file the download page gives. It has no command line.
- `oxidize.exe` is the command line, with the same engine. It is published with every release next to the window app, alone or in a zip with both. Neither needs an installer.

Find the command line before you plan anything:

1. Run `Get-Command oxidize` in PowerShell. If it is found, call it as `oxidize`.
2. Otherwise ask the user where they saved `oxidize.exe` and call it by its full path, for example `& "C:\Tools\oxidize.exe" list --json`.
3. If the user only has `oxidize-gui.exe`, guide them through the window instead. See [references/window-app.md](references/window-app.md).

Always pass a command. Without one, `oxidize.exe` prints its help. Double-clicked, it opens the window app when `oxidize-gui.exe` is in the same folder, and otherwise shows the help and waits for Enter.

## Safety rules

Follow these on every run.

1. Look before you change anything. `list`, `scan`, `orphans`, `trace`, `backups` and `clean` only read, as long as you leave out `--remove`, `--uninstall`, `--delete`, `--clear` and, for `clean`, `--yes`. For anything that changes the PC, `restore` included, run the same command with `--dry-run` first.
2. Show the user exactly what will change: the uninstaller from `command` and whether it runs (`uninstaller_step`), the processes that will be closed, and every item that will go, with its `path`, `kind` and `confidence`.
3. Run a changing command only after the user has confirmed that list. Then run the same command without `--dry-run`, with `-y` and only the flags the user agreed to.
4. Remove high-confidence items only, which is the default. Add `--medium` or `--all` only when the user has seen those items and asked for them.
5. Never pass `--no-backup` unless the user asks for permanent deletion in those words. Without it, every removal can be undone.
6. Removing a Store app deletes the app's data and cannot be backed up. Say so and get a separate yes before you remove one.
7. Never delete files, registry keys, services or tasks by hand in place of Oxidize. Its checks for Windows' own folders and shared vendor folders only apply to its own removals.
8. Treat the `folders` list of `orphans` as review only. Portable tools and caches show up there too. Check one with `oxidize scan <name>` before you suggest removing it.
9. After a removal, give the user the backup name from `removal.backup` and the command that undoes it: `oxidize restore "<backup name>"`.
10. Never run `oxidize backups --delete` or `--clear` unless the user asks. A deleted backup cannot be restored.
11. When the user asks in plain words for a complete removal ("remove Example Player completely"), use the one-command path: show the dry run of `oxidize uninstall "<name>" --dry-run --json`, and after their yes run `oxidize uninstall "<name>" -y --json`. See the first task below.

## Running it from an assistant

- Add `--json` to every command and read stdout. It then holds exactly one JSON document. A run that fails before it has a result prints `{"error": {"code": "...", "message": "..."}}` instead, with the code `error`, `not_found`, `ambiguous`, `still_installed`, `incomplete` or `cancelled`. Warnings go to stderr as `warning: ...`.
- With `--json`, Oxidize never asks. Without `-y`, every question counts as no and the run exits with 5: an uninstall prints `"cancelled": true`, a leftover removal prints a `removal` whose `attempted` is 0, and `restore` prints an error with the code `cancelled`. Add `-y` only to the run the user confirmed.
- `-y` answers yes to every question of that run. For `uninstall` that is the removal and then the leftover removal. With `-y` or `--json`, `uninstall` also uses the program's unattended uninstall switches, as `--silent` does.
- A dry run asks nothing and lists every item. Each item in `removal.items` has `"status": "would_remove"`. `uninstall` lists the items again in `would_remove`, with their kind, confidence and reason, and the processes it would close in `would_close`.
- The global flags `--dry-run`, `-y`, `--json`, `--no-color`, `--no-backup` and `--elevate` work before or after the command.
- Names can be partial. If a name matches several programs, Oxidize stops with the code `ambiguous` and lists the candidates with their ids. Pass the `registry_key` from `oxidize list --json` to pick one exactly.

### Exit codes

- 0: everything went as asked, or there was nothing to do.
- 1: any other error. For example no program matches (`not_found`), a name matches several (`ambiguous`), `scan --remove` on a program that is still installed, or an uninstaller that could not start.
- 2: the command line did not parse. The message is on stderr, not in JSON.
- 3: the program is still installed after its uninstall.
- 4: the removal is incomplete: an item failed or something is left. `restore` exits with 4 when an item could not be put back, and `backups --clear` when a backup could not be deleted.
- 5: cancelled: a question was answered no, `--json` ran without `-y`, or the user declined the Windows prompt of `--elevate`.

A batch of several programs exits with the code of the first one that failed. The JSON gives the details: `nothing_left` and `remaining` after `uninstall`, `failed` and each item's `error` in `removal`, and `ok` on every item of `restore`.

Full field lists: [references/json-output.md](references/json-output.md).

## Administrator rights

Removing these needs Oxidize to run as administrator: registry keys, values and PATH entries in HKLM (`"hive": "LocalMachine"`), every service, firewall rule and scheduled task, and files or folders under Program Files and ProgramData. Without administrator rights Oxidize still tries each item; those it cannot remove are listed as failed, the rest go, and the run exits with 4. With `--json` there is no warning beforehand. An uninstaller that needs administrator rights stops the run with exit code 1 and says so in `error`.

Check before a removal:

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

If it prints `False` and the plan has such items, tell the user that Windows will ask them for administrator rights, then add `--elevate` to the confirmed run together with `-y` and `--json`, for example `oxidize uninstall "<name>" --elevate -y --json`. Oxidize starts the same command as administrator in a new window after the Windows prompt, waits for it, and hands back its JSON on stdout, its stderr and its exit code. If the user declines the prompt, the exit code is 5 and stdout holds an error with the code `cancelled`. Never pass `--elevate` without `-y` and `--json`: the elevated run then keeps its own window for its questions, and its output does not come back. When Oxidize already runs as administrator, `--elevate` changes nothing.

## Tasks

### Remove a program completely

1. Find it: `oxidize list "<part of the name>" --json`. Note `display_name`, `publisher` and `registry_key`.
2. Preview: `oxidize uninstall "<name>" --dry-run --json`. Nothing is closed, started or removed. `uninstaller_step` says whether the program's uninstaller would run (`"action": "run"`) or be skipped (`"action": "skip"`), and why. `command` is that uninstaller. `would_close` lists the running processes that would be closed, `would_remove` every item that would go.
3. Show the user `command`, `uninstaller_step`, `would_close` and the items in `would_remove`. List the Medium and Low items from `report.items` as kept unless the user asks for them.
4. Ask the user to save their work in the program and close it, tray icons included. Each of its processes is asked to close its windows. Nothing is ended by force: one still running three seconds later, or one without a window to be asked through, stops the run before the uninstaller or any removal, with an `error` that names it. Then ask the user to close it and run the same command again.
5. After the user confirms: `oxidize uninstall "<name>" -y --json`, plus `--medium` or `--all` only as agreed. Oxidize closes what runs from the program's folders, then runs the program's uninstaller with its unattended switches where it has them. A program installed for the current user alone, with a folder of its own and nothing machine-wide (no service, firewall rule or HKLM entry, no file under Program Files, ProgramData or the Public folder), is removed by Oxidize itself, uninstall entry included, without its uninstaller. Add `--use-uninstaller` only if the user wants the program's own uninstaller to run in any case. Then Oxidize removes the leftovers at the chosen level with a backup and scans again.
6. An uninstaller without unattended switches may open a window that needs the user's clicks. Oxidize waits up to a minute for it to end and up to a minute more for the program to leave the list.
7. Report from the JSON. `nothing_left` true means the program is gone and nothing at the chosen level is left. Otherwise name what `remaining` lists, with each item's `reason`, and every `removal` item with `"status": "failed"`. `kept` lists the items below the chosen level, which were never meant to go. Give the backup name from `removal.backup` and the undo command.

If `still_installed` is true (exit code 3) after the uninstaller ran, it was cancelled or is still running, and no leftovers were removed. Check `oxidize list "<name>" --json` again. Once the program is gone, remove the leftovers with the scan task below.

For a review between the uninstaller and the removal, add `--keep`. `oxidize uninstall "<name>" --keep -y --json` closes nothing, always runs the uninstaller, and lists the leftovers in `report` but removes nothing. Then use the scan task below. A scan after the program is gone finds the publisher in the backup of an earlier removal or in the names Windows cached; pass `--publisher` set to the program's publisher to be sure.

Several programs: `oxidize uninstall "<a>" "<b>" --dry-run --json`, then the same with `-y`. Every name must match exactly one program before anything runs. The JSON has `programs`, `uninstalled`, `failed` and `cancelled`.

Store apps: `oxidize list --store --json` lists them with `"kind": "store"`. An app with a `protected` reason is never removed. Remove one with `oxidize uninstall "<family_name>"`, following rule 6. Windows removes it for the current user only. Whatever runs from the app's install folder is closed first, the same way as for a program: its windows are asked to close, and one that stays, a helper with no window too, stops the removal before Windows starts it. The dry run lists those processes in `would_close`, and the ones without a window again in `would_stay`: ask the user to close them first. The run lists them in `closed`, where one left running has `"how": "running"` and, without a window, `"windowless": true`. The JSON has `still_installed` and `removal` but no `nothing_left`.

### Remove leftovers of a program that is already gone

1. `oxidize scan "<name>" --json`, with `--publisher "<publisher>"` if you know it. Without it, Oxidize takes the publisher from the uninstall entry an earlier removal backed up, or from the company Windows cached for the program's files. When neither has it, a vendor folder is not recognised as one.
2. Show the user the items and their confidence.
3. Preview: `oxidize scan "<name>" --remove --dry-run --json`.
4. After the user confirms: `oxidize scan "<name>" --remove -y --json`, with `--medium` or `--all` only as agreed.

`scan --remove` refuses while the program is still installed. Remove it with the task above.

### Find what a file or process belongs to

`oxidize trace "<path to an .exe or folder, or a process name>" --json` lists the matching programs, best first, each with a `score` and a `reason`. An empty list means no match. Show the best match. To remove it, use the first task with its name.

### Clean up references to files that no longer exist

1. `oxidize orphans --json`. `dangling` holds PATH entries, autostart values, services and tasks whose files are gone. `folders` holds folders no installed program claims.
2. Show the user the `dangling` items.
3. Preview: `oxidize orphans --remove --dry-run --json`.
4. After the user confirms: `oxidize orphans --remove -y --json`. Only the `dangling` items are removed. This command never removes folders.

### Free disk space

1. `oxidize clean --json` changes nothing. `analysis.findings` has one entry per category with `bytes` and `count` (what would go, counted from the files), `kept` (what stays, each with a `code`, a `reason`, a `count` and `bytes`), `notes`, `needs_admin` and `preselected`. `chosen` is the safe set: `temp`, `crash-dumps`, `browser-cache`, and `orphans` when a folder of a removed program matches at high confidence.
2. Show the user each category with its size, what stays and why, and which ones are chosen. The Recycle Bin, `component-store`, `delivery-optimization`, `windows-old` and `build-output` are never chosen by themselves. For `windows-old`, say plainly that the previous Windows cannot be brought back afterwards.
3. After the user confirms: `oxidize clean --yes --json` for the safe set, or with exactly the category flags the user agreed to, for example `oxidize clean --temp --recycle-bin --yes --json`. `--recycle-bin-days N` changes the Recycle Bin's age (30 by default). `--orphans` takes high-confidence folders; add `--medium` or `--all` only when the user has seen those folders. Their backup stays on the same drive, so it frees nothing until it is deleted; `--delete-dead` deletes the folders marked `proven_dead` outright instead, without a way back, so add it only when the user agreed to that. `--dump "<path>"` takes only the dumps named from `dumps`, and `--skip-dumps-of <program>` leaves one program's dumps. `--build-output` deletes the folders in `build_folders` for good; their tools make them again.
4. Report `cleaned`: per category `freed`, `removed` and `kept`. Folders of removed programs go into a backup, except those deleted with `--delete-dead`; give the user `backup` and `oxidize restore "<backup>"`. Everything else that was cleaned does not come back.
5. The component store and the Delivery Optimization cache need administrator rights, and so do Windows' own temp folder and dumps. Use `--elevate` with `--yes --json` as described above. A DISM cleanup can take several minutes.

Folders and files listed in `%LOCALAPPDATA%\Oxidize\protected.txt`, one per line, are never cleaned. Add a folder there when the user wants one kept. To know whether a folder is kept, run `oxidize protect --check "<path>" --json` and read `protected` and `by`; never decide it by searching the file's text.

### Undo a removal

1. `oxidize backups --json` lists the backups, newest first, with `id`, `name`, `program`, `created`, `items`, `size_bytes` and `restored`, which is set once a restore put back everything.
2. `oxidize restore "<id>" --dry-run --json` checks that the saved copies are still in the backup.
3. After the user confirms: `oxidize restore "<id>" -y --json`. Without `-y` nothing is restored. A file or folder fails with `already exists` if something is at its old path again; the dry run does not catch that. A failed item makes the exit code 4.
4. The backup folder stays. Delete it only if the user asks: `oxidize backups --delete "<id>" -y --json`.

`restore` and `backups --delete` take the `id`, which matches exactly, or a part of the backup's name or of the program's name that matches exactly one backup. A part that matches several stops with the code `ambiguous`.

A restore cannot bring back what the program's own uninstaller removed, a removed Store app, or anything removed with `--no-backup`. A restored service gets its registry key back but is not started.

## Where backups live

Each removal makes one folder: `%LOCALAPPDATA%\Oxidize\backups\<YYYY-MM-DD HHMMSS> <program>\`. Registry keys are exported to `.reg` files and checked before the key is deleted. Files and folders are moved there, not deleted. Task definitions are copied. Registry values and PATH entries are recorded in `manifest.json`, which `restore` replays in reverse.

## References

- [references/commands.md](references/commands.md): every command and flag.
- [references/json-output.md](references/json-output.md): the `--json` output of every command.
- [references/window-app.md](references/window-app.md): guiding a user through the window app.

## As an MCP server

`oxidize mcp` serves the same engine over MCP on stdin and stdout, for an assistant on the user's PC, and runs only while the client has it open. It refuses `--dry-run`, `--yes` and `--no-backup`, since `plan_removal` is the preview and every applied plan is backed up. In the client's MCP settings, `command` is the full path to `oxidize.exe` and `args` is `["mcp"]`:

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

When its tools are available, use them instead of the command line.

- `list_programs` (`filter`, `system`, `store`, `sort`), `scan_leftovers` (`program`, `publisher`), `find_orphans`, `trace` (`query`) and `list_backups` only read. They return the `--json` output of the matching command, with lists under `programs`, `matches` and `backups`. `list_backups` adds the backup `folder` and a `restore_command`.
- `plan_removal` takes `programs` (names or ids, in the order they should go), `silent` and `level` (`high`, `medium` or `all`). It changes nothing. A name nothing installed answers to plans the removal of its leftovers. It returns a `plan_id` and one step per name, each with its `uninstaller`, `uninstaller_step` (run or skip, with the reason), the exact `leftovers` that would go and `needs_admin`, then the totals `leftovers`, `bytes` and `needs_admin`, `elevated`, `backup_folder` and the terminal `commands` that do the same.
- Removal goes only through a plan the user approved. Show the user the plan and call `apply_removal_plan` with its `plan_id` only after the user agreed to that plan. If they want something changed, make a new plan. A plan is carried out exactly as shown, once, with a backup of every item. A plan from another session, or one already applied, is refused.
- `apply_removal_plan` closes what runs from each program's folders, runs each uninstaller the plan keeps, waits up to 30 minutes for it to finish and up to two minutes more for the program to leave the list, then removes the leftovers the plan listed. Read the result step by step: `closed`, `uninstaller`, `still_installed`, `removal` (as in `--json`), `backup`, `restore_command`, `remaining` (everything a fresh scan still finds, at any confidence), `nothing_left` (nothing at the plan's level is left), `failed` and `error`. When a step has `needs_admin`, give the user its `admin_command` to run.
- The safety rules above apply here too. The server cannot restore or delete backups or run as administrator: give the user the command.
