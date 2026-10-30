# JSON output

Every command takes `--json` and prints exactly one pretty-printed JSON document on stdout. Warnings go to stderr as `warning: <message>`; `list` can print one when Store apps cannot be read. A command line that does not parse prints its message on stderr, not JSON, and exits with 2.

Optional fields are `null`, not left out, unless a field below is marked as sometimes missing. There is no `dry_run` field. A dry run of `uninstall` has fields of its own, listed there; every other command has the same shape in a dry run as in a real run.

## Errors

A run that fails before it has a result prints one object instead:

```json
{ "error": { "code": "not_found", "message": "no installed program or Store app matches \"Example Player\"" } }
```

| code | exit code | when |
|---|---|---|
| `error` | 1 | any other error |
| `not_found` | 1 | no installed program, Store app or backup answers to the name |
| `ambiguous` | 1 | several programs, apps or backups answer to the name; `message` lists them with their ids |
| `usage` | 2 | the command does not take a flag it was given, such as `--dry-run` with `mcp` |
| `still_installed` | 3 | the program is still installed after its uninstall |
| `incomplete` | 4 | an item failed or something is left |
| `cancelled` | 5 | a question was answered no, `--json` ran without `-y`, or the Windows prompt of `--elevate` was declined |

A run that already printed its result prints no error object. It only exits with the code from this table: an uninstall that leaves the program installed (3), a removal, restore or `backups --clear` with a failed item (4), a question answered no (5).

## Shared values

Enum values, exactly as printed:

| field | values |
|---|---|
| `confidence` | `"High"`, `"Medium"`, `"Low"` |
| `kind` of a leftover | `"RegistryKey"`, `"RegistryValue"`, `"File"`, `"Directory"`, `"Service"`, `"ScheduledTask"`, `"PathEntry"`, `"FirewallRule"` |
| `hive` | `"LocalMachine"`, `"CurrentUser"` |
| `view` | `"Native64"`, `"Wow6432"` |
| `signature` | `"none"`, `"developer"`, `"enterprise"`, `"store"`, `"system"` |
| `level` | `"high"`, `"medium"`, `"low"` |

### Program

| field | type |
|---|---|
| `registry_key` | string, the program's id |
| `source` | `{ "hive", "view" }` |
| `display_name` | string |
| `display_version` | string or null |
| `publisher` | string or null |
| `install_date` | string `YYYY-MM-DD` or null |
| `install_location` | string or null |
| `display_icon` | string or null |
| `estimated_size_kb` | number or null |
| `uninstall_string` | string or null |
| `quiet_uninstall_string` | string or null |
| `url_info_about` | string or null |
| `is_windows_installer` | bool |
| `is_system_component` | bool |

### Package (a Store app)

| field | type |
|---|---|
| `family_name` | string, the app's id |
| `full_name` | string |
| `name` | string |
| `display_name` | string |
| `publisher` | string or null |
| `version` | string |
| `signature` | see above |
| `is_framework`, `is_resource`, `is_bundle`, `is_sparse` | bool |
| `installed_path` | string or null |
| `installed_date` | string `YYYY-MM-DD` or null |
| `dependencies` | array of family names |

### Leftover

| field | type |
|---|---|
| `kind` | see above |
| `confidence` | see above |
| `reason` | string, why it was flagged |
| `path` | string: a file path, a short registry path, or a description for services, tasks, PATH entries and firewall rules |
| `size_bytes` | number or null |
| `is_empty_dir` | bool |
| `hive` | string or null |
| `subpath` | string or null |
| `value_name` | string or null, set when the item is one registry value |
| `name` | string or null: service name, task path or PATH entry text |

### ScanReport

`{ "program_name": string, "installed": bool, "items": [Leftover] }`. `installed: true` means the program is still registered and `items` is its current footprint, not leftovers.

### Removal

`null`, or:

```json
{
  "attempted": 0,
  "removed": 0,
  "already_gone": 0,
  "failed": 0,
  "backup": "2026-01-01 120000 Example Player",
  "items": [
    { "path": "...", "status": "removed", "error": null }
  ]
}
```

- `status` is `"removed"`, `"removed_after_restart"` for a service Windows only marked for deletion, `"gone"`, `"failed"`, or `"would_remove"` in a dry run; `error` is set when it failed. `removed` counts both kinds of removal.
- `backup` is the backup name for `oxidize restore`, or null with `--no-backup`.
- In a dry run, `items` lists every item that would go, `attempted` and `already_gone` both hold their number, `removed` and `failed` are 0 and `backup` is null.
- Declined, which is every run with `--json` and without `-y`: all counts 0, `backup` null, `items` empty, exit code 5.
- `null` when nothing reached the confidence level.

### Backup

`{ "id", "name", "path", "program", "created", "items", "size_bytes", "restored" }`. `id` is the backup's folder name, the same as `name`, and `oxidize restore <id>` takes it as an exact match. `created` is an RFC 3339 time, or `""` if the backup's manifest cannot be read. `restored` is the RFC 3339 time a restore put back every item, or null; `items` still counts what the backup recorded.

## list

An array. Each entry is a Program with `"kind": "program"` in front, or a Package with `"kind": "store"` and `"protected"`: the reason the app is never removed, or null when it may go. Reasons: `"part of Windows"`, `"a framework other apps run on"`, `"a resource package of another app"`, `"a bundle, not an app"`, `"belongs to a program; uninstall the program instead"`, `"a Windows component Oxidize keeps"`, `"<name> depends on it"`.

## uninstall, one program

An object:

| field | |
|---|---|
| `kind` | `"program"` |
| `program` | Program |
| `command` | string, the uninstall command line |
| `uninstaller_step` | whether the uninstaller runs: `{ "action": "run", "silent": bool, "reason" }` or `{ "action": "skip", "reason" }`. Reasons to run: `"Windows Installer product"`, `"installed for all users"`, `"no folder of its own is known"`, `"owns something machine-wide"`, `"asked for"` (with `--use-uninstaller`). Reasons to skip: `"installed for this user only; Oxidize removes all of it"`, `"no longer registered"`. |
| `level` | the lowest confidence removed, see above |
| `report` | ScanReport, what the removal works from. In a dry run, everything a scan finds as if the program were gone. |
| `seconds` | number, how long the run took |
| `would_close` | dry run only: `[{ "pid", "exe" }]`, the processes that would be closed |
| `would_remove` | dry run only: `[Leftover]`, every item that would go |
| `closed` | missing in a dry run: `[{ "pid", "exe", "how" }]`. `how` is `"closed"` (it closed by itself), `"running"` (still running after three seconds, or never asked for want of a window) or `"failed"` (it could not be asked), the last with an `error`. One with no window to be asked through has `"windowless": true`. Any process not `"closed"` stops the run before the uninstaller, and `error` names it. |
| `uninstaller` | missing in a dry run. `"skipped, <reason>"`, or how it ended: `"finished"`, `"finished, a reboot is required"`, `"finished, a reboot has been started"`, `"reported the product as not installed (1605)"`, `"was cancelled (1602)"`, `"found another installation in progress (1618)"`, `"exited with code N"`, `"ended without an exit code"` or `"was still running after N s"`. `null` when it could not start; `error` says why. |
| `still_installed` | bool, missing in a dry run |
| `remaining` | `[Leftover]`, missing in a dry run: the items at the chosen level that the second scan still found |
| `below_level` | number, missing in a dry run: the items found below the chosen level |
| `kept` | `[Leftover]`, missing in a dry run: those items, with their reasons |
| `nothing_left` | bool, missing in a dry run: the program is gone, every item went and nothing at the chosen level is left |
| `removal` | Removal. In a real run, missing when nothing reached the level or the run stopped before the removal. |
| `error` | string, sometimes missing: why the run stopped early |
| `cancelled` | `true`, sometimes missing: the leftover question was answered no |

The exit code is 0 when `nothing_left` is true, 3 when `still_installed` is true, 4 when an item failed or `remaining` is not empty, 1 with an `error`, and 5 when cancelled.

Cancelled, which is every run with `--json` and without `-y` or `--dry-run`: `{ "kind", "program", "command", "cancelled": true }`, exit code 5.

With `--keep`: `{ "kind", "program", "command", "uninstaller", "still_installed", "report" }`, without `uninstaller` and `still_installed` in a dry run. `report` holds the leftovers, or the footprint while the program is still registered, which exits with 3.

## uninstall, one Store app

`{ "kind": "store", "program": Package, "command", "closed", "uninstaller", "still_installed", "may_come_back", "report", "removal" }`

- `command` is `remove package <full_name> for this user`.
- `closed` lists what ran from the app's install folder and was closed first, as for a program. A dry run has `would_close` instead, and `would_stay` for the processes in it without a window, which cannot be asked and would stop the removal unless the user closes them first.
- `uninstaller` is `"removed by Windows"` or `"not started, no longer registered"`. It and `still_installed` are missing in a dry run.
- `may_come_back` is present once the app was removed: Windows may bring it back, as it installs the app for every new account.
- `removal` is missing when the report is empty, with `--keep`, or while the app is still registered.
- A removal that fails prints `{ "kind": "store", "program", "command", "error" }`, with `closed` when processes were closed before Windows failed, and exits with 1. An app still registered afterwards exits with 3.

## uninstall, several names

```
{ "programs": [ ... ], "uninstalled": 1, "failed": 0, "cancelled": false }
```

Each entry of `programs` is the one-program or Store app object plus `"failed": bool`. A program that stopped with an error is `{ "kind", "program", "command", "error", "failed": true }`. A program counts as failed when it stopped with an error, is still registered afterwards, has a leftover that failed, or has something left at the chosen level. The batch exits with the code of the first program that failed.

Cancelled: every entry is `{ "kind", "program", "command", "cancelled": true }`, `uninstalled` and `failed` are 0, `cancelled` is true, exit code 5.

## scan

- Without `--remove`: a ScanReport.
- With `--remove`: `{ "report": ScanReport, "removal": Removal }`. Exit code 4 when an item failed, 5 when declined.
- `--remove` on a program that is still installed, without `--dry-run`: `{ "report": ..., "removal": null }` and exit code 1.

## orphans

- Without `--remove`: `{ "folders": [Folder], "dangling": [Leftover] }`. A Folder is `{ "path": string, "size_bytes": number, "modified": string or null }`.
- With `--remove`: `{ "report": { "folders", "dangling" }, "removal": Removal }`. `removal` is null when `dangling` is empty. Exit code 4 when an item failed, 5 when declined.

## trace

Without `--uninstall`: an array, best match first. Each entry is `{ "id", "name", "publisher", "version", "score", "reason" }`. No match prints `[]` with exit code 0.

With `--uninstall`: the one-program `uninstall` object. No match is an error with the code `not_found`.

## backups

- The list: an array of Backup, newest first.
- `--delete NAME` or `--clear`: `{ "deleted": [names], "cancelled": bool }`. In a dry run the key is `"would_delete"`. With `--json` and without `-y`: `"cancelled": true`, an empty list and exit code 5. With `--clear`, a backup that could not be deleted is left out of `deleted`, the others still go, and the exit code is 4.

## clean

Without `--yes`, or with `--dry-run`:

```
{ "analysis": { "findings": [Finding], "elevated": bool, "recycle_bin_days": number, "protected": [string] },
  "chosen": [category], "chosen_folders": [path], "chosen_outright": [path], "chosen_bytes": number }
```

`category` is one of `"temp"`, `"crash-dumps"`, `"recycle-bin"`, `"browser-cache"`, `"component-store"`, `"delivery-optimization"`, `"windows-old"`, `"orphans"`, `"build-output"`. A Finding is `{ "category", "bytes", "count", "size_known", "kept": [Kept], "notes": [string], "needs_admin", "preselected" }`, plus `"folders"` for `orphans`: each `{ "path", "bytes", "modified", "confidence", "reason", "needs_admin", "proven_dead" }`, `"dumps"` for `crash-dumps`: each `{ "path", "bytes", "files", "program" }`, with `program` null where the name does not say it, and `"build_folders"` for `build-output`: each `{ "path", "bytes", "unchanged_days", "checkout" }`, with `checkout` the git checkout it lies in or null. Each of the three is left out when empty. `chosen_outright` holds the chosen folders that go without a backup, filled only with `--delete-dead`. `size_known` is false for the component store, whose cleanup only DISM can size. A Kept is `{ "code", "reason", "count", "bytes" }`, with `code` one of `"recent"`, `"recently_deleted"`, `"in_use"`, `"protected"`, `"repository"`, `"access_denied"`, `"unreadable"`, `"needs_admin"`, `"running"`, `"pinned"`, `"left_out"`, `"uncommitted"`, `"checkout_unknown"`, `"failed"`.

With `--yes`:

```
{ "cleaned": [ { "category", "freed", "removed", "kept": [Kept], "backup", "notes" } ], "freed": number }
```

`backup` is the backup the folders of removed programs went into, or null. A category with a `failed` entry in `kept` makes the exit code 4.

## restore

```
{ "backup": Backup,
  "items": [ { "path", "ok", "error" } ] }
```

In a dry run, `ok` means the item's saved copy is still there, and the exit code is 0. Otherwise an item with `"ok": false` makes the exit code 4. With `--json` and without `-y` or `--dry-run`, nothing is restored and the run prints an error with the code `cancelled`, exit code 5.
