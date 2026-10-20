# Changelog

## Unreleased

- A removal never takes the folders Windows keeps for the user (Downloads,
  Saved Games, the cloud folder, the desktops and the rest), wherever they
  really are, and a folder in Downloads or on a desktop that a removal
  empties stays.
- Restore puts a copy back only from its own backup and only to where it
  came from, and clears the backup's emptied folders after a whole restore.
- A registry path with an empty part, or a key every program shares, is
  never deleted.
- `oxidize mcp` refuses `--dry-run`, `--yes` and `--no-backup` instead of
  ignoring them. It waits for an uninstaller to finish, up to 30 minutes, and
  says so when one still runs.
- A restore imports a registry export only into the key it was taken from.
- A restore dry run refuses a copy whose place is taken, as the real run
  does.
- A file named like the program's but elsewhere, or anything in a recorded
  install folder whose name says nothing about the program, counts at
  Medium only. An install folder must name a drive and a root.
- An unquoted command line with spaces is read the way Windows reads it, so
  a working autostart is no longer taken for a dangling one.
- A file on a drive that is not plugged in counts as there, not gone; one
  vendor name starts another only at a word.
- Clean up asks again right before it cleans whether a browser runs, deletes
  a file only while its path still leads where the analysis found it, and
  reads a protected list saved with a byte order mark.
- The window runs one thing at a time, waits for running work before it
  closes, reports a removal as it ran, keeps the last result in the status
  line, and keeps a removal's Undo when another backup is restored. Clean up
  says Cleaning while it cleans and what it freed afterwards, shows an undone
  cleaning as freeing nothing, and offers no cleaning with every folder
  unticked.
- Clean up walks a temp folder only when it really is one. Without TMP and
  TEMP, Windows names the profile as the temp folder; a profile, a drive, a
  folder Windows keeps or anything holding one is left alone, with a note
  saying why. A folder named by the environment counts only as a full path,
  and the Windows folder is the one Windows names.

## 0.2.7, 2026-10-17

- Oxidize's own folder, which holds its backups, is never taken for a leftover
  or for a folder no program claims, so a clean-up can no longer move the
  backups.
- A calmer window: plain tabs, the settings in one Options menu, a dry run
  shown in the top bar, no size bars, and a quiet selected row.
- Clean up shows what it would free and its one action at the top. Files and
  Clean slate are two views, and beside the list each category says what it
  would free, what cleans it and whether it can be undone. The protected
  folders open when you ask for them.
- On a screen taller than it is wide, the details sit under the list.
- Ctrl+F searches the program list, and a search that finds nothing says what
  it looked for.
- A confirmation's button says what it does, and is red when it cannot be
  undone.
- An empty name is refused instead of matching every program, and what could
  not be read is counted in items.

## 0.2.6, 2026-10-17

- A Clean up tab and `oxidize clean` clear temporary files, crash dumps, the
  Recycle Bin, browser caches, Windows' component store, the Delivery
  Optimization cache, an old Windows installation and folders of removed
  programs. Folders you protect, recent files and a running browser are left
  alone.
- Clean slate on the Clean up tab and `oxidize clean --traces` clear the
  lists of recently used files and programs: recent items, jump lists, the
  Run, search and Open and Save history, launch counts, the thumbnail cache
  and the clipboard history. The files they point to stay, and so do pinned
  items.
- A complete removal also removes Windows' own records of the program's
  files: tray icons, per-app sound settings, Start tiles, shortcut history,
  and the compatibility and name caches. One more pass catches what only
  shows after the removal.
- A removed program's publisher is found in its backup or in Windows' cached
  names, so a scan by name still finds the vendor's folders.
- The Windows account name no longer counts as part of a product's name.
- A dry run counts nothing as already gone and scans once, and a shortcut
  inside a removed folder is listed once.
- The program count and total size sit beside the filters; the size bar is
  gone.
- The Store apps list loads about four times faster.
- A backup that was put back in full is listed as restored.

## 0.2.5, 2026-10-11

- The window opens on an overview: how many programs are installed, their
  total size and a bar of the eight biggest. Hovering a part names the
  program and its size, clicking it selects the program.
- The programs are a table with name, publisher, size, install date and
  source. A click on a header sorts by it, a second click reverses the order;
  Sort by size is gone. Search takes several words and covers name and
  publisher. The arrow keys and Page Up/Down move the selection, also while
  typing. Quick filters show programs of 1 GB or more, those installed in the
  last 30 days and those installed for the current user alone.
- The selected program's details sit on the right, with Remove completely as
  the main button. A scan's results are grouped by kind (files and folders,
  shortcuts, registry, link and file types, services, tasks, PATH entries,
  firewall rules), each with its count and size, and fold away.
- The settings share one row with Refresh, the log opens from the status
  line, and Escape cancels the question before a removal. Light and dark
  both get Oxidize's copper and verdigris.

## 0.2.4, 2026-10-11

- The window finds icons for more programs: the icon Windows Installer keeps
  for a product whose entry names none, the main executable in a `bin` folder
  or a folder named after the program when the install folder has none, and
  the one in the folder of the uninstaller or of a missing icon file. Icon
  paths in quotes, with variables or followed by arguments are read too.

## 0.2.3, 2026-10-10

- `oxidize uninstall <program> --yes` removes a program completely in one go:
  it closes what runs from the program's folders, runs the program's own
  uninstaller only when Oxidize cannot remove everything itself, removes the
  leftovers with a backup and scans again to say `Nothing left.` or what is
  still there.
- A program installed for the current user alone, with nothing machine-wide,
  is removed without its own uninstaller. `--use-uninstaller` always runs it.
- Uninstallers named `unins000.exe` run with their silent switches when no quiet
  command was recorded.
- A scan reads the installed programs, services and tasks once and runs its
  registry, file and system parts at the same time.
- New leftovers: link types and file types whose command runs from the
  program's folder, open-with entries, shortcuts by where they lead, folders
  in the user's temp folder, other uninstall entries left pointing into the
  program's folder, and the vendor's key under `HKCU\Software` when nothing
  else of theirs is installed.
- A program that installs each build in a folder below the vendor's
  (`Vendor\Versions\version-<id>`) is removed whole when nothing else of the
  vendor's is installed: its build folder, the vendor's folder around it, the
  vendor's folders in AppData, the temp folder and the Start menu, its keys
  under `SOFTWARE`, and the shortcuts and link types of the vendor's other
  products that lead into what goes. The vendor's word must be in the
  program's name or publisher and carried by at least two of its name,
  publisher, folders, uninstall key and uninstaller. A vendor's folder that a
  service or task runs from is listed at medium, and one on the desktop is
  left alone.
- A link type's permission to open without asking (`ProtocolExecute`, for the
  user and the machine in both views) goes with its handler when no other
  handler of the link type stays, at the handler's level. With the handler
  already gone it goes when the link type is named after the program. Web,
  mail and Windows' own link types keep theirs.
- A folder in the Start menu can be a leftover, never one of Windows' own;
  folders named after the product that hold a longer namesake are kept only
  while another installed program carries the name; shortcuts to a missing
  file on a drive that is there, whose path names the product, are leftovers
  too.
- `oxidize uninstall --json` lists the items below the chosen level in `kept`.
- The MCP server and the window close a program's running copies first and
  say whether anything is left. The window has a "Remove completely" button
  and an Undo.
