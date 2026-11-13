# Changelog

## 0.2.22, 2026-11-13

- A folder named like the program inside another program's folder, such as
  a plugin folder, stays that program's while it is there, and so do the
  files in it and the registry values that point at them.
- A scan of a second build of a program, such as its beta, no longer lists
  the main build's folder or registry key inside the vendor's folder, as
  long as the main build is installed too.

## 0.2.21, 2026-11-12

- Removals keep no backup unless you ask for one. Turn on Back up before
  deleting in the window, add `--backup` on the command line, or have an
  assistant make its plan with `backup` set to true, and everything removed
  is backed up first, as before. Without a backup a removal is permanent,
  and the window, a dry run and the assistant's plan say so before anything
  goes. `--no-backup` is still accepted and changes nothing.
- A file or folder that is still there in another program's folder stays
  that program's, even when it is named like the program being removed. A
  vendor key with a value that points at one stays too, and only the
  program's own subkeys go.
- Windows' records of a program folder that is already gone are found when
  that folder sat inside a vendor's folder, such as
  `%LOCALAPPDATA%\<vendor>\<program>`.

## 0.2.20, 2026-11-11

- A program's own registry key now goes whole only when nothing of another
  program's is in it. A browser's key that holds native messaging hosts
  other programs registered keeps them, and only what is the browser's goes.
- A registry key matches a program only by the program's own name, or by a
  name its install folders carry. A longer name made from it, such as a test
  build's, is another product's and stays.
- A file in another program's folder is that program's, even when it is
  named like the program's own or has its name in it. Firewall rules,
  services, tasks, autostart values, sound device choices and other records
  that point there stay.

## 0.2.19, 2026-11-11

- A vendor's registry key now goes whole only when everything in it goes
  with the program. When it also holds the settings of another of the
  vendor's products, such as a test build of its browser, the key stays and
  only the program's own subkeys go, whether that product is installed or
  not.

## 0.2.18, 2026-11-10

- Start's records of a program folder that was already gone before the
  scan now go too, when the missing path names the product. Before, only
  the records of folders the scan itself removed were found, so a program
  whose uninstaller had taken its folder left them behind.

## 0.2.17, 2026-11-10

- Once a program is gone, the records Windows keeps under its app id go
  too: notification settings, the Start menu record and taskbar usage. An
  app id is taken only when it carries both the product's and the vendor's
  name, such as `com.vendor.product`. These records had stayed behind after
  every uninstall.
- A COM class goes when every server it lists is a file of the program,
  such as the class a program registers so its notifications can start it.
  A class with a server that is still there stays.

## 0.2.16, 2026-11-10

- The vendor's key under `HKCU\Software` no longer goes whole when other
  programs registered themselves in it, such as the native messaging hosts
  a browser keeps for other programs, or when a value in it names another
  program's file that is still there. Only the subkeys that go with the
  program are taken and the rest stays. Before, removing one product could
  take a browser's key along with the hosts of other programs inside it.
- Scheduled tasks and autostart values that start a file in a folder the
  scan removes go with that folder, whatever they are called. An updater's
  task and its autostart value had stayed behind while the folder they
  start from was removed.

## 0.2.15, 2026-11-06

- The scan looks for a program's settings in the user's folder and in its
  `.config` folder, by the exact name. A dot folder, a folder inside
  `.config` or a settings file such as `name.json` counts as high confidence,
  and as medium when the name or the vendor is shared with other programs. A
  plain folder of that name in the user's folder is always medium. These
  stayed behind before, while the report said nothing was left.

## 0.2.14, 2026-11-03

- `--silent` gives `/S` to any uninstall command whose file carries the
  stamp read since 0.2.13, also when the stamp marks the file as an
  installer. Some programs register such an installer as their uninstaller,
  and without the switch it ran its wizard unseen and left the program
  installed. Only a stamp on the 512-byte grid counts, as before.

## 0.2.13, 2026-11-03

- `--silent` gives `/S` to an uninstaller from another widely used install
  system when the program records no quiet command. It is known by the
  stamp that system writes into the file, never by its name, and an
  installer of that kind, whose stamp lacks the uninstall flag, gets no
  switch. The wait afterwards also follows the copy of itself such an
  uninstaller runs from the temp folder.
- `clean --delete-dead` deletes the chosen unclaimed folders that are proven
  dead outright, each checked again right before it goes and taken whole or
  not at all. One that came alive goes into the backup instead.
- `clean --build-output` cleans stale build output in the profile: folders a
  build tool marked as its cache, beside a project file or ignored by git,
  untouched for 30 days and not in use. It is looked for only when named,
  and in the window only once its row is ticked.
- `clean --dump` cleans only the dumps named, and `--skip-dumps-of` leaves
  one program's dumps.
- Warnings and errors are coloured by whether stderr itself is a terminal.
- An unquoted uninstall command takes its program from disk before an exe
  named in its arguments, and a traced path has its `..` parts resolved
  before install folders are matched.

## 0.2.12, 2026-10-30

- A git repository in a temp folder stays whole, however old its files are.
  A folder with a `.git` folder or file, or a bare repository, is never
  entered, so a clean no longer takes old files out of a checkout and
  leaves it broken. It is counted in `kept` with the code `repository`.
- A clean refuses to start while the protected list cannot be read, and the
  list refuses entries that are not full paths.
- A temp folder inside Windows' own is counted once.
- A folder whose move into the backup stopped halfway is taken back whole,
  and a restore puts back what such a move took. A dry restore counts only
  what it would put back. Clearing backups goes on past one that cannot be
  deleted, and an empty backup name is refused.
- The 32-bit view of a shared registry key counts as shared, a program's
  icon entry is matched by its whole path, and a shortcut's path is read in
  the system code page.
- A process that stays is named before an uninstaller that never ran, a
  missing uninstaller file is named in plain words, and a dry run checks
  the registration the way the removal does.
- `--elevate` prints the output of `list` and `protect` again.
- In the window, every widget Tab reaches shows its focus, counts of one
  say "1 item", and grey text and the dry run badge read on their fills.

## 0.2.11, 2026-10-29

- A process is never ended. Each one that runs from the program's folders,
  or from a Store app's, is asked to close its windows. One that is still
  running three seconds later, or has no window to be asked through, is
  left running, and the removal stops before the uninstaller or anything
  else runs, with one sentence naming it. A dry run lists those without a
  window in `would_stay`, and a run lists them in `closed` as `running`.
- The window's questions for Remove completely and Run uninstaller say that
  what a program's own uninstaller removes is not backed up, and so does
  the tip of the backup setting.

## 0.2.10, 2026-10-28

- Before a Store app is removed, whatever runs from its install folder is
  closed the way a program's processes are: its windows are asked to close
  first. A helper with no window is ended and named. A dry run lists what
  it would close, and nothing is closed for an app that may not go.
- The vendor's key and folders stay while a Store app of the same vendor is
  installed, so removing the vendor's program first no longer takes what the
  app still uses. When Windows cannot list the Store apps, no vendor counts
  as alone.
- Leftovers are kept while a program's uninstaller is still running when
  the wait ends, whatever the registry already says.
- In the window, Undo stays a dry run when dry run is on, and Undo stays
  available after a restore where some items failed.
- A clean counts what it really freed: Windows.old only once the folder is
  gone, Delivery Optimization files only when the cache could be read and
  the file is gone afterwards, and a Recycle Bin item whose entry stays as
  kept.

## 0.2.9, 2026-10-24

- `oxidize protect` prints the protected list, and `oxidize protect --check
  <path>` says whether a path is kept out of every clean and which entry
  keeps it. With `--json`, a clean plan and a clean run carry a `summary` of
  bytes and items per category, with what the protected list kept.
- A service Windows only marks for deletion is listed as going at the next
  restart.
- When Windows refuses to remove a service or a scheduled task, the result
  says so in one sentence. What `sc` or `schtasks` printed goes to the
  window's log, or to standard error on the command line. Both tools now
  start without a console window.
- Messages from `sc`, `schtasks`, DISM, PowerShell and installer removal
  events are read in the code page they were written in, so accented text
  comes through intact.
- The window runs on eframe 0.37, with copy and paste still on the Windows
  clipboard.

## 0.2.8, 2026-10-20

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
