# Changelog

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
