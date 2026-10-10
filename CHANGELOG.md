# Changelog

## Unreleased

- `oxidize uninstall <program> --yes` removes a program completely in one go:
  it closes what runs from the program's folders, runs the program's own
  uninstaller only when Oxidize cannot remove everything itself, removes the
  leftovers with a backup and scans again to say `Nothing left.` or what is
  still there.
- A program installed for the current user alone, with nothing machine-wide,
  is removed without its own uninstaller. `--use-uninstaller` always runs it.
- Inno Setup uninstallers run with their silent switches when no quiet
  command was recorded.
- A scan reads the installed programs, services and tasks once and runs its
  registry, file and system parts at the same time.
- New leftovers: link types and file types whose command runs from the
  program's folder, open-with entries, shortcuts by where they lead, folders
  in the user's temp folder, other uninstall entries left pointing into the
  program's folder, and the vendor's key under `HKCU\Software` when nothing
  else of theirs is installed.
- The MCP server and the window close a program's running copies first and
  say whether anything is left. The window has a "Remove completely" button
  and an Undo.
