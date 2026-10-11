# The window app

`oxidize-gui.exe` is the file the download page gives. It is one file with no installer: the user double-clicks it. If Windows says it protected the PC, the user clicks More info, then Run anyway.

You cannot drive the window from a terminal. Tell the user what to click, one step at a time, and ask what they see.

## Layout

- Top bar: "Administrator", or "Not elevated" with a Restart as administrator button. Then the checkboxes Dry run, Backups (on at start), Silent uninstall and System components, and Refresh. In a narrow window the checkboxes get a row of their own.
- Overview: how many programs are installed, their total size, and a bar of the eight biggest. Hovering a part shows the program and its size; clicking it selects the program.
- Below it a Search box that filters by name or publisher, and the quick filters All, Large (1 GB or more), Recent (installed in the last 30 days) and Per user.
- The table of installed programs: name, publisher, size, install date and source. Clicking a header sorts by it, clicking it again reverses the order. The arrow keys and Page Up/Down move the selection, also while the cursor is in Search.
- Right: the selected program's name, version and publisher, the buttons Remove completely, Run uninstaller and Scan for leftovers, its size, install date, scope, registry location and install folder, and below them the result.
- Bottom: a status line, and a Log button that opens the log of what was closed, removed, already gone or failed.

## Remove a program completely

1. Ask the user to leave Backups ticked. Without it, removals are permanent and there is no Undo.
2. If the program has services, scheduled tasks, firewall rules or files under Program Files or ProgramData, ask the user to click Restart as administrator first and accept the Windows prompt. The window then opens again as administrator. Without administrator rights those items fail and the rest go.
3. The user types part of the name into Search and selects the program.
4. Preview: the user ticks Dry run, clicks Remove completely and confirms with Yes. Nothing is closed or removed. The window lists every item that would go at high confidence and says how many running processes would be closed. Go through the list with the user, then have them untick Dry run.
5. Ask the user to save their work in the program. Each process that runs from its folders is asked to close its windows; one still running three seconds later, or one without a window, is ended.
6. The user clicks Remove completely and confirms with Yes. Oxidize closes what runs from the program's folders and runs its uninstaller with its unattended switches where it has them. A program installed for this user alone, with nothing machine-wide, is removed by Oxidize without its uninstaller. Then Oxidize removes every high-confidence leftover with a backup and scans again.
7. The result shows "Nothing left." with the number of items removed, or that the program is still registered, or a "Still there:" list. A line counts the lower-confidence items that were kept. The log (Log button, bottom right) lists the closed processes, whether the uninstaller ran or was skipped, each item, and `Backup kept: <name>`. Ask the user to note that backup name.
8. Undo puts back everything that removal took, at once and without a further question. It shows after a removal with a backup, while that program is selected. Clicking Scan for leftovers replaces the result, and the Undo button with it. Later the user runs `oxidize restore "<name>"` with the name from the log.

Remove completely always takes high-confidence items only and ignores the Silent uninstall box. To choose items one by one, or to take medium or low ones, use the steps below.

## Uninstall step by step

1. Optional: Scan for leftovers shows what belongs to the program now. While it is still installed, the list is its footprint and nothing can be removed.
2. The user clicks Run uninstaller and confirms with Yes. The program's own uninstaller opens, with its unattended switches if Silent uninstall is ticked; the user finishes it. Nothing is closed first.
3. When the program is gone from the list, Oxidize scans its leftovers by itself. If the status line says the program is still registered, the uninstaller may still be running: the user finishes it, then clicks Refresh. High-confidence items start ticked. The items are grouped by kind (files and folders, shortcuts, registry, link and file types, services, tasks, PATH entries, firewall rules); each group shows its count and size and folds away. Each row shows a confidence tag (high, medium, low), the path, and the reason and size underneath.
4. Go through the ticked items with the user. Check High, Check all and Uncheck all change the ticks. Untick anything the user is not sure about.
5. The user clicks Remove N checked item(s) and confirms with Yes. The log lists each item, then a line `Undo from the command line: oxidize restore "<name>"`. Ask the user to note that backup name.

With Dry run ticked, Run uninstaller only logs the command it would run, and the remove button reads Preview removal of N item(s), asks nothing and changes nothing.

## What the window app does not do

- It lists programs from the Windows uninstall list only. Store apps are not shown.
- It cannot scan a program that is no longer installed, except the one it just removed while that one stays selected.
- It has no orphans or trace view.
- It cannot list backups. It restores only through Undo, right after Remove completely.

For any of these the user needs `oxidize.exe`, the command line, which is published with every release next to the window app. To undo an earlier removal, the user runs `oxidize restore "<name>"` with the name from the log, as described in [../SKILL.md](../SKILL.md).
