# The window app

`oxidize-gui.exe` is the file the download page gives. It is one file with no installer: the user double-clicks it. If Windows says it protected the PC, the user clicks More info, then Run anyway.

You cannot drive the window from a terminal. Tell the user what to click, one step at a time, and ask what they see.

## Layout

- Top bar, at the right: Refresh, the Options menu, and "Administrator" or a Restart as administrator button. The Options menu holds the checkboxes "Dry run, change nothing", "Back up before deleting" (ticked at start), "Uninstall silently where possible" and "Show system components". While Dry run is ticked, the bar says "Dry run: nothing changes". The backup state shows in the question each removal asks.
- Below it a Search box that filters by name or publisher, the quick filters All, Large (1 GB or more), Recent (installed in the last 30 days) and Per user, and at the right how many programs show and the total size of all installed programs.
- The table of installed programs: name, publisher, size, install date and source. Clicking a header sorts by it, clicking it again reverses the order. The arrow keys and Page Up/Down move the selection, also while the cursor is in Search.
- Right: the selected program's name, version and publisher, the buttons Remove completely, Run uninstaller and Scan for leftovers, its size, install date, scope, registry location and install folder, and below them the result.
- Bottom: a status line, and a Log button that opens the log of what was closed, removed, already gone or failed.
- While something runs (a spinner beside the status line), the buttons, Refresh, the Options menu and the protected folders wait until it is done. Closing the window then waits too, and it closes by itself once the work is finished.
- Beside the name in the top bar, Programs and Clean up switch between the program list and the cleanup.

## Remove a program completely

1. Ask the user to leave "Back up before deleting" ticked in the Options menu. Without it, removals are permanent and there is no Undo. The backup holds what Oxidize removes itself, never what the program's own uninstaller removes.
2. If the program has services, scheduled tasks, firewall rules or files under Program Files or ProgramData, ask the user to click Restart as administrator first and accept the Windows prompt. The window then opens again as administrator. Without administrator rights those items fail and the rest go.
3. The user types part of the name into Search and selects the program.
4. Preview: the user opens Options and ticks Dry run, change nothing, then clicks Remove completely and confirms with the Remove completely button in the question. Nothing is closed or removed. The window lists every item that would go at high confidence and says how many running processes would be closed. Go through the list with the user, then have them untick Dry run.
5. Ask the user to save their work in the program and close it, tray icons included. Each process that runs from its folders is asked to close its windows. Nothing is ended by force: one still running three seconds later, or one without a window, stops the removal before anything is uninstalled, and the status line names it. The user closes it and clicks Remove completely again.
6. The user clicks Remove completely and confirms with Remove completely, which is red when no backup is kept. Oxidize asks what runs from the program's folders to close and runs its uninstaller with its unattended switches where it has them. A program installed for this user alone, with nothing machine-wide, is removed by Oxidize without its uninstaller. Then Oxidize removes every high-confidence leftover with a backup and scans again.
7. The result shows "Nothing left." with the number of items removed, or that the program is still registered, or a "Still there:" list. A line counts the lower-confidence items that were kept. The log (Log button, bottom right) lists the closed processes, whether the uninstaller ran or was skipped, each item, and `Backup kept: <name>`. Ask the user to note that backup name.
8. Undo puts back everything that removal took, at once and without a further question. It shows after a removal with a backup, while that program is selected. Clicking Scan for leftovers replaces the result, and the Undo button with it. Later the user runs `oxidize restore "<name>"` with the name from the log.

Remove completely always takes high-confidence items only and ignores Uninstall silently where possible. To choose items one by one, or to take medium or low ones, use the steps below.

## Uninstall step by step

1. Optional: Scan for leftovers shows what belongs to the program now. While it is still installed, the list is its footprint and nothing can be removed.
2. The user clicks Run uninstaller and confirms with Run uninstaller. The program's own uninstaller opens, with its unattended switches if "Uninstall silently where possible" is ticked; the user finishes it. Nothing is closed first, and what the uninstaller removes is not backed up.
3. When the program is gone from the list, Oxidize scans its leftovers by itself. If the status line says the program is still registered, the uninstaller may still be running: the user finishes it, then clicks Refresh. High-confidence items start ticked. The items are grouped by kind (files and folders, shortcuts, registry, link and file types, services, tasks, PATH entries, firewall rules); each group shows its count and size and folds away. Each row shows a confidence tag (high, medium, low), the path, and the reason and size underneath.
4. Go through the ticked items with the user. Check High, Check all and Uncheck all change the ticks. Untick anything the user is not sure about.
5. The user clicks Remove N checked items and confirms with Remove N items. The log lists each item, then a line `Undo from the command line: oxidize restore "<name>"`. Ask the user to note that backup name.

With Dry run ticked, Run uninstaller only logs the command it would run, and the remove button reads Preview removal of N items, asks nothing and changes nothing.

## Clean up

1. The user clicks Clean up in the top bar, then Analyse. The analysis changes nothing and can take a minute. With Restart as administrator first, Windows' own temp folder and dumps, the component store and the Delivery Optimization cache count too.
2. Each category shows its size, what it is, and what stays and why. The safe set is ticked: temporary files, crash dumps, browser caches, and folders of removed programs at high confidence. The folders of removed programs open into a list with a tick, a confidence tag and a reason for each.
3. Go through the ticks with the user. The Recycle Bin, the component store, the Delivery Optimization cache, the previous Windows installation and stale build output are never ticked by themselves. Before the user ticks the previous Windows installation, say that it cannot come back afterwards.
4. The user clicks Clean N ticked categories and confirms with Clean. With Dry run ticked, the button only logs what would be cleaned.
5. The result shows what was freed per category and what stayed. Folders of removed programs went into a backup, and Undo beside them puts them back. Nothing else comes back.

The panel on the right is the list of protected folders: a folder or file typed into the field and added with Add is never cleaned, with everything inside it. Remove takes one off the list.

## What the window app does not do

- It lists programs from the Windows uninstall list only. Store apps are not shown.
- It cannot scan a program that is no longer installed, except the one it just removed while that one stays selected.
- It has no trace view, and it shows the dangling references of `orphans` nowhere. The Clean up tab lists the folders no program claims.
- It cannot pick single crash dumps or leave one program's, and it puts every folder of a removed program into a backup; `oxidize clean` with `--dump`, `--skip-dumps-of` and `--delete-dead` does those.
- It cannot list backups. It restores only through Undo, right after Remove completely.

For any of these the user needs `oxidize.exe`, the command line, which is published with every release next to the window app. To undo an earlier removal, the user runs `oxidize restore "<name>"` with the name from the log, as described in [../SKILL.md](../SKILL.md).
