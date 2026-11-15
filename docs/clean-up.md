# Clean up

`oxidize clean --traces` is a clean slate for what Windows remembers of your
use: recent items, the jump lists of every app on the taskbar, recent
documents, the Open and Save history, Run history, typed paths and searches
in File Explorer, program launch counts, the thumbnail cache and the
clipboard history. Only these lists go; the files they point to stay, and so
do pinned items. Windows clears the recent items and jump lists itself first,
so Explorer hears of it without a restart, and its own Disk Cleanup handler
empties the thumbnail cache. When the protected list reaches into the Recent
folder, Windows is not asked, since it would clear everything; the items go
one by one and the protected ones stay. `--traces` never touches temporary folders,
browser data, mail or the data of programs. It shows what it would clear;
`--yes` clears it. In the window it is Clean slate on the Clean up tab: one
list, one button.

```
oxidize clean --traces                what would be cleared, nothing changes
oxidize clean --traces --yes          clear every trace
```

Naming categories cleans exactly those: `--temp`, `--crash-dumps`,
`--recycle-bin`, `--browser-cache`, `--component-store`,
`--delivery-optimization`, `--windows-old`, `--orphans` and
`--build-output`. `--recycle-bin-days` sets the Recycle Bin's age. In the window, the Clean up
tab does the same: Analyse, tick, clean. Build output is looked for there
only once its row is ticked.

Temporary files go only when they were neither written nor created for 7
days, in your temp folder and in Windows' own. A git repository stays
whole, however old: a folder with a `.git` folder or file, or a bare
repository, is never entered. Crash dumps are the `.dmp`
files Windows and programs write, and the error reports Windows keeps
queued. Windows' own temp folder and dumps need administrator rights; without
them they are counted and listed as such, and `--elevate` includes them.
Browser caches are only the cache folders of Chrome, Edge, Brave,
Vivaldi, Chromium and Firefox profiles: cookies, history, sessions, saved
logins and site data are never opened, and a browser that is running is
left alone. The Windows component store is cleaned by
`DISM /Online /Cleanup-Image /StartComponentCleanup`, the cleanup Windows
runs on its own schedule (never with `/ResetBase`, so installed updates can
still be removed), and the Delivery Optimization cache by Windows' own
cmdlet; both need administrator rights. A previous Windows installation
(`Windows.old`) is shown with its size and removed only when you name it,
through Disk Cleanup: after that there is no going back to the Windows you
upgraded from. Folders of removed programs are the folders no installed
program claims, scored against the programs Oxidize and Windows Installer
removed: only high-confidence ones are chosen by default. With `--backup` they
go into a backup like any other leftover, so `oxidize restore` puts them back;
without it they are deleted for good. A backup
on the same drive frees nothing until it is deleted, so `--delete-dead`
deletes the chosen folders that are proven dead outright: no file in them
changed for 30 days or held open, nothing running from them, no git
repository in or above them and no cloud placeholder in them. Each is
checked again right before it goes and goes whole or not at all, and one
that came alive goes into the backup instead, when there is one. Without `--delete-dead` no
folder is proven dead, so none of their files are opened. Stale build output is
only ever looked for and cleaned when you name it: folders a build or package tool marked
as its cache with a `CACHEDIR.TAG` file, beside a project file such as
`Cargo.toml` or `package.json` or ignored by git, in your profile but outside the
temp folders, with nothing in them changed for 30 days, nothing running
from them, no file in them held open and no cloud placeholder. One inside a git
checkout goes only while `git status` shows no uncommitted work, and with
administrator rights git is not run at all, so those stay. Deleted
temporary files, dumps, caches, build output and Recycle Bin items do not
come back.

`--dump <path>` cleans only the dumps named, as the plan lists them, and
`--skip-dumps-of <program>` leaves one program's dumps; both go with
`--crash-dumps`, and what they leave is counted as left out.

Folders you list in `%LOCALAPPDATA%\Oxidize\protected.txt`, one per line,
are never cleaned, with everything in them, temp folders included. `%TEMP%`
and other variables work in the list, and the Clean up tab edits it.
A line that is not a full path once variables are expanded, or that names a
whole drive, protects nothing; it stays in the file but not in the list.
Lines starting with `#` are notes, and a save from the Clean up tab keeps
them where they are.
`oxidize protect` prints the list, and `oxidize protect --check <path>` says
whether that path is on it or inside a folder that is, and which entry
covers it.

Oxidize never cleans the registry, prefetch files, `WinSxS` or
`C:\Windows\Installer` directly, cookies, passwords or history, and it does
not wipe free space.
