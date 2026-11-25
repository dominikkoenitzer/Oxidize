# Other ways to install

Oxidize runs on Windows only and has no installer. Each release has three files:

| file | |
|---|---|
| [`oxidize-gui.exe`](https://portfolio-izanagi.vercel.app/projects/oxidize) | the window app |
| [`oxidize.exe`](https://portfolio-izanagi.vercel.app/projects/oxidize) | the command line |
| [`oxidize-windows-x64.zip`](https://portfolio-izanagi.vercel.app/projects/oxidize) | both in one zip |

To type `oxidize` in any terminal, `oxidize.exe` has to be in a folder on your
PATH. Make a folder such as `C:\Tools` and move `oxidize.exe` into it. Search
Windows for "Edit environment variables for your account", select `Path`,
click Edit, then New, type `C:\Tools` and close both windows with OK. Terminals
you open after that find it.

You can also skip PATH and run it from the folder you saved it to. Open a
terminal there (right-click an empty spot in the folder, then Open in Terminal)
and start it with its path:

```
.\oxidize.exe list
```

Double-clicking `oxidize.exe` in Explorer opens the window app when
`oxidize-gui.exe` is in the same folder. Otherwise it shows the help and waits
for Enter.

Each file has a `.sha256` file next to it in the release, for example
`oxidize-gui.exe.sha256`. To check a download, save both into the same folder,
open a terminal there and run:

```
Get-FileHash .\oxidize-gui.exe -Algorithm SHA256
```

The hash it prints has to match the one in `oxidize-gui.exe.sha256`; upper or
lower case does not matter. This line compares them for you and prints `True`
when they match:

```
(Get-FileHash .\oxidize-gui.exe -Algorithm SHA256).Hash -eq (Get-Content .\oxidize-gui.exe.sha256).Split(' ')[0]
```

## Your data, updates and removal

Oxidize stores nothing but its backups and the list of protected folders in
`%LOCALAPPDATA%\Oxidize\protected.txt`. Each removal made with a backup gets a folder
`%LOCALAPPDATA%\Oxidize\backups\<date and time> <program>\`. Registry keys are
exported to `.reg` files and validated before anything is deleted. Files and
folders are moved there, not deleted. Task definitions are copied. A manifest
records every step, and `oxidize restore` replays it in reverse.

`oxidize backups` lists the backups, newest first. With `--json` each entry's
`id` is its folder name, and `oxidize restore <id>` takes it as an exact
match; a part of the name or of the program's name works too when only one
backup matches it. `restore` asks first, Enter means yes; `-y` skips the
question. `oxidize backups --delete <name>` deletes one backup and
`oxidize backups --clear` deletes them all.

To remove Oxidize, delete `oxidize-gui.exe` and `oxidize.exe`, then the folder
`%LOCALAPPDATA%\Oxidize` once you no longer need the backups in it. If you
added a folder to your PATH for `oxidize.exe`, remove that entry too.
