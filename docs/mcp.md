# Use it with an AI assistant

`list_programs`, `scan_leftovers`, `find_orphans`, `trace` and `list_backups`
only read. To remove a program the assistant first calls `plan_removal`, which
changes nothing either: it returns the uninstaller and whether it runs at all,
every leftover that would go with its path, size, confidence and reason,
whether administrator rights are needed, and whether a backup is kept.
`apply_removal_plan` carries out a plan made in the same session, exactly as
shown and only once, after closing copies of the program still running from
its folders. Your assistant asks you before it calls a tool, unless you told it
to stop asking for this one, so nothing is removed until you agree to that
step.

A plan keeps no backup unless the assistant makes it with `backup` set to
true; then every removed item is backed up the same way as from the command
line. Without one the plan says its removal is permanent, so the assistant can
tell you before you agree. The result says what was removed, what was not and
why, what a fresh scan still finds, and with a backup the `oxidize restore`
command that puts the removed items back. The assistant cannot restore or delete backups, remove
anything that was not in a plan, or start Oxidize as administrator. Items that
need administrator rights are reported with the command that removes them as
administrator, for you to run. Every plan also lists the commands that do the
same from a terminal, for example `oxidize uninstall "Example Player"`, if you
would rather run the removal yourself.

Scripts can use the command line directly: every command takes `--json`, and
stdout then holds exactly one JSON document. See [JSON output](cli.md#json-output).
