# Zips the assistant skill in site/skill/oxidize into site/skill/oxidize.zip, the copy the download page
# serves, then checks the zip: the same files as the skill folder, each byte for byte as git stores it.
# Without -Rev it zips the staged folder, so stage your skill edits first. -Check only checks the zip,
# which CI and the release do against the commit they build.
#
#   powershell -ExecutionPolicy Bypass -File scripts\skill-zip.ps1 [-Rev HEAD] [-Check]

param(
    [string]$Rev,
    [string]$Zip = 'site/skill/oxidize.zip',
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$what = if ($Rev) { $Rev } else { 'the staged files' }
if (-not $Rev) {
    $Rev = git write-tree
    if ($LASTEXITCODE -ne 0) { throw 'git write-tree failed' }
}
$tree = "${Rev}:site/skill/oxidize"
$zipPath = [IO.Path]::GetFullPath([IO.Path]::Combine((Get-Location).Path, $Zip))

if (-not $Check) {
    $dir = Split-Path -Parent $zipPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory $dir | Out-Null }
    # With autocrlf off, the zip holds the files as git stores them, whatever the checkout did to line endings.
    git -c core.autocrlf=false archive --format=zip --prefix=oxidize/ -o $zipPath $tree
    if ($LASTEXITCODE -ne 0) { throw "git archive failed for $tree" }
}

# Each file in the tree, by the hash git keeps for it.
$lines = @(git ls-tree -r $tree)
if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0) { throw "No skill files at $tree" }
$want = @{}
foreach ($line in $lines) {
    if ($line -notmatch '^\d+ blob ([0-9a-f]+)\t(.+)$') { throw "Unexpected tree line: $line" }
    $want["oxidize/$($Matches[2])"] = $Matches[1]
}

# A file's git hash is the SHA-1 of "blob <length>", a zero byte and its bytes.
function Get-BlobHash([byte[]]$bytes) {
    $header = [Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
    $sha = [Security.Cryptography.SHA1]::Create()
    try { $hash = $sha.ComputeHash([byte[]]($header + $bytes)) } finally { $sha.Dispose() }
    -join ($hash | ForEach-Object { $_.ToString('x2') })
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$problems = @()
$seen = @{}
$archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    foreach ($entry in $archive.Entries) {
        if ($entry.FullName.EndsWith('/')) { continue }
        $seen[$entry.FullName] = $true
        if (-not $want.ContainsKey($entry.FullName)) { $problems += "not in the tree: $($entry.FullName)"; continue }
        $stream = $entry.Open()
        $buffer = New-Object IO.MemoryStream
        try { $stream.CopyTo($buffer) } finally { $stream.Dispose() }
        if ((Get-BlobHash $buffer.ToArray()) -ne $want[$entry.FullName]) { $problems += "differs: $($entry.FullName)" }
    }
} finally {
    $archive.Dispose()
}
foreach ($name in $want.Keys) {
    if (-not $seen.ContainsKey($name)) { $problems += "missing: $name" }
}

if ($problems.Count -gt 0) {
    $problems | Sort-Object | ForEach-Object { Write-Host $_ }
    Write-Host "The skill zip does not match the skill folder in $what."
    exit 1
}
Write-Host "The skill zip matches the skill folder in $what ($($want.Count) files)."
