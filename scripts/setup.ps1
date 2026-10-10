# Checks the tools Oxidize needs to build, then runs a release build.
# It installs nothing: anything missing is listed with the command to get it.
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rustCommand = 'winget install --id Rustlang.Rustup -e'
$buildToolsCommand = 'winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100"'

$programFilesX86 = ${env:ProgramFiles(x86)}
if (-not $programFilesX86) { $programFilesX86 = $env:ProgramFiles }
$vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'

function Test-Rust {
    if ((Get-Command cargo -ErrorAction SilentlyContinue) -and (Get-Command rustup -ErrorAction SilentlyContinue)) {
        return $true
    }
    # PATH can be stale right after installing rustup, so look in the default places too.
    $dirs = @()
    if ($env:CARGO_HOME) { $dirs += Join-Path $env:CARGO_HOME 'bin' }
    if ($env:USERPROFILE) { $dirs += Join-Path $env:USERPROFILE '.cargo\bin' }
    foreach ($dir in $dirs) {
        if ((Test-Path -LiteralPath (Join-Path $dir 'cargo.exe')) -and (Test-Path -LiteralPath (Join-Path $dir 'rustup.exe'))) {
            $env:PATH = "$dir;$env:PATH"
            return $true
        }
    }
    return $false
}

# Returns the installation paths vswhere reports, empty if vswhere is missing.
function Get-VsInstall {
    param([string[]]$Requires = @())
    if (-not (Test-Path -LiteralPath $vswhere)) { return @() }
    $ErrorActionPreference = 'Continue'
    $vsArgs = @('-products', '*')
    foreach ($component in $Requires) { $vsArgs += @('-requires', $component) }
    $vsArgs += @('-property', 'installationPath')
    $found = & $vswhere @vsArgs
    if ($LASTEXITCODE -ne 0) { return @() }
    return @($found | Where-Object { $_ })
}

# rc.exe from the Windows SDK embeds the icon (build.rs, winresource crate).
function Test-WindowsSdk {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots'
    )
    foreach ($key in $keys) {
        $root = $null
        try { $root = (Get-ItemProperty -LiteralPath $key -Name KitsRoot10).KitsRoot10 } catch { continue }
        if (-not $root) { continue }
        $bin = Join-Path $root 'bin'
        if (-not (Test-Path -LiteralPath $bin)) { continue }
        foreach ($dir in @(Get-ChildItem -LiteralPath $bin -Directory | Where-Object { $_.Name -like '10.*' })) {
            if (Test-Path -LiteralPath (Join-Path $dir.FullName 'x64\rc.exe')) { return $true }
        }
    }
    return $false
}

$missing = @()

if (-not (Test-Rust)) {
    $missing += 'Missing: Rust (cargo and rustup)'
    $missing += "  $rustCommand"
    $missing += '  Then open a new terminal so cargo is on PATH.'
}

$hasVs = @(Get-VsInstall).Count -gt 0
$hasMsvc = @(Get-VsInstall -Requires 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64').Count -gt 0

if (-not $hasMsvc) {
    $missing += 'Missing: MSVC build tools (C++ x64/x86 compiler and linker)'
    if ($hasVs) {
        $missing += '  Open the Visual Studio Installer, choose Modify on your installation'
        $missing += '  and add the workload "Desktop development with C++".'
    } else {
        $missing += "  $buildToolsCommand"
    }
}

if (-not (Test-WindowsSdk)) {
    $missing += 'Missing: Windows 10/11 SDK (rc.exe)'
    if ($hasVs) {
        $missing += '  Open the Visual Studio Installer, choose Modify on your installation'
        $missing += '  and tick "Windows 11 SDK" under Individual components.'
    } else {
        $missing += '  The Build Tools command above installs it as well.'
    }
}

if ($missing.Count -gt 0) {
    $missing | ForEach-Object { Write-Host $_ }
    Write-Host ''
    Write-Host 'Nothing was installed. Get the missing pieces, then run this script again.'
    exit 1
}

Write-Host 'Found cargo, rustup, the MSVC build tools and the Windows SDK.'

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Write-Host "Building in $repo"

Push-Location -LiteralPath $repo
try {
    # cargo prints progress on stderr; that must not count as a failure.
    $ErrorActionPreference = 'Continue'
    & cargo build --release --locked
    $code = $LASTEXITCODE
} finally {
    $ErrorActionPreference = 'Stop'
    Pop-Location
}

if ($code -ne 0) {
    Write-Host "cargo build failed with exit code $code."
    exit $code
}

$target = Join-Path $repo 'target'
if ($env:CARGO_TARGET_DIR) {
    $target = $env:CARGO_TARGET_DIR
    if (-not [System.IO.Path]::IsPathRooted($target)) { $target = Join-Path $repo $target }
}
$release = Join-Path $target 'release'

Write-Host ''
Write-Host 'Build finished:'
Write-Host "  $(Join-Path $release 'oxidize-gui.exe')"
Write-Host "  $(Join-Path $release 'oxidize.exe')"
Write-Host 'oxidize-gui.exe is the window app, oxidize.exe the command line tool.'
