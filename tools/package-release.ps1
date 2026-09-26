# Packages the Windows Release build into a zip for a GitHub release.
#
# Run it after building citra_meta (azahar.exe) in Release, e.g. from Visual Studio:
#   powershell -ExecutionPolicy Bypass -File tools\package-release.ps1
#   powershell -ExecutionPolicy Bypass -File tools\package-release.ps1 -Name "Azahar-UDS-windows-x64-esp32"
#
# The Qt/FFmpeg DLLs and plugins next to azahar.exe are put there by the build itself (windeployqt),
# so packaging is just copying that folder without the debug symbols and the test/room executables.
# It never overwrites an existing zip: pick a new -Name for each release.

param(
    [string]$Name = "Azahar-UDS-windows-x64",
    [string]$BuildDir = (Join-Path $PSScriptRoot "..\build\bin\Release"),
    [string]$OutputDir = (Join-Path $PSScriptRoot "..\..\release")
)

$ErrorActionPreference = "Stop"
$BuildDir = (Resolve-Path $BuildDir).Path
$exe = Join-Path $BuildDir "azahar.exe"
if (-not (Test-Path $exe)) { throw "azahar.exe not found in $BuildDir - build the citra_meta target in Release first." }
if (Get-Process azahar -ErrorAction SilentlyContinue) { throw "azahar.exe is running; close it first." }

New-Item -ItemType Directory -Force $OutputDir | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path
$zip = Join-Path $OutputDir "$Name.zip"
if (Test-Path $zip) { throw "$zip already exists; choose another -Name (nothing was overwritten)." }

$stage = Join-Path $env:TEMP "$Name-stage"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory $stage | Out-Null

# Everything the emulator needs to run, minus debug symbols and developer-only executables.
robocopy $BuildDir $stage /E /XF *.pdb tests.exe azahar-room.exe /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }

Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
Remove-Item -Recurse -Force $stage

$item = Get-Item $zip
"{0}  ({1:N1} MB)" -f $item.FullName, ($item.Length / 1MB)
"azahar.exe built: " + (Get-Item $exe).LastWriteTime
