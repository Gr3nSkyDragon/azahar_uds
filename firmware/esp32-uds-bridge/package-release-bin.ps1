# Builds the firmware and writes ONE flashable file (bootloader + partition table + app merged at
# offset 0x0) for a GitHub release, so users can flash without installing ESP-IDF.
#
# Run it from an "ESP-IDF 5.2 PowerShell" (Desktop/Start menu shortcut):
#   .\package-release-bin.ps1                       # writes ..\..\..\release\esp32-uds-bridge-fw<ver>-esp32s3.bin
#   .\package-release-bin.ps1 -OutputDir C:\some\folder

param(
    [string]$OutputDir = (Join-Path $PSScriptRoot "..\..\..\release")
)

$ErrorActionPreference = "Stop"
if (-not (Get-Command idf.py -ErrorAction SilentlyContinue)) {
    throw "idf.py not found. Run this from the 'ESP-IDF 5.2 PowerShell' shortcut."
}

Push-Location $PSScriptRoot
try {
    idf.py build
    if ($LASTEXITCODE -ne 0) { throw "build failed" }

    # Firmware version, from main.c (FW_MAJOR / FW_MINOR).
    $main = Get-Content (Join-Path $PSScriptRoot "main\main.c") -Raw
    $major = [regex]::Match($main, '#define FW_MAJOR (\d+)').Groups[1].Value
    $minor = [regex]::Match($main, '#define FW_MINOR (\d+)').Groups[1].Value

    New-Item -ItemType Directory -Force $OutputDir | Out-Null
    $out = Join-Path (Resolve-Path $OutputDir).Path "esp32-uds-bridge-fw$major.$minor-esp32s3.bin"

    Push-Location build
    try {
        # The same layout `idf.py flash` uses (see build\flash_args), merged into one image.
        python -m esptool --chip esp32s3 merge_bin -o $out --flash_mode dio --flash_freq 80m --flash_size 4MB "@flash_args"
        if ($LASTEXITCODE -ne 0) { throw "merge_bin failed" }
    } finally { Pop-Location }

    "{0}  ({1:N0} bytes) - flash at offset 0x0" -f $out, (Get-Item $out).Length
} finally { Pop-Location }
