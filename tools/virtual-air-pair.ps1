#Requires -Version 5.1
<#
.SYNOPSIS
Runs two Azahar instances against each other on the virtual air: the ESP32 radio path, no hardware.

.DESCRIPTION
Sets up two portable copies of the built Azahar (merge-check-style side folders, by default
E:\DS Emu\3DS\Azahar-UDS\virtual-air\A and \B). Each has its own "user" folder, so its own console
MAC address. The settings are copied from your normal Azahar config with the ESP32 radio switched
on. The script then starts azahar-virtual-air and the two emulators with AZAHAR_ESP32_PORT pointing
at it. Your own config and saves are not touched: the copies get their own.

Run -Setup alone to create or refresh the folders without starting anything.

.EXAMPLE
.\virtual-air-pair.ps1                       # set up if needed, start the air and both emulators
.\virtual-air-pair.ps1 -Setup                # only (re)create the two folders
.\virtual-air-pair.ps1 -Loss 0.1 -JitterMs 5 # a rougher air
#>
[CmdletBinding()]
param(
    [switch]$Setup,
    [string]$Root = 'E:\DS Emu\3DS\Azahar-UDS\virtual-air',
    [string]$Build = 'E:\DS Emu\3DS\Azahar-UDS\azahar\build\bin\Release',
    [int]$Port = 45800,
    [double]$LatencyMs = 0.3,
    [double]$JitterMs = 0,
    [double]$Loss = 0,
    [double]$Duplicate = 0,
    [switch]$NoTrace
)

$ErrorActionPreference = 'Stop'
$air = Join-Path $Build 'azahar-virtual-air.exe'
if (-not (Test-Path -LiteralPath (Join-Path $Build 'azahar.exe')) -or -not (Test-Path -LiteralPath $air)) {
    throw "build azahar (citra_meta) and azahar_virtual_air first: nothing in $Build"
}

function Sync-Instance([string]$name) {
    $dir = Join-Path $Root $name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # The program files only; the instance's own "user" folder is left alone.
    $null = & robocopy.exe $Build $dir /E /XD user /XF *.pdb tests.exe azahar-room.exe /NFL /NDL /NJH /NJS /NP
    # Keys and system files from your own Azahar, but not mac.txt: each instance makes its own MAC.
    $sysdata = Join-Path $dir 'user\sysdata'
    $mySysdata = Join-Path $env:APPDATA 'Azahar\sysdata'
    if (-not (Test-Path -LiteralPath $sysdata) -and (Test-Path -LiteralPath $mySysdata)) {
        $null = & robocopy.exe $mySysdata $sysdata /E /XF mac.txt /NFL /NDL /NJH /NJS /NP
    }
    $config = Join-Path $dir 'user\config'
    New-Item -ItemType Directory -Force -Path $config | Out-Null
    $ini = Join-Path $config 'qt-config.ini'
    if (-not (Test-Path -LiteralPath $ini)) {
        $mine = Join-Path $env:APPDATA 'Azahar\config\qt-config.ini'
        if (Test-Path -LiteralPath $mine) { Copy-Item -LiteralPath $mine -Destination $ini }
    }
    if (Test-Path -LiteralPath $ini) {
        $text = [System.IO.File]::ReadAllText($ini)
        $text = $text -replace '(?m)^use_esp32_uds\\default=.*$', 'use_esp32_uds\default=false'
        $text = $text -replace '(?m)^use_esp32_uds=.*$', 'use_esp32_uds=true'
        $text = $text -replace '(?m)^use_mgba_vc_bridge=.*$', 'use_mgba_vc_bridge=false'
        if ($text -notmatch '(?m)^use_esp32_uds=') {
            $text = $text -replace '(?m)^\[WebService\]\r?$', "[WebService]`r`nuse_esp32_uds\default=false`r`nuse_esp32_uds=true"
        }
        [System.IO.File]::WriteAllText($ini, $text)
    }
    return $dir
}

$a = Sync-Instance 'A'
$b = Sync-Instance 'B'
Write-Host "instances: $a, $b (each has its own user folder and MAC)"
if ($Setup) { return }

$airArgs = @('--port', $Port, '--latency-ms', $LatencyMs, '--jitter-ms', $JitterMs, '--loss', $Loss, '--duplicate', $Duplicate)
if (-not $NoTrace) { $airArgs += '--trace' }
Write-Host "starting the virtual air on port $Port (its window shows the trace)"
Start-Process -FilePath $air -ArgumentList $airArgs -WindowStyle Minimized | Out-Null
Start-Sleep -Milliseconds 500

$env:AZAHAR_ESP32_PORT = "tcp:127.0.0.1:$Port"
foreach ($dir in $a, $b) {
    Start-Process -FilePath (Join-Path $dir 'azahar.exe') -WorkingDirectory $dir | Out-Null
}
Remove-Item Env:AZAHAR_ESP32_PORT
Write-Host 'started both emulators; each one logs "connected to the virtual board" when a game starts local wireless'
