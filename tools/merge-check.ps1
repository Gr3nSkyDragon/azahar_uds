#Requires -Version 5.1
<#
.SYNOPSIS
Checks whether the newest upstream Azahar and mGBA commits merge into our branches without breaking them.

.DESCRIPTION
For each repo (Azahar uds-real, mGBA mgba-ldn) it:
  1. fetches the upstream branch,
  2. lists the commits we are behind, the files both sides changed, and upstream changes to code our
     LDN/UDS features rely on,
  3. merges in memory and lists any conflicts with their hunks,
  4. on a clean merge, builds the merged code in a separate clone and build folder beside the repo
     (merge-check\) and runs the unit tests; for Azahar also compiles the Android app's Kotlin,
  5. writes a report to merge-check\reports\ and prints a verdict.

Your checkouts, branches, build folders and remotes are never changed: the only thing it updates in your
repo is the upstream remote-tracking ref (a normal fetch). The check clone and its build folder are kept
between runs, so later builds are incremental; the first Azahar build is a full one.

Exit code: 0 when every checked repo is safe to merge (or already up to date), 1 when one needs attention
(conflicts, a failed build or failed tests), 2 when the check itself could not run.

.PARAMETER Target
azahar, mgba or both (default).

.PARAMETER Quick
Commit list, overlaps and conflicts only: no build, no tests.

.PARAMETER IncludeUncommitted
Check your uncommitted changes too (tracked files only), as if they were committed.

.PARAMETER Force
Build and test even when the branch is already up to date with upstream (checks the branch as it is).

.PARAMETER NoFetch
Use the upstream ref as last fetched.

.PARAMETER SkipAndroid
Skip the Android Kotlin compile for Azahar.

.PARAMETER Ref
Check this commit instead of the branch tip (one -Target only), e.g. to replay an older merge.

.EXAMPLE
.\merge-check.ps1
.\merge-check.ps1 -Target mgba -Quick
.\merge-check.ps1 -Target azahar -IncludeUncommitted
#>
[CmdletBinding()]
param(
    [ValidateSet('azahar', 'mgba', 'both')] [string]$Target = 'both',
    [switch]$Quick,
    [switch]$IncludeUncommitted,
    [switch]$Force,
    [switch]$NoFetch,
    [switch]$SkipAndroid,
    [string]$Ref
)

Set-StrictMode -Version 1.0  # 1.0: catches unset variables; empty results stay countable
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# ---- Configuration -------------------------------------------------------------------------------------------------

$VsDir = 'C:\Program Files\Microsoft Visual Studio\18\Professional'

$Profiles = [ordered]@{
    azahar = @{
        Name           = 'Azahar'
        Repo           = 'E:\DS Emu\3DS\Azahar-UDS\azahar'
        Branch         = 'uds-real'
        Remote         = 'origin'            # the official azahar-emu/azahar
        UpstreamBranch = 'master'
        MainBuild      = 'E:\DS Emu\3DS\Azahar-UDS\azahar\build'   # its CMake options are copied
        Generator      = 'msbuild'
        Targets        = @('citra_meta', 'tests', 'azahar_virtual_air')
        SeedDlls       = 'bin\Release'
        Android        = $true
        # Upstream code our features lean on without our having changed it. Files both sides changed are found
        # automatically; these are flagged as well so a behaviour change there gets a look.
        Watch          = @(
            'src/core/hle/service/nwm/', 'src/core/hle/service/frd/', 'src/core/hle/kernel/', 'src/core/hle/ipc',
            'src/core/core.cpp', 'src/core/core_timing.', 'src/core/hle/service/service.', 'src/network/',
            'src/common/settings.', 'src/citra_qt/configuration/config.', 'src/citra_qt/citra_qt.',
            'src/citra_qt/multiplayer/', 'src/citra_qt/configuration/configure_network',
            'src/android/app/src/main/java/org/citra/citra_emu/features/settings/',
            'src/android/app/src/main/java/org/citra/citra_emu/activities/EmulationActivity.kt',
            'src/android/app/src/main/jni/config.', 'src/android/app/src/main/jni/native.cpp',
            'src/android/app/src/main/jni/default_ini.h', 'src/android/app/build.gradle.kts',
            'src/android/app/src/main/AndroidManifest.xml', 'CMakeModules/GenerateSettingKeys.cmake',
            'src/core/CMakeLists.txt', 'src/tests/CMakeLists.txt'
        )
    }
    mgba   = @{
        Name           = 'mGBA'
        Repo           = 'E:\DS Emu\GBA Files\mGba_real\mgba'
        Branch         = 'mgba-ldn'
        Remote         = 'upstream'          # the official mgba-emu/mgba
        UpstreamBranch = 'master'
        MainBuild      = 'E:\DS Emu\GBA Files\mGba_real\build'
        Generator      = 'ninja'
        Targets        = @()                 # everything, as build-mgba.cmd does
        Android        = $false
        Watch          = @(
            'src/gb/sio/', 'src/gba/sio/', 'include/mgba/internal/gb/sio/', 'include/mgba/internal/gba/sio/',
            'include/mgba/gb/interface.h', 'include/mgba/gba/interface.h', 'src/gb/io.c', 'src/gba/io.c',
            'src/gb/gb.c', 'src/gba/gba.c', 'src/core/thread.c', 'src/core/timing.c', 'src/core/sync.c',
            'src/platform/qt/CoreController.', 'src/platform/qt/Window.', 'src/platform/qt/MultiplayerController.',
            'src/platform/qt/ConfigController.', 'src/platform/qt/CMakeLists.txt', 'src/platform/android-ldn/',
            'CMakeLists.txt', 'src/feature/', 'src/util/socket'
        )
    }
}

$AndroidEnv = @{
    JAVA_HOME        = 'E:\Android\jdk'
    ANDROID_HOME     = 'E:\Android\Sdk'
    ANDROID_SDK_ROOT = 'E:\Android\Sdk'
    GRADLE_USER_HOME = 'E:\Android\gradle-home'
}

# ---- Helpers -------------------------------------------------------------------------------------------------------

function Format-Arg([string]$a) {
    if ($a -ne '' -and $a -notmatch '[\s"]') { return $a }
    $b = [regex]::Replace($a, '(\\*)"', { param($m) $m.Groups[1].Value + $m.Groups[1].Value + '\"' })
    $b = [regex]::Replace($b, '(\\+)$', { param($m) $m.Groups[1].Value + $m.Groups[1].Value })
    return '"' + $b + '"'
}

# Runs a program without a window, returning its exit code, stdout and stderr. -Arguments is a raw command line
# when -Raw is given (for cmd /c), otherwise a list that is quoted here.
function Invoke-Program {
    param(
        [string]$File, [string[]]$Arguments = @(), [string]$Dir = $null, [switch]$Raw, [int]$TimeoutSec = 0,
        [hashtable]$Environment = $null
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    if ($Raw) { $psi.Arguments = ($Arguments -join ' ') } else { $psi.Arguments = (($Arguments | ForEach-Object { Format-Arg $_ }) -join ' ') }
    if ($Dir) { $psi.WorkingDirectory = $Dir }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    if ($Environment) { foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[$k] = $Environment[$k] } }
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $timedOut = $false
    if ($TimeoutSec -gt 0) {
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            $timedOut = $true
            try { & taskkill.exe /T /F /PID $p.Id 2>$null | Out-Null } catch {}
        }
    }
    $p.WaitForExit()
    [pscustomobject]@{
        Code     = $(if ($timedOut) { -1 } else { $p.ExitCode })
        Out      = $outTask.Result
        Err      = $errTask.Result
        TimedOut = $timedOut
    }
}

# Git <dir> <args...>: plain $args (no param block), so git options such as -c are not taken as PowerShell parameters.
# Array arguments are flattened.
function Get-GitArgs($all) {
    $list = New-Object System.Collections.Generic.List[string]
    $list.Add('-C'); $list.Add([string]$all[0])
    foreach ($a in @($all | Select-Object -Skip 1)) { foreach ($x in @($a)) { $list.Add([string]$x) } }
    return , $list.ToArray()
}

function Git {
    Invoke-Program -File 'git' -Arguments (Get-GitArgs $args)
}

function GitOut {
    $ga = Get-GitArgs $args
    $r = Invoke-Program -File 'git' -Arguments $ga
    if ($r.Code -ne 0) { throw "git $(($ga | Select-Object -Skip 2) -join ' ') failed in $($args[0]): $($r.Err.Trim())" }
    return $r.Out
}

function Lines([string]$text) {
    if (-not $text) { return @() }
    return @($text -split "`r?`n" | Where-Object { $_ -ne '' })
}

# Runs a command line through cmd with all output going to a log file. Returns the exit code.
function Invoke-Logged {
    param([string]$CommandLine, [string]$Log, [string]$Dir, [hashtable]$Environment = $null, [int]$TimeoutSec = 0)
    $inner = "$CommandLine > `"$Log`" 2>&1"
    $r = Invoke-Program -File $env:ComSpec -Arguments @('/d', '/s', '/c', "`"$inner`"") -Raw -Dir $Dir -Environment $Environment -TimeoutSec $TimeoutSec
    if ($r.TimedOut) { Add-Content -LiteralPath $Log -Value "`r`n[merge-check] timed out after $TimeoutSec s" }
    return $r.Code
}

function Say([string]$text, [string]$color = 'Gray') { Write-Host $text -ForegroundColor $color }

function Normalize-Path([string]$p) { return ($p -replace '\\', '/').TrimEnd('/').ToLowerInvariant() }

# ---- Steps ---------------------------------------------------------------------------------------------------------

# Clones the repo (local, hardlinked) beside it the first time, hands it the commit to check and checks that out.
function Sync-CheckClone($prof, [string]$work, [string]$sha) {
    if (-not (Test-Path -LiteralPath (Join-Path $work '.git'))) {
        Say "  creating the check clone in $work (first run)"
        New-Item -ItemType Directory -Force -Path (Split-Path $work) | Out-Null
        $r = Invoke-Program -File 'git' -Arguments @('clone', '--quiet', '--no-checkout', $prof.Repo, $work)
        if ($r.Code -ne 0) { throw "could not clone $($prof.Repo): $($r.Err.Trim())" }
        Git $work checkout --quiet --detach | Out-Null
    }
    # Pushed from your repo into the clone: this writes a ref in the clone only, never in your repo.
    $r = Git $prof.Repo push --quiet --force $work "${sha}:refs/heads/mc-check"
    if ($r.Code -ne 0) { throw "could not hand the commit to the check clone: $($r.Err.Trim())" }
    $r = Git $work -c advice.detachedHead=false checkout --quiet --force --detach $sha
    if ($r.Code -ne 0) { throw "could not check out the trial merge: $($r.Err.Trim())" }
    Git $work clean -fdq | Out-Null
}

# Initializes submodules, cloning each from your checkout's copy when it has one (fast, offline), else from its URL.
function Update-Submodules([string]$work, [string]$mainGitDir, [string]$indent = '  ') {
    if (-not (Test-Path -LiteralPath (Join-Path $work '.gitmodules'))) { return $true }
    $map = Lines (Invoke-Program -File 'git' -Arguments @('-C', $work, 'config', '-f', '.gitmodules', '--get-regexp', '^submodule\..*\.path$')).Out
    $ok = $true
    foreach ($line in $map) {
        if ($line -notmatch '^submodule\.(.+)\.path (.+)$') { continue }
        $name = $Matches[1]; $path = $Matches[2]
        $local = Join-Path $mainGitDir ("modules\" + ($name -replace '/', '\'))
        $remoteUrl = (Invoke-Program -File 'git' -Arguments @('-C', $work, 'config', '-f', '.gitmodules', "submodule.$name.url")).Out.Trim()
        $tried = @()
        if (Test-Path -LiteralPath $local) { $tried += $local }
        $tried += $remoteUrl
        $done = $false
        $subWork = Join-Path $work ($path -replace '/', '\')
        foreach ($url in $tried) {
            Git $work config "submodule.$name.url" $url | Out-Null
            # An existing clone fetches from its own origin, so point that at the same place.
            if (Test-Path -LiteralPath (Join-Path $subWork '.git')) { Git $subWork remote set-url origin $url | Out-Null }
            $r = Git $work -c protocol.file.allow=always submodule update --init --force --quiet '--' $path
            if ($r.Code -eq 0) { $done = $true; break }
        }
        if (-not $done) {
            Say "${indent}submodule $path could not be checked out" 'Red'
            $ok = $false
            continue
        }
        $subMain =$(if (Test-Path -LiteralPath $local) { $local } else { Join-Path $subWork '.git' })
        if (-not (Update-Submodules $subWork $subMain ($indent + '  '))) { $ok = $false }
    }
    return $ok
}

# Writes a CMake initial cache with the options of your main build folder, so the check builds the same way.
function Write-InitialCache($prof, [string]$cachePath) {
    $mainCache = Join-Path $prof.MainBuild 'CMakeCache.txt'
    if (-not (Test-Path -LiteralPath $mainCache)) { throw "no CMakeCache.txt in $($prof.MainBuild): build the main tree once first" }
    $skipA = Normalize-Path $prof.Repo
    $skipB = Normalize-Path $prof.MainBuild
    $want = '^(ENABLE_|USE_|CITRA_|BUILD_|WITH_|VCPKG_)|^(CMAKE_BUILD_TYPE|CMAKE_PREFIX_PATH|CMAKE_TOOLCHAIN_FILE|CMAKE_C_FLAGS|CMAKE_CXX_FLAGS|Qt6_DIR)$'
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in [System.IO.File]::ReadAllLines($mainCache)) {
        if ($line -notmatch '^([A-Za-z0-9_\.\-]+):([A-Z]+)=(.*)$') { continue }
        $n = $Matches[1]; $t = $Matches[2]; $v = $Matches[3]
        if ($t -eq 'INTERNAL' -or $t -eq 'STATIC') { continue }
        # UNINITIALIZED entries are the -D options given by hand on the cmake command line: always copied.
        if ($t -ne 'UNINITIALIZED' -and $n -notmatch $want) { continue }
        $nv = Normalize-Path $v
        if ($nv -and ($nv.StartsWith($skipA) -or $nv.StartsWith($skipB))) { continue }
        if ($t -eq 'UNINITIALIZED') { $t = 'STRING' }
        $ev = $v -replace '\\', '/' -replace '"', '\"'
        $out.Add("set($n `"$ev`" CACHE $t `"`" FORCE)")
    }
    [System.IO.File]::WriteAllLines($cachePath, $out)
}

function Get-ErrorLines([string]$log, [int]$max = 40) {
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    $pat = '(\berror\b\s*[A-Z]*\d*\s*:|: fatal error|FAILED:|^e: |error MSB\d+|LINK : fatal|CMake Error)'
    return @(Select-String -LiteralPath $log -Pattern $pat | Select-Object -First $max | ForEach-Object { $_.Line.Trim() } | Select-Object -Unique)
}

# Builds the checked-out tree. Returns @{ Ok; Log; Errors }.
function Invoke-Build($prof, [string]$work, [string]$buildDir, [string]$logDir, [string]$stamp) {
    $log = Join-Path $logDir "$($prof.Name.ToLower())-build-$stamp.log"
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    $vcvars = Join-Path $VsDir 'VC\Auxiliary\Build\vcvars64.bat'
    $pre = $(if ($prof.Generator -eq 'ninja') { "call `"$vcvars`" >nul && " } else { '' })
    $cacheFile = Join-Path $buildDir 'merge-check-init.cmake'
    if (-not (Test-Path -LiteralPath (Join-Path $buildDir 'CMakeCache.txt'))) {
        Say "  configuring (first run)"
        Write-InitialCache $prof $cacheFile
        if ($prof.Generator -eq 'ninja') {
            $gen = '-G Ninja'
        } else {
            $main = Get-Content -LiteralPath (Join-Path $prof.MainBuild 'CMakeCache.txt')
            $g = ($main | Where-Object { $_ -match '^CMAKE_GENERATOR:INTERNAL=' }) -replace '^[^=]*=', ''
            $a = ($main | Where-Object { $_ -match '^CMAKE_GENERATOR_PLATFORM:INTERNAL=' }) -replace '^[^=]*=', ''
            $gen = "-G `"$g`"" + $(if ($a) { " -A $a" } else { '' })
        }
        $cfgLog = Join-Path $logDir "$($prof.Name.ToLower())-configure-$stamp.log"
        $code = Invoke-Logged -CommandLine "$pre cmake -S `"$work`" -B `"$buildDir`" $gen -C `"$cacheFile`"" -Log $cfgLog -Dir $work
        if ($code -ne 0) {
            Remove-Item -LiteralPath (Join-Path $buildDir 'CMakeCache.txt') -ErrorAction SilentlyContinue
            return @{ Ok = $false; Log = $cfgLog; Errors = (Get-ErrorLines $cfgLog) }
        }
    }
    if ($prof.ContainsKey('SeedDlls')) {
        # Qt 6.10 ships its own FFmpeg DLLs, so Azahar's in-place bundling finds two avcodec-61.dll and stops when the exe's
        # folder is empty. Your main build has the right ones beside the exe already; seed the check build with the same.
        $dst = Join-Path $buildDir $prof.SeedDlls
        $src = Join-Path $prof.MainBuild $prof.SeedDlls
        if (Test-Path -LiteralPath $src) {
            New-Item -ItemType Directory -Force -Path $dst | Out-Null
            foreach ($d in (Get-ChildItem -LiteralPath $src -Filter '*.dll' -File)) {
                $t = Join-Path $dst $d.Name
                if (-not (Test-Path -LiteralPath $t)) { Copy-Item -LiteralPath $d.FullName -Destination $t }
            }
        }
    }
    $targets = $(if ($prof.Targets.Count) { '--target ' + ($prof.Targets -join ' ') } else { '' })
    if ($prof.Generator -eq 'ninja') {
        $cmd = "$pre cmake --build `"$buildDir`" $targets"
    } else {
        $cmd = "cmake --build `"$buildDir`" --config Release $targets -- /m /v:minimal /nologo"
    }
    $code = Invoke-Logged -CommandLine $cmd -Log $log -Dir $work
    return @{ Ok = ($code -eq 0); Log = $log; Errors = $(if ($code -ne 0) { Get-ErrorLines $log } else { @() }) }
}

# Runs the unit tests. Returns a list of @{ Name; Ok; Summary }.
function Invoke-Tests($prof, [string]$buildDir) {
    $results = New-Object System.Collections.Generic.List[object]
    if ($prof.Generator -eq 'msbuild') {
        $exe = Join-Path $buildDir 'bin\Release\tests.exe'
        if (-not (Test-Path -LiteralPath $exe)) { $results.Add(@{ Name = 'tests.exe'; Ok = $false; Summary = 'not built' }); return $results }
        $r = Invoke-Program -File $exe -Dir (Split-Path $exe) -TimeoutSec 1800
        $text = $r.Out + "`n" + $r.Err
        $sum = (Lines $text | Where-Object { $_ -match '^(test cases|assertions|All tests passed)' }) -join '; '
        if ($r.TimedOut) { $sum = 'timed out' }
        $results.Add(@{ Name = 'tests.exe'; Ok = ($r.Code -eq 0); Summary = $sum; Output = $text })
    } else {
        $exes = @(Get-ChildItem -LiteralPath $buildDir -Filter 'uds-*test.exe' -File | Sort-Object Name)
        if (-not $exes.Count) { $results.Add(@{ Name = 'uds-*-test'; Ok = $false; Summary = 'no uds-*test programs built' }) }
        foreach ($e in $exes) {
            $r = Invoke-Program -File $e.FullName -Dir $buildDir -TimeoutSec 600
            $text = $r.Out + "`n" + $r.Err
            $sum = (Lines $text | Where-Object { $_ -match '\d+ checks, \d+ failures' } | Select-Object -Last 1)
            if (-not $sum) { $sum = "exit $($r.Code)" }
            if ($r.TimedOut) { $sum = 'timed out' }
            $ok = ($r.Code -eq 0) -and ($sum -notmatch '[1-9]\d* failures')
            $results.Add(@{ Name = $e.BaseName; Ok = $ok; Summary = $sum; Output = $text })
        }
    }
    return $results
}

function Invoke-AndroidCompile([string]$work, [string]$logDir, [string]$stamp) {
    foreach ($k in 'JAVA_HOME', 'ANDROID_HOME') {
        if (-not (Test-Path -LiteralPath $AndroidEnv[$k])) { return @{ Ok = $null; Summary = "skipped: $k ($($AndroidEnv[$k])) not found"; Errors = @() } }
    }
    $dir = Join-Path $work 'src\android'
    $log = Join-Path $logDir "azahar-android-$stamp.log"
    # Full path: cmd may be set not to run programs from the current folder (NoDefaultCurrentDirectoryInExePath).
    $gradlew = Join-Path $dir 'gradlew.bat'
    $code = Invoke-Logged -CommandLine "`"$gradlew`" compileVanillaReleaseKotlin --console=plain --no-daemon" -Log $log -Dir $dir -Environment $AndroidEnv -TimeoutSec 3600
    $errs = $(if ($code -ne 0) { Get-ErrorLines $log } else { @() })
    return @{ Ok = ($code -eq 0); Summary = $(if ($code -eq 0) { 'Kotlin compiles' } else { "gradle failed (exit $code)" }); Errors = $errs; Log = $log }
}

# Pulls the conflict hunks of one file out of the merged tree (which holds the conflict markers).
function Get-ConflictHunks([string]$repo, [string]$tree, [string]$path, [int]$maxHunks = 6, [int]$maxLines = 40) {
    $r = Git $repo show "${tree}:$path"
    if ($r.Code -ne 0) { return @('(no text to show: the file was deleted or is binary on one side)') }
    $lines = $r.Out -split "`r?`n"
    $out = New-Object System.Collections.Generic.List[string]
    $hunks = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch '^<<<<<<< ') { continue }
        if (++$hunks -gt $maxHunks) { $out.Add('... more conflicts in this file'); break }
        $out.Add("@@ line $($i + 1)")
        $n = 0
        for ($j = $i; $j -lt $lines.Count; $j++) {
            if ($n++ -lt $maxLines) { $out.Add($lines[$j]) } elseif ($n -eq $maxLines + 1) { $out.Add('   ...') }
            if ($lines[$j] -match '^>>>>>>> ') { $i = $j; break }
        }
    }
    return $out
}

# ---- One repo ------------------------------------------------------------------------------------------------------

function Test-Repo($prof) {
    $name = $prof.Name
    $repo = $prof.Repo
    $root = Join-Path (Split-Path $repo) 'merge-check'
    $work = Join-Path $root ($name.ToLower())
    $buildDir = Join-Path $root "$($name.ToLower())-build"
    $logDir = Join-Path $root 'logs'
    $reportDir = Join-Path $root 'reports'
    New-Item -ItemType Directory -Force -Path $logDir, $reportDir | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $report = New-Object System.Collections.Generic.List[string]
    $verdict = 'ok'      # ok | review | fail
    $notes = New-Object System.Collections.Generic.List[string]

    Say ''
    Say "=== $name ($($prof.Branch) vs $($prof.Remote)/$($prof.UpstreamBranch)) ===" 'Cyan'
    $up = "refs/remotes/$($prof.Remote)/$($prof.UpstreamBranch)"
    $oursRef = "refs/heads/$($prof.Branch)"

    if (-not $NoFetch) {
        Say "  fetching $($prof.Remote) $($prof.UpstreamBranch)"
        $r = Git $repo fetch --quiet --no-tags $prof.Remote "+refs/heads/$($prof.UpstreamBranch):$up"
        if ($r.Code -ne 0) { throw "fetch failed: $($r.Err.Trim())" }
    }

    $ours = (GitOut $repo rev-parse --verify $oursRef).Trim()
    $upSha = (GitOut $repo rev-parse --verify $up).Trim()
    $current = (Git $repo symbolic-ref --quiet --short HEAD).Out.Trim()
    $dirty = Lines (GitOut $repo status --porcelain --untracked-files=no)
    $oursLabel = $prof.Branch
    if ($Ref) {
        $ours = (GitOut $repo rev-parse --verify "$Ref^{commit}").Trim()
        $oursLabel = $Ref
        $dirty = @()
    }
    if ($dirty.Count) {
        if ($IncludeUncommitted -and $current -eq $prof.Branch) {
            $stash = (GitOut $repo stash create 'merge-check').Trim()
            if ($stash) { $ours = $stash; $oursLabel = "$($prof.Branch) + uncommitted changes" }
            $notes.Add("Checked with your $($dirty.Count) uncommitted file(s) included (new untracked files are not).")
        } else {
            $notes.Add("You have $($dirty.Count) uncommitted file(s); they are not part of this check (use -IncludeUncommitted).")
        }
    }
    if ($current -and $current -ne $prof.Branch) { $notes.Add("Your checkout is on '$current', not $($prof.Branch); the check uses $($prof.Branch).") }

    $base = (GitOut $repo merge-base $ours $upSha).Trim()
    $counts = (GitOut $repo rev-list --left-right --count "$ours...$upSha").Trim() -split '\s+'
    $ahead = [int]$counts[0]; $behind = [int]$counts[1]
    $upDate = (GitOut $repo log -1 --format=%cs $upSha).Trim()

    $report.Add("# Merge check: $name")
    $report.Add('')
    $report.Add("Run $(Get-Date -Format 'yyyy-MM-dd HH:mm'). ``$oursLabel`` (``$($ours.Substring(0,9))``) against ``$($prof.Remote)/$($prof.UpstreamBranch)`` (``$($upSha.Substring(0,9))``, $upDate).")
    $report.Add('')
    $report.Add("- Behind upstream: **$behind** commits")
    $report.Add("- Ahead (our own commits since the last merge base): $ahead")
    $report.Add("- Merge base: ``$($base.Substring(0,9))``")
    Say "  behind $behind, ahead $ahead"

    $doBuild = -not $Quick
    $merged = $null
    if ($behind -eq 0) {
        $report.Add(''); $report.Add('Already up to date with upstream.')
        if (-not $Force) { $doBuild = $false }
        $merged = $ours
    } else {
        # Commits we are missing
        $commits = Lines (GitOut $repo log --reverse --no-merges --format=%h%x09%as%x09%s "$base..$upSha")
        $report.Add(''); $report.Add("## Upstream commits ($behind)"); $report.Add('')
        $shown = 0
        foreach ($c in $commits) {
            if (++$shown -gt 300) { $report.Add("- ... $($commits.Count - 300) more"); break }
            $p = $c -split "`t", 3
            $report.Add("- ``$($p[0])`` $($p[1]) $($p[2])")
        }

        # Files both sides changed, and watched upstream changes
        $upFiles = Lines (GitOut $repo diff --name-only $base $upSha)
        $ourFiles = Lines (GitOut $repo diff --name-only $base $ours)
        $ourSet = New-Object 'System.Collections.Generic.HashSet[string]' (, [string[]]$ourFiles)
        $overlap = @($upFiles | Where-Object { $ourSet.Contains($_) })
        $report.Add(''); $report.Add("## Files both we and upstream changed ($($overlap.Count))"); $report.Add('')
        if (-not $overlap.Count) { $report.Add('None.') }
        foreach ($f in $overlap) {
            $report.Add("- ``$f``")
            foreach ($c in (Lines (GitOut $repo log --no-merges --format=%h%x09%s "$base..$upSha" '--' $f))) {
                $p = $c -split "`t", 2; $report.Add("  - ``$($p[0])`` $($p[1])")
            }
        }
        $watched = @($upFiles | Where-Object { -not $ourSet.Contains($_) } | Where-Object { $f = $_; @($prof.Watch | Where-Object { $f.StartsWith($_) }).Count -gt 0 })
        $report.Add(''); $report.Add("## Upstream changes to code our features rely on ($($watched.Count) files)"); $report.Add('')
        if (-not $watched.Count) { $report.Add('None.') }
        else {
            foreach ($f in $watched) { $report.Add("- ``$f``") }
            $report.Add(''); $report.Add('Commits touching them:'); $report.Add('')
            foreach ($c in (Lines (GitOut $repo log --no-merges --format=%h%x09%s "$base..$upSha" '--' $watched))) {
                $p = $c -split "`t", 2; $report.Add("- ``$($p[0])`` $($p[1])")
            }
        }

        # Submodule bumps
        $subs = @(Lines (GitOut $repo diff --raw --no-abbrev $base $upSha) | Where-Object { $_ -match '^:\d+ 160000 |^:160000 ' })
        if ($subs.Count) {
            $report.Add(''); $report.Add('## Submodules upstream moved'); $report.Add('')
            foreach ($s in $subs) {
                $p = ($s -split "`t")[1]; $h = ($s -split '\s+')
                $report.Add("- ``$p`` $($h[2].Substring(0,9)) -> $($h[3].Substring(0,9))")
            }
            $notes.Add("Upstream moved $($subs.Count) submodule(s): after the real merge run ``git submodule update --init --recursive``.")
        }

        # The merge itself, in memory
        Say '  merging in memory'
        $mt = Git $repo merge-tree --write-tree $ours $upSha
        if ($mt.Code -gt 1) { throw "git merge-tree failed (needs git 2.38 or newer): $($mt.Err.Trim())" }
        $mtLines = $mt.Out -split "`r?`n"
        $tree = $mtLines[0].Trim()
        $conflicts = New-Object System.Collections.Generic.List[string]
        $i = 1
        while ($i -lt $mtLines.Count -and $mtLines[$i] -ne '') {
            $path = ($mtLines[$i] -split "`t", 2)[1]
            if ($path -and -not $conflicts.Contains($path)) { $conflicts.Add($path) }
            $i++
        }
        $messages = @($mtLines | Select-Object -Skip $i | Where-Object { $_ -match '^CONFLICT' })
        $report.Add(''); $report.Add("## Conflicts ($($conflicts.Count))"); $report.Add('')
        if (-not $conflicts.Count) {
            $report.Add('None: git merges everything on its own.')
            Say '  no conflicts' 'Green'
            # A commit object with no branch pointing at it (git prunes it in time); the check clone builds it.
            $merged = (GitOut $repo -c user.name=merge-check -c user.email=merge-check@localhost commit-tree $tree -p $ours -p $upSha -m 'merge-check trial merge').Trim()
        } else {
            $verdict = 'fail'
            Say "  $($conflicts.Count) conflict(s): $($conflicts -join ', ')" 'Yellow'
            foreach ($m in $messages) { $report.Add("- $m") }
            foreach ($f in $conflicts) {
                $report.Add(''); $report.Add("### ``$f``"); $report.Add(''); $report.Add('```')
                foreach ($l in (Get-ConflictHunks $repo $tree $f)) { $report.Add($l) }
                $report.Add('```')
            }
            $notes.Add('Not built: the merge has conflicts. Resolve them in the real merge, then rerun with -Force to build and test it.')
            $doBuild = $false
        }
    }

    # Build and test the merged tree in the check clone
    $buildResult = $null; $testResults = @(); $android = $null
    if ($doBuild) {
        Sync-CheckClone $prof $work $merged
        Say '  submodules'
        if (-not (Update-Submodules $work (Join-Path $repo '.git'))) { $notes.Add('Some submodules could not be checked out; the build may fail because of that.') }

        Say "  building (log in $logDir)"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $buildResult = Invoke-Build $prof $work $buildDir $logDir $stamp
        $mins = [math]::Round($sw.Elapsed.TotalMinutes, 1)
        $report.Add(''); $report.Add('## Build'); $report.Add('')
        if ($buildResult.Ok) {
            Say "  build ok ($mins min)" 'Green'
            $report.Add("Builds ($mins min). Log: ``$($buildResult.Log)``")
            Say '  running tests'
            $testResults = Invoke-Tests $prof $buildDir
            $report.Add(''); $report.Add('## Tests'); $report.Add('')
            foreach ($t in $testResults) {
                $mark = $(if ($t.Ok) { 'pass' } else { 'FAIL' })
                $report.Add("- $mark ``$($t.Name)``: $($t.Summary)")
                Say ("  {0,-4} {1}: {2}" -f $mark, $t.Name, $t.Summary) $(if ($t.Ok) { 'Green' } else { 'Red' })
                if (-not $t.Ok) {
                    $verdict = 'fail'
                    $tail = @(Lines $t.Output | Select-Object -Last 40)
                    if ($tail.Count) { $report.Add(''); $report.Add('```'); foreach ($l in $tail) { $report.Add($l) }; $report.Add('```') }
                }
            }
        } else {
            $verdict = 'fail'
            Say "  BUILD FAILED ($mins min), log: $($buildResult.Log)" 'Red'
            $report.Add("**Fails to build.** Log: ``$($buildResult.Log)``"); $report.Add(''); $report.Add('```')
            foreach ($e in $buildResult.Errors) { $report.Add($e); Say "    $e" 'Red' }
            $report.Add('```')
        }

        if ($prof.Android -and -not $SkipAndroid) {
            Say '  Android: compiling Kotlin'
            $android = Invoke-AndroidCompile $work $logDir $stamp
            $report.Add(''); $report.Add('## Android'); $report.Add('')
            $report.Add($android.Summary + $(if ($android.ContainsKey('Log') -and $android.Log) { ". Log: ``$($android.Log)``" } else { '' }))
            if ($android.Ok -eq $false) {
                $verdict = 'fail'
                $report.Add(''); $report.Add('```'); foreach ($e in $android.Errors) { $report.Add($e) }; $report.Add('```')
                Say "  Android: $($android.Summary)" 'Red'
                foreach ($e in $android.Errors) { Say "    $e" 'Red' }
            } elseif ($android.Ok) { Say "  Android: $($android.Summary)" 'Green' }
            else { Say "  Android: $($android.Summary)" 'Yellow' }
        }
    } elseif ($Quick -and $behind -gt 0 -and $verdict -ne 'fail') {
        $notes.Add('Quick check: not built or tested.')
    }

    if ($verdict -eq 'ok' -and $behind -gt 0 -and (-not $doBuild)) { $verdict = 'review' }

    $headline = switch ($verdict) {
        'ok'     { if ($behind -eq 0 -and -not $doBuild) { 'Up to date: nothing to merge.' } elseif ($behind -eq 0) { 'Up to date; the branch builds and its tests pass.' } else { 'Safe to merge: no conflicts, builds, tests pass.' } }
        'review' { 'No conflicts, but not built or tested in this run.' }
        default  { 'Needs attention before merging (see below).' }
    }
    $report.Insert(2, "**Verdict: $headline**")
    $report.Insert(3, '')
    if ($notes.Count) {
        $report.Add(''); $report.Add('## Notes'); $report.Add('')
        foreach ($n in $notes) { $report.Add("- $n") }
    }
    if ($verdict -ne 'fail' -and $behind -gt 0) {
        $report.Add(''); $report.Add('## To merge for real'); $report.Add(''); $report.Add('```')
        $report.Add("git -C `"$repo`" checkout $($prof.Branch)")
        $report.Add("git -C `"$repo`" merge $($prof.Remote)/$($prof.UpstreamBranch)")
        if ($subs.Count) { $report.Add("git -C `"$repo`" submodule update --init --recursive") }
        $report.Add('```')
    }

    $reportPath = Join-Path $reportDir "$($name.ToLower())-$stamp.md"
    [System.IO.File]::WriteAllLines($reportPath, $report, (New-Object System.Text.UTF8Encoding($false)))
    $color = switch ($verdict) { 'ok' { 'Green' } 'review' { 'Yellow' } default { 'Red' } }
    Say "  $headline" $color
    foreach ($n in $notes) { Say "  note: $n" 'DarkYellow' }
    Say "  report: $reportPath"
    return $verdict
}

# ---- Main ----------------------------------------------------------------------------------------------------------

$gitVer = (Invoke-Program -File 'git' -Arguments @('--version')).Out
if ($gitVer -match '(\d+)\.(\d+)') {
    if ([int]$Matches[1] -lt 2 -or ([int]$Matches[1] -eq 2 -and [int]$Matches[2] -lt 38)) { Say "git 2.38 or newer is needed (found: $gitVer)" 'Red'; exit 2 }
}

if ($Ref -and $Target -eq 'both') { Say '-Ref needs a single -Target (azahar or mgba)' 'Red'; exit 2 }
$names = $(if ($Target -eq 'both') { @($Profiles.Keys) } else { @($Target) })
$verdicts = @{}
$broken = $false
foreach ($n in $names) {
    try {
        $verdicts[$n] = Test-Repo $Profiles[$n]
    } catch {
        Say "  check failed: $($_.Exception.Message)" 'Red'
        $verdicts[$n] = 'error'
        $broken = $true
    }
}

Say ''
Say '=== Summary ===' 'Cyan'
foreach ($n in $names) {
    $v = $verdicts[$n]
    $text = switch ($v) { 'ok' { 'safe to merge / up to date' } 'review' { 'no conflicts, not built' } 'fail' { 'needs attention' } default { 'check could not run' } }
    $color = switch ($v) { 'ok' { 'Green' } 'review' { 'Yellow' } 'fail' { 'Red' } default { 'Red' } }
    Say ("  {0,-7} {1}" -f $Profiles[$n].Name, $text) $color
}
if ($broken) { exit 2 }
if (@($verdicts.Values | Where-Object { $_ -eq 'fail' }).Count) { exit 1 }
exit 0
