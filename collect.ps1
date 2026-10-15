# collect.ps1 - EventMonitor agent.
#
# Runs on an event machine we own. Captures:
#   window  - foreground process/title/idle transitions   (the primary evidence)
#   input   - keystroke COUNTS per focused window         (activity proof)
#   chars   - actual characters, ONLY in Mode=content      (opt-in)
#   proc    - process start/stop, builds the session story
#   shot    - periodic downscaled screenshot
#   redacted- emitted instead of input/shot on excluded windows
#
# Usage:
#   powershell -ExecutionPolicy Bypass -STA -File collect.ps1
#   powershell -ExecutionPolicy Bypass -STA -File collect.ps1 -Once   # one sample, for testing

[CmdletBinding()]
param(
    [int]$SampleSeconds       = 5,
    [int]$HeartbeatSeconds    = 60,
    [int]$IdleThreshold       = 300,
    [int]$ProcessScanSeconds  = 15,
    [int]$ScreenshotSeconds   = 120,
    [int]$FlushSeconds        = 30,
    [int]$IdentityRefreshSeconds = 20,
    [int]$MaxSpoolMB          = 512,
    [int]$KeyPollMs           = 40,
    [switch]$Once,
    [switch]$Quiet
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $ScriptDir 'lib.ps1')

$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- consent gate: refuses to run without a signed-off record --------------
$consent = Get-EMConsent
$problem = Test-EMConsent -Consent $consent
if ($problem) {
    Add-EMLog -Level 'error' -Message "REFUSING TO START: $problem. Run install-agent.ps1 first."
    exit 2
}

$mode = [string]$consent.Mode
$takeChars = ($mode -eq 'content')
$takeShots = $true
if ($consent.PSObject.Properties.Name.Contains('Screenshots')) { $takeShots = [bool]$consent.Screenshots }
$retention = 7
if ($consent.PSObject.Properties.Name.Contains('RetentionDays')) { $retention = [int]$consent.RetentionDays }

# single instance
$mutex = New-Object System.Threading.Mutex($false, 'Local\EventMonitorAgent')
$gotLock = $false
try { $gotLock = $mutex.WaitOne(0) } catch { $gotLock = $false }
if (-not $gotLock) {
    if (-not $Quiet) { Add-EMLog -Level 'warn' -Message 'another agent instance is already running' }
    exit 0
}

$sid = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))

# Identity goes into every event, and is re-read from consent.json periodically so
# Set-Identity.ps1 can re-label this machine mid-event without a restart.
$script:Identity = Get-EMIdentity -Consent $consent

function New-Event {
    param([string]$Type, [hashtable]$Fields = @{})
    $e = [ordered]@{
        ts       = (Get-Date -Format o)
        sid      = $sid
        type     = $Type
        machine  = [string]$script:Identity.machineId
        station  = [string]$script:Identity.station
        attendee = [string]$script:Identity.attendee
    }
    foreach ($k in $Fields.Keys) { $e[$k] = $Fields[$k] }
    return $e
}

Add-EMLog -Message ("agent start sid={0} mode={1} machine={2} chars={3} shots={4}" -f $sid, $mode, $consent.MachineId, $takeChars, $takeShots)
Add-EMSpool -Consent $consent -Event (New-Event -Type 'agent' -Fields @{ action = 'start'; mode = $mode; machine = [string]$consent.MachineId; aup = [string]$consent.AupVersion }) | Out-Null

# --- state -----------------------------------------------------------------
$prevKeys = New-Object 'bool[]' 256
$lastWindowKey = ''
$lastWindowWrite = [datetime]::MinValue
$pendingCount = 0
$pendingChars = New-Object System.Text.StringBuilder
$knownProcs = @{}
$lastSample = [datetime]::MinValue
$lastProcessScan = [datetime]::MinValue
$lastShot = [datetime]::MinValue
$lastFlush = Get-Date
$lastSidPrune = Get-Date
$lastIdentityRefresh = Get-Date

# seed the process table so we only report new starts
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    $knownProcs[$p.ProcessName] = $true
}

try {
    while ($true) {
        $now = Get-Date

        # --- keystroke activity polling ---
        for ($vk = 8; $vk -le 254; $vk++) {
            $down = ([EM.Native]::GetAsyncKeyState($vk) -band 0x8000) -ne 0
            if ($down -and -not $prevKeys[$vk]) {
                $pendingCount++
                if ($takeChars) {
                    $ch = Get-EMKeyChar -Vk $vk
                    if ($ch) { [void]$pendingChars.Append($ch) }
                }
            }
            $prevKeys[$vk] = $down
        }

        # --- window sampling ---
        if (($now - $lastSample).TotalSeconds -ge $SampleSeconds) {
            $lastSample = $now
            $fg = Get-EMForeground

            $excluded = Test-EMExcludedTitle -Title ([string]$fg.title) -Consent $consent
            $state = if ($fg.idle -ge $IdleThreshold) { 'idle' } else { 'active' }
            $proc = if ($state -eq 'idle') { 'IDLE' } else { [string]$fg.process }
            $title = if ($state -eq 'idle') { '' } else { [string]$fg.title }
            if ($excluded) { $title = '' }

            $windowKey = '{0}|{1}|{2}' -f $proc, $title, $state
            $heartbeatDue = (($now - $lastWindowWrite).TotalSeconds -ge $HeartbeatSeconds)

            if ($windowKey -ne $lastWindowKey -or $heartbeatDue) {
                $lastWindowKey = $windowKey
                $lastWindowWrite = $now
                Add-EMSpool -Consent $consent -Event (New-Event -Type 'window' -Fields @{
                    process = $proc; title = $title; state = $state; idle = [int]$fg.idle
                }) | Out-Null
            }

            # input summary for the interval
            if ($excluded -and $pendingCount -gt 0) {
                Add-EMSpool -Consent $consent -Event (New-Event -Type 'redacted' -Fields @{
                    process = $proc; reason = 'excluded-window'; keys = $pendingCount
                }) | Out-Null
            } elseif ($pendingCount -gt 0) {
                $fields = @{ process = $proc; title = $title; keys = $pendingCount }
                if ($takeChars -and $pendingChars.Length -gt 0) { $fields['chars'] = $pendingChars.ToString() }
                Add-EMSpool -Consent $consent -Event (New-Event -Type 'input' -Fields $fields) | Out-Null
            }
            $pendingCount = 0
            [void]$pendingChars.Clear()
        }

        # --- process starts ---
        if (($now - $lastProcessScan).TotalSeconds -ge $ProcessScanSeconds) {
            $lastProcessScan = $now
            $current = @{}
            foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $current[$p.ProcessName] = $true }
            foreach ($name in $current.Keys) {
                if (-not $knownProcs.ContainsKey($name)) {
                    Add-EMSpool -Consent $consent -Event (New-Event -Type 'proc' -Fields @{ action = 'start'; process = $name }) | Out-Null
                }
            }
            foreach ($name in $knownProcs.Keys) {
                if (-not $current.ContainsKey($name)) {
                    Add-EMSpool -Consent $consent -Event (New-Event -Type 'proc' -Fields @{ action = 'stop'; process = $name }) | Out-Null
                }
            }
            $knownProcs = $current
        }

        # --- screenshots ---
        $spoolBytes = Get-EMSpoolBytes
        $spoolFull = ($spoolBytes / 1MB) -ge $MaxSpoolMB
        if ($takeShots -and -not $spoolFull -and (($now - $lastShot).TotalSeconds -ge $ScreenshotSeconds)) {
            $lastShot = $now
            $fg = Get-EMForeground
            $excluded = Test-EMExcludedTitle -Title ([string]$fg.title) -Consent $consent
            if (-not $excluded) {
                try {
                    $b64 = Get-EMScreenJpeg -MaxWidth 1280 -Quality 45
                    Add-EMSpool -Consent $consent -Event (New-Event -Type 'shot' -Fields @{
                        process = [string]$fg.process; title = [string]$fg.title; b64 = $b64
                    }) | Out-Null
                } catch {
                    Add-EMLog -Level 'warn' -Message "screenshot skipped: $_"
                }
            }
        }
        if ($spoolFull) {
            Add-EMLog -Level 'warn' -Message ("spool over {0}MB - uploads failing?" -f $MaxSpoolMB)
        }

        # --- identity refresh: operator can re-label this machine live --------
        if (($now - $lastIdentityRefresh).TotalSeconds -ge $IdentityRefreshSeconds) {
            $lastIdentityRefresh = $now
            $fresh = Get-EMConsent
            if ($fresh) {
                $new = Get-EMIdentity -Consent $fresh
                $changed = ($new.machineId -ne $script:Identity.machineId) -or
                           ($new.station -ne $script:Identity.station) -or
                           ($new.attendee -ne $script:Identity.attendee)
                if ($changed) {
                    $was = $script:Identity
                    $script:Identity = $new
                    Add-EMSpool -Consent $consent -Event (New-Event -Type 'agent' -Fields @{
                        action = 'identity'
                        from   = ('{0} | {1} | {2}' -f $was.machineId, $was.station, $was.attendee)
                        to     = ('{0} | {1} | {2}' -f $new.machineId, $new.station, $new.attendee)
                    }) | Out-Null
                    Add-EMLog -Message ("identity now {0} | {1} | {2}" -f $new.machineId, $new.station, $new.attendee)
                    [void](Send-EMSpool -Consent $consent -MaxFiles 2)
                }
            }
        }

        # --- flush to collector ---
        if (($now - $lastFlush).TotalSeconds -ge $FlushSeconds) {
            $lastFlush = $now
            [void](Send-EMSpool -Consent $consent -MaxFiles 4)
        }

        # --- retention ---
        if (($now - $lastSidPrune).TotalMinutes -ge 60) {
            $lastSidPrune = $now
            Remove-EMOldSpool -RetentionDays $retention
        }

        if ($Once) { break }
        Start-Sleep -Milliseconds $KeyPollMs
    }
}
finally {
    try {
        Add-EMSpool -Consent $consent -Event (New-Event -Type 'agent' -Fields @{ action = 'stop'; sid = $sid }) | Out-Null
        [void](Send-EMSpool -Consent $consent -MaxFiles 8)
    } catch {}
    try { $mutex.ReleaseMutex() } catch {}
}
