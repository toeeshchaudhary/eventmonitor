# Dump-Evidence.ps1 - pull the whole event off the collector into one folder.
#
# Produces a self-contained, tamper-evident package you can copy to a USB stick,
# archive, or hand to whoever needs to see it:
#
#   Evidence-<timestamp>\
#     PROVENANCE.txt              how/when this was exported, from where
#     summary.csv                 per-machine counts and time span
#     MANIFEST.sha256             hash of every file, for integrity checking
#     <machine>\events.jsonl      every recorded event, flat
#     <machine>\screenshots\*.jpg the actual screenshots
#
# Examples
#   .\Dump-Evidence.ps1
#   .\Dump-Evidence.ps1 -Machine LAB-PC-02 -OutDir D:\evidence
#   .\Dump-Evidence.ps1 -From 2026-11-14T09:00:00 -SkipScreenshots

[CmdletBinding()]
param(
    [string]$CollectorUrl,
    [string]$AdminToken,
    [string]$OutDir,
    [string]$Machine,
    [string]$From,
    [string]$To,
    [switch]$SkipScreenshots
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $ScriptDir 'lib.ps1')

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# defaults come from the collector config if this is the collector box
$configPath = Join-Path $ScriptDir 'collector\collector.json'
if (Test-Path $configPath) {
    try {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        if (-not $AdminToken) { $AdminToken = [string]$cfg.adminToken }
        if (-not $CollectorUrl) { $CollectorUrl = 'http://127.0.0.1:{0}' -f $cfg.port }
    } catch {}
}
if (-not $CollectorUrl) { throw 'Need -CollectorUrl (or a collector.json on this machine).' }
if (-not $AdminToken) { throw 'Need -AdminToken (or a collector.json on this machine).' }
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) ('Evidence-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }

$base = $CollectorUrl.TrimEnd('/')
$encToken = [uri]::EscapeDataString($AdminToken)

function Get-Api {
    param([string]$Path)
    return Invoke-RestMethod -Uri ($base + $Path + '&token=' + $encToken) -TimeoutSec 60
}

Write-Host ("exporting from {0}" -f $base)
New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

# --- who is out there -------------------------------------------------------
$machines = Get-Api '/api/machines?x=1'
$targets = @($machines.enrolled | ForEach-Object { $_.id })
if ($Machine) {
    $targets = @($targets | Where-Object { $_ -eq $Machine })
    if ($targets.Count -eq 0) { throw ("machine '{0}' is not enrolled on this collector" -f $Machine) }
}
if ($targets.Count -eq 0) { Write-Warning 'no enrolled machines - nothing to export'; return }

$filter = ''
if ($From) { $filter += '&from=' + [uri]::EscapeDataString([string]$From) }
if ($To)   { $filter += '&to='   + [uri]::EscapeDataString([string]$To) }

$summaryRows = @()
$fileCount = 0
$shotCount = 0
$totalBytes = 0

foreach ($m in $targets) {
    Write-Host ("  {0} ..." -f $m) -NoNewline
    $machineDir = Join-Path $OutDir $m
    New-Item -Path $machineDir -ItemType Directory -Force | Out-Null

    $raw = (Invoke-WebRequest -Uri ($base + '/api/export?machine=' + [uri]::EscapeDataString($m) + $filter + '&token=' + $encToken) `
        -UseBasicParsing -TimeoutSec 120).Content
    $jsonlPath = Join-Path $machineDir 'events.jsonl'
    Set-Content -Path $jsonlPath -Value $raw -Encoding UTF8
    $fileCount++
    $totalBytes += (Get-Item $jsonlPath).Length

    $lines = @()
    if ($raw) { $lines = @($raw -split "`n" | Where-Object { $_.Trim() -ne '' }) }

    $counts = @{ window = 0; input = 0; proc = 0; shot = 0; redacted = 0; agent = 0; other = 0 }
    $keys = 0
    $first = $null
    $last = $null
    $station = ''
    $attendee = ''
    $shots = New-Object System.Collections.ArrayList

    foreach ($line in $lines) {
        $e = $null
        try { $e = $line | ConvertFrom-Json } catch { continue }
        $t = [string]$e.type
        if ($counts.ContainsKey($t)) { $counts[$t]++ } else { $counts['other']++ }
        if ($t -eq 'input' -and $e.keys) { $keys += [int]$e.keys }
        if ($e.station) { $station = [string]$e.station }
        if ($e.attendee) { $attendee = [string]$e.attendee }
        $ts = [string]$e.ts
        if ($ts) {
            if (-not $first -or $ts -lt $first) { $first = $ts }
            if (-not $last  -or $ts -gt $last)  { $last = $ts }
        }
        if ($t -eq 'shot' -and $e.blob) { [void]$shots.Add([string]$e.blob) }
    }

    if (-not $SkipScreenshots -and $shots.Count -gt 0) {
        $shotDir = Join-Path $machineDir 'screenshots'
        New-Item -Path $shotDir -ItemType Directory -Force | Out-Null
        foreach ($blob in $shots) {
            $name = ($blob -split '/')[-1]
            $dest = Join-Path $shotDir $name
            try {
                Invoke-WebRequest -Uri ($base + '/blob/' + $blob + '?token=' + $encToken) -OutFile $dest -UseBasicParsing -TimeoutSec 60
                $fileCount++
                $shotCount++
                $totalBytes += (Get-Item $dest).Length
            } catch {
                Write-Warning ("failed to download screenshot {0}: {1}" -f $blob, $_.Exception.Message)
            }
        }
    }

    $summaryRows += [pscustomobject]@{
        machine     = $m
        station     = $station
        attendee    = $attendee
        first_event = $first
        last_event  = $last
        events      = $lines.Count
        window      = $counts['window']
        input       = $counts['input']
        keys        = $keys
        proc        = $counts['proc']
        shot        = $counts['shot']
        redacted    = $counts['redacted']
        agent       = $counts['agent']
    }

    Write-Host (" {0} events, {1} shot(s)" -f $lines.Count, $shots.Count)
}

# --- summary + provenance ---------------------------------------------------
$summaryPath = Join-Path $OutDir 'summary.csv'
$summaryRows | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
$fileCount++

$stats = $null
try { $stats = Get-Api '/api/stats?x=1' } catch {}
$retention = 'unknown'
if ($stats -and $stats.storage) { $retention = [string]$stats.storage.retentionDays }

$tokenFingerprint = (Get-EMHmac -Key 'eventmon-provenance' -Bytes ([Text.Encoding]::UTF8.GetBytes($AdminToken))).Substring(0, 16)

$provenance = @(
    ('EventMonitor evidence export'),
    (''),
    ('exported at        : {0}' -f (Get-Date -Format o)),
    ('exported from      : {0}' -f $base),
    ('admin token fp     : {0}   (HMAC fingerprint, not the token itself)' -f $tokenFingerprint),
    ('agent machine      : {0}' -f $env:COMPUTERNAME),
    ('machines included  : {0}' -f ($targets -join ', ')),
    ('filter from/to     : {0} / {1}' -f $(if ($From) { $From } else { '(none)' }), $(if ($To) { $To } else { '(none)' }))
    ('collector retention : {0} days  - the collector deletes data past this window' -f $retention),
    ('screenshots included: {0}' -f (-not $SkipScreenshots)),
    (''),
    ('CONTENTS'),
    ('  summary.csv                     one row per machine: counts, key totals, time span'),
    ('  <machine>/events.jsonl          every recorded event, one JSON object per line'),
    ('  <machine>/screenshots/*.jpg     the screenshots themselves'),
    ('  MANIFEST.sha256                 SHA-256 of every file in this folder'),
    (''),
    ('HOW TO VERIFY INTEGRITY LATER'),
    ('  powershell -c "Get-Content MANIFEST.sha256 | foreach { $p,$h = $_ -split ''  '',2; '),
    ('    if ((Get-FileHash -Algorithm SHA256 $p).Hash -ne $h) { Write-Host ''TAMPERED: '' $p } }"'),
    (''),
    ('WHAT THIS DATA IS'),
    ('  window : which application/window was focused, and when'),
    ('  input  : how many keys were pressed while that window was focused'),
    ('  shot   : periodic screenshots of the screen'),
    ('  redacted: an excluded window (password manager / banking / sign-in) was active;'),
    ('            no content and no screenshot were captured for it'),
    ('  chars  : only present if character capture was explicitly enabled for this event'),
    (''),
    ('  This is evidence of activity, not proof of authorship on its own. Corroborate'),
    ('  with submission timestamps, git commit signatures, and check-in records.')
)
Set-Content -Path (Join-Path $OutDir 'PROVENANCE.txt') -Value ($provenance -join "`r`n") -Encoding UTF8
$fileCount++

# --- hash manifest ----------------------------------------------------------
$manifestPath = Join-Path $OutDir 'MANIFEST.sha256'
$entries = @()
foreach ($f in (Get-ChildItem -Path $OutDir -Recurse -File | Where-Object { $_.FullName -ne $manifestPath })) {
    $rel = $f.FullName.Substring($OutDir.Length).TrimStart('\', '/')
    $h = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
    $entries += ('{0}  {1}' -f $h, $rel)
}
Set-Content -Path $manifestPath -Value ($entries -join "`r`n") -Encoding UTF8

Write-Host ''
Write-Host ('=' * 74)
Write-Host 'EVIDENCE EXPORT COMPLETE'
Write-Host ('=' * 74)
Write-Host ("  folder      : {0}" -f (Resolve-Path $OutDir).Path)
Write-Host ("  machines    : {0}" -f $targets.Count)
Write-Host ("  files       : {0}  ({1} screenshots)" -f $fileCount, $shotCount)
Write-Host ("  size        : {0} MB" -f [math]::Round($totalBytes / 1MB, 2))
Write-Host ("  manifest    : MANIFEST.sha256 ({0} entries)" -f $entries.Count)
Write-Host ("  retention   : {0} days on the collector - archive this folder before that expires" -f $retention)
Write-Host ''
Write-Host '  Next: copy the whole folder to your archive/USB, then keep MANIFEST.sha256 with it.'
