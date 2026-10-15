# uninstall-agent.ps1 - stop and remove the agent.
#
# By default the collected evidence in data\ is KEPT (you probably still need it
# for the event). Pass -PurgeData to delete the spool and logs as well.
#
#   powershell -ExecutionPolicy Bypass -File uninstall-agent.ps1
#   powershell -ExecutionPolicy Bypass -File uninstall-agent.ps1 -PurgeData

[CmdletBinding()]
param(
    [switch]$PurgeData,
    [switch]$KeepConsent
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $ScriptDir 'lib.ps1')

$ErrorActionPreference = 'Continue'

# flush anything still local before we tear down
$consent = Get-EMConsent
if ($consent -and (Test-EMConsent -Consent $consent) -eq $null) {
    $n = Send-EMSpool -Consent $consent -MaxFiles 20
    Add-EMLog -Message "final flush before uninstall: $n batch(es) sent"
}

# stop processes
foreach ($name in @('EventMonitorAgent', 'EventMonitorNotice')) { } # named mutexes, not processes
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'EventMonitor\\(collect|notice)\.ps1' } |
    ForEach-Object {
        Add-EMLog -Message ("stopping pid {0}" -f $_.ProcessId)
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

# scheduled task
try {
    Unregister-ScheduledTask -TaskName 'EventMonitor-Agent' -Confirm:$false -ErrorAction Stop
    Add-EMLog -Message 'scheduled task removed'
} catch {
    Add-EMLog -Level 'warn' -Message 'no scheduled task to remove'
}

# startup shortcuts
$startup = [Environment]::GetFolderPath('Startup')
foreach ($f in @('EventMonitor-Agent.lnk', 'EventMonitor-Notice.lnk')) {
    $p = Join-Path $startup $f
    if (Test-Path $p) { Remove-Item $p -Force; Add-EMLog -Message "removed $f" }
}

# logon banner
$backup = Join-Path (Get-EMDataDir) 'banner-backup.json'
$policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
try {
    if (Test-Path $backup) {
        Remove-ItemProperty -Path $policy -Name LegalNoticeCaption -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $policy -Name LegalNoticeText -ErrorAction SilentlyContinue
        Add-EMLog -Message 'logon banner cleared'
    }
} catch {
    Add-EMLog -Level 'warn' -Message "could not clear logon banner (need admin): $_"
}

if (-not $KeepConsent) {
    Remove-Item -Path (Get-EMConsentPath) -Force -ErrorAction SilentlyContinue
    Add-EMLog -Message 'consent.json removed (agent can no longer start)'
}

if ($PurgeData) {
    $spool = Get-EMSpoolDir
    $removed = 0
    foreach ($f in (Get-ChildItem -Path $spool -Filter '*.emq' -ErrorAction SilentlyContinue)) {
        Remove-Item -Path $f.FullName -Force; $removed++
    }
    Remove-Item -Path (Join-Path (Get-EMDataDir) 'agent.log') -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $backup -Force -ErrorAction SilentlyContinue
    Add-EMLog -Message "purged $removed local spool file(s)"
}

Write-Host ''
Write-Host '--- EventMonitor removed ---'
Write-Host ("  local evidence : {0}" -f $(if ($PurgeData) { 'purged' } else { 'KEPT in data\ - retain per your policy' }))
Write-Host '  collector copy : unaffected - prune it from the collector side when your retention window closes'
