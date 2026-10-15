# Set-Identity.ps1 - set this machine's ID, station and attendee.
#
# Works WHILE the event is running. The agent re-reads consent.json every ~20
# seconds, so the change takes effect on its own and gets recorded as an
# 'identity' event (with from/to), which is exactly what you want in the log when
# a machine is handed to a different team mid-event.
#
#   .\Set-Identity.ps1 -Id LAB-PC-03 -Station "TABLE-2" -Attendee "Team Kryptix"
#   .\Set-Identity.ps1 -Table 4                  # station only (alias for -Station)
#   .\Set-Identity.ps1 -Show                     # what is it set to right now?
#   .\Set-Identity.ps1 -Station ""               # clear the station
#
# Use -Restart if you want it applied immediately rather than within ~20s.

[CmdletBinding()]
param(
    [Alias('Machine', 'Name', 'Id')][string]$MachineId,
    [Alias('System', 'Seat', 'Table', 'Bench', 'Desk', 'Workstation')][string]$Station,
    [Alias('Team', 'User', 'Person')][string]$Attendee,
    [switch]$Show,
    [switch]$Restart
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $ScriptDir 'lib.ps1')

$ErrorActionPreference = 'Stop'

$consent = Get-EMConsent
if (-not $consent) {
    throw "No consent.json on this machine - run Setup-EventMonitor.ps1 -Role Agent first."
}

$before = Get-EMIdentity -Consent $consent

function Show-Identity {
    param($Id)
    Write-Host ''
    Write-Host '  machine id : ' -NoNewline; Write-Host $(if ($Id.machineId) { $Id.machineId } else { '(unset)' })
    Write-Host '  station    : ' -NoNewline; Write-Host $(if ($Id.station) { $Id.station } else { '(unset)' })
    Write-Host '  attendee   : ' -NoNewline; Write-Host $(if ($Id.attendee) { $Id.attendee } else { '(unset)' })
    Write-Host ''
}

if ($Show -or $PSBoundParameters.Count -eq 0) {
    Write-Host 'current identity:'
    Show-Identity -Id $before
    Write-Host ("  consent file: {0}" -f (Get-EMConsentPath))
    Write-Host ("  collector   : {0}" -f $consent.CollectorUrl)
    Write-Host ''
    return
}

$touched = @()
if ($PSBoundParameters.ContainsKey('MachineId')) { Set-EMField -Object $consent -Name 'MachineId' -Value $MachineId; $touched += 'machine id' }
if ($PSBoundParameters.ContainsKey('Station'))   { Set-EMField -Object $consent -Name 'Station'   -Value $Station;   $touched += 'station' }
if ($PSBoundParameters.ContainsKey('Attendee'))  { Set-EMField -Object $consent -Name 'Attendee'  -Value $Attendee;  $touched += 'attendee' }

if ($touched.Count -eq 0) { Write-Warning 'nothing to change'; return }

Save-EMConsent -Consent $consent
$after = Get-EMIdentity -Consent $consent
Add-EMLog -Message ("identity set by operator: {0} | {1} | {2}" -f $after.machineId, $after.station, $after.attendee)

Write-Host ("updated: {0}" -f ($touched -join ', '))

if ($PSBoundParameters.ContainsKey('MachineId')) {
    Write-Warning ('Changing the machine id does NOT change how the collector files this machine: that binding is the token issued at enrollment. ' +
                   'Events and the identity-change record carry the new label, but the console still lists the enrolled id. ' +
                   'To change the enrolled id, re-run Setup-EventMonitor.ps1 -Role Agent with the new -MachineId.')
}

Show-Identity -Id $after

# The agent picks this up on its own; -Restart just makes it instant.
if ($Restart) {
    $stopped = 0
    Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'EventMonitor\\collect\.ps1' } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            $stopped++
        }
    Start-Sleep -Milliseconds 900

    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $quoted = '"{0}"' -f (Join-Path $ScriptDir 'collect.ps1')
    Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', $quoted) | Out-Null
    Add-EMLog -Message ("agent restarted for identity change (stopped {0})" -f $stopped)
    Write-Host 'agent restarted - applied immediately.'
} else {
    Write-Host 'the agent will pick this up within ~20 seconds (no restart needed).'
}
