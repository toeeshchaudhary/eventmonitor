# install-agent.ps1 - provision EventMonitor on a machine we own.
#
# Writes consent.json (the gate the agent checks), registers autostart, shows the
# notice watermark, and optionally sets the Windows logon banner.
#
# Default is Mode=activity: keystroke COUNTS + window/process + screenshots.
# Raw characters require BOTH -Mode content AND -CaptureCharacters.
#
# Example (safe default):
#   powershell -ExecutionPolicy Bypass -File install-agent.ps1 `
#     -CollectorUrl https://collector.hash12.local -MachineToken <token> `
#     -Operator "Toeesh Chaudhary" -MachineId LAB-PC-01
#
# Example (explicit content capture, AUP must say so):
#   ... -Mode content -CaptureCharacters

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CollectorUrl,
    [string]$MachineToken,
    [string]$EnrollSecret,
    [Parameter(Mandatory)][string]$Operator,
    [string]$MachineId = $env:COMPUTERNAME,
    [string]$Label = '',
    [string]$Station = '',
    [string]$Attendee = '',
    [ValidateSet('activity', 'content')][string]$Mode = 'activity',
    [switch]$CaptureCharacters,
    [bool]$Screenshots = $true,
    [int]$RetentionDays = 7,
    [string]$AupVersion = 'HASH12-AUP-v1',
    [switch]$NoAdmin,
    [switch]$SkipBanner,
    [switch]$NoStart
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $ScriptDir 'lib.ps1')

$ErrorActionPreference = 'Stop'

if ($CaptureCharacters -and $Mode -ne 'content') {
    throw "Refusing: -CaptureCharacters requires -Mode content (explicit opt-in, not a side effect)."
}

if ($EnrollSecret -and $MachineToken) {
    throw "Refusing: pass either -MachineToken or -EnrollSecret, not both."
}
if ($EnrollSecret) {
    Add-EMLog -Message ("enrolling {0} with collector {1}" -f $MachineId, $CollectorUrl)
    $enrolled = Invoke-EMEnroll -CollectorUrl $CollectorUrl -EnrollSecret $EnrollSecret -MachineId $MachineId -Label $Label
    if (-not $enrolled) {
        throw "Enrollment failed. Check that the collector is reachable and /enroll is open with a matching secret."
    }
    $MachineToken = $enrolled
} elseif (-not $MachineToken) {
    throw "Refusing: pass -MachineToken <token>, or -EnrollSecret <secret> to self-enroll."
}

if ($CollectorUrl -notmatch '^https://') {
    Write-Warning "CollectorUrl is not https - batches are HMAC-signed so they cannot be forged, but content is readable on the wire. Use TLS or an isolated/guest VLAN."
}

$dataDir = Get-EMDataDir
$consentPath = Get-EMConsentPath

$consent = [ordered]@{
    MachineId       = $MachineId
    Station         = $Station
    Attendee        = $Attendee
    AupVersion      = $AupVersion
    AckedBy         = $Operator
    AckedAt         = (Get-Date -Format o)
    CollectorUrl    = $CollectorUrl.TrimEnd('/')
    MachineToken    = $MachineToken
    Mode            = $Mode
    Screenshots     = $Screenshots
    RetentionDays   = $RetentionDays
    ExcludeTitleRegex = @(
        'password', 'keepass', 'bitwarden', 'lastpass', '1password', 'dashlane',
        'bank', 'netbanking', 'upi', 'login', 'sign in', 'authenticat', 'otp'
    )
}

Save-EMConsent -Consent $consent
Add-EMLog -Message ("consent written: machine={0} station='{1}' attendee='{2}' mode={3} aup={4} by={5}" -f $MachineId, $Station, $Attendee, $Mode, $AupVersion, $Operator)

# --- autostart --------------------------------------------------------------
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$collectScript = Join-Path $ScriptDir 'collect.ps1'
$noticeScript  = Join-Path $ScriptDir 'notice.ps1'
$registered = $false

if (-not $NoAdmin) {
    try {
        $action = New-ScheduledTaskAction -Execute $ps `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "{0}"' -f $collectScript)
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName 'EventMonitor-Agent' -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null
        $registered = $true
        Add-EMLog -Message 'registered scheduled task EventMonitor-Agent (AtLogOn)'
    } catch {
        Add-EMLog -Level 'warn' -Message "scheduled task failed (need admin?), falling back to Startup shortcut: $_"
    }
}

if (-not $registered) {
    $startup = [Environment]::GetFolderPath('Startup')
    $shell = New-Object -ComObject WScript.Shell

    $lnk = $shell.CreateShortcut((Join-Path $startup 'EventMonitor-Agent.lnk'))
    $lnk.TargetPath = $ps
    $lnk.Arguments = ('-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "{0}"' -f $collectScript)
    $lnk.WorkingDirectory = $ScriptDir
    $lnk.Save()

    $lnk2 = $shell.CreateShortcut((Join-Path $startup 'EventMonitor-Notice.lnk'))
    $lnk2.TargetPath = $ps
    $lnk2.Arguments = ('-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "{0}"' -f $noticeScript)
    $lnk2.WorkingDirectory = $ScriptDir
    $lnk2.Save()

    Add-EMLog -Message 'installed Startup shortcuts (agent + notice)'
}

# --- logon banner (visible notice before anyone touches the keyboard) -------
if (-not $SkipBanner) {
    $policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try {
        $existing = (Get-ItemProperty -Path $policy -Name LegalNoticeCaption -ErrorAction SilentlyContinue).LegalNoticeCaption
        if ($existing) {
            Add-EMLog -Level 'warn' -Message "logon banner already set ('$existing') - leaving it alone"
        } else {
            $backup = Join-Path $dataDir 'banner-backup.json'
            [System.IO.File]::WriteAllText($backup, (@{ caption = ''; text = '' } | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
            Set-ItemProperty -Path $policy -Name LegalNoticeCaption -Value ("EVENT MONITORING - " + $MachineId)
            Set-ItemProperty -Path $policy -Name LegalNoticeText -Value ('This machine is monitored for event verification (' + $AupVersion + '). ' +
                'Session activity - windows, applications, screenshots and typing activity - is recorded and reviewed by event staff. ' +
                'Do not enter personal passwords or banking details on this machine. Ask staff for an unmonitored device if you need one.')
            Add-EMLog -Message 'logon banner set (backup saved)'
        }
    } catch {
        Add-EMLog -Level 'warn' -Message "could not set logon banner (need admin): $_"
    }
}

# --- start now --------------------------------------------------------------
if (-not $NoStart) {
    $quotedCollect = '"{0}"' -f $collectScript
    Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', $quotedCollect) | Out-Null
    $quotedNotice = '"{0}"' -f $noticeScript
    Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', $quotedNotice) | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host ''
Write-Host '--- EventMonitor installed ---'
Write-Host ('  machine     : {0}' -f $MachineId)
Write-Host ('  station     : {0}' -f $(if ($Station) { $Station } else { '(unset - set it with Set-Identity.ps1 -Station <value>)' }))
Write-Host ('  attendee    : {0}' -f $(if ($Attendee) { $Attendee } else { '(unset)' }))
Write-Host ("  mode        : {0}   (characters captured: {1})" -f $Mode, [bool]($Mode -eq 'content' -and $CaptureCharacters))
Write-Host ("  screenshots : {0}" -f $Screenshots)
Write-Host ("  collector   : {0}" -f $CollectorUrl)
Write-Host ("  retention   : {0} days" -f $RetentionDays)
Write-Host ("  consent     : {0}" -f $consentPath)
Write-Host ("  autostart   : {0}" -f $(if ($registered) { 'scheduled task' } else { 'Startup shortcut' }))
Write-Host ''
Write-Host 'Before attendees arrive: display aup.txt at the desk and confirm the watermark is visible.'
