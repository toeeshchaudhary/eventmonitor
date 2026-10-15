# Setup-EventMonitor.ps1 - one script, whole event.
#
#   Collector  : generates tokens, writes collector.json, opens the firewall port,
#                starts the collector, prints the console URL and the exact
#                command to run on every other machine.
#   Agent      : self-enrolls (no token copying) and installs the capture agent.
#   Both       : common case - one laptop is the storage box AND a monitored machine.
#   Status     : prints config, health, enrolled machines and storage usage.
#
# Examples
#   # on the storage laptop (wired to the lab switch), elevated:
#   .\Setup-EventMonitor.ps1 -Role Both -Operator "Toeesh Chaudhary" -RetentionDays 7
#
#   # on every other lab machine, elevated:
#   .\Setup-EventMonitor.ps1 -Role Agent -CollectorUrl http://192.168.1.50:8787 `
#     -EnrollSecret <printed by the collector run> -Operator "Toeesh Chaudhary" -MachineId LAB-PC-02
#
#   # check everything later:
#   .\Setup-EventMonitor.ps1 -Role Status

[CmdletBinding()]
param(
    [ValidateSet('Collector', 'Agent', 'Both', 'Status')][string]$Role = 'Both',
    [string]$CollectorUrl,
    [int]$Port = 8787,
    [string]$AdminToken,
    [string]$EnrollSecret,
    [int]$RetentionDays = 7,
    [string]$Operator,
    [string]$MachineId = $env:COMPUTERNAME,
    [string]$Label = '',
    [Alias('System', 'Seat', 'Table', 'Bench', 'Desk', 'Workstation')][string]$Station = '',
    [Alias('Team', 'User', 'Person')][string]$Attendee = '',
    [ValidateSet('activity', 'content')][string]$Mode = 'activity',
    [switch]$CaptureCharacters,
    [bool]$Screenshots = $true,
    [switch]$Foreground,
    [switch]$NoFirewall,
    [switch]$NoAutostart,
    [switch]$SkipBanner,
    [switch]$PurgeOnUninstall
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $ScriptDir 'lib.ps1')

$collectorDir = Join-Path $ScriptDir 'collector'
$serverPath = Join-Path $collectorDir 'server.ts'
$configPath = Join-Path $collectorDir 'collector.json'
$logPath = Join-Path $collectorDir 'collector.log'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function New-Token { return [guid]::NewGuid().ToString('N') }

# Set a property on a PSCustomObject whether or not it already exists.
# Config files written by hand (or by an older version) are missing keys, and
# plain assignment throws "property cannot be found on this object".
function Set-Cfg {
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Name, $Value)
    if ($Config.PSObject.Properties.Name.Contains($Name)) { $Config.$Name = $Value }
    else { $Config | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force }
}

function Get-LanIp {
    try {
        $cands = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -notlike '127.*' -and
                $_.IPAddress -notlike '169.254.*' -and
                $_.AddressState -eq 'Preferred'
            }
        $pick = $cands | Where-Object { $_.PrefixOrigin -eq 'Dhcp' } | Select-Object -First 1
        if (-not $pick) { $pick = $cands | Select-Object -First 1 }
        if ($pick) { return [string]$pick.IPAddress }
    } catch {}
    try {
        $addr = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' -and -not [System.Net.IPAddress]::IsLoopback($_) } |
            Select-Object -First 1
        if ($addr) { return [string]$addr.IPAddress }
    } catch {}
    return '127.0.0.1'
}

function Resolve-Bun {
    $cmd = Get-Command bun -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $guess = Join-Path $env:USERPROFILE '.bun\bin\bun.exe'
    if (Test-Path $guess) { return $guess }
    return $null
}

function Write-Bar { param([string]$Text) ; Write-Host '' ; Write-Host ('=' * 74) ; Write-Host $Text ; Write-Host ('=' * 74) }

# --- collector --------------------------------------------------------------

function Start-CollectorRole {
    $bun = Resolve-Bun
    if (-not $bun) {
        throw "bun not found. Install it first: powershell -c `"irm bun.sh/install.ps1 | iex`""
    }

    # Load or create config. Re-running is idempotent: existing secrets are kept
    # so agents that already enrolled do not break.
    $cfg = $null
    if (Test-Path $configPath) {
        try { $cfg = Get-Content $configPath -Raw | ConvertFrom-Json } catch { $cfg = $null }
    }

    if (-not $cfg) {
        $cfg = [pscustomobject]@{
            host          = '0.0.0.0'
            port          = $Port
            dataDir       = './data'
            adminToken    = ''
            retentionDays = $RetentionDays
            maxBatchBytes = 8388608
            dumpJsonl     = $true
            enroll        = [pscustomobject]@{ enabled = $true; secret = '' }
            machines      = [pscustomobject]@{}
        }
    }

    # older or hand-written configs may predate these sections
    if (-not $cfg.PSObject.Properties.Name.Contains('enroll') -or -not $cfg.enroll) {
        $cfg | Add-Member -NotePropertyName 'enroll' -NotePropertyValue ([pscustomobject]@{ enabled = $true; secret = '' }) -Force
    }
    if (-not $cfg.PSObject.Properties.Name.Contains('machines') -or -not $cfg.machines) {
        $cfg | Add-Member -NotePropertyName 'machines' -NotePropertyValue ([pscustomobject]@{}) -Force
    }

    # drop shipped placeholder entries so the registry starts clean
    $kept = @{}
    if ($cfg.machines) {
        foreach ($p in $cfg.machines.PSObject.Properties) {
            if ($p.Name -like 'CHANGE-ME*') { continue }
            if ($p.Value.token -and $p.Value.token -like '*CHANGE-ME*') {
                Add-EMLog -Level 'warn' -Message ("dropping placeholder machine entry: {0}" -f $p.Name)
                continue
            }
            $kept[$p.Name] = $p.Value
        }
    }
    $cfg.machines = ([pscustomobject]$kept)

    if ($AdminToken) { Set-Cfg -Config $cfg -Name 'adminToken' -Value $AdminToken }
    elseif (-not $cfg.adminToken -or $cfg.adminToken.Length -lt 16 -or $cfg.adminToken -like '*CHANGE-ME*') {
        Set-Cfg -Config $cfg -Name 'adminToken' -Value (New-Token)
    }

    if ($EnrollSecret) { Set-Cfg -Config $cfg.enroll -Name 'secret' -Value $EnrollSecret }
    elseif (-not $cfg.enroll.secret -or $cfg.enroll.secret -like '*CHANGE-ME*') {
        Set-Cfg -Config $cfg.enroll -Name 'secret' -Value (New-Token)
    }
    Set-Cfg -Config $cfg.enroll -Name 'enabled' -Value $true
    Set-Cfg -Config $cfg -Name 'port' -Value $Port
    Set-Cfg -Config $cfg -Name 'retentionDays' -Value $RetentionDays
    Set-Cfg -Config $cfg -Name 'dumpJsonl' -Value $true

    # Write without a BOM: PowerShell 5.1's -Encoding UTF8 would prepend one and
    # Bun's JSON.parse rejects it.
    [System.IO.File]::WriteAllText($configPath, ($cfg | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Add-EMLog -Message ("collector.json written: port={0} retention={1}d" -f $Port, $RetentionDays)

    # firewall: inbound TCP on the private profile only. Public profile stays closed.
    if (-not $NoFirewall) {
        if ($isAdmin) {
            try {
                $existing = Get-NetFirewallRule -DisplayName ("EventMonitor collector {0}" -f $Port) -ErrorAction SilentlyContinue
                if ($existing) {
                    Add-EMLog -Message ("firewall rule already present for port {0}" -f $Port)
                } else {
                    New-NetFirewallRule -DisplayName ("EventMonitor collector {0}" -f $Port) `
                        -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port `
                        -Profile Private -Description 'EventMonitor agent ingest (LAN only)' | Out-Null
                    Add-EMLog -Message ("firewall rule added for TCP {0} (Private profile)" -f $Port)
                }
            } catch {
                Add-EMLog -Level 'warn' -Message "could not add firewall rule: $_"
            }
        } else {
            Add-EMLog -Level 'warn' -Message 'not elevated: firewall rule NOT added (other machines may not reach the collector)'
        }
    }

    # autostart the collector
    if (-not $NoAutostart -and -not $Foreground) {
        if ($isAdmin) {
            try {
                $action = New-ScheduledTaskAction -Execute $bun -Argument ('run "{0}"' -f $serverPath) -WorkingDirectory $collectorDir
                $trigger = New-ScheduledTaskTrigger -AtLogOn
                $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
                    -MultipleInstances IgnoreNew
                Register-ScheduledTask -TaskName 'EventMonitor-Collector' -Action $action -Trigger $trigger `
                    -Principal $principal -Settings $settings -Force | Out-Null
                Add-EMLog -Message 'registered scheduled task EventMonitor-Collector (AtLogOn)'
            } catch {
                Add-EMLog -Level 'warn' -Message "collector scheduled task failed: $_"
            }
        } else {
            $startup = [Environment]::GetFolderPath('Startup')
            $shell = New-Object -ComObject WScript.Shell
            $lnk = $shell.CreateShortcut((Join-Path $startup 'EventMonitor-Collector.lnk'))
            $lnk.TargetPath = $bun
            $lnk.Arguments = ('run "{0}"' -f $serverPath)
            $lnk.WorkingDirectory = $collectorDir
            $lnk.Save()
            Add-EMLog -Message 'installed Startup shortcut for collector'
        }
    }

    # launch now
    $already = $false
    try {
        $health = Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/health" -f $Port) -TimeoutSec 3
        if ($health.ok) { $already = $true }
    } catch {}

    if ($already) {
        Add-EMLog -Message ("collector already responding on port {0}" -f $Port)
    } else {
        if ($Foreground) {
            Write-Host ''
            Write-Host '--- collector starting in the foreground (Ctrl+C to stop) ---'
            Push-Location $collectorDir
            try { & $bun run $serverPath } finally { Pop-Location }
            return
        }
        # Start-Process does NOT quote arguments, and this path contains spaces.
        Start-Process -FilePath $bun -ArgumentList @('run', ('"{0}"' -f $serverPath)) -WorkingDirectory $collectorDir `
            -RedirectStandardOutput $logPath -RedirectStandardError ($logPath + '.err') -WindowStyle Hidden
        Add-EMLog -Message ("collector launched, logging to {0}" -f $logPath)
        Start-Sleep -Seconds 4
    }

    return $cfg
}

# --- agent ------------------------------------------------------------------

function Start-AgentRole {
    param([string]$Url)

    if (-not $Operator) { throw "-Operator is required for the Agent role (who acknowledged the AUP)." }
    if (-not $Url) {
        if ($Role -eq 'Both') { $Url = 'http://{0}:{1}' -f (Get-LanIp), $Port }
        else { throw "-CollectorUrl is required for the Agent role." }
    }

    $args = @{
        CollectorUrl = $Url
        Operator     = $Operator
        MachineId    = $MachineId
        Mode         = $Mode
        Screenshots  = $Screenshots
        RetentionDays = $RetentionDays
        NoAdmin      = (-not $isAdmin)
        SkipBanner   = $SkipBanner
        NoStart      = $false
    }
    if ($Label) { $args['Label'] = $Label }
    if ($Station) { $args['Station'] = $Station }
    if ($Attendee) { $args['Attendee'] = $Attendee }
    if ($CaptureCharacters) { $args['CaptureCharacters'] = $true }
    if ($EnrollSecret) { $args['EnrollSecret'] = $EnrollSecret }

    # When provisioning the collector box itself, reuse the secret it just wrote.
    if (-not $args.ContainsKey('EnrollSecret') -and (Test-Path $configPath)) {
        try {
            $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
            if ($cfg.enroll.secret) { $args['EnrollSecret'] = [string]$cfg.enroll.secret }
        } catch {}
    }

    & (Join-Path $ScriptDir 'install-agent.ps1') @args
}

# --- status -----------------------------------------------------------------

function Show-Status {
    Write-Bar 'EventMonitor status'

    if (-not (Test-Path $configPath)) {
        Write-Host 'no collector.json - the collector has never been set up on this machine.'
    } else {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        $admin = [string]$cfg.adminToken
        $secret = [string]$cfg.enroll.secret
        $mask = { param($t) if ($t.Length -gt 10) { $t.Substring(0, 6) + '...' + $t.Substring($t.Length - 4) } else { $t } }

        Write-Host ("collector port   : {0}" -f $cfg.port)
        Write-Host ("admin token      : {0}" -f (& $mask $admin))
        Write-Host ("enroll secret    : {0}   (enrollment enabled: {1})" -f (& $mask $secret), $cfg.enroll.enabled)
        Write-Host ("retention        : {0} days" -f $cfg.retentionDays)
        Write-Host ("flat JSONL dump  : {0}" -f $cfg.dumpJsonl)

        $dataDir = Join-Path $collectorDir ([string]$cfg.dataDir).Replace('./', '')
        Write-Host ''
        Write-Host ("storage dir      : {0}" -f $dataDir)
        foreach ($sub in @('events.db', 'dump', 'blobs')) {
            $p = Join-Path $dataDir $sub
            if (Test-Path $p) {
                $item = Get-Item $p
                if ($item.PSIsContainer) {
                    $files = @(Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue)
                    $mb = [math]::Round((($files | Measure-Object -Property Length -Sum).Sum) / 1MB, 2)
                    Write-Host ("  {0,-12} {1} file(s), {2} MB" -f $sub, $files.Count, $mb)
                } else {
                    Write-Host ("  {0,-12} {1} MB" -f $sub, [math]::Round($item.Length / 1MB, 2))
                }
            } else {
                Write-Host ("  {0,-12} (missing)" -f $sub)
            }
        }

        Write-Host ''
        try {
            $health = Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/health" -f $cfg.port) -TimeoutSec 3
            Write-Host ("collector health : OK ({0} machine(s) enrolled)" -f $health.machines)
            $m = Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/api/machines?token={1}" -f $cfg.port, $admin) -TimeoutSec 5
            Write-Host ''
            Write-Host 'enrolled machines:'
            foreach ($e in $m.enrolled) { Write-Host ("  - {0}" -f $e.id) }
            Write-Host ''
            Write-Host 'event counts:'
            foreach ($r in $m.items) { Write-Host ("  {0,-16} {1} events   last {2}" -f $r.id, $r.n_events, $r.last_seen) }
            if (@($m.items).Count -eq 0) { Write-Host '  (nothing received yet)' }
        } catch {
            Write-Host ("collector health : NOT RESPONDING on port {0}" -f $cfg.port)
        }
    }

    Write-Host ''
    Write-Host 'agent state:'
    Write-Host ("  consent.json   : {0}" -f (Test-Path (Get-EMConsentPath)))
    $consent = Get-EMConsent
    if ($consent) {
        Write-Host ("  machine id     : {0}" -f $consent.MachineId)
        Write-Host ("  mode           : {0}" -f $consent.Mode)
        Write-Host ("  collector      : {0}" -f $consent.CollectorUrl)
    }
    Write-Host ("  scheduled task : {0}" -f [bool](Get-ScheduledTask -TaskName 'EventMonitor-Agent' -ErrorAction SilentlyContinue))
    Write-Host ("  spool dir      : {0} file(s), {1} MB" -f (Get-EMSpoolFiles).Count, [math]::Round((Get-EMSpoolBytes) / 1MB, 2))
    Write-Host ''
}

# --- main -------------------------------------------------------------------

Write-Bar ("EventMonitor setup - role {0}" -f $Role)
Add-EMLog -Message ("setup start role={0} admin={1} machine={2}" -f $Role, $isAdmin, $MachineId)

if (-not $isAdmin -and $Role -ne 'Status') {
    Write-Warning 'Not running elevated. Autostart tasks and the firewall rule need admin; Startup shortcuts will be used instead.'
}

$CollectorUrlResolved = $CollectorUrl

if ($Role -eq 'Status') {
    Show-Status
    return
}

if ($Role -eq 'Collector' -or $Role -eq 'Both') {
    $cfg = Start-CollectorRole
    if ($cfg) {
        $ip = Get-LanIp
        if (-not $CollectorUrlResolved) { $CollectorUrlResolved = 'http://{0}:{1}' -f $ip, $cfg.port }
        $admin = [string]$cfg.adminToken
        $secret = [string]$cfg.enroll.secret

        Write-Bar 'COLLECTOR READY'
        Write-Host ("  dashboard    : http://{0}:{1}/" -f $ip, $cfg.port)
        Write-Host ("  admin token  : {0}" -f $admin)
        Write-Host ("  enroll secret: {0}" -f $secret)
        Write-Host ''
        Write-Host ("  storage      : {0}" -f (Join-Path $collectorDir 'data'))
        Write-Host  '                 events.db  +  dump\<machine>\<day>.jsonl  +  blobs\<machine>\*.jpg'
        Write-Host ("  log          : {0}" -f $logPath)
        Write-Host ''
        Write-Host '  ON EVERY OTHER LAB MACHINE (elevated), run:' -ForegroundColor White
        Write-Host ''
        Write-Host ("  .\Setup-EventMonitor.ps1 -Role Agent -CollectorUrl http://{0}:{1} ``" -f $ip, $cfg.port)
        Write-Host ("    -EnrollSecret {0} -Operator `"{1}`" -MachineId <THIS-PC-NAME>" -f $secret, $Operator)
        Write-Host ''
        Write-Host '  Write the admin token down now. It is stored in collector.json and shown by -Role Status.'
    }
}

if ($Role -eq 'Agent' -or $Role -eq 'Both') {
    Start-AgentRole -Url $CollectorUrlResolved
    Write-Bar 'AGENT READY'
    Write-Host ("  machine  : {0}" -f $MachineId)
    Write-Host ("  station  : {0}" -f $(if ($Station) { $Station } else { '(unset - set it any time with Set-Identity.ps1)' }))
    Write-Host ("  attendee : {0}" -f $(if ($Attendee) { $Attendee } else { '(unset)' }))
    Write-Host ("  mode     : {0}   (characters captured: {1})" -f $Mode, [bool]($Mode -eq 'content' -and $CaptureCharacters))
    Write-Host ("  sending  : {0}" -f $CollectorUrlResolved)
    Write-Host ''
    Write-Host '  Re-label this machine at any time while the event runs:' -ForegroundColor White
    Write-Host ('    .\Set-Identity.ps1 -Id <id> -Station "TABLE-2" -Attendee "Team Name"')
    Write-Host ''
    Write-Host '  Now: confirm the [REC] watermark is visible, and put aup.txt on the desk.'
}

Write-Host ''
Add-EMLog -Message 'setup done'
