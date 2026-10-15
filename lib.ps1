# lib.ps1 - shared bits for EventMonitor
# ASCII only. Dot-source this from the other scripts.
#
# Design invariants (do not weaken these without an explicit decision):
#   * no consent.json  -> nothing runs
#   * spool on disk is DPAPI-encrypted (CurrentUser)
#   * content capture is opt-in, not default

$script:EM_ROOT = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

function Get-EMRoot { return $script:EM_ROOT }

function Get-EMDataDir {
    $d = Join-Path $script:EM_ROOT 'data'
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    return $d
}

function Get-EMSpoolDir {
    $d = Join-Path (Get-EMDataDir) 'spool'
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    return $d
}

function Get-EMConsentPath { return (Join-Path (Get-EMDataDir) 'consent.json') }

function Get-EMConsent {
    $p = Get-EMConsentPath
    if (-not (Test-Path $p)) { return $null }
    try { return (Get-Content $p -Raw | ConvertFrom-Json) } catch { return $null }
}

# Write consent.json without a BOM (Bun's JSON.parse rejects a BOM).
function Save-EMConsent {
    param([Parameter(Mandatory)]$Consent)
    $p = Get-EMConsentPath
    [System.IO.File]::WriteAllText($p, ($Consent | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
}

# Set a property on an object whether or not it already exists. consent.json files
# written by an older version are missing Station/Attendee, and plain assignment
# throws "property cannot be found on this object".
function Set-EMField {
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Name, $Value)
    if ($Object.PSObject.Properties.Name.Contains($Name)) { $Object.$Name = $Value }
    else { $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force }
}

# Who/where this machine is. These travel with every event, so the evidence dump
# is self-describing and a station can be re-assigned mid-event.
function Get-EMIdentity {
    param($Consent)
    if (-not $Consent) { $Consent = Get-EMConsent }
    if (-not $Consent) { return [ordered]@{ machineId = ''; station = ''; attendee = '' } }
    $names = $Consent.PSObject.Properties.Name
    $station = ''
    $attendee = ''
    if ($names.Contains('Station')) { $station = [string]$Consent.Station }
    if ($names.Contains('Attendee')) { $attendee = [string]$Consent.Attendee }
    return [ordered]@{
        machineId = [string]$Consent.MachineId
        station   = $station
        attendee  = $attendee
    }
}

# Validate the consent record. Returns $null when usable, else a reason string.
function Test-EMConsent {
    param($Consent)
    if (-not $Consent) { return 'consent.json missing' }
    foreach ($f in @('MachineId', 'AupVersion', 'AckedBy', 'AckedAt', 'CollectorUrl', 'MachineToken', 'Mode')) {
        if (-not $Consent.PSObject.Properties.Name.Contains($f)) { return "consent.json missing field: $f" }
        if ([string]::IsNullOrWhiteSpace([string]$Consent.$f)) { return "consent.json empty field: $f" }
    }
    if (@('activity', 'content') -notcontains $Consent.Mode) { return "consent.json bad Mode: $($Consent.Mode)" }
    return $null
}

function Add-EMLog {
    param([string]$Message, [string]$Level = 'info')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    $log = Join-Path (Get-EMDataDir) 'agent.log'
    try { Add-Content -Path $log -Value $line -Encoding UTF8 } catch {}
    Write-Host $line
}

# --- at-rest encryption (DPAPI, CurrentUser) --------------------------------
function Protect-EMString {
    param([Parameter(Mandatory)][string]$Value)
    Add-Type -AssemblyName System.Security
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')
    return [Convert]::ToBase64String($enc)
}

function Unprotect-EMString {
    param([Parameter(Mandatory)][string]$Value)
    Add-Type -AssemblyName System.Security
    $enc = [Convert]::FromBase64String($Value)
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, 'CurrentUser')
    return [Text.Encoding]::UTF8.GetString($bytes)
}

# --- batch integrity -------------------------------------------------------
# The collector verifies this signature. A sniffer on the event LAN can read
# cleartext HTTP but cannot forge or alter a batch without the machine token.
function Get-EMHmac {
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][byte[]]$Bytes)
    $h = New-Object System.Security.Cryptography.HMACSHA256
    $h.Key = [Text.Encoding]::UTF8.GetBytes($Key)
    try { $mac = $h.ComputeHash($Bytes) } finally { $h.Dispose() }
    return (($mac | ForEach-Object { $_.ToString('x2') }) -join '')
}

# --- enrollment ------------------------------------------------------------
# Asks the collector for this machine's token so nobody has to copy-paste one
# per lab machine. Returns the token, or $null on failure.
function Invoke-EMEnroll {
    param(
        [Parameter(Mandatory)][string]$CollectorUrl,
        [Parameter(Mandatory)][string]$EnrollSecret,
        [Parameter(Mandatory)][string]$MachineId,
        [string]$Label = ''
    )
    $uri = $CollectorUrl.TrimEnd('/') + '/enroll'
    $midJson = [string]$MachineId | ConvertTo-Json -Compress
    $body = '{"machineId":' + $midJson
    if (-not [string]::IsNullOrWhiteSpace($Label)) {
        $body += ',"label":' + ([string]$Label | ConvertTo-Json -Compress)
    }
    $body += '}'

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ 'X-Enroll-Secret' = $EnrollSecret } `
            -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 20
    } catch {
        Add-EMLog -Level 'error' -Message "enrollment failed: $($_.Exception.Message)"
        return $null
    }
    if ($null -eq $resp -or $resp.ok -ne $true -or [string]::IsNullOrWhiteSpace([string]$resp.token)) {
        Add-EMLog -Level 'error' -Message 'enrollment rejected by collector'
        return $null
    }
    Add-EMLog -Message ("enrolled as {0} (token {1}..., reused={2})" -f $MachineId, ([string]$resp.token).Substring(0, 8), $resp.reused)
    return [string]$resp.token
}

# --- Win32 helpers ----------------------------------------------------------
if (-not ('EM.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace EM {
    public static class Native {
        [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
        [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
        [DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
        [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
        [StructLayout(LayoutKind.Sequential)] public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
        public static string Title(IntPtr h) { StringBuilder sb = new StringBuilder(600); GetWindowText(h, sb, 600); return sb.ToString(); }
        public static int IdleSeconds() {
            LASTINPUTINFO li = new LASTINPUTINFO();
            li.cbSize = (uint)Marshal.SizeOf(li);
            GetLastInputInfo(ref li);
            uint diff = (uint)Environment.TickCount - li.dwTime;
            return (int)(diff / 1000);
        }
    }
}
'@
}

# Current foreground window as a plain object.
function Get-EMForeground {
    $h = [EM.Native]::GetForegroundWindow()
    $procId = [uint32]0
    [void][EM.Native]::GetWindowThreadProcessId($h, [ref]$procId)
    $title = ''
    $proc = 'unknown'
    try { $title = [EM.Native]::Title($h) } catch {}
    if ($procId -gt 0) {
        try { $proc = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $proc = 'unknown' }
    }
    if ([string]::IsNullOrWhiteSpace($proc)) { $proc = 'unknown' }
    $idle = 0
    try { $idle = [EM.Native]::IdleSeconds() } catch {}
    return [ordered]@{ hwnd = [int64]$h; pid = [int]$procId; process = $proc; title = $title; idle = $idle }
}

# --- screen capture (downscaled JPEG, base64) ------------------------------
function Get-EMScreenJpeg {
    param([int]$MaxWidth = 1280, [int]$Quality = 45)
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $full = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $gfx = [System.Drawing.Graphics]::FromImage($full)
    try {
        $gfx.CopyFromScreen($bounds.Left, $bounds.Top, 0, 0, $full.Size)
    } catch {
        $full.Dispose(); $gfx.Dispose()
        throw "screen capture failed: $_"
    }

    $scale = 1.0
    if ($bounds.Width -gt $MaxWidth) { $scale = $MaxWidth / $bounds.Width }
    $tw = [int]($bounds.Width * $scale)
    $th = [int]($bounds.Height * $scale)
    $small = New-Object System.Drawing.Bitmap($tw, $th)
    $g2 = [System.Drawing.Graphics]::FromImage($small)
    $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    try { $g2.DrawImage($full, 0, 0, $tw, $th) } catch {}

    $codec = $null
    foreach ($c in [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()) {
        if ($c.MimeType -eq 'image/jpeg') { $codec = $c; break }
    }
    $eps = New-Object System.Drawing.Imaging.EncoderParameters(1)
    $eps.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [int64]$Quality)

    $ms = New-Object System.IO.MemoryStream
    try { $small.Save($ms, $codec, $eps) } catch {}
    $b64 = [Convert]::ToBase64String($ms.ToArray())

    $ms.Dispose(); $eps.Dispose()
    $small.Dispose(); $full.Dispose(); $g2.Dispose(); $gfx.Dispose()
    return $b64
}

# --- keystroke classification ----------------------------------------------
# Virtual-key -> character map (US layout, ASCII only). Approximate by design:
# we are counting activity, exact reconstruction is not a goal.
$script:EM_VK_MAP = @{
    0x20 = ' '; 0x0D = "`n"; 0x09 = "`t"
    0x30='0';0x31='1';0x32='2';0x33='3';0x34='4';0x35='5';0x36='6';0x37='7';0x38='8';0x39='9'
    0x41='a';0x42='b';0x43='c';0x44='d';0x45='e';0x46='f';0x47='g';0x48='h';0x49='i';0x4A='j'
    0x4B='k';0x4C='l';0x4D='m';0x4E='n';0x4F='o';0x50='p';0x51='q';0x52='r';0x53='s';0x54='t'
    0x55='u';0x56='v';0x57='w';0x58='x';0x59='y';0x5A='z'
    0xBA=';';0xBB='=';0xBC=',';0xBD='-';0xBE='.';0xBF='/';0xC0='`';0xDB='[';0xDC='\';0xDD=']';0xDE="'"
}

# Returns the character for a VK press, or '' when unmappable.
function Get-EMKeyChar {
    param([int]$Vk)
    if (-not $script:EM_VK_MAP.ContainsKey($Vk)) { return '' }
    $ch = $script:EM_VK_MAP[$Vk]
    if ($ch -match '^[a-z]$') {
        $shift = ([EM.Native]::GetAsyncKeyState(0x10) -band 0x8000) -ne 0
        $caps  = ([EM.Native]::GetAsyncKeyState(0x14) -band 0x10000) -ne 0
        if ($shift -xor $caps) { return $ch.ToUpper() }
        return $ch
    }
    return $ch
}

# --- exclusion ---------------------------------------------------------------
function Get-EMExcludeRegex {
    param($Consent)
    if ($Consent -and $Consent.PSObject.Properties.Name.Contains('ExcludeTitleRegex')) {
        return @($Consent.ExcludeTitleRegex)
    }
    return @(
        'password', 'keepass', 'bitwarden', 'lastpass', '1password', 'dashlane',
        'bank', 'netbanking', 'upi', 'login', 'sign in', 'authenticat', 'otp'
    )
}

function Test-EMExcludedTitle {
    param([string]$Title, $Consent)
    if ([string]::IsNullOrWhiteSpace($Title)) { return $false }
    foreach ($pat in (Get-EMExcludeRegex -Consent $Consent)) {
        if ($Title -match $pat) { return $true }
    }
    return $false
}

# --- spool ------------------------------------------------------------------
# Events are DPAPI-encrypted, one per line, appended to the ACTIVE spool file.
# Files rotate by size so an 8-hour event leaves a few dozen files, not millions.

$script:EM_CurrentSpool = $null

function Get-EMSpoolRotateBytes {
    param([int]$Megabytes = 4)
    return [int64]($Megabytes * 1MB)
}

function Add-EMSpool {
    param([Parameter(Mandatory)]$Event, $Consent)
    try {
        $json = $Event | ConvertTo-Json -Compress -Depth 6
        $enc = Protect-EMString -Value $json

        $file = $script:EM_CurrentSpool
        if (-not $file -or -not (Test-Path $file) -or (Get-Item $file).Length -ge (Get-EMSpoolRotateBytes)) {
            $name = 'q-{0}-{1}.emq' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 6))
            $file = Join-Path (Get-EMSpoolDir) $name
            $script:EM_CurrentSpool = $file
        }

        $utf8 = New-Object Text.UTF8Encoding($false)   # no BOM, so lines read back clean
        [System.IO.File]::AppendAllText($file, $enc + "`r`n", $utf8)
        return $file
    } catch {
        Add-EMLog -Level 'error' -Message "spool write failed: $_"
        return $null
    }
}

function Get-EMSpoolFiles {
    $d = Get-EMSpoolDir
    return @(Get-ChildItem -Path $d -Filter '*.emq' -ErrorAction SilentlyContinue | Sort-Object Name)
}

function Get-EMSpoolBytes {
    $d = Get-EMSpoolDir
    $files = @(Get-ChildItem -Path $d -Filter '*.emq' -ErrorAction SilentlyContinue)
    $sum = 0
    foreach ($f in $files) { $sum += $f.Length }
    return $sum
}

# Send one spool file. Returns $true when the collector accepted it.
function Send-EMSpoolFile {
    param([Parameter(Mandatory)][System.IO.FileInfo]$File, [Parameter(Mandatory)]$Consent)

    $events = @()
    try {
        foreach ($line in [System.IO.File]::ReadAllLines($File.FullName)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $events += (Unprotect-EMString -Value $line)
        }
    } catch {
        Add-EMLog -Level 'error' -Message ("spool corrupt, dropping {0}: {1}" -f $File.Name, $_.Exception.Message)
        Remove-Item -Path $File.FullName -Force -ErrorAction SilentlyContinue
        return $false
    }
    if ($events.Count -eq 0) {
        Remove-Item -Path $File.FullName -Force -ErrorAction SilentlyContinue
        return $true
    }

    # NOTE: built by concatenation, not -f. The -f operator treats the literal JSON
    # braces as format items and throws "Input string was not in a correct format".
    $midJson = [string]$Consent.MachineId | ConvertTo-Json -Compress
    $body = '{"machineId":' + $midJson +
            ',"sentAt":"' + (Get-Date -Format o) + '"' +
            ',"agent":"ps1-1.0","events":[' + ($events -join ',') + ']}'
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)

    $uri = ([string]$Consent.CollectorUrl).TrimEnd('/') + '/ingest'
    $headers = @{
        'X-Machine-Id' = [string]$Consent.MachineId
        'X-Token'      = [string]$Consent.MachineToken
        'X-Signature'  = (Get-EMHmac -Key ([string]$Consent.MachineToken) -Bytes $bytes)
    }

    # only the network call is inside the try, so failures are reported honestly
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers `
            -ContentType 'application/json' -Body $bytes -TimeoutSec 30
    } catch {
        Add-EMLog -Level 'warn' -Message ("send failed ({0}): {1}" -f $File.Name, $_.Exception.Message)
        return $false
    }

    if ($null -eq $resp -or $resp.ok -ne $true) {
        Add-EMLog -Level 'warn' -Message ("collector rejected {0}" -f $File.Name)
        return $false
    }

    Remove-Item -Path $File.FullName -Force -ErrorAction SilentlyContinue
    if ($script:EM_CurrentSpool -eq $File.FullName) { $script:EM_CurrentSpool = $null }
    return $true
}

# Drain the spool oldest-first, stopping on first failure.
function Send-EMSpool {
    param([Parameter(Mandatory)]$Consent, [int]$MaxFiles = 4)
    $sent = 0
    foreach ($f in (Get-EMSpoolFiles)) {
        if ($sent -ge $MaxFiles) { break }
        if (Send-EMSpoolFile -File $f -Consent $Consent) { $sent++ } else { break }
    }
    return $sent
}

function Remove-EMOldSpool {
    param([int]$RetentionDays = 7)
    $cut = (Get-Date).AddDays(-$RetentionDays)
    foreach ($f in (Get-EMSpoolFiles)) {
        if ($f.CreationTime -lt $cut) {
            Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
            Add-EMLog -Level 'warn' -Message "dropped unshipped spool past retention: $($f.Name)"
        }
    }
}
