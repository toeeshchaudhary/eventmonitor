# notice.ps1 - on-screen notice that monitoring is active.
# Always-on-top, borderless, top-right. This is NOT optional decoration:
# monitoring without notice is the thing we are explicitly not building.
#
#   powershell -ExecutionPolicy Bypass -STA -File notice.ps1

[CmdletBinding()]
param(
    [string]$MachineId = $env:COMPUTERNAME,
    [string]$Text = 'SESSION MONITORED',
    [int]$RefreshMs = 250
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $ScriptDir 'lib.ps1')

$consent = Get-EMConsent
if ($consent) { $MachineId = [string]$consent.MachineId }

# only one watermark
$mutex = New-Object System.Threading.Mutex($false, 'Local\EventMonitorNotice')
$gotLock = $false
try { $gotLock = $mutex.WaitOne(0) } catch { $gotLock = $false }
if (-not $gotLock) { exit 0 }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$form.TopMost = $true
$form.ShowInTaskbar = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$form.Opacity = 0.85
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual

$label = New-Object System.Windows.Forms.Label
$label.Text = '[ REC ] ' + $Text + ' - ' + $MachineId
$label.ForeColor = [System.Drawing.Color]::White
$label.BackColor = [System.Drawing.Color]::Transparent
$label.Font = New-Object System.Drawing.Font('Consolas', 8.5)
$label.AutoSize = $true
$label.Padding = New-Object System.Windows.Forms.Padding(6, 3, 6, 3)
[void]$form.Controls.Add($label)

$form.ClientSize = New-Object System.Drawing.Size($label.PreferredWidth, $label.PreferredHeight)
$work = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$form.Location = New-Object System.Drawing.Point(($work.Right - $form.Width - 8), ($work.Top + 8))

$form.Show()
Add-EMLog -Message ("notice watermark active on {0}" -f $MachineId)

try {
    while ($true) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds $RefreshMs
    }
}
finally {
    try { $form.Close(); $form.Dispose() } catch {}
    try { $mutex.ReleaseMutex() } catch {}
}
