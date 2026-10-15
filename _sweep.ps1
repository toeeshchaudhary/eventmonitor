function Sweep {
    param([string]$Prefix, [int]$TimeoutMs = 1000)
    $tasks = New-Object System.Collections.ArrayList
    foreach ($i in 1..254) {
        $ip = "$Prefix.$i"
        $ping = New-Object System.Net.NetworkInformation.Ping
        [void]$tasks.Add([pscustomobject]@{ IP = $ip; Task = $ping.SendPingAsync($ip, $TimeoutMs) })
    }
    [void][System.Threading.Tasks.Task]::WaitAll(($tasks | ForEach-Object { $_.Task }), 8000)
    $live = @()
    foreach ($t in $tasks) {
        if ($t.Task.IsCompleted -and $t.Task.Result.Status -eq 'Success') { $live += $t.IP }
    }
    return $live
}
foreach ($subnet in @('192.168.1', '10.12.47')) {
    Write-Host ("=== sweeping {0}.0/24 ===" -f $subnet)
    $live = Sweep -Prefix $subnet
    if (@($live).Count -eq 0) { Write-Host '  no hosts answered' }
    else {
        foreach ($ip in $live) {
            $name = ''
            try { $name = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $name = '(no reverse dns)' }
            Write-Host ("  UP  {0,-16} {1}" -f $ip, $name)
        }
    }
    Write-Host ("  total live: {0}" -f @($live).Count)
    Write-Host ''
}
