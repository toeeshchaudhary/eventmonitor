Write-Host '=== ADAPTERS (link state) ==='
Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress | Format-Table -AutoSize

Write-Host '=== IP CONFIG ==='
Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | ForEach-Object {
  Write-Host ("  iface   : {0} - {1}" -f $_.InterfaceAlias, $_.InterfaceDescription)
  Write-Host ("  ipv4    : {0}/{1}" -f $_.IPv4Address.IPAddress, $_.IPv4Address.PrefixLength)
  $gw = if ($_.IPv4DefaultGateway) { $_.IPv4DefaultGateway.NextHop } else { '(none)' }
  Write-Host ("  gateway : {0}" -f $gw)
  $dns = ($_.DNSServer | Where-Object AddressFamily -eq 2 | Select-Object -ExpandProperty ServerAddresses) -join ', '
  Write-Host ("  dns     : {0}" -f $dns)
}

Write-Host ''
Write-Host '=== NETWORK CATEGORY (decides which firewall profile applies) ==='
Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,NetworkCategory,IPv4Connectivity | Format-Table -AutoSize

Write-Host '=== REACHABILITY ==='
$gw = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4DefaultGateway.NextHop
if ($gw) {
  $p = Test-Connection -ComputerName $gw -Count 2 -Quiet -ErrorAction SilentlyContinue
  Write-Host ("  ping gateway {0,-16}: {1}" -f $gw, $(if ($p) { 'OK' } else { 'FAIL' }))
}
$net = Test-Connection -ComputerName 1.1.1.1 -Count 2 -Quiet -ErrorAction SilentlyContinue
Write-Host ("  ping internet (1.1.1.1) : {0}" -f $(if ($net) { 'OK' } else { 'FAIL (may be blocked by school)' }))
try { $r = Resolve-DnsName -Name 'github.com' -Type A -ErrorAction Stop; Write-Host ("  dns resolve github.com   : OK ({0})" -f $r[0].IPAddress) }
catch { Write-Host '  dns resolve github.com   : FAIL' }

Write-Host ''
Write-Host '=== FIREWALL RULES FOR 8787 ==='
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*EventMonitor*' -or $_.DisplayName -like '*8787*' })
if ($rules.Count -eq 0) { Write-Host '  NONE - other machines will NOT be able to reach the collector' }
else {
  foreach ($r in $rules) {
    $pf = ($r | Get-NetFirewallPortFilter).LocalPort
    $af = ($r | Get-NetFirewallAddressFilter)
    Write-Host ("  {0}`n     enabled={1} dir={2} action={3} profile={4} port={5}`n     remote={6}" -f `
      $r.DisplayName, $r.Enabled, $r.Direction, $r.Action, $r.Profile, $pf, $af.RemoteAddress)
  }
}

Write-Host ''
Write-Host '=== IS ANYTHING LISTENING ON 8787? ==='
$listen = @(Get-NetTCPConnection -LocalPort 8787 -State Listen -ErrorAction SilentlyContinue)
if ($listen.Count -eq 0) { Write-Host '  nothing listening - the collector is not running' }
else {
  foreach ($c in $listen) {
    $proc = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Write-Host ("  {0}:{1}  pid={2} ({3})" -f $c.LocalAddress, $c.LocalPort, $c.OwningProcess, $proc)
  }
}
