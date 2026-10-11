param([Parameter(Mandatory=$true)][string]$Session, [Parameter(Mandatory=$true)][int]$OwnerProcessId)
$ErrorActionPreference='Stop'
# This process alone is elevated. It holds TUN after phone loss until explicit Stop.
if($Session -notmatch '^[a-f0-9]{32}$'){throw 'Invalid VPN session'}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.tools/vpn'))
$folder=Join-Path $root $Session
$engine=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.tools/sing-box/sing-box.exe'))
$statusFile=Join-Path $folder 'status.json'
function State($state){[IO.File]::WriteAllText($statusFile,(@{state=$state}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))}
$child=$null;$phase='integrity';$failureType=$null
$tree=$null;$appCount=0;$extraRoutes=@();$lastTransport=''
try {
    if((Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash -ne '5C19BB3F8C12D4E85B3D47FE63123A7624B314B58DD7A8E32F51004F1C4D2FAF'){throw 'Engine integrity check failed'}
    $phase='check'
    $appRulesFile=Join-Path $folder 'applications-rules.json'
    if(Test-Path -LiteralPath $appRulesFile){
        Add-Type -Path (Join-Path $PSScriptRoot 'process-tree.cs')
        . (Join-Path $PSScriptRoot 'app-routing.ps1')
        $apps=@([IO.File]::ReadAllText((Join-Path $folder 'applications.json'))|ConvertFrom-Json|ForEach-Object{$_})
        if(!$apps.Count -or $apps.Count -gt 64){throw 'Invalid selected application list'}
        $tree=[PhoneExit.ProcessTree]::new([string[]]$apps)
        $appCount=WriteApplicationRules $tree $appRulesFile
    }
    $physicalRoute=Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object InterfaceAlias -ne 'PhoneExit' | Sort-Object RouteMetric | Select-Object -First 1
    & $engine check -c (Join-Path $folder 'config.json') 2>$null
    if($LASTEXITCODE -ne 0){throw 'Invalid VPN configuration'}
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$engine;$info.Arguments='run -c "'+(Join-Path $folder 'config.json')+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardError=$true;$info.RedirectStandardOutput=$true
    $phase='start'
    $child=New-Object Diagnostics.Process;$child.StartInfo=$info;$null=$child.Start()
    $err=$child.StandardError.ReadToEndAsync();$out=$child.StandardOutput.ReadToEndAsync()
    $phase='tun'
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    while([DateTime]::UtcNow -lt $deadline -and !$child.HasExited){
        if(Get-NetAdapter -Name PhoneExit -ErrorAction SilentlyContinue){break};Start-Sleep -Milliseconds 250
    }
    if($child.HasExited -or !(Get-NetAdapter -Name PhoneExit -ErrorAction SilentlyContinue)){throw 'TUN did not start'}
    $phase='owner'
    $owner=Get-Process -Id $OwnerProcessId -ErrorAction Stop
    $ownerStarted=$owner.StartTime
    State 'active'
    while(!$child.HasExited -and !(Test-Path -LiteralPath (Join-Path $folder 'stop'))){
        $currentOwner=Get-Process -Id $OwnerProcessId -ErrorAction SilentlyContinue
        if(!$currentOwner -or $currentOwner.StartTime -ne $ownerStarted){[IO.File]::WriteAllText((Join-Path $folder 'stop'),'owner closed');break}
        if($tree){
            $scanError=$false
            try{$appCount=WriteApplicationRules $tree $appRulesFile}catch{$scanError=$true}
            try{[IO.File]::WriteAllText((Join-Path $folder 'applications-status.json'),(@{count=$appCount;limit=$tree.AtLimit;error=$scanError}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))}catch{}
        }
        $transportFile=Join-Path $folder 'transport.json'
        if(Test-Path -LiteralPath $transportFile){
            $transport=[IO.File]::ReadAllText($transportFile)
            if($transport.Length -gt 8192){continue}
            if($transport -ne $lastTransport){
                $addresses=@($transport|ConvertFrom-Json|ForEach-Object{$_})
                if($addresses.Count -gt 64){continue}
                foreach($address in $addresses){
                    $ip=$null
                    if(![Net.IPAddress]::TryParse([string]$address,[ref]$ip)){continue}
                    if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){continue}
                    $prefix=$ip.ToString()+'/32'
                    if(!(Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Where-Object InterfaceIndex -eq $physicalRoute.InterfaceIndex)){
                        try{$extraRoutes+=New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $physicalRoute.InterfaceIndex -NextHop $physicalRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore}catch{}
                    }
                }
                $lastTransport=$transport
            }
        }
        Start-Sleep -Milliseconds 300
    }
    if($child.HasExited){State 'failed'}
} catch {$failureType=$_.Exception.GetType().Name;[IO.File]::WriteAllText((Join-Path $folder 'failure.json'),(@{phase=$phase;type=$failureType;line=$_.InvocationInfo.ScriptLineNumber}|ConvertTo-Json -Compress));State 'failed'} finally {
    if($child -and !$child.HasExited){$child.Kill();$null=$child.WaitForExit(5000)}
    if($err -and $err.IsCompleted){
        $raw=$err.GetAwaiter().GetResult()
        $safe=@{phase=$phase;failureType=$failureType;fakeip=$raw.Contains('fakeip');fatal=$raw.Contains('FATAL');loopbackDial=$raw.Contains('127.0.0.1:1080');timeout=$raw.Contains('timeout');refused=$raw.Contains('refused');bind=$raw.Contains('bind:');socksError=$raw.Contains('SOCKS');reset=$raw.Contains('reset');dns=$raw.Contains('DNS')}
        $safe.startup=@($raw -split "`n" | Where-Object {$_ -match 'FATAL'} | ForEach-Object {($_ -replace '\x1b\[[0-9;]*m','' -replace '[a-fA-F0-9]{32,}','[id]' -replace '(?:[0-9]{1,3}\.){3}[0-9]{1,3}','[address]' -replace '(?:https?://)?[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+','[host]')} | Select-Object -First 1)
        $safe.reasons=@($raw -split "`n" | ForEach-Object {
            if($_ -match '(?:dial tcp 127\.0\.0\.1:1080:|connectex:|wsarecv:|wsasend:)\s*(.+)$'){
                $text=$Matches[1] -replace '[0-9a-fA-F:.]*[0-9][0-9a-fA-F:.]*','[address]' -replace '[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+','[host]'
                $text.Trim()
            }
        } | Select-Object -Unique -First 3)
        [IO.File]::WriteAllText((Join-Path $folder 'diagnostics.json'),($safe|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    }
    if($child){$child.Dispose()}
    foreach($route in $extraRoutes){$route|Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue}
    if(Test-Path -LiteralPath (Join-Path $folder 'stop')){State 'stopped'}
}
