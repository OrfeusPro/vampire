$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'process-tree.cs')
. (Join-Path $PSScriptRoot 'desktop-applications.ps1')
$paths=@(MergeApplicationPaths @('C:\Games\one.exe') @('c:\games\ONE.exe','D:\Launcher\two.exe'))
if($paths.Count -ne 2){throw 'Application list did not retain/deduplicate multiple EXEs'}
$json=ConvertTo-Json -InputObject @($paths) -Compress
$restored=@($json|ConvertFrom-Json|ForEach-Object{$_})
if(([PhoneExit.ProcessTree]::new([string[]]$restored).Poll()).Count -lt 2){throw 'Windows PowerShell JSON list collapsed'}
$tree=[PhoneExit.ProcessTree]::new([string[]]@('C:\Games\one.exe'))
$rows=[PhoneExit.ProcessRecord[]]@(
    [PhoneExit.ProcessRecord]::new(30,20,300,'C:\Games\game.exe'),
    [PhoneExit.ProcessRecord]::new(20,10,200,'C:\Games\launcher-child.exe'),
    [PhoneExit.ProcessRecord]::new(10,1,100,'c:\games\ONE.exe'),
    [PhoneExit.ProcessRecord]::new(40,1,400,'C:\Other\direct.exe'))
$found=@($tree.Observe($rows))
if($found.Count -ne 3 -or $found -contains 'C:\Other\direct.exe'){throw 'Nested ancestry isolation failed'}
$found=@($tree.Observe([PhoneExit.ProcessRecord[]]@([PhoneExit.ProcessRecord]::new(30,20,300,'C:\Games\game.exe'),[PhoneExit.ProcessRecord]::new(50,30,500,'C:\Games\late.exe'))))
if($found -notcontains 'C:\Games\late.exe'){throw 'Descendants lost when launcher exited'}
$found=@($tree.Observe([PhoneExit.ProcessRecord[]]@([PhoneExit.ProcessRecord]::new(30,1,600,'C:\Other\reused.exe'),[PhoneExit.ProcessRecord]::new(60,30,700,'C:\Other\unselected.exe'))))
if($found -contains 'C:\Other\unselected.exe'){throw 'Reused PID inherited selection'}
# Exercise a real parent/child process snapshot, without network changes.
$live=[PhoneExit.ProcessTree]::new([string[]]@((Get-Command powershell.exe).Source))
$child=Start-Process cmd.exe -ArgumentList '/c ping -n 8 127.0.0.1 >nul' -WindowStyle Hidden -PassThru
try{$found=@($live.Poll());if($found -notcontains (Get-Command cmd.exe).Source){throw 'Real child executable not detected'}}finally{if(!$child.HasExited){Stop-Process -Id $child.Id -Force}}
$status=[PSCustomObject]@{Text=''};$hint=[PSCustomObject]@{Text=''}
$start=[PSCustomObject]@{Enabled=$true};$stopButton=[PSCustomObject]@{Enabled=$false};$mode=[PSCustomObject]@{Enabled=$true};$chooseApps=[PSCustomObject]@{Enabled=$true};$phoneList=[PSCustomObject]@{SelectedIndex=-1}
. (Join-Path $PSScriptRoot 'desktop-reconnect.ps1')
$script:client=$null;$script:vpnState='active';$script:connectionWanted=$true;$script:reconnectPhone='target';$script:phoneRows=@([PSCustomObject]@{id='other';online=$true;busy=$false},[PSCustomObject]@{id='target';online=$false;busy=$false})
$script:started=0
function StartClient([switch]$Reconnect){if(!$Reconnect){throw 'Recovery lost intent'};$script:started++}
QueueReconnect
if($start.Enabled -or !$stopButton.Enabled){throw 'Recovery buttons invalid'}
$script:reconnectAt=[DateTime]::MinValue;ReadReconnect
if($script:started){throw 'Connected another or unavailable phone'}
$script:phoneRows[1].online=$true;$script:phoneRows[1].busy=$true;ReadReconnect
if($script:started){throw 'Connected busy phone'}
$script:phoneRows[1].busy=$false;ReadReconnect
if($script:started -ne 1 -or $phoneList.SelectedIndex -ne 1){throw 'Available target did not reconnect'}
CancelReconnect;ReadReconnect
if($script:started -ne 1){throw 'Explicit stop did not cancel recovery'}
Write-Output 'PASS: multiple applications, nested/late descendants, PID reuse, real Windows child, same-phone recovery, offline/busy waiting, explicit cancellation'
