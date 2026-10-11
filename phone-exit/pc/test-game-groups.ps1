$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'process-tree.cs')
. (Join-Path $PSScriptRoot 'desktop-applications.ps1')
$rows=[PhoneExit.ProcessRecord[]]@(
    [PhoneExit.ProcessRecord]::new(1,0,1,'C:\Windows\explorer.exe'),
    [PhoneExit.ProcessRecord]::new(10,1,10,'C:\Netmarble\Launcher\Netmarble Launcher.exe'),
    [PhoneExit.ProcessRecord]::new(11,10,11,'C:\Netmarble\Launcher\Netmarble Launcher.exe'),
    [PhoneExit.ProcessRecord]::new(12,10,12,'C:\Netmarble\Launcher\resources\helper.exe'),
    [PhoneExit.ProcessRecord]::new(20,10,20,'C:\Games\VAMPIR\VAMPIR.exe'),
    [PhoneExit.ProcessRecord]::new(21,20,21,'C:\Games\VAMPIR\ProjectRED\game.exe'),
    [PhoneExit.ProcessRecord]::new(22,21,22,'C:\Games\VAMPIR\Engine\web.exe'),
    [PhoneExit.ProcessRecord]::new(23,21,23,'C:\Epic\overlay.exe'),
    [PhoneExit.ProcessRecord]::new(30,10,30,'C:\Games\Other\other.exe'),
    [PhoneExit.ProcessRecord]::new(31,30,31,'C:\Games\Other\child.exe'),
    [PhoneExit.ProcessRecord]::new(40,1,40,'C:\Apps\Discord.exe'))
$related=@([PhoneExit.ProcessTree]::RelatedPaths($rows,20))
if($related.Count -ne 6 -or $related -notcontains 'C:\Epic\overlay.exe' -or $related -contains 'C:\Games\Other\other.exe' -or $related -contains 'C:\Apps\Discord.exe' -or $related -contains 'C:\Windows\explorer.exe'){throw 'Game relation scope failed'}
$engine=@([PhoneExit.ProcessTree]::RelatedPaths($rows,21))
if($engine.Count -ne 6){throw 'Game ancestor and launcher inference failed'}
$routing=[PhoneExit.ProcessTree]::new([string[]]$related)
$routed=@($routing.Observe($rows))
if($routed -contains 'C:\Games\Other\other.exe' -or $routed -contains 'C:\Games\Other\child.exe'){throw 'Shared launcher routed another game'}
$late=[PhoneExit.ProcessRecord[]]@($rows+[PhoneExit.ProcessRecord]::new(50,21,50,'C:\Epic\late-overlay.exe'))
if(@($routing.Observe($late)) -notcontains 'C:\Epic\late-overlay.exe'){throw 'Selected game lost its late overlay'}
$reused=[PhoneExit.ProcessRecord[]]@([PhoneExit.ProcessRecord]::new(10,1,100,'C:\Apps\Launcher.exe'),[PhoneExit.ProcessRecord]::new(20,10,20,'C:\Games\game.exe'))
if(@([PhoneExit.ProcessTree]::RelatedPaths($reused,20)).Count -ne 1){throw 'Reused parent PID was accepted'}
$first=AddApplicationGroup @('C:\Apps\Discord.exe') @() ([PSCustomObject]@{name='Vampire';paths=$related})
$updated=AddApplicationGroup $first.paths $first.groups ([PSCustomObject]@{name='vampire';paths=@('c:\games\vampir\VAMPIR.exe','C:\Games\VAMPIR\late.exe')})
if($updated.groups.Count -ne 1 -or @($updated.groups[0].paths).Count -ne 7){throw 'Group merge/dedup failed'}
$directory=Join-Path ([IO.Path]::GetTempPath()) ('PhoneExit-groups-test-'+[Guid]::NewGuid().ToString('N'))
$script:profileDirectory=$directory
try {
    $group=[PSCustomObject]@{name='Vampire';paths=$related;enabled=$false}
    SaveApplicationSelection $first.paths @($group)
    if($script:appPaths.Count -ne 1 -or $script:appPaths[0] -ne 'C:\Apps\Discord.exe'){throw 'Disabled group is still routed'}
    $restored=@(ReadApplicationGroups $script:appPaths)
    if($restored.Count -ne 1 -or $restored[0].enabled -ne $false -or @($restored[0].paths).Count -ne 6){throw 'Disabled group did not survive restart'}
    $restored[0].enabled=$true
    SaveApplicationSelection $first.paths $restored
    if($script:appPaths.Count -ne 7){throw 'Re-enabled group did not restore routes'}
    $pruned=@(NormalizeApplicationGroups $restored @('C:\Apps\Discord.exe'))
    if($pruned.Count){throw 'Deleted group survived'}
    $legacy=@(MergeApplicationPaths @() @('C:\Apps\Discord.exe'))
    if($legacy.Count -ne 1){throw 'Legacy flat list was not retained'}
    Write-Host 'PASS: game/launcher/helpers/overlay, sibling isolation, reused parent PID, group dedup, disabled persistence, route selection'
}finally {
    $resolved=[IO.Path]::GetFullPath($directory)
    if([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ne [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($resolved) -notlike 'PhoneExit-groups-test-*'){throw 'Unsafe cleanup path'}
    if([IO.Directory]::Exists($resolved)){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
