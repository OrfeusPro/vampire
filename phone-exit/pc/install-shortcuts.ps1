$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$launcher=Join-Path $projectRoot 'Phone Exit.exe'
$icon=Join-Path $PSScriptRoot 'assets/phone-exit.ico'
if(!(Test-Path -LiteralPath $launcher) -or !(Test-Path -LiteralPath $icon)){throw 'Phone Exit launcher or icon is missing'}
$shell=New-Object -ComObject WScript.Shell
$desktop=[Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
$programs=[Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
foreach($folder in @($projectRoot,$desktop,$programs)){
    $shortcutPath=Join-Path $folder 'Phone Exit.lnk'
    $shortcut=$shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath=$launcher
    $shortcut.Arguments=''
    $shortcut.WorkingDirectory=$projectRoot
    $shortcut.IconLocation=$icon+',0'
    $shortcut.Description='Phone Exit'
    $shortcut.Save()
    $verified=$shell.CreateShortcut($shortcutPath)
    if($verified.Arguments -ne $shortcut.Arguments -or $verified.IconLocation -ne $shortcut.IconLocation){throw 'Shortcut verification failed'}
    Write-Output $shortcutPath
}
