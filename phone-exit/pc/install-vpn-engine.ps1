$ErrorActionPreference='Stop'
$taskVersion='1.14.3'
$taskFolder=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.tools/sing-box'))
$null=[IO.Directory]::CreateDirectory($taskFolder)
$taskArchive=Join-Path $taskFolder 'engine.zip'
Invoke-WebRequest -UseBasicParsing ('https://github.com/SagerNet/sing-box/releases/download/v'+$taskVersion+'/sing-box-'+$taskVersion+'-windows-amd64.zip') -OutFile $taskArchive
if((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash -ne 'D8B86EF58936DBA9230EC6A57FFA4243933F3C14EF4809828B6C553440ED1518'){throw 'VPN package checksum mismatch'}
Expand-Archive -LiteralPath $taskArchive -DestinationPath $taskFolder -Force
$taskPackage=Join-Path $taskFolder ('sing-box-'+$taskVersion+'-windows-amd64')
Copy-Item -LiteralPath (Join-Path $taskPackage 'sing-box.exe') -Destination (Join-Path $taskFolder 'sing-box.exe') -Force
Copy-Item -LiteralPath (Join-Path $taskPackage 'LICENSE') -Destination (Join-Path $taskFolder 'LICENSE') -Force
Write-Output 'Pinned VPN engine installed and checksum verified.'
