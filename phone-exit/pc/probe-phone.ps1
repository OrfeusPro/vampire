param([string]$Name='V2061')
Add-Type -AssemblyName System.Security
$taskFile=Join-Path $env:LOCALAPPDATA 'PhoneExit/account.bin'
$taskRaw=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($taskFile),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
Push-Location $PSScriptRoot
try {$taskRaw | node.exe probe-phone.js $Name;if($LASTEXITCODE -ne 0){throw 'Phone probe failed'}}finally{Pop-Location}
