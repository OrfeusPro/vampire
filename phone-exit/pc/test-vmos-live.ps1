param([switch]$Screens,[switch]$Fixture,[switch]$ReadNew,[switch]$Benchmark,[switch]$Pipeline,[ValidateSet(1,2)][int]$Rate=1,[ValidateRange(5,180)][int]$Count=10,[string]$Phone='')
$ErrorActionPreference='Stop'
$OutputEncoding=New-Object Text.UTF8Encoding($false)
$env:PYTHONUTF8='1'
Add-Type -AssemblyName System.Security
. (Join-Path $PSScriptRoot 'profile.ps1')
$taskPath=Join-Path (GetPhoneExitProfileDirectory) 'control-api.bin'
$taskSecret=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($taskPath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
$taskArgs=@((Join-Path $PSScriptRoot 'test-vmos-live.py'));if($Screens){$taskArgs+='--screens'};if($Fixture){$taskArgs+='--fixture'}
if($Pipeline){$taskArgs+='--pipeline';$taskArgs+="--rate=$Rate";$taskArgs+="--count=$Count"}
if($Benchmark){$taskArgs+="--benchmark"}
if($ReadNew){$taskArgs+='--read-new'}
@{secret=$taskSecret;reference='C:/Users/Валентин/Documents/ИИ/src/l9bot/vmos_api.py';onlyName=$Phone}|ConvertTo-Json -Compress|& python @taskArgs
if($LASTEXITCODE -ne 0){throw 'Real VMOS control test failed'}
