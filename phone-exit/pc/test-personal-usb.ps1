param([string]$Serial='81865352')
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$taskFile=Join-Path $env:LOCALAPPDATA 'PhoneExit/account.bin'
$taskBytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($taskFile),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
$taskRaw=[Text.Encoding]::UTF8.GetString($taskBytes)
$taskInfo=New-Object Diagnostics.ProcessStartInfo
$taskInfo.FileName=(Get-Command node.exe).Source
$taskInfo.Arguments='"'+(Join-Path $PSScriptRoot 'test-personal-usb.js')+'" '+$Serial
$taskInfo.UseShellExecute=$false; $taskInfo.CreateNoWindow=$true; $taskInfo.RedirectStandardInput=$true
$taskProcess=New-Object Diagnostics.Process; $taskProcess.StartInfo=$taskInfo
$null=$taskProcess.Start()
$taskProcess.StandardInput.Write($taskRaw); $taskProcess.StandardInput.Close()
$taskProcess.WaitForExit()
$taskExit=$taskProcess.ExitCode; $taskProcess.Dispose()
if($taskExit -ne 0) { throw 'Personal USB test failed' }
