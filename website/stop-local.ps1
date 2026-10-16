$ErrorActionPreference = 'Stop'
$stateFile = Join-Path $PSScriptRoot 'var/server.pid'
if (-not (Test-Path -LiteralPath $stateFile)) { Write-Output 'No managed local server.'; exit 0 }
$serverProcessId = [int](Get-Content -LiteralPath $stateFile)
$serverProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$serverProcessId"
if ($serverProcess -and $serverProcess.Name -eq 'php.exe' -and $serverProcess.CommandLine.Contains('127.0.0.1:8787') -and $serverProcess.CommandLine.Contains((Join-Path $PSScriptRoot 'dist'))) { Stop-Process -Id $serverProcessId }
Remove-Item -LiteralPath $stateFile
