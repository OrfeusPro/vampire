$ErrorActionPreference = 'Stop'
$php = 'G:/OSPanel/modules/PHP-8.3/PHP/php.exe'
$publicDirectory = Join-Path $PSScriptRoot 'dist'
$stateDirectory = Join-Path $PSScriptRoot 'var'
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null
try {
    $response = Invoke-WebRequest 'http://127.0.0.1:8787/' -UseBasicParsing -TimeoutSec 2
    if ($response.Content -match 'VAMPIR.TOP') { Write-Output 'http://127.0.0.1:8787/'; exit 0 }
    throw 'Port 8787 is used by another application.'
} catch {
    if ($_.Exception.Message -eq 'Port 8787 is used by another application.') { throw }
}
if (-not (Test-Path -LiteralPath $php)) { throw "OSPanel PHP not found: $php" }
$serverProcess = Start-Process -FilePath $php -ArgumentList @('-S','127.0.0.1:8787','-t',('"' + $publicDirectory + '"'), ('"' + (Join-Path $PSScriptRoot 'router.php') + '"')) -WindowStyle Hidden -RedirectStandardOutput (Join-Path $stateDirectory 'server.out.log') -RedirectStandardError (Join-Path $stateDirectory 'server.err.log') -PassThru
$serverProcess.Id | Set-Content (Join-Path $stateDirectory 'server.pid')
Write-Output 'http://127.0.0.1:8787/'
