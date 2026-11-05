param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$consoleUrl = 'http://127.0.0.1:17949/'
$workspaceKey = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($PSScriptRoot)).Replace('/', '_')
$mutex = [Threading.Mutex]::new($false, 'Local\PhoneExit.AccountConsole.' + $workspaceKey)
$ownsMutex = $false
$browserJob = $null
function Test-Console {
    try {
        $page = Invoke-WebRequest -UseBasicParsing -Uri $consoleUrl -TimeoutSec 2
        return $page.StatusCode -eq 200 -and $page.Content.Contains('id="connection-settings"') -and $page.Content.Contains('id="roster"')
    } catch { return $false }
}
try {
    try { $ownsMutex = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
    if (-not $ownsMutex -or (Test-Console)) {
        if (-not (Test-Console)) { throw 'Панель ещё запускается. Повторите открытие через несколько секунд.' }
        if (-not $NoBrowser) { Start-Process $consoleUrl }
        return
    }
    $listener = Get-NetTCPConnection -LocalPort 17949 -State Listen -ErrorAction SilentlyContinue
    if ($listener) { throw 'Порт 17949 занят другим приложением.' }
    $python = (Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    if (-not $NoBrowser) {
        $browserJob = Start-Job -ArgumentList $consoleUrl -ScriptBlock {
            param($address)
            for ($attempt = 0; $attempt -lt 40; $attempt++) {
                try {
                    $page = Invoke-WebRequest -UseBasicParsing -Uri $address -TimeoutSec 1
                    if ($page.StatusCode -eq 200 -and $page.Content.Contains('id="connection-settings"')) {
                        Start-Process $address
                        return
                    }
                } catch {}
                Start-Sleep -Milliseconds 250
            }
        }
    }
    Write-Host ('Панель аккаунтов: ' + $consoleUrl)
    Write-Host 'Для остановки панели и её задач нажмите Ctrl+C в этом окне.'
    & $python -X utf8 (Join-Path $PSScriptRoot 'account-manager.py')
} finally {
    if ($browserJob) { Stop-Job $browserJob -ErrorAction SilentlyContinue; Remove-Job $browserJob -Force -ErrorAction SilentlyContinue }
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
