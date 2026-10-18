param(
    [string]$ResourceRoot = 'F:\PhoneExit Resources\Vampir',
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$url = 'http://127.0.0.1:17946/maps/atlas/index.html'
try {
    if (-not (Test-Path -LiteralPath (Join-Path $ResourceRoot 'maps\atlas\index.html') -PathType Leaf)) {
        throw "Map files not found in: $ResourceRoot"
    }
    $listener = Get-NetTCPConnection -LocalPort 17946 -State Listen -ErrorAction SilentlyContinue
    if ($listener) {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -ne 200) { throw 'Port 17946 is occupied, but the map is unavailable.' }
        Write-Host "Server is already running: $url"
        if (-not $NoBrowser) { Start-Process $url }
        exit 0
    }
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $python) { throw 'Python 3 is required. Install Python and add it to PATH.' }
    Write-Host "Vampir map: $url"
    Write-Host 'Keep this window open. Press Ctrl+C or close it to stop the server.'
    if (-not $NoBrowser) { Start-Process $url }
    & $python.Source -m http.server 17946 --bind 127.0.0.1 --directory $ResourceRoot
    exit $LASTEXITCODE
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
