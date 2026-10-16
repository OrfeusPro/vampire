$ErrorActionPreference = 'Stop'
$tunnelDir = Join-Path (Split-Path -Parent $PSScriptRoot) '.tools/hev-socks5-tunnel-2.19.0'
$null = New-Item -ItemType Directory -Force $tunnelDir
$tunnelFile = Join-Path $tunnelDir 'hev-socks5-tunnel.aar'
$tunnelHash = 'fbbf014c1c4c6d1e0922db88542abd9dc726600473bdfdc8039ed157b4ba02b0'
if (!(Test-Path -LiteralPath $tunnelFile)) {
    Invoke-WebRequest 'https://github.com/heiher/hev-socks5-tunnel/releases/download/2.19.0/hev-socks5-tunnel.aar' -OutFile ($tunnelFile + '.download')
    if ((Get-FileHash -LiteralPath ($tunnelFile + '.download') -Algorithm SHA256).Hash -ne $tunnelHash) { throw 'Tunnel download SHA256 mismatch' }
    Move-Item -LiteralPath ($tunnelFile + '.download') -Destination $tunnelFile
}
if ((Get-FileHash -LiteralPath $tunnelFile -Algorithm SHA256).Hash -ne $tunnelHash) { throw 'Tunnel SHA256 mismatch' }
