$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
& (Join-Path $PSScriptRoot 'fetch-tunnel.ps1')
$taskRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $taskRoot 'pc/profile.ps1')
$taskAccountFile = Join-Path (GetPhoneExitProfileDirectory) 'account.bin'
if (Test-Path -LiteralPath $taskAccountFile) {
    $taskEncrypted = [IO.File]::ReadAllBytes($taskAccountFile)
    $taskBytes = [Security.Cryptography.ProtectedData]::Unprotect($taskEncrypted,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $taskAccount = [Text.Encoding]::UTF8.GetString($taskBytes) | ConvertFrom-Json
} else {
    $taskAccountRaw = & node.exe (Join-Path $taskRoot 'pc/src/account.js')
    if ($LASTEXITCODE -ne 0) { throw 'Account generation failed' }
    $taskAccount = $taskAccountRaw | ConvertFrom-Json
    $taskProtected = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($taskAccountRaw),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $taskAccountFile))
    [IO.File]::WriteAllBytes($taskAccountFile,$taskProtected)
}
$taskAssets = Join-Path $taskRoot '.tools/personal-assets'
$null = [IO.Directory]::CreateDirectory($taskAssets)
$taskPublic = @{version=1;signal='https://demochko.com/hosting-webrtc-probe/signal.php';feedToken=$taskAccount.feedToken;publicKey=$taskAccount.publicKey} | ConvertTo-Json -Compress
[IO.File]::WriteAllText((Join-Path $taskAssets 'phone-exit-account.json'),$taskPublic,(New-Object Text.UTF8Encoding($false)))
$taskTools = Join-Path $taskRoot '.tools'
$env:JAVA_HOME = (Get-ChildItem (Join-Path $taskTools 'jdk') -Directory | Select-Object -First 1).FullName
$env:GRADLE_USER_HOME = Join-Path $taskTools 'gradle-cache'
$env:JDK_JAVA_OPTIONS = '-Djava.net.preferIPv4Stack=true -Djdk.net.unixdomain.tmpdir=C:/dev/phone-exit-java-tmp'
$null = [IO.Directory]::CreateDirectory('C:/dev/phone-exit-java-tmp')
Push-Location $PSScriptRoot
try {
    & (Join-Path $taskTools 'gradle/gradle-8.11.1/bin/gradle.bat') --no-daemon "-PpersonalAssetsDir=$taskAssets" :app:assembleDebug :app:lintDebug
    if ($LASTEXITCODE -ne 0) { throw 'Personal APK build failed' }
    Copy-Item -LiteralPath 'app/build/outputs/apk/debug/app-debug.apk' -Destination (Join-Path $taskRoot 'PhoneExit-personal.apk')
    Write-Output 'Personal APK built. Account keys remain protected; no secrets printed.'
} finally { Pop-Location }
