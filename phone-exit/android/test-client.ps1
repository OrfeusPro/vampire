$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'fetch-tunnel.ps1')
$clientTools = Join-Path (Split-Path -Parent $PSScriptRoot) '.tools'
$env:JAVA_HOME = (Get-ChildItem (Join-Path $clientTools 'jdk') -Directory | Select-Object -First 1).FullName
$env:GRADLE_USER_HOME = Join-Path $clientTools 'gradle-cache'
$env:JDK_JAVA_OPTIONS = '-Djava.net.preferIPv4Stack=true -Djdk.net.unixdomain.tmpdir=C:/dev/phone-exit-java-tmp'
$null = New-Item -ItemType Directory -Force 'C:/dev/phone-exit-java-tmp'
Push-Location $PSScriptRoot
try {
    & (Join-Path $clientTools 'gradle/gradle-8.11.1/bin/gradle.bat') --no-daemon :app:testDebugUnitTest :app:assembleDebugAndroidTest
    if ($LASTEXITCODE -ne 0) { throw 'Android client tests failed' }
} finally { Pop-Location }
