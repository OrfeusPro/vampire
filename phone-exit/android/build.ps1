$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolsRoot = Join-Path $projectRoot '.tools'
$env:JAVA_HOME = (Get-ChildItem (Join-Path $toolsRoot 'jdk') -Directory | Select-Object -First 1).FullName
$env:GRADLE_USER_HOME = Join-Path $toolsRoot 'gradle-cache'
# Java AF_UNIX IPC fails with the non-ASCII default TEMP path on this PC.
$javaTmp = 'C:/dev/phone-exit-java-tmp'
New-Item -ItemType Directory -Force $javaTmp | Out-Null
$env:JDK_JAVA_OPTIONS = "-Djava.net.preferIPv4Stack=true -Djdk.net.unixdomain.tmpdir=$javaTmp"
Push-Location $PSScriptRoot
try {
    & (Join-Path $toolsRoot 'gradle/gradle-8.11.1/bin/gradle.bat') --no-daemon :app:assembleDebug
    if ($LASTEXITCODE -ne 0) { throw 'Android build failed' }
} finally { Pop-Location }
