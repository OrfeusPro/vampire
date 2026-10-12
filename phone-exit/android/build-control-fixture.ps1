$ErrorActionPreference='Stop'
$taskTools=Join-Path (Split-Path -Parent $PSScriptRoot) '.tools'
$env:JAVA_HOME=(Get-ChildItem (Join-Path $taskTools 'jdk') -Directory|Select-Object -First 1).FullName
$env:GRADLE_USER_HOME=Join-Path $taskTools 'gradle-cache'
$env:JDK_JAVA_OPTIONS='-Djava.net.preferIPv4Stack=true -Djdk.net.unixdomain.tmpdir=C:/dev/phone-exit-java-tmp'
Push-Location $PSScriptRoot
try {& (Join-Path $taskTools 'gradle/gradle-8.11.1/bin/gradle.bat') --no-daemon :control-fixture:assembleDebug :control-fixture:lintDebug;if($LASTEXITCODE -ne 0){throw 'Fixture build failed'}} finally {Pop-Location}
