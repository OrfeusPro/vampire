$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
. (Join-Path $PSScriptRoot 'profile.ps1')
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskProfile=GetPhoneExitProfileDirectory
$encrypted=[IO.File]::ReadAllBytes((Join-Path $taskProfile 'account.bin'))
$account=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($encrypted,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))|ConvertFrom-Json
$feed=New-Object byte[] 32;for($i=0;$i -lt 32;$i++){$feed[$i]=[Convert]::ToByte($account.feedToken.Substring($i*2,2),16)}
$hmac=New-Object Security.Cryptography.HMACSHA256;$hmac.Key=$feed
$token=([BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes('phone-exit-catalog-v1')))).Replace('-','').ToLowerInvariant();$hmac.Dispose()
$sha=[Security.Cryptography.SHA256]::Create();$accountName=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($token)))).Replace('-','').ToLowerInvariant();$sha.Dispose()
$gradle=[IO.File]::ReadAllText((Join-Path $taskRoot 'android/app/build.gradle'))
$code=[int]([regex]::Match($gradle,'versionCode (\d+)').Groups[1].Value)
$name=[regex]::Match($gradle,"versionName '([^']+)'").Groups[1].Value
$apk=Join-Path $taskRoot 'PhoneExit-personal.apk'
if(!(Test-Path -LiteralPath $apk)){throw 'Build APK first'}
$aapt=Join-Path $taskRoot '.tools/android-sdk/build-tools/35.0.0/aapt.exe'
$packageLine=(& $aapt dump badging $apk | Select-String '^package:').ToString()
if($LASTEXITCODE -ne 0 -or $packageLine -notmatch "name='net.phoneexit'" -or $packageLine -notmatch "versionCode='$code'" -or $packageLine -notmatch "versionName='$name'"){throw 'Built APK version does not match source. Rebuild first.'}
$release=Join-Path $taskRoot '.tools/update-release';$null=[IO.Directory]::CreateDirectory($release)
Copy-Item -LiteralPath $apk -Destination (Join-Path $release ($accountName+'.apk'))
$meta=@{versionCode=$code;versionName=$name;size=(Get-Item -LiteralPath $apk).Length;sha256=(Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()}
[IO.File]::WriteAllText((Join-Path $release ($accountName+'.json')),($meta|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
Write-Output "Private update prepared: $name. Account capability not printed."
