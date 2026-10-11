$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$root=Split-Path -Parent $PSScriptRoot
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /reference:System.Windows.Forms.dll ('/reference:'+([System.Management.Automation.PSObject].Assembly.Location)) ('/win32icon:'+(Join-Path $PSScriptRoot 'assets/phone-exit.ico')) ('/out:'+(Join-Path $root 'Phone Exit.exe')) (Join-Path $PSScriptRoot 'launcher.cs')
if($LASTEXITCODE -ne 0){throw 'Launcher build failed'}
Write-Output 'Phone Exit.exe built.'
