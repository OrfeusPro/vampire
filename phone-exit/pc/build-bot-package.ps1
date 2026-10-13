param([string]$Bot='lordnine')
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
. (Join-Path $PSScriptRoot 'profile.ps1')
$taskKeyFile=Join-Path (GetPhoneExitProfileDirectory) 'bot-signing.bin'
if(!(Test-Path -LiteralPath $taskKeyFile)){
    $taskRaw=& node -e "const c=require('node:crypto');const k=c.generateKeyPairSync('rsa',{modulusLength:2048});process.stdout.write(JSON.stringify({privateKey:k.privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),publicKey:k.publicKey.export({format:'der',type:'spki'}).toString('base64')}));"
    if($LASTEXITCODE -ne 0){throw 'Signing key generation failed'}
    [IO.File]::WriteAllBytes($taskKeyFile,[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($taskRaw),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
}
$taskKey=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($taskKeyFile),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))|ConvertFrom-Json
$taskAssets=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.tools/personal-assets'))
$null=[IO.Directory]::CreateDirectory($taskAssets)
[IO.File]::WriteAllText((Join-Path $taskAssets 'bot-publisher.json'),(@{version=1;publicKey=$taskKey.publicKey}|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
@{bot=$Bot;privateKey=$taskKey.privateKey}|ConvertTo-Json -Compress|& node (Join-Path $PSScriptRoot '../bots/build-package.mjs')
if($LASTEXITCODE -ne 0){throw 'Bot package failed'}
