param([Parameter(Mandatory=$true)][string]$Name,[Parameter(Mandatory=$true)][string]$Country,
    [Parameter(Mandatory=$true)][string]$Command,[string]$ArgsJson='{}',[string]$ImagePath,[string]$BotSettingsJson)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
. (Join-Path $PSScriptRoot 'profile.ps1')
$taskSecret=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path (GetPhoneExitProfileDirectory) 'control-api.bin')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
$taskHeaders=@{Authorization="Bearer $taskSecret"}
$taskPhones=Invoke-RestMethod 'http://127.0.0.1:17842/bot/v1/phones' -Headers $taskHeaders -TimeoutSec 10
$taskPhone=@($taskPhones.phones|Where-Object {$_.name -eq $Name -and $_.country -eq $Country})
if($taskPhone.Count -ne 1){throw 'Expected exactly one matching phone'}
if($BotSettingsJson){
    if($Command -ne 'bot'){throw 'BotSettingsJson requires bot command'}
    $taskSettings=ConvertFrom-Json $BotSettingsJson
    $taskSettingsBody=@{settings=$taskSettings}|ConvertTo-Json -Depth 30 -Compress
    $taskSettingsUrl='http://127.0.0.1:17842/bot/v1/devices/'+$taskPhone[0].id+'/settings'
    return Invoke-RestMethod $taskSettingsUrl -Method Post -Headers $taskHeaders -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($taskSettingsBody)) -TimeoutSec 15
}
$taskBase='http://127.0.0.1:17842/v1/devices/'+$taskPhone[0].id+'/commands'
$taskArgs=ConvertFrom-Json $ArgsJson
$taskBody=@{command=$Command;args=$taskArgs}|ConvertTo-Json -Depth 20 -Compress
$taskJob=Invoke-RestMethod $taskBase -Method Post -Headers $taskHeaders -ContentType 'application/json' -Body $taskBody -TimeoutSec 15
$taskDeadline=[DateTime]::UtcNow.AddSeconds(160)
do {
    $taskStatus=Invoke-RestMethod ($taskBase+'/'+$taskJob.id) -Headers $taskHeaders -TimeoutSec 15
    if($taskStatus.status -eq 'done'){
        if(!$taskStatus.result.ok){throw $taskStatus.result.error}
        $taskPayload=$taskStatus.result.result
        if($ImagePath){
            if(!$taskPayload.image){throw 'No screenshot in result'}
            [IO.File]::WriteAllBytes([IO.Path]::GetFullPath($ImagePath),[Convert]::FromBase64String($taskPayload.image))
            return [pscustomobject]@{width=$taskPayload.width;height=$taskPayload.height;format=$taskPayload.format;saved=$true}
        }
        return $taskPayload
    }
    if($taskStatus.status -in @('expired','unknown')){throw 'Outcome unknown; inspect status before repeating actions'}
    Start-Sleep -Milliseconds 250
} while([DateTime]::UtcNow -lt $taskDeadline)
throw 'Command timeout; inspect status before repeating actions'
