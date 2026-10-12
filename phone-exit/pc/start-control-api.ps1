param([switch]$ShowKey)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
. (Join-Path $PSScriptRoot 'profile.ps1')
$taskProfile=GetPhoneExitProfileDirectory
function ReadPrivate($name){
    $bytes=[IO.File]::ReadAllBytes((Join-Path $taskProfile $name))
    [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
}
$taskKeyPath=Join-Path $taskProfile 'control-api.bin'
if(!(Test-Path -LiteralPath $taskKeyPath)){
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create();$bytes=New-Object byte[] 32;$rng.GetBytes($bytes);$rng.Dispose()
    $key=([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant()
    [IO.File]::WriteAllBytes($taskKeyPath,[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($key),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
}
$taskKey=ReadPrivate 'control-api.bin'
if($ShowKey){Write-Output $taskKey;return}
$taskAccount=ReadPrivate 'account.bin'|ConvertFrom-Json
$taskPhones=@();if(Test-Path -LiteralPath (Join-Path $taskProfile 'phones.bin')){foreach($p in (ReadPrivate 'phones.bin'|ConvertFrom-Json)){$taskPhones+=$p}}
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=(Get-Command node.exe).Source;$info.Arguments='"'+(Join-Path $PSScriptRoot 'src/control-api.js')+'"'
$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true
$process=New-Object Diagnostics.Process;$process.StartInfo=$info
try{
    $null=$process.Start()
    $process.StandardInput.WriteLine((@{account=$taskAccount;phones=$taskPhones;secret=$taskKey}|ConvertTo-Json -Depth 12 -Compress));$process.StandardInput.Flush()
    $taskAccountStamp=(Get-Item -LiteralPath (Join-Path $taskProfile 'account.bin')).LastWriteTimeUtc.Ticks
    while(!$process.WaitForExit(1000)){
        $taskStamp=(Get-Item -LiteralPath (Join-Path $taskProfile 'account.bin')).LastWriteTimeUtc.Ticks
        if($taskStamp -ne $taskAccountStamp){
            $taskCurrent=ReadPrivate 'account.bin'|ConvertFrom-Json
            if($taskCurrent.feedToken -ne $taskAccount.feedToken){throw 'Account changed: restart HTTP gateway'}
            $process.StandardInput.WriteLine((@{op='blocked';blocked=@($taskCurrent.blocked)}|ConvertTo-Json -Depth 8 -Compress));$process.StandardInput.Flush()
            $taskAccountStamp=$taskStamp
        }
    }
}finally{if(!$process.HasExited){$process.StandardInput.Close();if(!$process.WaitForExit(2000)){$process.Kill()}};$process.Dispose()}
