$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'profile.ps1')
$taskValue=@{profilePath='C:\Users\Валентин\данные';name='Телефон 🔋';phones=@(@{label='Япония'})}
$taskJson=ConvertToPhoneExitTransportJson $taskValue
if($taskJson -match '[^\x00-\x7f]'){throw 'Non-ASCII child transport JSON'}
$taskInfo=New-Object Diagnostics.ProcessStartInfo
$taskInfo.FileName=(Get-Command node.exe).Source
$taskInfo.Arguments='-e "let s='''' ;process.stdin.on(''data'',b=>s+=b);process.stdin.on(''end'',()=>process.stdout.write(JSON.stringify(JSON.parse(s))));"'
$taskInfo.UseShellExecute=$false;$taskInfo.CreateNoWindow=$true
$taskInfo.RedirectStandardInput=$true;$taskInfo.RedirectStandardOutput=$true
$taskInfo.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
$taskProcess=New-Object Diagnostics.Process;$taskProcess.StartInfo=$taskInfo
try{
    $null=$taskProcess.Start();$taskProcess.StandardInput.WriteLine($taskJson);$taskProcess.StandardInput.Close()
    $taskResult=$taskProcess.StandardOutput.ReadToEnd()|ConvertFrom-Json
    if(!$taskProcess.WaitForExit(5000)-or $taskProcess.ExitCode -ne 0){throw 'Child JSON parse failed'}
    if($taskResult.profilePath -cne $taskValue.profilePath -or $taskResult.name -cne $taskValue.name -or $taskResult.phones[0].label -cne 'Япония'){throw 'Unicode child transport changed values'}
    Write-Output 'PASS Windows child stdin: Cyrillic paths, emoji and nested phone arrays.'
}finally{if(!$taskProcess.HasExited){$taskProcess.Kill()};$taskProcess.Dispose()}
