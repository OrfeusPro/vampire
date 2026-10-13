function EnsureBotGateway {
        $taskKeyPath=Join-Path $script:profileDirectory 'control-api.bin'
        if(!(Test-Path -LiteralPath $taskKeyPath)){
            $taskRng=[Security.Cryptography.RandomNumberGenerator]::Create();$taskBytes=New-Object byte[] 32;$taskRng.GetBytes($taskBytes);$taskRng.Dispose()
            $taskRaw=([BitConverter]::ToString($taskBytes)).Replace('-','').ToLowerInvariant()
            [IO.File]::WriteAllBytes($taskKeyPath,[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($taskRaw),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
        }
        $script:botApiSecret=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($taskKeyPath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
        $taskReady=$false
        try{$null=Invoke-RestMethod 'http://127.0.0.1:17842/bot/v1/catalog' -Headers @{Authorization="Bearer $script:botApiSecret"} -TimeoutSec 2;$taskReady=$true}catch{}
        if(!$taskReady){
            $taskInfo=New-Object Diagnostics.ProcessStartInfo
            $taskInfo.FileName=TransportRuntime;$taskInfo.Arguments='"'+(Join-Path $PSScriptRoot 'src/control-api.js')+'"'
            $taskInfo.UseShellExecute=$false;$taskInfo.CreateNoWindow=$true;$taskInfo.RedirectStandardInput=$true;$taskInfo.RedirectStandardOutput=$true;$taskInfo.RedirectStandardError=$true
            $script:botGateway=New-Object Diagnostics.Process;$script:botGateway.StartInfo=$taskInfo;$null=$script:botGateway.Start()
            $script:botGateway.StandardInput.WriteLine((ConvertToPhoneExitTransportJson @{account=(LoadAccount);phones=@(LoadPhones);secret=$script:botApiSecret;profilePath=$script:profileDirectory}));$script:botGateway.StandardInput.Flush()
        }

}
$script:botPhoneBadges=@{}
$script:botBadgeRead=$null
$script:botBadgeNext=[DateTime]::MinValue
$script:botBadgeLast=[DateTime]::MinValue
$script:botRowJobs=@{}
function InvokePhoneBotAction([int]$index,[string]$action) {
    if($index -lt 0 -or $index -ge $script:phoneRows.Count){return}
    $taskPhone=$script:phoneRows[$index];$taskId=[string]$taskPhone.id
    if($action -eq 'settings'){OpenBotPanel $taskId;return}
    if(!$script:botBadgeHttp -or $script:botRowJobs.ContainsKey($taskId)){return}
    $taskBadge=$script:botPhoneBadges[$taskId]
    if(!$taskPhone.online -or !$taskBadge -or $taskBadge.botStatusStale -or ([DateTime]::UtcNow-$script:botBadgeLast).TotalSeconds -gt 15 -or (!$taskBadge.bot.botId -and !$taskBadge.profile.botId)){return}
    try{
        $taskOp=$action
        $taskBody=New-Object Net.Http.StringContent((ConvertTo-Json @{op=$taskOp} -Compress),[Text.Encoding]::UTF8,'application/json')
        $script:botRowJobs[$taskId]=@{task=$script:botBadgeHttp.PostAsync(('http://127.0.0.1:17842/bot/v1/devices/'+$taskId+'/action'),$taskBody);content=$taskBody;stage='post';deadline=[DateTime]::UtcNow.AddSeconds(190);name=[string]$taskPhone.name}
        $hint.Text='Отправляется команда боту: '+$taskPhone.name;$phoneList.Invalidate()
    }catch{$hint.Text='Команда не отправлена: '+$_.Exception.Message}
}
$phoneList.Add_RowAction({param($sender,$event) InvokePhoneBotAction $event.Index $event.Action})
function RefreshBotRowJobs {
    foreach($taskId in @($script:botRowJobs.Keys)){
        $taskJob=$script:botRowJobs[$taskId]
        try{
            if([DateTime]::UtcNow -gt $taskJob.deadline){throw 'Результат неизвестен. Проверьте статус телефона; команда автоматически не повторяется.'}
            if(!$taskJob.task.IsCompleted -or ($taskJob.nextPoll -and [DateTime]::UtcNow -lt $taskJob.nextPoll)){continue}
            if($taskJob.task.IsFaulted -or $taskJob.task.IsCanceled){throw 'Нет подтверждения HTTP API. Проверьте статус перед повторной командой.'}
            if($taskJob.stage -eq 'post'){
                $taskResponse=$taskJob.task.Result
                $taskJob.content.Dispose();$taskJob.Remove('content')
                $taskJob.task=$taskResponse.Content.ReadAsStringAsync();$taskJob.response=$taskResponse;$taskJob.stage='body';continue
            }
            $taskResult=$taskJob.task.Result|ConvertFrom-Json
            if($taskJob.stage -eq 'body'){
                $taskOk=$taskJob.response.IsSuccessStatusCode;$taskJob.response.Dispose();$taskJob.Remove('response')
                if(!$taskOk){throw 'API отклонил команду: '+$taskResult.error}
                $taskJob.jobId=[string]$taskResult.id;$taskJob.stage='poll'
            }elseif($taskResult.status -eq 'done'){
                if($script:botPhoneBadges[$taskId] -and $taskResult.result){$script:botPhoneBadges[$taskId].bot=$taskResult.result}
                $hint.Text='Команда боту выполнена: '+$taskJob.name;$script:botRowJobs.Remove($taskId);$script:botBadgeNext=[DateTime]::MinValue;$phoneList.Invalidate();continue
            }elseif($taskResult.status -eq 'failed'){throw ('Команда боту не выполнена: '+$taskResult.error)}
            $taskJob.task=$script:botBadgeHttp.GetStringAsync('http://127.0.0.1:17842/bot/v1/jobs/'+$taskJob.jobId)
            $taskJob.nextPoll=[DateTime]::UtcNow.AddSeconds(1)
        }catch{
            $hint.Text=$_.Exception.Message
            if($taskJob.content){$taskJob.content.Dispose()};if($taskJob.response){$taskJob.response.Dispose()}
            $script:botRowJobs.Remove($taskId);$phoneList.Invalidate()
        }
    }
}
function RefreshBotBadges {
    if(!$script:botBadgeHttp){return}
    if($script:botBadgeRead -and $script:botBadgeRead.IsCompleted){
        try{if(!$script:botBadgeRead.IsFaulted -and !$script:botBadgeRead.IsCanceled){$taskPayload=$script:botBadgeRead.Result|ConvertFrom-Json;$taskBadges=@{};foreach($taskPhone in $taskPayload.phones){$taskBadges[[string]$taskPhone.id]=$taskPhone};$script:botPhoneBadges=$taskBadges;$script:botBadgeLast=[DateTime]::UtcNow;$phoneList.Invalidate()}}catch{}
        $script:botBadgeRead=$null
    }
    if(!$script:botBadgeRead -and [DateTime]::UtcNow -ge $script:botBadgeNext){$script:botBadgeNext=[DateTime]::UtcNow.AddSeconds(5);$script:botBadgeRead=$script:botBadgeHttp.GetStringAsync('http://127.0.0.1:17842/bot/v1/phones')}
}
$script:botBadgeTimer=New-Object Windows.Forms.Timer
$script:botBadgeTimer.Interval=250
$script:botBadgeTimer.Add_Tick({RefreshBotBadges;RefreshBotRowJobs})
$form.Add_Shown({
    if($SelfTest -or $VpnTest -or $StartupTest -or $RecoveryTest){return}
    try{EnsureBotGateway;Add-Type -AssemblyName System.Net.Http;$script:botBadgeHttp=New-Object Net.Http.HttpClient;$script:botBadgeHttp.Timeout=[TimeSpan]::FromSeconds(3);$script:botBadgeHttp.DefaultRequestHeaders.Authorization=New-Object Net.Http.Headers.AuthenticationHeaderValue('Bearer',$script:botApiSecret);$script:botBadgeTimer.Start()}catch{}
})
$form.Add_FormClosed({$script:botBadgeTimer.Stop();$script:botBadgeTimer.Dispose();if($script:botBadgeHttp){$script:botBadgeHttp.Dispose()}})
# A panel owned by the main EXE. The local gateway lifetime is independent of bots.
function OpenBotPanel([string]$phoneId='', [string[]]$targetIds=@()) {
    try {
        Add-Type -AssemblyName System.Net.Http
        Add-Type -AssemblyName System.Web.Extensions
        if(!('PhoneExit.BotPanel' -as [type])){Add-Type -Path @((Join-Path $PSScriptRoot 'desktop-controls.cs'),(Join-Path $PSScriptRoot 'desktop-bots.cs')) -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions}
        EnsureBotGateway
        $taskSecret=$script:botApiSecret
        $taskPanel=New-Object PhoneExit.BotPanel($taskSecret,([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../bots'))))
        if($phoneId){$taskPanel.DevicePhoneId=$phoneId}
        $taskPanel.InitialCopyTargets=$targetIds
        $null=$taskPanel.ShowDialog($form);$taskPanel.Dispose()
    }catch{$hint.Text='Панель ботов недоступна: '+$_.Exception.Message}
}
$form.Add_FormClosed({if($script:botGateway){try{$script:botGateway.StandardInput.Close();if(!$script:botGateway.WaitForExit(2000)){$script:botGateway.Kill()}}catch{};$script:botGateway.Dispose()}})
$script:botsButton=ButtonAt 'Боты и настройки' 38 87 230
$script:botsButton.Anchor='Top,Right'
$script:botsButton.Height=UiPixel 34
$script:botsButton.SetBounds(($form.ClientSize.Width-(UiPixel 430)),(UiPixel 87),(UiPixel 230),(UiPixel 34))
$script:botsButton.Add_Click({OpenBotPanel})
