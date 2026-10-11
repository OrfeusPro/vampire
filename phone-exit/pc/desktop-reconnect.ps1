# A connection intent survives transport failure, but never an explicit Stop.
$script:connectionWanted=$false
$script:reconnectPhone=$null
$script:reconnectAttempts=0
$script:reconnectAt=[DateTime]::MinValue
function CancelReconnect {
    $script:connectionWanted=$false;$script:reconnectPhone=$null;$script:reconnectAttempts=0
}
function QueueReconnect {
    if(!$script:connectionWanted -or !$script:reconnectPhone){return}
    $delay=[Math]::Min(30,2*[Math]::Pow(2,[Math]::Min($script:reconnectAttempts,4)))
    $script:reconnectAttempts++;$script:reconnectAt=[DateTime]::UtcNow.AddSeconds($delay)
    $status.Text='Ожидаю телефон · переподключение'
    $hint.Text='Связь будет восстановлена автоматически. «Отключить» отменяет ожидание.'
    $start.Enabled=$false;$stopButton.Enabled=$true;$mode.Enabled=$false;$chooseApps.Enabled=$false
}
function ReadReconnect {
    if(!$script:connectionWanted -or !$script:reconnectPhone -or $script:client){return}
    if($script:vpnState -eq 'failed'){CancelReconnect;return}
    if([DateTime]::UtcNow -lt $script:reconnectAt){return}
    for($i=0;$i -lt $script:phoneRows.Count;$i++){
        $phone=$script:phoneRows[$i]
        if($phone.id -eq $script:reconnectPhone -and $phone.online -and !$phone.busy){
            $phoneList.SelectedIndex=$i
            StartClient -Reconnect
            return
        }
    }
    $status.Text='Ожидаю телефон · переподключение'
    $hint.Text='Включите Wi-Fi и доступ на выбранном телефоне. ПК подключится сам.'
}
