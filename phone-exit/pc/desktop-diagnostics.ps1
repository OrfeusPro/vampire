# No saved enabled flag. Each transport starts with capture off.
$script:diagnosticState=$null
$script:diagnosticMessage=''
$script:diagnosticPending=$false
function SendDiagnosticCommand($request) {
    if(!$script:client -or $script:client.HasExited -or $script:stopping -or !$script:transportReady){throw 'Подключите телефон перед записью.'}
    $script:client.StandardInput.WriteLine(($request|ConvertTo-Json -Depth 5 -Compress))
    $script:client.StandardInput.Flush()
}
function ShowTcpDiagnostics([switch]$Preview) {
    $window=[PhoneExit.DesktopWindow]::new();$window.Text='Диагностика TCP Phone Exit';$window.StartPosition='CenterParent';$window.FormBorderStyle='None'
    $window.Font=$form.Font;$window.ClientSize=[Drawing.Size]::new((UiPixel 640),(UiPixel 520))
    $header=[Windows.Forms.Label]::new();$header.Text='Запись игрового TCP';$header.Font=[Drawing.Font]::new('Segoe UI Semibold',16)
    $header.SetBounds((UiPixel 24),(UiPixel 16),(UiPixel 592),(UiPixel 35));$window.Controls.Add($header)
    $note=[Windows.Forms.Label]::new();$note.Text="Только новые TCP-соединения к адресам ниже.`r`nЗапись может содержать токены. Храните её локально.`r`nЛимиты: 3 минуты · 8 МиБ · 16 соединений."
    $note.SetBounds((UiPixel 24),(UiPixel 62),(UiPixel 592),(UiPixel 72));$window.Controls.Add($note)
    $label=[Windows.Forms.Label]::new();$label.Text='Адреса игры: хост:порт, по одному в строке'
    $label.SetBounds((UiPixel 24),(UiPixel 143),(UiPixel 592),(UiPixel 26));$window.Controls.Add($label)
    $filter=[Windows.Forms.TextBox]::new();$filter.Multiline=$true;$filter.ScrollBars='Vertical';$filter.MaxLength=4096;$filter.AccessibleName='Фильтр адресов игры'
    $filter.SetBounds((UiPixel 24),(UiPixel 176),(UiPixel 592),(UiPixel 104));$window.Controls.Add($filter)
    $state=[Windows.Forms.Label]::new();$state.AccessibleName='Состояние записи';$state.SetBounds((UiPixel 24),(UiPixel 292),(UiPixel 592),(UiPixel 76));$window.Controls.Add($state)
    $folder=[Windows.Forms.TextBox]::new();$folder.ReadOnly=$true;$folder.Text=Join-Path $script:profileDirectory 'diagnostics';$folder.AccessibleName='Каталог диагностических записей'
    $folder.SetBounds((UiPixel 24),(UiPixel 378),(UiPixel 592),(UiPixel 30));$window.Controls.Add($folder)
    $begin=[PhoneExit.DarkButton]::new();$begin.Text='Начать запись';$begin.AccessibleName='Начать запись TCP';$begin.SetBounds((UiPixel 24),(UiPixel 430),(UiPixel 186),(UiPixel 42));$window.Controls.Add($begin)
    $end=[PhoneExit.DarkButton]::new();$end.Text='Остановить';$end.SetBounds((UiPixel 226),(UiPixel 430),(UiPixel 186),(UiPixel 42));$window.Controls.Add($end)
    $close=[PhoneExit.DarkButton]::new();$close.Text='Закрыть';$close.SetBounds((UiPixel 428),(UiPixel 430),(UiPixel 188),(UiPixel 42));$window.Controls.Add($close)
    $foot=[Windows.Forms.Label]::new();$foot.Text='Закрытие окна остановит запись.'
    $foot.SetBounds((UiPixel 24),(UiPixel 483),(UiPixel 592),(UiPixel 25));$window.Controls.Add($foot)
    $script:diagnosticMessage=''
    $update={
        $live=$script:client -and !$script:client.HasExited -and !$script:stopping -and $script:transportReady
        $recording=$live -and ($script:diagnosticPending -or ($script:diagnosticState -and $script:diagnosticState.state -in @('active','stopping')))
        $begin.Enabled=$live -and !$recording -and !$Preview;$end.Enabled=$recording -and !$Preview;$filter.Enabled=!$recording
        $text=if(!$live){'Запись выключена. Подключите телефон.'}elseif(!$script:diagnosticState){'Запись выключена.'}else{
            $name=switch($script:diagnosticState.state){'active'{'ИДЁТ ЗАПИСЬ'}'stopping'{'Завершаю запись'}'stopped'{'Запись остановлена'}'failed'{'Ошибка записи'}default{'Запись выключена'}}
            $reason=switch($script:diagnosticState.reason){'byte_limit'{'Лимит данных'}'file_limit'{'Лимит файла'}'queue_limit'{'Диск не успевает'}'time_limit'{'Лимит времени'}'flow_limit'{'Лимит соединений'}'record_limit'{'Лимит событий'}'io_error'{'Ошибка диска'}'transport_stopped'{'Соединение остановлено'}default{''}}
            "$name · $($script:diagnosticState.bytes) байт · $($script:diagnosticState.flows) соединений`r`n$reason"
        }
        $state.Text=$text+"`r`n"+$script:diagnosticMessage
        $id=if($script:diagnosticState -and $script:diagnosticState.id -match '^[a-f0-9]{32}$'){$script:diagnosticState.id}else{''}
        $folder.Text=Join-Path (Join-Path $script:profileDirectory 'diagnostics') $id
        $diagnosticButton.Text=if($recording){'● Запись TCP'}else{'Диагностика TCP'}
    }
    $begin.Add_Click({
        try{
            $filters=@();foreach($line in @($filter.Lines)){
                $value=$line.Trim();if(!$value){continue}
                if($value -notmatch '^([a-zA-Z0-9.-]{1,253}):([0-9]{1,5})$' -or [int]$Matches[2] -lt 1 -or [int]$Matches[2] -gt 65535){throw 'Нужны точные адреса хост:порт, без URL и масок.'}
                $filters+=@{host=$Matches[1];port=[int]$Matches[2]}
            }
            if($filters.Count -lt 1 -or $filters.Count -gt 16){throw 'Укажите от 1 до 16 адресов игры.'}
            SendDiagnosticCommand @{op='capture-start';filters=@($filters)}
            $script:diagnosticPending=$true
            $script:diagnosticMessage='Запуск записи…';$begin.Enabled=$false
        }catch{$script:diagnosticMessage=$_.Exception.Message}
    })
    $end.Add_Click({try{SendDiagnosticCommand @{op='capture-stop'};$script:diagnosticMessage='Останавливаю…'}catch{$script:diagnosticMessage='Транспорт уже остановлен.'}})
    $close.Add_Click({$window.Close()})
    $window.Add_FormClosing({try{SendDiagnosticCommand @{op='capture-stop'}}catch{}})
    SetDesktopDialogStyle $window $header $filter $null
    $refresh=[Windows.Forms.Timer]::new();$refresh.Interval=300;$refresh.Add_Tick($update)
    $previewTimer=$null
    if($Preview){$previewTimer=[Windows.Forms.Timer]::new();$previewTimer.Interval=400;$previewTimer.Add_Tick({$previewTimer.Stop();SaveDesktopDialogPreview $window 'diagnostics';$window.Close()});$previewTimer.Start()}
    try{& $update;$refresh.Start();$null=$window.ShowDialog($form)}finally{$refresh.Dispose();if($previewTimer){$previewTimer.Dispose()};$header.Font.Dispose();$window.Dispose()}
}
$diagnosticButton=ButtonAt 'Диагностика TCP' 12 0 168
$diagnosticButton.BackColor=$form.BackColor;$diagnosticButton.ForeColor=$muted;$diagnosticButton.AccessibleName='Диагностика TCP'
$diagnosticButton.Add_Click({ShowTcpDiagnostics})
$placeDiagnostic={PlaceControl $diagnosticButton 12 (($form.ClientSize.Height/$script:uiScale)-156) 168 38}
$form.Add_ClientSizeChanged($placeDiagnostic);& $placeDiagnostic
