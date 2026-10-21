# No saved enabled flag. Each transport starts with capture off.
$script:diagnosticState=$null
$script:diagnosticMessage=''
$script:diagnosticPending=$false
function ConvertToDiagnosticFilters([string[]]$lines) {
    $filters=@();foreach($line in $lines){
        $value=$line.Trim();if(!$value){continue}
        if($value -notmatch '^([a-zA-Z0-9.-]{1,253}):([0-9]{1,5})$' -or [int]$Matches[2] -lt 1 -or [int]$Matches[2] -gt 65535){throw 'Нужны точные адреса хост:порт, без URL и масок.'}
        $filters+=@{host=$Matches[1];port=[int]$Matches[2]}
    }
    if($filters.Count -lt 1 -or $filters.Count -gt 16){throw 'Укажите от 1 до 16 адресов игры.'}
    return $filters
}
function ReadDiagnosticFilterFile([string]$path) {
    $file=[IO.File]::OpenRead($path)
    try{
        if($file.Length -gt 4096){throw 'Файл фильтра слишком большой.'}
        $bytes=New-Object byte[] 4097;$count=0
        while($count -lt $bytes.Length){$n=$file.Read($bytes,$count,($bytes.Length-$count));if(!$n){break};$count+=$n}
        if($count -gt 4096){throw 'Файл фильтра слишком большой.'}
        $text=([Text.UTF8Encoding]::new($false,$true)).GetString($bytes,0,$count).TrimStart([char]0xfeff)
        $lines=@($text -split "`r?`n");$null=@(ConvertToDiagnosticFilters $lines)
        return ($lines -join "`r`n")
    }finally{$file.Dispose()}
}
function SendDiagnosticCommand($request) {
    if(!$script:client -or $script:client.HasExited -or $script:stopping -or !$script:transportReady){throw 'Подключите телефон перед записью.'}
    $script:client.StandardInput.WriteLine(($request|ConvertTo-Json -Depth 5 -Compress))
    $script:client.StandardInput.Flush()
}
function ShowTcpDiagnostics([switch]$Preview) {
    $window=[PhoneExit.DesktopWindow]::new();$window.Text='Диагностика TCP Phone Exit';$window.StartPosition='CenterParent';$window.FormBorderStyle='None'
    $window.Font=$form.Font;$window.ClientSize=[Drawing.Size]::new((UiPixel 640),(UiPixel 580))
    $header=[Windows.Forms.Label]::new();$header.Text='Запись TCP через телефон';$header.Font=[Drawing.Font]::new('Segoe UI Semibold',16)
    $header.SetBounds((UiPixel 24),(UiPixel 16),(UiPixel 592),(UiPixel 35));$window.Controls.Add($header)
    $note=[Windows.Forms.Label]::new();$note.Text=""
    $note.SetBounds((UiPixel 24),(UiPixel 62),(UiPixel 592),(UiPixel 90));$window.Controls.Add($note)
    $all=[Windows.Forms.CheckBox]::new();$all.Text='';$all.AccessibleName='Записывать весь TCP через телефон';$all.AutoSize=$false
    $all.SetBounds((UiPixel 24),(UiPixel 158),(UiPixel 24),(UiPixel 30));$window.Controls.Add($all)
    $allLabel=[Windows.Forms.Label]::new();$allLabel.Text='Весь TCP через телефон (3 минуты)';$allLabel.TextAlign='MiddleLeft'
    $allLabel.SetBounds((UiPixel 52),(UiPixel 158),(UiPixel 564),(UiPixel 30));$window.Controls.Add($allLabel)
    $allLabel.Add_Click({if($all.Enabled){$all.Checked=!$all.Checked}})
    $all.Checked=$script:diagnosticState -and $script:diagnosticState.mode -eq 'all-tcp'
    $label=[Windows.Forms.Label]::new();$label.Text='Адреса игры: хост:порт, по одному в строке'
    $label.SetBounds((UiPixel 24),(UiPixel 203),(UiPixel 446),(UiPixel 26));$window.Controls.Add($label)
    $load=[PhoneExit.DarkButton]::new();$load.Text='Загрузить…';$load.AccessibleName='Загрузить фильтр TCP'
    $load.SetBounds((UiPixel 484),(UiPixel 199),(UiPixel 132),(UiPixel 32));$window.Controls.Add($load)
    $filter=[Windows.Forms.TextBox]::new();$filter.Multiline=$true;$filter.ScrollBars='Vertical';$filter.MaxLength=4096;$filter.AccessibleName='Фильтр адресов игры'
    $filter.SetBounds((UiPixel 24),(UiPixel 236),(UiPixel 592),(UiPixel 104));$window.Controls.Add($filter)
    $state=[Windows.Forms.Label]::new();$state.AccessibleName='Состояние записи';$state.SetBounds((UiPixel 24),(UiPixel 352),(UiPixel 592),(UiPixel 76));$window.Controls.Add($state)
    $folder=[Windows.Forms.TextBox]::new();$folder.ReadOnly=$true;$folder.Text=Join-Path $script:profileDirectory 'diagnostics';$folder.AccessibleName='Каталог диагностических записей'
    $folder.SetBounds((UiPixel 24),(UiPixel 438),(UiPixel 592),(UiPixel 30));$window.Controls.Add($folder)
    $begin=[PhoneExit.DarkButton]::new();$begin.Text='Начать запись';$begin.AccessibleName='Начать запись TCP';$begin.SetBounds((UiPixel 24),(UiPixel 490),(UiPixel 186),(UiPixel 42));$window.Controls.Add($begin)
    $end=[PhoneExit.DarkButton]::new();$end.Text='Остановить';$end.SetBounds((UiPixel 226),(UiPixel 490),(UiPixel 186),(UiPixel 42));$window.Controls.Add($end)
    $close=[PhoneExit.DarkButton]::new();$close.Text='Закрыть';$close.SetBounds((UiPixel 428),(UiPixel 490),(UiPixel 188),(UiPixel 42));$window.Controls.Add($close)
    $foot=[Windows.Forms.Label]::new();$foot.Text='Закрытие окна остановит запись.'
    $foot.SetBounds((UiPixel 24),(UiPixel 543),(UiPixel 592),(UiPixel 25));$window.Controls.Add($foot)
    $script:diagnosticMessage=''
    $update={
        $live=$script:client -and !$script:client.HasExited -and !$script:stopping -and $script:transportReady
        $recording=$live -and ($script:diagnosticPending -or ($script:diagnosticState -and $script:diagnosticState.state -in @('active','stopping')))
        $begin.Enabled=$live -and !$recording -and !$Preview;$end.Enabled=$recording -and !$Preview;$all.Enabled=!$recording -and !$Preview;$filter.Enabled=!$recording -and !$all.Checked;$load.Enabled=!$recording -and !$all.Checked -and !$Preview
        $note.Text=if($all.Checked){"Новые TCP через VPN: выбранные EXE или весь ПК — по режиму VPN.`r`nЗапись может содержать токены. Храните её локально.`r`nДо 3 минут · 32 МиБ · 1024 соединения. HTTPS остаётся зашифрованным."}else{"Только новые TCP-соединения к адресам ниже.`r`nЗапись может содержать токены. Храните её локально.`r`nДо 3 минут · 8 МиБ · 16 соединений."}
        $text=if(!$live){'Запись выключена. Подключите телефон.'}elseif(!$script:diagnosticState){'Запись выключена.'}else{
            $name=switch($script:diagnosticState.state){'active'{'ИДЁТ ЗАПИСЬ'}'stopping'{'Завершаю запись'}'stopped'{'Запись остановлена'}'failed'{'Ошибка записи'}default{'Запись выключена'}}
            $reason=switch($script:diagnosticState.reason){'byte_limit'{'Лимит данных'}'file_limit'{'Лимит файла'}'queue_limit'{'Диск не успевает'}'time_limit'{'Лимит времени'}'flow_limit'{'Лимит соединений'}'record_limit'{'Лимит событий'}'io_error'{'Ошибка диска'}'transport_stopped'{'Соединение остановлено'}default{''}}
            $remaining=if($script:diagnosticState.state -eq 'active' -and $null -ne $script:diagnosticState.remainingMs){" · осталось $([Math]::Ceiling($script:diagnosticState.remainingMs/1000)) с"}else{''}
            "$name · $($script:diagnosticState.bytes) байт · $($script:diagnosticState.flows) соединений$remaining`r`n$reason"
        }
        $state.Text=$text+"`r`n"+$script:diagnosticMessage
        $id=if($script:diagnosticState -and $script:diagnosticState.id -match '^[a-f0-9]{32}$'){$script:diagnosticState.id}else{''}
        $folder.Text=Join-Path (Join-Path $script:profileDirectory 'diagnostics') $id
        $diagnosticButton.Text=if($recording){'● Запись TCP'}else{'Диагностика TCP'}
    }
    $all.Add_CheckedChanged($update)
    $begin.Add_Click({
        try{
            if($all.Checked){SendDiagnosticCommand @{op='capture-start';mode='all-tcp'}}
            else{
                $filters=@(ConvertToDiagnosticFilters $filter.Lines)
                SendDiagnosticCommand @{op='capture-start';mode='endpoints';filters=@($filters)}
            }
            $script:diagnosticPending=$true
            $script:diagnosticMessage='Запуск записи…';$begin.Enabled=$false
        }catch{$script:diagnosticMessage=$_.Exception.Message}
    })
    $load.Add_Click({
        $picker=[Windows.Forms.OpenFileDialog]::new();$picker.Filter='Фильтр TCP (*.txt)|*.txt';$picker.Title='Адреса игровых соединений'
        $initial=Join-Path $script:profileDirectory 'diagnostic-filters';if(Test-Path -LiteralPath $initial){$picker.InitialDirectory=$initial}
        try{if($picker.ShowDialog($window) -eq 'OK'){$filter.Text=ReadDiagnosticFilterFile $picker.FileName;$script:diagnosticMessage='Фильтр загружен. Запись не включена.'}}
        catch{$script:diagnosticMessage='Не удалось прочитать фильтр. Нужен UTF-8 файл до 4096 байт с адресами хост:порт.'}
        finally{$picker.Dispose()}
    })
    $end.Add_Click({try{SendDiagnosticCommand @{op='capture-stop'};$script:diagnosticMessage='Останавливаю…'}catch{$script:diagnosticMessage='Транспорт уже остановлен.'}})
    $close.Add_Click({$window.Close()})
    $window.Add_FormClosing({try{SendDiagnosticCommand @{op='capture-stop'}}catch{}})
    SetDesktopDialogStyle $window $header $filter $null
    $load.Anchor='Top, Right';$all.Anchor='Top, Left'
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
