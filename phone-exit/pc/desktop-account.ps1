. (Join-Path $PSScriptRoot 'account-transfer.ps1')
function ShowAccountTransfer([switch]$Preview) {
    if(!$Preview -and ($script:client -or $script:connectionWanted -or ($script:vpnState -and $script:vpnState -ne 'off'))){$hint.Text='Перед переносом аккаунта отключите VPN.';return}
    $window=[PhoneExit.DesktopWindow]::new();$window.Text='Перенос аккаунта Phone Exit';$window.FormBorderStyle='None';$window.StartPosition='CenterParent'
    $window.BackColor=$form.BackColor;$window.ForeColor=$form.ForeColor;$window.Font=$form.Font
    $window.ClientSize=[Drawing.Size]::new((UiPixel 600),(UiPixel 400))
    $header=[Windows.Forms.Label]::new();$header.Text='Перенос на другой ПК';$header.Font=[Drawing.Font]::new('Segoe UI Semibold',16)
    $header.SetBounds((UiPixel 24),(UiPixel 20),(UiPixel 552),(UiPixel 38));$window.Controls.Add($header)
    $note=[Windows.Forms.Label]::new();$note.Text="Экспортируйте аккаунт и телефоны в файл, затем импортируйте`r`nна другом ПК. APK на телефонах менять не нужно.`r`nФайл и пароль дают доступ к вашим телефонам.";$note.ForeColor=$muted
    $note.SetBounds((UiPixel 24),(UiPixel 65),(UiPixel 552),(UiPixel 80));$window.Controls.Add($note)
    $fields=@()
    foreach($spec in @(@('Пароль · минимум 12 символов',154),@('Повторите пароль для экспорта',223))){
        $label=[Windows.Forms.Label]::new();$label.Text=$spec[0];$label.ForeColor=$muted;$label.SetBounds((UiPixel 24),(UiPixel $spec[1]),(UiPixel 552),(UiPixel 24));$window.Controls.Add($label)
        $field=[Windows.Forms.TextBox]::new();$field.UseSystemPasswordChar=$true;$field.MaxLength=1024;$field.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$field.ForeColor=$form.ForeColor;$field.BorderStyle='FixedSingle'
        $field.SetBounds((UiPixel 24),(UiPixel ($spec[1]+27)),(UiPixel 552),(UiPixel 30));$window.Controls.Add($field);$fields+=$field
    }
    $message=[Windows.Forms.Label]::new();$message.ForeColor=$muted;$message.SetBounds((UiPixel 24),(UiPixel 291),(UiPixel 552),(UiPixel 40));$window.Controls.Add($message)
    $buttons=@()
    foreach($spec in @(@('Экспорт…',24,170),@('Импорт…',206,170),@('Закрыть',398,178))){
        $b=[PhoneExit.DarkButton]::new();$b.Text=$spec[0];$b.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$b.ForeColor=$form.ForeColor;$b.FlatStyle='Flat';$b.FlatAppearance.BorderSize=0
        $b.SetBounds((UiPixel $spec[1]),(UiPixel 340),(UiPixel $spec[2]),(UiPixel 40));$window.Controls.Add($b);$buttons+=$b
    }
    $buttons[0].Enabled=$false;$buttons[1].Enabled=$false
    $update={ $buttons[0].Enabled=($script:personalMode -and $fields[0].Text.Length -ge 12 -and $fields[0].Text -ceq $fields[1].Text);$buttons[1].Enabled=$fields[0].Text.Length -ge 12 }
    foreach($field in $fields){$field.Add_TextChanged($update)}
    $buttons[0].Add_Click({
        $dialog=[Windows.Forms.SaveFileDialog]::new();$dialog.Filter='Аккаунт Phone Exit (*.phoneexit)|*.phoneexit';$dialog.FileName='PhoneExit-account.phoneexit';$dialog.Title='Экспорт аккаунта';$dialog.OverwritePrompt=$true
        try{if($dialog.ShowDialog($window) -eq 'OK'){
            $window.UseWaitCursor=$true
            $result=InvokeAccountTransfer @{op='export';password=$fields[0].Text;profile=@{version=1;account=(LoadAccount);phones=@(LoadPhones)}}
            $temp=$dialog.FileName+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
            try{[IO.File]::WriteAllText($temp,$result.archive,[Text.UTF8Encoding]::new($false));if([IO.File]::Exists($dialog.FileName)){[IO.File]::Replace($temp,$dialog.FileName,$temp+'.bak')}else{[IO.File]::Move($temp,$dialog.FileName)}}finally{foreach($path in @($temp,$temp+'.bak')){if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}}
            $fields[0].Clear();$fields[1].Clear();$message.Text='Аккаунт экспортирован. Сохраните пароль отдельно от файла.'
        }}catch{$message.Text=$_.Exception.Message}finally{$window.UseWaitCursor=$false;$dialog.Dispose()}
    })
    $buttons[1].Add_Click({
        $dialog=[Windows.Forms.OpenFileDialog]::new();$dialog.Filter='Аккаунт Phone Exit (*.phoneexit)|*.phoneexit';$dialog.Title='Импорт аккаунта'
        try{if($dialog.ShowDialog($window) -eq 'OK'){
            if(([IO.FileInfo]::new($dialog.FileName)).Length -gt 524288){throw 'Файл аккаунта слишком большой.'}
            $window.UseWaitCursor=$true
            $result=InvokeAccountTransfer @{op='import';password=$fields[0].Text;archive=[IO.File]::ReadAllText($dialog.FileName)}
            if((LoadAccount) -and [Windows.Forms.MessageBox]::Show($window,'Импорт заменит текущий аккаунт и список телефонов на этом ПК. Продолжить?','Phone Exit','YesNo','Question') -ne 'Yes'){return}
            CloseDirectory
            try{WriteTransferredProfile $result.profile $script:profileDirectory}finally{StartDirectory}
            if($script:personalMode){$apkFolder.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$apkFolder.ForeColor=$form.ForeColor;$apkFolder.FlatStyle='Flat';$apkFolder.FlatAppearance.BorderSize=0}
            UpdateWindowLayout;$fields[0].Clear();$fields[1].Clear();$message.Text='Аккаунт импортирован. Телефоны обновляются автоматически.'
        }}catch{$message.Text=$_.Exception.Message}finally{$window.UseWaitCursor=$false;$dialog.Dispose()}
    })
    $buttons[2].Add_Click({$window.Close()});$window.KeyPreview=$true;$window.Add_KeyDown({param($sender,$e)if($e.KeyCode -eq 'Escape'){$window.Close()}})
    SetDesktopDialogStyle $window $header $null $null
    foreach($button in $buttons){$button.Anchor='Bottom, Left'}
    $message.Anchor='Bottom, Left, Right'
    $previewTimer=$null
    if($Preview){$previewTimer=[Windows.Forms.Timer]::new();$previewTimer.Interval=400;$previewTimer.Add_Tick({$previewTimer.Stop();SaveDesktopDialogPreview $window 'account';$window.Close()});$previewTimer.Start()}
    try{$null=$window.ShowDialog($form)}finally{if($previewTimer){$previewTimer.Dispose()};foreach($field in $fields){$field.Clear()};$header.Font.Dispose();$window.Dispose()}
}
$accountButton=ButtonAt 'Аккаунт…' 850 87 180
$accountButton.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$accountButton.ForeColor=$form.ForeColor;$accountButton.FlatStyle='Flat';$accountButton.FlatAppearance.BorderSize=0
$accountButton.Add_Click({try{ShowAccountTransfer}catch{$hint.Text='Не удалось открыть настройки аккаунта. Закройте окно настроек и повторите.'}})
