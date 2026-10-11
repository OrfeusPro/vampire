# Dot-sourced by desktop.ps1; all secrets travel only through private child pipes.
Add-Type -AssemblyName System.Security
$script:directory = $null
$script:directoryRead = $null
$script:directoryErr = $null
$script:phoneRows = @()
$script:selectedPhone = $null
$script:personalMode = $false
$script:phonesFile = Join-Path $script:profileDirectory 'phones.bin'
$script:accountFile = Join-Path $script:profileDirectory 'account.bin'
$null = LabelAt 'Мои телефоны по странам' 660 112 280 40
$phoneList = New-Object PhoneExit.DarkPhoneList
$phoneList.SetBounds(660,161,276,220)
$phoneList.AccessibleName = 'Мои телефоны'
$form.Controls.Add($phoneList)
$phoneNameLabel = LabelAt 'Имя нового телефона' 660 392 275 25
$phoneName = New-Object System.Windows.Forms.TextBox
$phoneName.SetBounds(660,420,276,28)
$phoneName.MaxLength = 40
$phoneName.Text = 'Мой телефон'
$form.Controls.Add($phoneName)
$addPhone = ButtonAt 'Добавить телефон' 660 464 276
$removePhone = ButtonAt 'Удалить выбранный' 660 513 276
$removePhone.Enabled = $false
$phoneList.Add_SelectedIndexChanged({ $removePhone.Enabled = $phoneList.SelectedIndex -ge 0 })

function TransportRuntime {
    $target=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.tools/transport/PhoneExitTransport.exe'))
    if(!(Test-Path -LiteralPath $target)){$null=[IO.Directory]::CreateDirectory((Split-Path -Parent $target));Copy-Item -LiteralPath (Get-Command node.exe -ErrorAction Stop).Source -Destination $target}
    return $target
}
function DirectoryCommand($command) {
    if (!$script:directory -or $script:directory.HasExited) { throw 'Каталог телефонов недоступен. Перезапустите приложение.' }
    $script:directory.StandardInput.WriteLine(($command | ConvertTo-Json -Depth 10 -Compress))
    $script:directory.StandardInput.Flush()
}
function SavePhones($phones) {
    $raw = ConvertTo-Json -InputObject @($phones) -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $null = [System.IO.Directory]::CreateDirectory((Split-Path -Parent $script:phonesFile))
    $temp = $script:phonesFile + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [System.IO.File]::WriteAllBytes($temp,$protected)
    if ([System.IO.File]::Exists($script:phonesFile)) { [System.IO.File]::Replace($temp,$script:phonesFile,$temp+'.bak'); [IO.File]::Delete($temp+'.bak') }
    else { [System.IO.File]::Move($temp,$script:phonesFile) }
}
function LoadPhones {
    if (!(Test-Path -LiteralPath $script:phonesFile)) { return @() }
    $bytes = [System.IO.File]::ReadAllBytes($script:phonesFile)
    if ($bytes.Length -gt 262144) { throw 'Файл привязок повреждён' }
    $raw = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    # Windows PowerShell 5.1 emits a JSON array as one pipeline object.
    # Enumerate explicitly so ConvertTo-Json cannot wrap it as {value, Count}.
    $decoded = [System.Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
    foreach ($phone in $decoded) { Write-Output $phone }
}
function LoadAccount {
    if (!(Test-Path -LiteralPath $script:accountFile)) { return $null }
    $bytes=[IO.File]::ReadAllBytes($script:accountFile)
    if($bytes.Length -gt 65536) { throw 'Файл личного списка повреждён' }
    $raw=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    return ([Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json)
}
function SaveAccount($account) {
    $raw=$account | ConvertTo-Json -Depth 8 -Compress
    $bytes=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($raw),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $temp=$script:accountFile+'.tmp'; [IO.File]::WriteAllBytes($temp,$bytes)
    [IO.File]::Replace($temp,$script:accountFile,$temp+'.bak'); [IO.File]::Delete($temp+'.bak')
}
function PersonalMode {
    $script:personalMode = $true
    $phoneNameLabel.Visible=$false; $phoneName.Visible=$false; $addPhone.Visible=$false
    $code.Visible=$false; $copy.Visible=$false
    $codeHeading.Text='Автоматическое подключение'
    if(!(Get-Command UiPixel -ErrorAction SilentlyContinue)){$null=LabelAt 'Установите персональный APK на свои телефоны и откройте приложение один раз. Телефоны появятся в списке справа автоматически. Выберите телефон по стране и подключитесь. При потере Wi-Fi телефон сам повторяет подключение к серверу.' 26 252 605 104}
    $hint.SetBounds(26,368,605,100)
    $hint.Text='Телефоны с включённым автоматическим доступом появятся в списке.'
    $removePhone.SetBounds(660,464,276,40)
    if(!(Get-Command UiPixel -ErrorAction SilentlyContinue)){$null=LabelAt 'Добавление без кодов: установите PhoneExit-personal.apk на свой телефон.' 660 400 276 54}
    $script:apkFolder=ButtonAt 'Папка с APK' 660 513 276
    $apkFolder.Add_Click({ Start-Process explorer.exe -ArgumentList ('/select,"'+(Join-Path $PSScriptRoot '../PhoneExit-personal.apk')+'"') })
}
function CountryName($country) {
    $names = @{UA='Украина';PL='Польша';DE='Германия';US='США';GB='Великобритания';NL='Нидерланды';FR='Франция';JP='Япония';CZ='Чехия';RO='Румыния';MD='Молдова';RU='Россия';CA='Канада';FI='Финляндия';SE='Швеция';IT='Италия';ES='Испания';BG='Болгария';TR='Турция'}
    if (!$country) { return 'Страна неизвестна' }
    if ($names.ContainsKey($country)) { return $names[$country] }
    if(!$script:allCountryNames){$script:allCountryNames=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'assets/flags/countries-ru.json'))|ConvertFrom-Json}
    if($script:allCountryNames.$country){return $script:allCountryNames.$country}
    return $country
}
function DirectoryEvent($event) {
    switch ($event.event) {
        'save' { SavePhones $event.phones }
        'saveAccount' { SaveAccount $event.account }
        'enroll' {
            $script:usbPhoneId = ($event.code | ConvertFrom-Json).id
            $code.Text = $event.code; $copy.Enabled = $true
            $hint.Text = 'Один раз вставьте этот код в Phone Exit на телефоне. Затем включайте «Доступ для своего ПК», а здесь выбирайте телефон по стране.'
            if ($UsbTestSerial) {
                $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($event.code))
                & adb.exe -s $UsbTestSerial shell am force-stop net.phoneexit | Out-Null
                & adb.exe -s $UsbTestSerial shell am start -n net.phoneexit/.UsbTestActivity --es testPairingBase64 $encoded | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'USB enrollment failed' }
            }
        }
        'phones' {
            $selected = if ($phoneList.SelectedIndex -ge 0) { $script:phoneRows[$phoneList.SelectedIndex].id } else { $null }
            $script:phoneRows = @($event.phones | Sort-Object country,name)
            if($heading){$heading.Text='Мои телефоны · '+$script:phoneRows.Count}
            $phoneList.BeginUpdate(); $phoneList.Items.Clear()
            for ($i=0; $i -lt $script:phoneRows.Count; $i++) {
                $phone = $script:phoneRows[$i]
                $state = if (!$phone.online) { 'не в сети' } elseif ($phone.busy) { 'занят' } else { 'доступен' }
                if ($script:client -and !$script:stopping -and $script:selectedPhone -eq $phone.id) { $state = 'подключён к этому ПК' }
                $null = $phoneList.Items.Add("$(CountryName $phone.country) · $($phone.name) · $state")
                if ($phone.id -eq $selected) { $phoneList.SelectedIndex = $i }
            }
            if ($phoneList.SelectedIndex -lt 0 -and $script:phoneRows.Count -eq 1) { $phoneList.SelectedIndex=0 }
            $phoneList.EndUpdate()
            if($hint.Text.StartsWith('Обновляю доступность телефонов') -and @($script:phoneRows | Where-Object online).Count -gt 0){$hint.Text='Список телефонов обновлён. Выберите устройство и нажмите «Подключить VPN».'}
        }
        'error' { $hint.Text = $event.message; if ($SelfTest) { Write-Host ('Directory command failed: ' + $event.reason) }; if ($script:selectedPhone -and !$script:transportReady) { StopClient } }
    }
}
function StartDirectory {
    $phones = @(LoadPhones)
    $account=LoadAccount
    if($account -and !$script:personalMode) { PersonalMode }
    DirectoryEvent ([PSCustomObject]@{event='phones';phones=@($phones | ForEach-Object {[PSCustomObject]@{id=$_.id;name=$_.name;country='';online=$false;busy=$false}})})
    $hint.Text='Обновляю доступность телефонов… Сохранённые устройства уже в списке.'
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = TransportRuntime
    $info.Arguments = '"' + (Join-Path $PSScriptRoot 'src/directory.js') + '"'
    $info.WorkingDirectory = $PSScriptRoot; $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [System.Text.Encoding]::UTF8; $info.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $script:directory = New-Object System.Diagnostics.Process
    $script:directory.StartInfo = $info
    $null = $script:directory.Start()
    $script:directoryRead = $script:directory.StandardOutput.ReadLineAsync()
    $script:directoryErr = $script:directory.StandardError.ReadLineAsync()
    DirectoryCommand @{op='init';phones=$phones;account=$account}
}
function ReadDirectory {
    if (!$script:directory) { return }
    while ($script:directoryRead -and $script:directoryRead.IsCompleted) {
        $line = $script:directoryRead.GetAwaiter().GetResult()
        if ($null -eq $line) { $script:directoryRead = $null; break }
try { DirectoryEvent ($line | ConvertFrom-Json) } catch { $hint.Text = 'Не удалось обработать каталог или сохранить привязку.'; if ($SelfTest) { Write-Host ('Directory event failed: ' + $_.Exception.GetType().Name) } }
        $script:directoryRead = $script:directory.StandardOutput.ReadLineAsync()
    }
    while ($script:directoryErr -and $script:directoryErr.IsCompleted) {
        $line = $script:directoryErr.GetAwaiter().GetResult()
        if ($null -eq $line) { $script:directoryErr = $null; break }
        $script:directoryErr = $script:directory.StandardError.ReadLineAsync()
    }
    if ($script:directory.HasExited) {
        $script:directory.Dispose(); $script:directory=$null
        foreach ($phone in $script:phoneRows) { $phone.online=$false }
        DirectoryEvent ([PSCustomObject]@{event='phones';phones=$script:phoneRows})
        $addPhone.Enabled=$false; $hint.Text='Каталог телефонов остановлен. Перезапустите приложение.'
    }
}
function CloseDirectory {
    if ($script:directory) {
        try { DirectoryCommand @{op='stop'} } catch {}
        if (!$script:directory.WaitForExit(2000)) { $script:directory.Kill() }
        $script:directory.Dispose(); $script:directory = $null
    }
}
$addPhone.Add_Click({
    if ($script:client) { $hint.Text = 'Перед добавлением телефона остановите соединение.'; return }
    try { DirectoryCommand @{op='add';name=$phoneName.Text} }
    catch { $hint.Text = $_.Exception.Message }
})
$removePhone.Add_Click({
    if ($phoneList.SelectedIndex -lt 0) { return }
    $phone = $script:phoneRows[$phoneList.SelectedIndex]
    if ([System.Windows.Forms.MessageBox]::Show('Удалить телефон из списка? Удалите также привязку в приложении телефона.','Phone Exit','YesNo','Question') -eq 'Yes') {
        if ($script:selectedPhone -eq $phone.id -or $script:reconnectPhone -eq $phone.id) { CancelReconnect;StopVpn;StopClient }
        DirectoryCommand @{op='remove';id=$phone.id}
        $code.Clear(); $copy.Enabled = $false
    }
})
function TestDirectoryTick {
    if ($script:testStage -eq 0) {
        $script:testStage=10
        $saved = @(LoadPhones) | Where-Object { $_.name -eq 'vivo V2061' } | Select-Object -Last 1
        if ($saved) {
            $enroll = @{version=2;mode='directory';signal='https://demochko.com/hosting-webrtc-probe/signal.php';id=$saved.id;name=$saved.name;token=$saved.token} | ConvertTo-Json -Compress
            DirectoryEvent ([PSCustomObject]@{event='enroll';code=$enroll})
        } else { $phoneName.Text='vivo V2061'; $addPhone.PerformClick() }
    }
    elseif ($script:testStage -eq 10) {
        for ($i=0; $i -lt $script:phoneRows.Count; $i++) {
            if ($script:phoneRows[$i].id -eq $script:usbPhoneId -and $script:phoneRows[$i].online -and !$script:phoneRows[$i].busy) { $phoneList.SelectedIndex=$i; $script:testStage=11; $start.PerformClick(); break }
        }
    } elseif ($script:testStage -eq 11 -and $status.Text.StartsWith('Подключено')) {
        & curl.exe --max-time 20 --silent --fail --socks5-hostname 127.0.0.1:1080 https://api.ipify.org | Out-Null
        if ($LASTEXITCODE -ne 0) { $script:testStage=99; $form.Close(); return }
        $bitmap = New-Object System.Drawing.Bitmap($form.Width,$form.Height)
        $form.DrawToBitmap($bitmap,(New-Object System.Drawing.Rectangle(0,0,$form.Width,$form.Height)))
        $bitmap.Save((Join-Path $PSScriptRoot '../desktop-preview.png')); $bitmap.Dispose()
        $script:testStage=12; $stopButton.PerformClick()
    } elseif ($script:testStage -eq 12 -and $null -eq $script:client) {
        $selected = $script:phoneRows[$phoneList.SelectedIndex]
        if ($selected.online -and !$selected.busy) { $script:testStage=13; $start.PerformClick() }
    } elseif ($script:testStage -eq 13 -and $status.Text.StartsWith('Подключено')) {
        & curl.exe --max-time 20 --silent --fail --socks5-hostname 127.0.0.1:1080 https://api.ipify.org | Out-Null
        if ($LASTEXITCODE -ne 0) { $form.Close(); return }
        $script:testPassed=$true; $form.Close()
    }
    if (([DateTime]::UtcNow - $script:testStarted).TotalSeconds -gt 90) {
        Write-Output "USB desktop timeout: stage=$($script:testStage), status=$($status.Text), phones=$($script:phoneRows.Count)"
        $form.Close()
    }
}
