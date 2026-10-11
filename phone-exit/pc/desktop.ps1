param([switch]$SelfTest, [string]$UsbTestSerial, [switch]$VpnTest, [switch]$VpnTestApps)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-controls.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing
if(!$SelfTest -and !$VpnTest){
    $script:instanceCreated=$false
    $script:instanceMutex=[Threading.Mutex]::new($true,('Local\PhoneExitDesktop-'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value),[ref]$script:instanceCreated)
    if(!$script:instanceCreated){
        foreach($existing in [Diagnostics.Process]::GetProcessesByName('powershell')){
            if($existing.Id -ne $PID -and $existing.MainWindowTitle -eq 'Phone Exit'){
                $null=[PhoneExit.DesktopDpi]::ShowWindow($existing.MainWindowHandle,9)
                $null=[PhoneExit.DesktopDpi]::SetForegroundWindow($existing.MainWindowHandle)
            }
        }
        $script:instanceMutex.Dispose();return
    }
}
[PhoneExit.DesktopDpi]::Enable()
[System.Windows.Forms.Application]::EnableVisualStyles()
[Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)
[Windows.Forms.Application]::SetUnhandledExceptionMode([Windows.Forms.UnhandledExceptionMode]::ThrowException)
$script:client = $null
$script:outRead = $null
$script:errRead = $null
$script:stopping = $false
$script:failure = $false
$script:testStage = 0
$script:testStarted = [DateTime]::UtcNow
$script:testPassed = $false

$form = New-Object PhoneExit.DesktopWindow
$form.AutoScaleMode=[Windows.Forms.AutoScaleMode]::None
$form.Text = 'Phone Exit'
$form.Icon=[Drawing.Icon]::new((Join-Path $PSScriptRoot 'assets/phone-exit.ico'))
$form.Add_FormClosed({$form.Icon.Dispose()})
$form.ClientSize = New-Object System.Drawing.Size(960, 570)
$form.MinimumSize = $form.Size
$form.MaximumSize = $form.Size
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::FromArgb(245,247,250)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 10)

function LabelAt($text, $x, $y, $width, $height) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $text
    $label.SetBounds($x,$y,$width,$height)
    $form.Controls.Add($label)
    return $label
}
function ButtonAt($text, $x, $y, $width) {
    $button = New-Object PhoneExit.DarkButton
    $button.Text = $text
    $button.SetBounds($x,$y,$width,40)
    $form.Controls.Add($button)
    return $button
}
$title = LabelAt 'Phone Exit' 24 20 610 42
$title.Font = New-Object System.Drawing.Font('Segoe UI', 22, [System.Drawing.FontStyle]::Bold)
$null = LabelAt 'Интернет на ПК через Wi-Fi телефона' 26 69 610 28
$status = LabelAt 'Отключено' 26 112 610 44
$status.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
$start = ButtonAt 'Подключить телефон' 24 161 220
$stopButton = ButtonAt 'Остановить' 256 161 160
$stopButton.Enabled = $false
$codeHeading = LabelAt 'Код подключения' 26 222 600 25
$code = New-Object System.Windows.Forms.TextBox
$code.Multiline = $true
$code.ReadOnly = $true
$code.ScrollBars = 'Vertical'
$code.SetBounds(24,252,610,104)
$code.BackColor = [System.Drawing.Color]::White
$form.Controls.Add($code)
$copy = ButtonAt 'Скопировать код' 24 368 190
$copy.Enabled = $false
$hint = LabelAt 'Нажмите «Подключить телефон», затем вставьте код в Phone Exit на Android и нажмите «Подключить ПК».' 26 425 605 54
$detail = LabelAt 'TCP-прокси: SOCKS5 127.0.0.1:1080. Его нужно указать в настройках программы. Весь трафик Windows, UDP и выбор игр ещё не поддерживаются.' 26 489 605 64
$detail.ForeColor = [System.Drawing.Color]::FromArgb(75,85,100)

function StopClient {
    if ($null -eq $script:client -or $script:client.HasExited -or $script:stopping) { return }
    $script:stopping = $true
    $script:stopAt = [DateTime]::UtcNow
    $status.Text = 'Остановка соединения…'
    $stopButton.Enabled = $false
    $copy.Enabled = $false
    $code.Clear()
    try { $script:client.StandardInput.WriteLine('stop'); $script:client.StandardInput.Flush() } catch {}
}
function StartClient {
    try {
        if ($script:client) { return }
        if(!$SelfTest -and $mode.SelectedIndex -eq 1 -and $script:appPaths.Count -eq 0){$hint.Text='Добавьте EXE приложений, которые должны использовать VPN.';return}

        if ($script:personalMode -and !$SelfTest -and $script:phoneRows.Count -eq 0) {
            $hint.Text = 'Откройте персональное приложение на телефоне и включите Wi-Fi. Телефон появится здесь автоматически.'; return
        }
        $script:selectedPhone = $null
        if (!$SelfTest -and $script:phoneRows.Count -gt 0 -and $phoneList.SelectedIndex -lt 0) {
            $hint.Text = 'Выберите доступный телефон в списке стран справа.'; return
        }
        if ($phoneList.SelectedIndex -ge 0 -and (!$SelfTest -or $UsbTestSerial)) {
            $selected = $script:phoneRows[$phoneList.SelectedIndex]
            if (!$selected.online -or $selected.busy) { $hint.Text = 'Телефон недоступен. Включите на нём Wi-Fi и доступ в приложении Phone Exit.'; return }
            $script:selectedPhone = $selected.id
        }
        if (!(Test-Path -LiteralPath (Join-Path $PSScriptRoot 'node_modules/werift'))) {
            throw 'Не установлены зависимости. В каталоге pc выполните npm ci.'
        }
        $mode.Enabled=$false;$chooseApps.Enabled=$false
        $node = TransportRuntime
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $node
        $info.Arguments = '"' + (Join-Path $PSScriptRoot 'src/main.js') + '"'
        $info.WorkingDirectory = $PSScriptRoot
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardInput = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $info.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        $info.EnvironmentVariables['PHONE_EXIT_DESKTOP'] = '1'
        $info.EnvironmentVariables['PHONE_EXIT_PORT'] = '1080'
        $physicalRoute=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Where-Object InterfaceAlias -ne 'PhoneExit' | Sort-Object RouteMetric | Select-Object -First 1
        $physicalAddress=Get-NetIPAddress -InterfaceIndex $physicalRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop | Where-Object {$_.AddressState -eq 'Preferred' -and !$_.SkipAsSource} | Select-Object -First 1
        if(!$physicalAddress){throw 'Не найден исходный сетевой интерфейс'}
        $info.EnvironmentVariables['PHONE_EXIT_BIND_V4']=$physicalAddress.IPAddress
        $info.EnvironmentVariables['PHONE_EXIT_SIGNAL'] = 'https://demochko.com/hosting-webrtc-probe/signal.php'
        $script:client = New-Object System.Diagnostics.Process
        $script:client.StartInfo = $info
        $null = $script:client.Start()
        $script:startedAt = [DateTime]::UtcNow
        $script:outRead = $script:client.StandardOutput.ReadLineAsync()
        $script:errRead = $script:client.StandardError.ReadLineAsync()
        $script:failure = $false
        $script:stopping = $false
        $start.Enabled = $false
        $stopButton.Enabled = $true
        $copy.Enabled = $false
        $code.Clear()
        $script:lastPingAt=$null;$pingLabel.Text='Пинг до телефона: —'
        $status.Text = 'Подготовка подключения…'
        $hint.Text = if($script:personalMode){'Телефон принимает подключение автоматически.'}else{'Код действует 10 минут. Передайте его своему телефону; не публикуйте код.'}
    } catch {
        if ($script:client) { $script:client.Dispose(); $script:client = $null }
        $mode.Enabled=$true;$chooseApps.Enabled=$true
        $status.Text = 'Не удалось запустить клиент'
        $hint.Text = $_.Exception.Message
        if ($SelfTest) { throw }
    }
}
function HandleOutput([string]$line, [bool]$isError) {
    if ($script:stopping) { return }
    if ($line.StartsWith('{')) {
        try {
            $pair = $line | ConvertFrom-Json
            if($pair.event -eq 'ping' -and $null -ne $pair.rtt -and [double]$pair.rtt -ge 0 -and [double]$pair.rtt -le 60000){$script:lastPingAt=[DateTime]::UtcNow;$pingLabel.Text='Пинг до телефона: '+[int]$pair.rtt+' мс';return}
            if($pair.event -eq 'metrics'){$script:metrics=$pair;return}
            if($pair.event -eq 'transport'){$script:transportAddresses=@($pair.addresses);$script:udpAvailable=$pair.udp;return}
            if ($pair.version -eq 1 -and $pair.token -match '^[a-f0-9]{64}$') {
                if ($script:selectedPhone) {
                    DirectoryCommand @{op='connect';id=$script:selectedPhone;code=$pair}
                    $status.Text = 'Подключаю выбранный телефон…'
                    $hint.Text = 'Телефон принимает подключение автоматически. Дождитесь прямой связи.'
                } else {
                    $code.Text = $line
                    $copy.Enabled = $true
                    $status.Text = 'Ожидаю телефон'
                }
            }
        } catch {}
    } elseif ($line.StartsWith('Готово: SOCKS5')) {
        $status.Text = 'Подключено · TCP через Wi-Fi телефона'
        $code.Clear()
        $copy.Enabled = $false
        $hint.Text = 'SOCKS5: 127.0.0.1, порт 1080. В программе включите DNS через прокси (SOCKS5h).'
        StartVpn
    } elseif ($line -eq 'WebRTC: connecting') {
        $status.Text = 'Устанавливаю прямую связь…'
    } elseif ($isError) {
        if($VpnTest -and $line -match '^(TypeError:|RangeError:|Error:|Телефон |Нет прямой |Сигнализация:)'){Write-Host ('PC error: '+($line -replace '[a-f0-9]{32,}','[id]' -replace '(?:[0-9]{1,3}\.){3}[0-9]{1,3}','[address]'))}
        # Display known operational messages only; never expose raw stacks or capabilities.
        $script:failure = $true
        $status.Text = 'Соединение остановлено'
        if ($line -match '^(Истекло время сопряжения|Телефон остановил выход|Телефон не отвечает, прокси остановлен|Нет прямой связи с телефоном|Телефон отключён|Сигнализация: HTTP [0-9]{3})$') {
            $hint.Text = $line
        } elseif ($line -match 'EADDRINUSE') {
            $hint.Text = 'Порт 1080 занят. Остановите другой клиент или программу, использующую этот порт.'
        } else {
            $hint.Text = 'Не удалось установить связь. Проверьте интернет на ПК и Wi-Fi на телефоне, затем повторите подключение.'
        }
    }
}
$start.Add_Click({ StartClient })
$stopButton.Add_Click({ StopVpn; $script:failure = $false; StopClient; if(!$script:client){$status.Text='Отключено';$hint.Text='Обычное подключение восстанавливается.';$start.Enabled=$true;$stopButton.Enabled=$false;$mode.Enabled=$true;$chooseApps.Enabled=$true} })
$copy.Add_Click({
    if ($code.Text) {
        try { [System.Windows.Forms.Clipboard]::SetText($code.Text); $hint.Text = 'Код скопирован. Вставьте его в приложение на телефоне.' }
        catch { $hint.Text = 'Не удалось скопировать. Выделите код и нажмите Ctrl+C.' }
    }
})
. (Join-Path $PSScriptRoot 'desktop-directory.ps1')
. (Join-Path $PSScriptRoot 'desktop-vpn.ps1')
if($VpnTest){ . (Join-Path $PSScriptRoot 'test-vpn-desktop.ps1') }
if ($SelfTest) { $script:expectedPhoneCount = @(LoadPhones).Count }
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 100
$timer.Add_Tick({
    if($script:tickBusy){return};$script:tickBusy=$true
    try {
    ReadDirectory
    if ($script:client) {
        if ($script:selectedPhone -and !$script:stopping -and !$status.Text.StartsWith('Подключено') -and ([DateTime]::UtcNow - $script:startedAt).TotalSeconds -gt 45) {
            $script:failure = $true
            StopClient
            $hint.Text = 'Телефон не установил прямую связь за 45 секунд. Проверьте Wi-Fi и фильтры трафика, затем повторите подключение.'
        }
        foreach ($kind in @('out','err')) {
            for ($i = 0; $i -lt 50; $i++) {
                $task = if ($kind -eq 'out') { $script:outRead } else { $script:errRead }
                if ($null -eq $task -or !$task.IsCompleted) { break }
                $line = $task.GetAwaiter().GetResult()
                if ($null -ne $line) { HandleOutput $line ($kind -eq 'err') }
                $next = $null
                if ($null -ne $line) {
                    $reader = if ($kind -eq 'out') { $script:client.StandardOutput } else { $script:client.StandardError }
                    $next = $reader.ReadLineAsync()
                }
                if ($kind -eq 'out') { $script:outRead = $next } else { $script:errRead = $next }
            }
        }
        if ($script:stopping -and !$script:client.HasExited -and ([DateTime]::UtcNow - $script:stopAt).TotalSeconds -gt 5) { $script:client.Kill() }
        if ($script:client.HasExited -and $null -eq $script:outRead -and $null -eq $script:errRead) {
            if (!$script:failure) { $status.Text = 'Отключено'; $hint.Text = 'Соединение остановлено. Можно подключиться заново.' }
            else { $status.Text = 'Соединение остановлено' }
            $script:client.Dispose(); $script:client = $null
            $code.Clear(); $copy.Enabled = $false; $stopButton.Enabled = $false; $start.Enabled = $true
            $mode.Enabled=$script:vpnState -ne 'active';$chooseApps.Enabled=$mode.Enabled
        }
    }
    if(!$script:client -or $script:stopping -or $script:client.HasExited -or !$script:lastPingAt -or ([DateTime]::UtcNow-$script:lastPingAt).TotalSeconds -gt 6){$pingLabel.Text='Пинг до телефона: —'}
    ReadVpn
    if($VpnTest){ TestVpnTick }
    if ($SelfTest) {
        if ($UsbTestSerial) { TestDirectoryTick; return }
        if ($script:testStage -eq 0) { $script:testStage = 1; $start.PerformClick() }
        elseif ($script:testStage -eq 1 -and $copy.Enabled) {
            $script:testStage = 2
            $stopButton.PerformClick()
        } elseif ($script:testStage -eq 2 -and $null -eq $script:client -and $start.Enabled -and !$code.Text -and $script:phoneRows.Count -eq $script:expectedPhoneCount) {
            . (Join-Path $PSScriptRoot 'test-window-layout.ps1')
            TestWindowLayout
            $bitmap = New-Object System.Drawing.Bitmap($form.Width,$form.Height)
            $form.DrawToBitmap($bitmap, (New-Object System.Drawing.Rectangle(0,0,$form.Width,$form.Height)))
            $bitmap.Save((Join-Path $PSScriptRoot '../desktop-preview.png'))
            $bitmap.Dispose()
            $script:testStage = 3
            $start.PerformClick()
        } elseif ($script:testStage -eq 3 -and $copy.Enabled) {
            $script:testPassed = $true
            $form.Close()
        }
        if (([DateTime]::UtcNow - $script:testStarted).TotalSeconds -gt 30) { $form.Close() }
    }
    } finally {$script:tickBusy=$false}
})
$form.Add_FormClosing({
    $timer.Stop()
    StopVpn
    if ($script:client) {
        StopClient
        if (!$script:client.WaitForExit(5000)) { $script:client.Kill(); $script:client.WaitForExit(2000) | Out-Null }
        $script:client.Dispose(); $script:client = $null
    }
    CloseDirectory
})
try { StartDirectory } catch { $hint.Text = 'Не удалось открыть список телефонов. Проверьте Node.js и файл привязок.' }
. (Join-Path $PSScriptRoot 'desktop-theme.ps1')
$timer.Start()
try { $null = $form.ShowDialog() } finally { StopVpn; if($script:client){try{$script:client.StandardInput.Close();if(!$script:client.WaitForExit(4000)){$script:client.Kill()}}catch{}};CloseDirectory }
$timer.Dispose()
$form.Dispose()
if($VpnTest -and !$script:vpnTestPassed){throw 'VPN system test did not pass'}
if ($SelfTest) {
    if (!$script:testPassed) { throw "Desktop smoke test failed at stage $($script:testStage), phones=$($script:phoneRows.Count), status=$($status.Text), hint=$($hint.Text)" }
    if ($UsbTestSerial) { Write-Output 'PASS: saved private enrollment, country and online status, automatic WebRTC, HTTPS through phone, reconnect without new enrollment' }
    else { Write-Output 'PASS: desktop starts real client, shows pairing, stops child, clears code, reconnects, closes active child on window close' }
}
