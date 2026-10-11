$script:vpnFolder=$null
$script:vpnState='off'
$script:transportAddresses=@()
$script:udpAvailable=$false
$script:appPaths=@()
function StartVpn {
    if($SelfTest -or $mode.SelectedIndex -eq 2){return}
    if(!$script:udpAvailable){$hint.Text='Для VPN обновите APK на выбранном телефоне: текущая версия поддерживает только TCP.';return}
    if($mode.SelectedIndex -eq 1 -and $script:appPaths.Count -eq 0){$hint.Text='Сначала добавьте EXE программ и игр.';return}
    try {
        if($VpnTest){$script:expectedIp=(& curl.exe --silent --show-error --fail --max-time 15 --socks5-hostname 127.0.0.1:1080 https://api.ipify.org);if($LASTEXITCODE -ne 0){throw 'Baseline proxy check failed'}}
        $id=[Guid]::NewGuid().ToString('N');$script:vpnFolder=Join-Path $PSScriptRoot ('../.tools/vpn/'+$id)
        $null=[IO.Directory]::CreateDirectory($script:vpnFolder)
        $request=@{mode=$(if($mode.SelectedIndex -eq 1){'apps'}else{'all'});applications=@($script:appPaths);transportAddresses=@($script:transportAddresses);nodePath=(TransportRuntime)}|ConvertTo-Json -Depth 5 -Compress
        $config=$request | & node.exe (Join-Path $PSScriptRoot 'src/vpn-config-cli.js')
        if($LASTEXITCODE -ne 0){throw 'Configuration failed'}
        if($VpnTest){$testConfig=$config | ConvertFrom-Json;$testConfig.log=[PSCustomObject]@{disabled=$false;level='error'};$config=$testConfig|ConvertTo-Json -Depth 12 -Compress}
        [IO.File]::WriteAllText((Join-Path $script:vpnFolder 'config.json'),$config,[Text.UTF8Encoding]::new($false))
        $engine=Join-Path $PSScriptRoot '../.tools/sing-box/sing-box.exe'
        & $engine check -c (Join-Path $script:vpnFolder 'config.json') 2>$null
        if($LASTEXITCODE -ne 0){throw 'Engine check failed'}
        $script:vpnState='starting'
        if($VpnTest){Write-Host 'TEST: launching elevated VPN helper'}
        $null=Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $PSScriptRoot 'vpn-helper.ps1')+'" -Session '+$id+' -OwnerProcessId '+$PID) -PassThru
        if($VpnTest){Write-Host 'TEST: helper launch returned';$script:testStarted=[DateTime]::UtcNow}
        $hint.Text='Подтвердите запрос Windows. Включается виртуальный сетевой интерфейс.'
    }catch{if($VpnTest){Write-Host ('TEST: helper launch error '+$_.Exception.GetType().Name)};$script:vpnState='off';$hint.Text='VPN не включён. Запрос администратора отменён или движок недоступен. Соединение с телефоном остаётся в режиме прокси.'}
}
function StopVpn {
    if($script:vpnFolder){[IO.File]::WriteAllText((Join-Path $script:vpnFolder 'stop'),'stop')}
    $script:vpnState='off'
}
function ReadVpn {
    if(!$script:vpnFolder -or $script:vpnState -eq 'off'){return}
    $file=Join-Path $script:vpnFolder 'status.json'
    if(Test-Path -LiteralPath $file){try{$state=([IO.File]::ReadAllText($file)|ConvertFrom-Json).state}catch{return}
        if($state -eq 'active'){
            $script:vpnState='active'
            if($script:client -and !$script:failure -and !$script:stopping){$status.Text='Подключено · VPN';$hint.Text=if($mode.SelectedIndex -eq 1){'Выбранные EXE используют телефон. Остальные программы работают через обычный интернет.'}else{'TCP, UDP и DNS идут через телефон. Чтобы вернуть обычный интернет, нажмите «Отключить».'}}
            elseif(!$script:stopping){$status.Text='Связь потеряна · трафик заблокирован';$hint.Text='VPN удерживает выбранный трафик. Нажмите «Отключить», чтобы вернуть обычное подключение.';$stopButton.Enabled=$true;$start.Enabled=$false}
        }elseif($state -eq 'failed'){$script:vpnState='failed';$status.Text='VPN не запущен';$hint.Text='Не удалось запустить виртуальный интерфейс. Проверьте права администратора и другой активный VPN.'}
    }
}
