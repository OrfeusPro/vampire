$script:vpnFolder=$null
$script:vpnState='off'
$script:transportAddresses=@()
$script:udpAvailable=$false
$script:appPaths=@()
function StartVpn {
    if($SelfTest -or $mode.SelectedIndex -eq 2){return}
    if($script:vpnState -in @('starting','active')){
        # Keep the existing TUN (and its blocking policy) during recovery.
        [IO.File]::WriteAllText((Join-Path $script:vpnFolder 'transport.json'),(ConvertTo-Json -InputObject @($script:transportAddresses) -Compress),[Text.UTF8Encoding]::new($false))
        return
    }
    if(!$script:udpAvailable){$hint.Text='Для VPN обновите APK на выбранном телефоне: текущая версия поддерживает только TCP.';return}
    if($mode.SelectedIndex -eq 1 -and $script:appPaths.Count -eq 0){$hint.Text='Сначала добавьте EXE программ и игр.';return}
    try {
        if($VpnTest){$script:expectedIp=(& curl.exe --silent --show-error --fail --max-time 15 --socks5-hostname 127.0.0.1:1080 https://api.ipify.org);if($LASTEXITCODE -ne 0){throw 'Baseline proxy check failed'}}
        $id=[Guid]::NewGuid().ToString('N');$script:vpnFolder=Join-Path $PSScriptRoot ('../.tools/vpn/'+$id)
        $null=[IO.Directory]::CreateDirectory($script:vpnFolder)
        $script:appRulesFile=Join-Path $script:vpnFolder 'applications-rules.json'
        $script:appPaths=@($script:appPaths|ForEach-Object{[IO.Path]::GetFullPath($_)})
        $directRoute=Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object InterfaceAlias -ne 'PhoneExit' | Sort-Object RouteMetric | Select-Object -First 1
        $request=@{mode=$(if($mode.SelectedIndex -eq 1){'apps'}else{'all'});physicalInterface=$directRoute.InterfaceAlias;applications=@($script:appPaths);applicationRuleFile=$script:appRulesFile;transportAddresses=@($script:transportAddresses)+@($script:bootstrapAddresses);nodePath=(TransportRuntime)}|ConvertTo-Json -Depth 5 -Compress
        [IO.File]::WriteAllText((Join-Path $script:vpnFolder 'applications.json'),(ConvertTo-Json -InputObject @($script:appPaths) -Compress),[Text.UTF8Encoding]::new($false))
        $regexPaths=@($script:appPaths | ForEach-Object {'(?i)^'+[regex]::Escape($_)+'$'})
        $rules=@{version=3;rules=@(@{process_path_regex=$regexPaths})}|ConvertTo-Json -Depth 5 -Compress
        if($mode.SelectedIndex -eq 1){[IO.File]::WriteAllText($script:appRulesFile,$rules,[Text.UTF8Encoding]::new($false))}
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
            if($script:client -and $script:transportReady -and !$script:failure -and !$script:stopping){$status.Text='Подключено · VPN';$hint.Text=if($mode.SelectedIndex -eq 1){'Выбранные приложения и найденные дочерние EXE используют телефон. Остальные — обычный интернет.'}else{'TCP, UDP и DNS идут через телефон. При обрыве ПК автоматически восстановит связь.'}}
            elseif(!$script:stopping){$status.Text='Связь потеряна · трафик заблокирован';$hint.Text=if($script:connectionWanted){'VPN удерживает выбранный трафик. Ожидаю тот же телефон для автоматического подключения.'}else{'VPN удерживает выбранный трафик. Нажмите «Отключить», чтобы вернуть обычное подключение.'};$stopButton.Enabled=$true;$start.Enabled=$false}
        }elseif($state -eq 'failed'){$script:vpnState='failed';CancelReconnect;StopClient;$status.Text='VPN не запущен';$hint.Text='Виртуальный интерфейс остановлен. Проверьте права администратора и другой активный VPN.'}
    }
    if($mode.SelectedIndex -eq 1 -and $script:vpnState -eq 'active'){
        try{$appsState=[IO.File]::ReadAllText((Join-Path $script:vpnFolder 'applications-status.json'))|ConvertFrom-Json
            $appNote.Text="В списке: $($script:appPaths.Count) · в VPN: $($appsState.count) EXE"
            if($appsState.limit -or $appsState.error){$hint.Text='Новые дочерние EXE не добавляются. Остановите VPN и добавьте EXE игры явно.'}
        }catch{}
    }
}
