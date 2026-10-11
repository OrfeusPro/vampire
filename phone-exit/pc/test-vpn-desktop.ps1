$script:vpnTestStage=0;$script:vpnTestPassed=$false
function TestVpnTick {
    try {
        if($script:vpnTestStage -eq 0){
            for($i=0;$i -lt $script:phoneRows.Count;$i++){
                $p=$script:phoneRows[$i]
                if($p.name -match 'V2061' -and $p.online -and !$p.busy){$phoneList.SelectedIndex=$i;$mode.SelectedIndex=$(if($VpnTestApps){1}else{0});if($VpnTestApps){$script:appPaths=@((Get-Command curl.exe).Source,(Join-Path $PSHOME 'powershell.exe'));$script:directProbe=Join-Path $PSScriptRoot '../.tools/transport/DirectProbe.exe';Copy-Item -LiteralPath (Get-Command curl.exe).Source -Destination $script:directProbe -Force};$script:vpnTestStage=1;StartClient;break}
            }
        }elseif($script:vpnTestStage -eq 1 -and $script:vpnState -eq 'active'){
            $script:vpnTestStage=2
            $viaPhone=$script:expectedIp
            $viaSystem=(& curl.exe --noproxy '*' --silent --show-error --fail --max-time 15 https://api.ipify.org)
            Write-Host ('System TCP curl exit code: '+$LASTEXITCODE+'; phone exit matches: '+($viaPhone -eq $viaSystem))
            if($LASTEXITCODE -ne 0 -or $viaPhone -ne $viaSystem){
                while($script:outRead -and $script:outRead.IsCompleted){$line=$script:outRead.GetAwaiter().GetResult();if($null -eq $line){break};HandleOutput $line $false;$script:outRead=$script:client.StandardOutput.ReadLineAsync()}
                if($script:metrics){Write-Host ('TCP counters: active='+$script:metrics.active+' rejected='+$script:metrics.rejected+' opened='+$script:metrics.opened+' ready='+$script:metrics.ready+' errors='+$script:metrics.errors)}
                throw 'System TCP exit differs'
            }
            Write-Host 'PASS: system TCP uses phone exit without application proxy settings (IP not logged)'
            $udp=New-Object Net.Sockets.UdpClient
            try {
                $udp.Client.ReceiveTimeout=3000
                $ip=[Net.Dns]::GetHostAddresses('stun.l.google.com') | Where-Object AddressFamily -eq InterNetwork | Select-Object -First 1
                $packet=[byte[]](0,1,0,0,0x21,0x12,0xa4,0x42,1,2,3,4,5,6,7,8,9,16,17,18)
                $udp.Connect($ip,19302)
                $reply=$null
                for($attempt=0;$attempt -lt 3 -and !$reply;$attempt++){
                    $null=$udp.Send($packet,$packet.Length)
                    $remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
                    try{$reply=$udp.Receive([ref]$remote)}catch [Net.Sockets.SocketException]{}
                }
                if(!$reply){throw 'No system UDP STUN response'}
                if($reply.Length -lt 20 -or $reply[0] -ne 1 -or $reply[1] -ne 1){throw 'UDP STUN response invalid'}
                for($n=8;$n -lt 20;$n++){if($reply[$n] -ne $packet[$n]){throw 'UDP transaction mismatch'}}
            }finally{$udp.Close()}
            Write-Host 'PASS: system UDP STUN and DNS through VPN'
            $script:client.Kill()
            Start-Sleep -Milliseconds 500
            & curl.exe --silent --fail --connect-timeout 3 --max-time 4 https://1.1.1.1/cdn-cgi/trace 2>$null | Out-Null
            if($LASTEXITCODE -eq 0){throw 'Traffic escaped after proxy loss'}
            Write-Host 'PASS: system traffic stays blocked when phone proxy disappears'
            if($VpnTestApps){& $script:directProbe --noproxy '*' --silent --fail --max-time 15 https://example.com | Out-Null;if($LASTEXITCODE -ne 0){throw 'Unselected program lost ordinary internet'};Write-Host 'PASS: unselected EXE still has DNS and HTTPS after phone loss'}
            StopVpn;$script:vpnTestStage=3
        }elseif($script:vpnTestStage -eq 3){
            $statusFile=Join-Path $script:vpnFolder 'status.json'
            if(Test-Path -LiteralPath $statusFile){$state=([IO.File]::ReadAllText($statusFile)|ConvertFrom-Json).state
                if($state -eq 'stopped'){
                    & curl.exe --silent --fail --max-time 15 https://example.com | Out-Null
                    if($LASTEXITCODE -ne 0){throw 'Normal network not restored'}
                    Write-Host 'PASS: disabling VPN restores ordinary internet'
                    $script:vpnTestPassed=$true;$form.Close()
                }
            }
        }elseif($script:vpnState -eq 'failed') {throw 'Elevated VPN helper failed'}
    }catch {while($script:client -and $script:errRead -and $script:errRead.IsCompleted){$errorLine=$script:errRead.GetAwaiter().GetResult();if($null -eq $errorLine){break};if($errorLine -match '^(TypeError:|RangeError:|Error:|Телефон |Нет прямой |Сигнализация:)'){Write-Host ('PC error: '+($errorLine -replace '[a-f0-9]{32,}','[id]' -replace '(?:[0-9]{1,3}\.){3}[0-9]{1,3}','[address]'))};$script:errRead=$script:client.StandardError.ReadLineAsync()};Write-Host ('FAIL: '+$_.Exception.Message);Write-Host ('Client exited: '+$(if($script:client){$script:client.HasExited}else{$true})+'; UI state: '+$status.Text+'; hint: '+$hint.Text);while($script:client -and $script:outRead -and $script:outRead.IsCompleted){$line=$script:outRead.GetAwaiter().GetResult();if($null -eq $line){break};HandleOutput $line $false;$script:outRead=$script:client.StandardOutput.ReadLineAsync()};if($script:metrics){Write-Host ($script:metrics | ConvertTo-Json -Compress)};StopVpn;Start-Sleep -Seconds 2;$diag=Join-Path $script:vpnFolder 'diagnostics.json';if(Test-Path $diag){Write-Host ([IO.File]::ReadAllText($diag))};$form.Close()}
    if(([DateTime]::UtcNow-$script:testStarted).TotalSeconds -gt 120){Write-Host 'FAIL: system test timed out';StopVpn;$form.Close()}
}
