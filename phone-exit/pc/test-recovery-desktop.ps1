$script:recoveryStage=0;$script:recoveryPassed=$false
$script:recoveryFolder=Join-Path $PSScriptRoot '../.tools/recovery-test'
[IO.Directory]::CreateDirectory($script:recoveryFolder)|Out-Null
$script:gameLauncher=Join-Path $script:recoveryFolder 'GameLauncher.exe'
$script:gameChild=Join-Path $script:recoveryFolder 'GameChild.exe'
$script:udpProbe=Join-Path $script:recoveryFolder 'UdpProbe.exe'
$script:directProbe=Join-Path $script:recoveryFolder 'DirectProbe.exe'
$compiler=Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
& $compiler /nologo /target:exe ('/out:'+$script:gameLauncher) (Join-Path $PSScriptRoot 'test/recovery-probe.cs')
if($LASTEXITCODE -ne 0){throw 'Recovery probe compilation failed'}
Copy-Item -LiteralPath $script:gameLauncher -Destination $script:gameChild -Force
Copy-Item -LiteralPath $script:gameLauncher -Destination $script:udpProbe -Force
Copy-Item -LiteralPath (Get-Command curl.exe).Source -Destination $script:directProbe -Force
function RecoveryHttps {
    $result=& curl.exe --noproxy '*' --silent --fail --max-time 15 https://api.ipify.org
    if($LASTEXITCODE -ne 0 -or $result -ne $script:expectedIp){throw 'Recovered HTTPS did not use phone'}
    & $script:udpProbe udp
    if($LASTEXITCODE -ne 0){throw 'Recovered UDP/DNS failed'}
}
function TestRecoveryTick {
    try{
        if($script:recoveryStage -eq 2 -and (!$script:lastRecoveryReport -or ([DateTime]::UtcNow-$script:lastRecoveryReport).TotalSeconds -gt 15)){
            $script:lastRecoveryReport=[DateTime]::UtcNow
            $target=@($script:phoneRows|Where-Object {$_.id -eq $script:reconnectPhone})
            Write-Host ('TEST: recovery wanted='+$script:connectionWanted+' client='+[bool]$script:client+' ready='+$script:transportReady+' targetOnline='+[bool]$target.online+' targetBusy='+[bool]$target.busy+' attempts='+$script:reconnectAttempts)
        }
        if($script:vpnState -eq 'failed'){throw 'VPN helper failed'}
        if($script:recoveryStage -eq 0){
            for($i=0;$i -lt $script:phoneRows.Count;$i++){
                $p=$script:phoneRows[$i]
                if($p.name -match 'V2061' -and $p.online -and !$p.busy){
                    $phoneList.SelectedIndex=$i;$mode.SelectedIndex=$(if($RecoveryAll){0}else{1})
                    $script:appPaths=@((Get-Command curl.exe).Source,$script:gameLauncher,$script:udpProbe)
                    $script:recoveryStage=1;StartClient;break
                }
            }
        }elseif($script:recoveryStage -eq 1 -and $script:vpnState -eq 'active' -and $script:transportReady){
            RecoveryHttps
            $viaChild=& $script:gameLauncher child $script:gameChild https://api.ipify.org
            if($LASTEXITCODE -ne 0 -or $viaChild -ne $script:expectedIp){throw 'New child did not use phone'}
            if(!$RecoveryAll){$rules=[IO.File]::ReadAllText((Join-Path $script:vpnFolder 'applications-rules.json'));if(!$rules.Contains('GameChild')){throw 'Child rule not discovered'}}
            & $script:directProbe --noproxy '*' --silent --fail --max-time 15 https://example.com | Out-Null
            if($LASTEXITCODE -ne 0){throw 'Unselected program failed'}
            Write-Host $(if($RecoveryAll){'PASS: full TUN HTTPS, child HTTPS, UDP DNS/STUN'}else{'PASS: multiple selected EXEs, new launcher child HTTPS, UDP DNS/STUN, unselected internet'})
            $script:originalVpnFolder=$script:vpnFolder
            $script:recoveryStage=2;$script:client.Kill()
            & curl.exe --noproxy '*' --silent --fail --max-time 4 https://1.1.1.1/cdn-cgi/trace 2>$null|Out-Null
            if($LASTEXITCODE -eq 0){throw 'Selected traffic escaped on loss'}
            & $script:directProbe --noproxy '*' --silent --fail --max-time 15 https://example.com|Out-Null
            if($RecoveryAll){if($LASTEXITCODE -eq 0){throw 'Full VPN traffic escaped on loss'};Write-Host 'PASS: full VPN traffic remains blocked on loss'}
            else{if($LASTEXITCODE -ne 0){throw 'Unselected internet blocked on loss'};Write-Host 'PASS: selected traffic blocked on transport loss; unselected HTTPS/DNS preserved'}
        }elseif($script:recoveryStage -eq 2 -and $script:client -and !$script:client.HasExited -and $script:transportReady -and !$script:failure){
            if($script:originalVpnFolder -ne $script:vpnFolder){throw 'Recovery recreated TUN'}
            RecoveryHttps
            Write-Host 'PASS: same phone recovered automatically; existing TUN retained; HTTPS/UDP restored'
            $script:recoveryStage=3;$stopButton.PerformClick();$script:cancelledAt=[DateTime]::UtcNow
        }elseif($script:recoveryStage -eq 3 -and !$script:client -and ([DateTime]::UtcNow-$script:cancelledAt).TotalSeconds -gt 5){
            if($script:connectionWanted){throw 'Stop retained recovery intent'}
            $state=[IO.File]::ReadAllText((Join-Path $script:vpnFolder 'status.json'))|ConvertFrom-Json
            if($state.state -ne 'stopped'){return}
            & curl.exe --noproxy '*' --silent --fail --max-time 15 https://example.com|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Normal internet not restored'}
            Write-Host 'PASS: explicit Stop cancels recovery and restores ordinary internet'
            $script:recoveryPassed=$true;$form.Close()
        }
        if(([DateTime]::UtcNow-$script:testStarted).TotalSeconds -gt 200){throw 'Recovery test timeout'}
    }catch{Write-Host ('FAIL: '+$_.Exception.Message);CancelReconnect;StopVpn;$form.Close()}
}
