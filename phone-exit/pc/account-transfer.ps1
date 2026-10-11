function InvokeAccountTransfer($request) {
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=TransportRuntime
    $info.Arguments='"'+(Join-Path $PSScriptRoot 'src/account-transfer.js')+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardOutputEncoding=[Text.Encoding]::UTF8
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    try {
        $null=$process.Start();$output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
        $writer=[IO.StreamWriter]::new($process.StandardInput.BaseStream,[Text.UTF8Encoding]::new($false))
        try{$writer.Write(($request|ConvertTo-Json -Depth 12 -Compress))}finally{$writer.Dispose()}
        if(!$process.WaitForExit(15000)){$process.Kill();throw 'Не удалось завершить перенос аккаунта.'}
        if($process.ExitCode -ne 0){throw 'Неверный пароль или повреждённый файл аккаунта.'}
        return ($output.Result|ConvertFrom-Json)
    } finally {if($process.Id -and !$process.HasExited){$process.Kill()};$process.Dispose()}
}
function WriteTransferredProfile($profile,$directory) {
    Add-Type -AssemblyName System.Security
    $null=[IO.Directory]::CreateDirectory($directory)
    $names=@('phones.bin','account.bin');$temps=@();$backups=@();$committed=@();$cleanupBackups=$false
    try {
        foreach($name in $names){
            if($name -eq 'account.bin'){$raw=ConvertTo-Json -InputObject $profile.account -Depth 10 -Compress}
            else{$raw=ConvertTo-Json -InputObject @($profile.phones|ForEach-Object{$_}) -Depth 10 -Compress}
            $bytes=[Text.Encoding]::UTF8.GetBytes($raw)
            try{$protected=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)}finally{[Array]::Clear($bytes,0,$bytes.Length)}
            $target=Join-Path $directory $name;$temp=$target+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
            $temps+=$temp;$backup=$temp+'.bak';$backups+=$backup
            [IO.File]::WriteAllBytes($temp,$protected)
        }
        for($i=0;$i -lt $names.Count;$i++){
            $target=Join-Path $directory $names[$i]
            if([IO.File]::Exists($target)){[IO.File]::Replace($temps[$i],$target,$backups[$i])}else{[IO.File]::Move($temps[$i],$target)}
            $committed+=$i
        }
        $cleanupBackups=$true
    } catch {
        foreach($i in @($committed|Sort-Object -Descending)){
            $target=Join-Path $directory $names[$i]
            if([IO.File]::Exists($backups[$i])){$failed=$target+'.'+[Guid]::NewGuid().ToString('N')+'.failed';[IO.File]::Replace($backups[$i],$target,$failed);[IO.File]::Delete($failed)}else{[IO.File]::Delete($target)}
        }
        $cleanupBackups=$true
        throw
    } finally {foreach($path in $temps){if([IO.File]::Exists($path)){[IO.File]::Delete($path)}};if($cleanupBackups){foreach($path in $backups){if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}}}
}
