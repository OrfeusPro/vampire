# A user-home folder avoids MSIX AppData virtualization inherited by child
# processes. Keep the same DPAPI account when migrating earlier installations.
function GetPhoneExitProfileDirectory {
    $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders')
    try {$local=if($key){[string]$key.GetValue('Local AppData')}else{''}} finally {if($key){$key.Dispose()}}
    if(!$local -or ![IO.Path]::IsPathRooted($local) -or $local.Contains('%')){
        $local=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    }
    if(!$local -or ![IO.Path]::IsPathRooted($local)){throw 'Windows user profile directory is unavailable'}
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $profileKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$sid)
    try {$homePath=if($profileKey){[string]$profileKey.GetValue('ProfileImagePath')}else{''}} finally {if($profileKey){$profileKey.Dispose()}}
    if(!$homePath -or ![IO.Path]::IsPathRooted($homePath) -or $homePath.Contains('%')){throw 'Windows user home directory is unavailable'}
    $target=[IO.Path]::Combine($homePath,'.phone-exit')
    if(![IO.File]::Exists([IO.Path]::Combine($target,'account.bin'))){
        $sources=@([IO.Path]::Combine($local,'PhoneExit'))
        $packages=[IO.Path]::Combine($local,'Packages')
        if([IO.Directory]::Exists($packages)){
            foreach($package in [IO.Directory]::GetDirectories($packages,'OpenAI.Codex*')){
                $sources += [IO.Path]::Combine($package,'LocalCache\Local\PhoneExit')
            }
        }
        $source=$sources | Where-Object {[IO.File]::Exists([IO.Path]::Combine($_,'account.bin'))} | Select-Object -First 1
        if($source){
            Add-Type -AssemblyName System.Security
            $account=[IO.File]::ReadAllBytes([IO.Path]::Combine($source,'account.bin'))
            if($account.Length -gt 65536){throw 'Legacy account file is too large'}
            $null=[Security.Cryptography.ProtectedData]::Unprotect($account,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
            $null=[IO.Directory]::CreateDirectory($target)
            foreach($name in @('phones.bin','applications.json')){
                $from=[IO.Path]::Combine($source,$name);$to=[IO.Path]::Combine($target,$name)
                if([IO.File]::Exists($from) -and ![IO.File]::Exists($to)){[IO.File]::Copy($from,$to,$false)}
            }
            # Commit the migration marker last. Never overwrite an existing account.
            [IO.File]::Copy([IO.Path]::Combine($source,'account.bin'),[IO.Path]::Combine($target,'account.bin'),$false)
        }
    }
    return $target
}
