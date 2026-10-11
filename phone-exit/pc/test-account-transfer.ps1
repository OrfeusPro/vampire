$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'account-transfer.ps1')
function TransportRuntime {return (Get-Command node.exe).Source}
Add-Type -AssemblyName System.Security
$testDirectory=Join-Path ([IO.Path]::GetTempPath()) ('PhoneExit-transfer-test-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($testDirectory)
try {
    $account=(& node.exe (Join-Path $PSScriptRoot 'src/account.js'))|ConvertFrom-Json
    $profile=@{version=1;account=$account;phones=@(@{id=('a'*32);token=('b'*64);name='Test phone'})}
    $password='test password for transfer 2026'
    $archive=(InvokeAccountTransfer @{op='export';profile=$profile;password=$password}).archive
    $decoded=(InvokeAccountTransfer @{op='import';archive=$archive;password=$password}).profile
    WriteTransferredProfile $decoded $testDirectory
    $saved=[IO.File]::ReadAllBytes((Join-Path $testDirectory 'account.bin'))
    $raw=[Security.Cryptography.ProtectedData]::Unprotect($saved,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    if(([Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json).feedToken -cne $account.feedToken){throw 'DPAPI roundtrip failed'}
    $phoneRaw=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path $testDirectory 'phones.bin')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $phones=[Text.Encoding]::UTF8.GetString($phoneRaw)|ConvertFrom-Json
    if($phones.Count -ne 1 -or $phones[0].token -cne ('b'*64)){throw 'Phones roundtrip failed'}
    $failed=$false;try{$null=InvokeAccountTransfer @{op='import';archive=$archive;password='wrong password 2026'}}catch{$failed=$true}
    if(!$failed){throw 'Wrong password was accepted'}
    if([Convert]::ToBase64String($saved) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $testDirectory 'account.bin')))){throw 'Wrong password changed profile'}
    # Hold the second target against replacement: first replacement must roll back.
    $beforePhones=[IO.File]::ReadAllBytes((Join-Path $testDirectory 'phones.bin'))
    $lock=[IO.File]::Open((Join-Path $testDirectory 'account.bin'),'Open','Read','Read')
    try {
        $decoded.phones[0].name='Changed';$failed=$false
        try{WriteTransferredProfile $decoded $testDirectory}catch{$failed=$true}
        if(!$failed){throw 'Locked profile replacement unexpectedly succeeded'}
    }finally{$lock.Dispose()}
    if([Convert]::ToBase64String($beforePhones) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $testDirectory 'phones.bin')))){throw 'Rollback did not restore phones'}
    if(@([IO.Directory]::GetFiles($testDirectory)).Count -ne 2){throw 'Temporary files remain'}
    WriteTransferredProfile $decoded $testDirectory
    Write-Host 'PASS: encrypted pipe transfer, DPAPI storage, wrong password, rollback, replacement and cleanup'
}finally {
    # Only this randomly created, verified test directory is removed.
    $resolved=[IO.Path]::GetFullPath($testDirectory)
    if([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ne [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($resolved) -notlike 'PhoneExit-transfer-test-*'){throw 'Unsafe test cleanup path'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
