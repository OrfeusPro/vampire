$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing,System.Security,System.Net.Http,System.Web.Extensions
. (Join-Path $PSScriptRoot 'profile.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-bots.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
$secret=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path (GetPhoneExitProfileDirectory) 'control-api.bin')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
$catalog=Invoke-RestMethod 'http://127.0.0.1:17842/bot/v1/phones' -Headers @{Authorization="Bearer $secret"} -TimeoutSec 10
$phone=@($catalog.phones)[-1]
$flags=[Reflection.BindingFlags]'NonPublic,Instance'
foreach($id in @([string]$phone.id,'missing-test-device')) {
    $panel=New-Object PhoneExit.BotPanel($secret,([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../bots'))))
    $panel.DevicePhoneId=$id
    try {
        $panel.Show();$deadline=[DateTime]::UtcNow.AddSeconds(20)
        $rows=$panel.GetType().GetField('phones',$flags).GetValue($panel)
        do {[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 50} while([DateTime]::UtcNow -lt $deadline -and ($rows.Rows.Count -eq 0 -or $panel.GetType().GetField('loading',$flags).GetValue($panel)))
        if($rows.Visible){throw 'Device settings still display the global phone list'}
        if($panel.GetType().GetField('selected',$flags).GetValue($panel) -ne $id){throw 'Device settings switched to another phone'}
        $profile=$panel.GetType().GetField('profile',$flags).GetValue($panel)
        if($id -eq 'missing-test-device'){
            if($profile){throw 'Missing device loaded a different profile'}
            foreach($action in $panel.GetType().GetField('actions',$flags).GetValue($panel)){if($action.Enabled){throw 'Missing device actions are enabled'}}
        }else{
            if(!$profile){throw 'Selected profile was not loaded'}
            if(!$panel.Text.Contains([string]$phone.name)){throw 'Device title does not identify the selected phone'}
            $bitmap=[Drawing.Bitmap]::new($panel.Width,$panel.Height)
            try{$panel.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$panel.Width,$panel.Height));$bitmap.Save((Join-Path $PSScriptRoot '../.tools/device-settings-preview.png'))}finally{$bitmap.Dispose()}
            $panel.GetType().GetField('dirty',$flags).SetValue($panel,$true)
            $script:discardSeen=$false
            $timer=New-Object Windows.Forms.Timer;$timer.Interval=100
            $timer.Add_Tick({
                $dialog=@([Windows.Forms.Application]::OpenForms|Where-Object {$_.Text -eq 'Несохранённые настройки'})[0]
                if(!$dialog){return};$timer.Stop();$script:discardSeen=$true
                $dialog.DialogResult='Cancel';$dialog.Close()
            })
            try{$timer.Start();$panel.Close()}finally{$timer.Dispose();$panel.GetType().GetField('dirty',$flags).SetValue($panel,$false)}
            if(!$script:discardSeen -or !$panel.Visible){throw 'Unsaved close did not offer staying in the editor'}
        }
    } finally {$panel.Close();$panel.Dispose()}
}
'PASS: scoped settings, exact profile, missing device never falls back, no commands or saves'
