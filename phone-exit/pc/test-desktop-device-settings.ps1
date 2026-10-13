$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing,System.Security,System.Net.Http,System.Web.Extensions
. (Join-Path $PSScriptRoot 'profile.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-bots.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
$secret=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path (GetPhoneExitProfileDirectory) 'control-api.bin')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
$catalog=Invoke-RestMethod 'http://127.0.0.1:17842/bot/v1/phones' -Headers @{Authorization="Bearer $secret"} -TimeoutSec 10
$phone=@($catalog.phones|Where-Object {$_.country -eq 'SG'})[0]
if(!$phone){$phone=@($catalog.phones)[-1]}
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
            $tabs=$panel.GetType().GetField('deviceTabs',$flags).GetValue($panel)
            if($tabs.TabPages.Count -ne 4){throw 'Device settings tabs are missing'}
            $points=$panel.GetType().GetField('points',$flags).GetValue($panel)
            $before=$points.Count
            foreach($width in @(1200,1440)){
                $panel.Size=[Drawing.Size]::new($width,900)
                for($tab=0;$tab -lt 4;$tab++){
                    $tabs.SelectedIndex=$tab;[Windows.Forms.Application]::DoEvents()
                    if($points.Count -ne $before){throw 'Tab switching changed farm points'}
                    if($tab -eq 1){
                        $picture=$panel.GetType().GetField('picture',$flags).GetValue($panel)
                        if(!$picture.Image -or $picture.Width -lt 50 -or $picture.Height -lt 50){throw 'Embedded farm map is blank'}
                    }
                    $preview=[Drawing.Bitmap]::new($panel.Width,$panel.Height)
                    try{$panel.DrawToBitmap($preview,[Drawing.Rectangle]::new(0,0,$panel.Width,$panel.Height));$preview.Save((Join-Path $PSScriptRoot "../.tools/device-tab-$tab-$width.png"))}finally{$preview.Dispose()}
                }
            }
            $tabs.SelectedIndex=0
            $farm=$panel.GetType().GetField('farm',$flags).GetValue($panel)
            $originalFarm=$farm.Checked;$farm.Checked=!$originalFarm
            $tabs.SelectedIndex=1;$tabs.SelectedIndex=2;$tabs.SelectedIndex=0
            if($farm.Checked -eq $originalFarm -or !$panel.GetType().GetField('dirty',$flags).GetValue($panel)){throw 'Switching tabs lost unsaved settings'}
            $farm.Checked=$originalFarm;$panel.GetType().GetField('dirty',$flags).SetValue($panel,$false)
            $mapItems=$panel.GetType().GetField('mapItems',$flags).GetValue($panel)
            $maps=$panel.GetType().GetField('maps',$flags).GetValue($panel)
            $map=$mapItems[$maps.SelectedIndex];$image=$map['image']
            try{
                $map['image']='missing-ui-test-map.png'
                $panel.GetType().GetMethod('LoadMap',$flags).Invoke($panel,@())
                if($panel.GetType().GetField('picture',$flags).GetValue($panel).Image){throw 'Missing map displays a previous map image'}
            }finally{$map['image']=$image;$panel.GetType().GetMethod('LoadMap',$flags).Invoke($panel,@())}
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
