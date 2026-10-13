$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing,System.Security,System.Net.Http,System.Web.Extensions
. (Join-Path $PSScriptRoot 'profile.ps1')
Add-Type -Path @((Join-Path $PSScriptRoot 'desktop-controls.cs'),(Join-Path $PSScriptRoot 'desktop-bots.cs')) -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
$taskSecret=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path (GetPhoneExitProfileDirectory) 'control-api.bin')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
$taskPanel=New-Object PhoneExit.BotPanel($taskSecret,([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../bots'))))
$taskInitialPhones=Invoke-RestMethod 'http://127.0.0.1:17842/bot/v1/phones' -Headers @{Authorization="Bearer $taskSecret"} -TimeoutSec 10
$taskInitialPhone=@($taskInitialPhones.phones|Where-Object {$_.name -eq 'realme RMX3830' -and $_.country -eq 'SG'})[0]
if(!$taskInitialPhone){throw 'Expected SG phone for initial selection'}
$taskPanel.InitialPhoneId=[string]$taskInitialPhone.id
try {
    $taskPanel.Show()
    $taskDeadline=[DateTime]::UtcNow.AddSeconds(15)
    $taskFlags=[Reflection.BindingFlags]'NonPublic,Instance'
    $taskPhones=$taskPanel.GetType().GetField('phones',$taskFlags).GetValue($taskPanel)
    $taskMaps=$taskPanel.GetType().GetField('maps',$taskFlags).GetValue($taskPanel)
    while([DateTime]::UtcNow -lt $taskDeadline -and ($taskPhones.Rows.Count -eq 0 -or $taskMaps.Items.Count -eq 0)){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 50}
    if($taskPhones.Rows.Count -lt 1 -or $taskMaps.Items.Count -lt 1){throw 'Panel did not load phones/maps'}
    if($taskPhones.SelectedRows.Count -ne 1 -or $taskPhones.SelectedRows[0].Tag -ne $taskInitialPhone.id){throw 'Settings panel ignored selected phone'}
    $taskSG=@($taskPhones.Rows|Where-Object { $_.Cells[0].Value -like '*RMX3830*SG*' })[0]
    if(!$taskSG){throw 'Expected SG profile for editor verification'}
    $taskPhones.ClearSelection();$taskSG.Selected=$true
    $taskDeadline=[DateTime]::UtcNow.AddSeconds(10)
    $taskPoints=$taskPanel.GetType().GetField('points',$taskFlags).GetValue($taskPanel)
    while([DateTime]::UtcNow -lt $taskDeadline -and $taskPoints.Count -lt 7){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 50}
    if($taskPoints.Count -ne 7){throw 'SG points failed to load'}
    $taskSpots=$taskPanel.GetType().GetField('spots',$taskFlags).GetValue($taskPanel)
    $taskSpots.SelectedIndex=3
    $taskDialogFailure=$null
    $taskTimer=New-Object Windows.Forms.Timer
    $taskTimer.Interval=500
    $taskTimer.Add_Tick({
        $taskDialog=@([Windows.Forms.Application]::OpenForms|Where-Object {$_.Text -like 'Фарм:*'})[0]
        if(!$taskDialog){return}
        $taskTimer.Stop()
        try{
            $taskPanel.GetType().GetMethod('SetZoom',$taskFlags).Invoke($taskPanel,@([double]2))
            $taskRectangle=$taskPanel.GetType().GetMethod('ImageRect',$taskFlags).Invoke($taskPanel,@())
            $taskBefore=@($taskPoints[3]['map_points']).Count
            $taskClick=New-Object Windows.Forms.MouseEventArgs([Windows.Forms.MouseButtons]::Left,1,($taskRectangle.X+[int]($taskRectangle.Width*.3)),($taskRectangle.Y+[int]($taskRectangle.Height*.4)),0)
            $taskPanel.GetType().GetMethod('PlacePoint',$taskFlags).Invoke($taskPanel,@($taskClick.PSObject.BaseObject))
            $taskAdded=@($taskPoints[3]['map_points'])[-1]
            if([Math]::Abs($taskAdded[0]-.406) -gt .01 -or [Math]::Abs($taskAdded[1]-.435) -gt .01){throw 'Zoomed point coordinates changed'}
            $taskPointList=$taskPanel.GetType().GetField('pointList',$taskFlags).GetValue($taskPanel)
            $taskDelete=@($taskPointList.Controls|Where-Object {$_.Text -like "#$($taskBefore+1) *"})[0]
            $taskDelete.PerformClick()
            if(@($taskPoints[3]['map_points']).Count -ne $taskBefore){throw 'Individual point delete failed'}
            $taskPanel.GetType().GetMethod('SetZoom',$taskFlags).Invoke($taskPanel,@([double]1))
            $taskImage=New-Object Drawing.Bitmap($taskDialog.Width,$taskDialog.Height)
            try{$taskDialog.DrawToBitmap($taskImage,(New-Object Drawing.Rectangle(0,0,$taskDialog.Width,$taskDialog.Height)));$taskImage.Save((Join-Path $PSScriptRoot '../.tools/farm-editor-preview.png'))}finally{$taskImage.Dispose()}
        }catch{$script:taskDialogFailure=$_.Exception.Message}finally{$taskDialog.Close()}
    })
    try{$taskTimer.Start();$taskPanel.GetType().GetMethod('OpenFarmEditor',$taskFlags).Invoke($taskPanel,@())}finally{$taskTimer.Dispose()}
    if($script:taskDialogFailure){throw $script:taskDialogFailure}
    $taskPanel.GetType().GetField('dirty',$taskFlags).SetValue($taskPanel,$false)
    $taskPanel.InitialCopyTargets=[string[]]@($taskPhones.Rows|Where-Object {$_.Tag -ne $taskInitialPhone.id}|Select-Object -First 2|ForEach-Object {[string]$_.Tag})
    $taskCopyTimer=New-Object Windows.Forms.Timer;$taskCopyTimer.Interval=250
    $script:taskCopyFailure=$null
    $taskCopyTimer.Add_Tick({
        $taskCopyDialog=@([Windows.Forms.Application]::OpenForms|Where-Object {$_.Text -eq 'Копирование настроек'})[0]
        if(!$taskCopyDialog){return};$taskCopyTimer.Stop()
        try{
            $taskCopyList=@($taskCopyDialog.Controls|Where-Object {$_ -is [Windows.Forms.CheckedListBox]})[0]
            if($taskCopyList.CheckedIndices.Count -ne 2){throw 'Selected fleet targets were not prechecked in copy dialog'}
            if(!@($taskCopyDialog.Controls|Where-Object {$_.Text -like 'Источник:*'}).Count){throw 'Copy source is not identified'}
            $taskCopyBitmap=[Drawing.Bitmap]::new($taskCopyDialog.Width,$taskCopyDialog.Height)
            try{$taskCopyDialog.DrawToBitmap($taskCopyBitmap,[Drawing.Rectangle]::new(0,0,$taskCopyDialog.Width,$taskCopyDialog.Height));$taskCopyBitmap.Save((Join-Path $PSScriptRoot '../.tools/bot-copy-preview.png'))}finally{$taskCopyBitmap.Dispose()}
        }catch{$script:taskCopyFailure=$_.Exception.Message}finally{$taskCopyDialog.DialogResult='Cancel';$taskCopyDialog.Close()}
    })
    try{$taskCopyTimer.Start();$taskPanel.GetType().GetMethod('Copy',$taskFlags).Invoke($taskPanel,@())|Out-Null}finally{$taskCopyTimer.Dispose()}
    if($script:taskCopyFailure){throw $script:taskCopyFailure}
    $taskBitmap=New-Object Drawing.Bitmap($taskPanel.Width,$taskPanel.Height)
    try{$taskPanel.DrawToBitmap($taskBitmap,(New-Object Drawing.Rectangle(0,0,$taskPanel.Width,$taskPanel.Height)));$taskBitmap.Save((Join-Path $PSScriptRoot '../.tools/bot-panel-preview.png'))}finally{$taskBitmap.Dispose()}
    Write-Output "PASS bot panel: $($taskPhones.Rows.Count) phones, $($taskMaps.Items.Count) maps; no settings or commands sent."
} finally {$taskPanel.GetType().GetField('dirty',$taskFlags).SetValue($taskPanel,$false);$taskPanel.Close();$taskPanel.Dispose()}
