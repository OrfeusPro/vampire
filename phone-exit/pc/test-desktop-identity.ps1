$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
Add-Type -Path @((Join-Path $PSScriptRoot 'desktop-controls.cs'),(Join-Path $PSScriptRoot 'desktop-bots.cs')) -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
[PhoneExit.DesktopDpi]::Enable()
[PhoneExit.DesktopActionIcons]::DirectoryPath=Join-Path $PSScriptRoot 'assets/actions'
$flags=[Reflection.BindingFlags]'NonPublic,Instance'
$script:savedName=$null;$script:savedProvider=$null;$script:calls=0
$save=[Func[string,string,Threading.Tasks.Task]]{param($name,$provider) $script:calls++;$script:savedName=$name;$script:savedProvider=$provider;return [Threading.Tasks.Task]::FromResult($true)}
function WaitTask($task){while(!$task.IsCompleted){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 10};return $task.GetAwaiter().GetResult()}
foreach($dpi in @(96,144)){
    $dialog=[PhoneExit.PhoneIdentityDialog]::new('Старое имя','VMOS',$save)
    try{
        $dialog.Show();[Windows.Forms.Application]::DoEvents()
        if($dialog.MonitorDpi -ne $dpi){$dialog.ApplyMonitorDpi($dpi,[Drawing.Rectangle]::Empty)}
        $dialog.CharacterName='  Новое имя  ';$dialog.Provider='LDCloud'
        $bitmap=[Drawing.Bitmap]::new($dialog.Width,$dialog.Height)
        try{$dialog.DrawToBitmap($bitmap,$dialog.ClientRectangle);$bitmap.Save((Join-Path $PSScriptRoot "../.tools/identity-dialog-$dpi.png"))}finally{$bitmap.Dispose()}
        $button=$dialog.GetType().GetField('save',$flags).GetValue($dialog)
        if($button.Right -gt $button.Parent.ClientSize.Width -or $button.Bottom -gt $button.Parent.ClientSize.Height){throw 'Identity footer is clipped'}
        if(!(WaitTask ($dialog.SaveAsync())) -or $script:savedName -ne 'Новое имя' -or $script:savedProvider -ne 'LDCloud'){throw 'Identity save lost the name or provider'}
    }finally{$dialog.Dispose()}
}
$failure=[Func[string,string,Threading.Tasks.Task]]{param($name,$provider) throw 'simulated offline API'}
$dialog=[PhoneExit.PhoneIdentityDialog]::new('Имя сохранится','UgPhone',$failure)
try{
    $dialog.Show();[Windows.Forms.Application]::DoEvents()
    if((WaitTask ($dialog.SaveAsync())) -or !$dialog.Visible -or !$dialog.ErrorText -or $dialog.CharacterName -ne 'Имя сохранится'){throw 'Failed save closed the form or lost input'}
    $bitmap=[Drawing.Bitmap]::new($dialog.Width,$dialog.Height)
    try{$dialog.DrawToBitmap($bitmap,$dialog.ClientRectangle);$bitmap.Save((Join-Path $PSScriptRoot '../.tools/identity-dialog-error.png'))}finally{$bitmap.Dispose()}
    $dialog.Close()
}finally{$dialog.Dispose()}
$dialog=[PhoneExit.PhoneIdentityDialog]::new('Не менять','VMOS',$save)
try{$dialog.Show();$dialog.CancelButton.PerformClick();if($script:calls -ne 2){throw 'Cancel saved the identity'}}finally{$dialog.Dispose()}
$window=[Windows.Forms.Form]::new();$tabs=[PhoneExit.BotTabs]::new();$tabs.Dock='Fill';$window.Controls.Add($tabs)
try{
    foreach($title in @('Бот','Фарм','Устройство','Ошибки')){$tabs.AddPage($title)}
    $window.Show();[Windows.Forms.Application]::DoEvents()
    $buttons=$tabs.GetType().GetField('buttons',$flags).GetValue($tabs)
    $buttons[2].PerformClick();if($tabs.SelectedIndex -ne 2){throw 'Tab click did not switch page'}
    $tabs.SetPageAvailable(1,$false);$tabs.SelectedIndex=0
    $key=[Windows.Forms.KeyEventArgs]::new([Windows.Forms.Keys]::Right)
    $buttons[0].GetType().GetMethod('OnKeyDown',$flags).Invoke($buttons[0],@($key))
    if($tabs.SelectedIndex -ne 2 -or !$key.Handled){throw 'Keyboard did not skip unavailable game tab'}
    for($i=1;$i -lt $buttons.Count;$i++){if($buttons[$i].Visible -and $buttons[$i].Left -lt $buttons[0].Right){throw 'Tab hit areas overlap'}}
}finally{$window.Dispose()}
'PASS: identity dialog at 96/144 DPI; name/provider save; error keeps input and allows retry; cancel never saves. No real profiles changed.'
