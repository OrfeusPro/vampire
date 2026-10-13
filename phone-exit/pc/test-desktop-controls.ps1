$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-controls.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing
[PhoneExit.DesktopDpi]::Enable()
[Windows.Forms.Application]::EnableVisualStyles()
$form=New-Object Windows.Forms.Form
$form.ClientSize=[Drawing.Size]::new(500,400)
$form.BackColor=[Drawing.ColorTranslator]::FromHtml('#10151f')
$list=New-Object PhoneExit.DarkPhoneList
$list.SetBounds(20,20,300,140);$list.ItemHeight=70
$list.BackColor=[Drawing.ColorTranslator]::FromHtml('#192231');$list.ForeColor=[Drawing.ColorTranslator]::FromHtml('#eff4fa')
$form.Controls.Add($list)
$select=New-Object PhoneExit.DarkSelect
$select.SetBounds(20,200,420,42);$select.Font=[Drawing.Font]::new('Segoe UI',10)
$select.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$select.ForeColor=$list.ForeColor
foreach($item in @('Весь трафик · VPN','Выбранные EXE · VPN (тестовый)','Прокси · TCP')){$select.Items.Add($item)}
$select.SelectedIndex=0;$form.Controls.Add($select)
$script:drawn=@();$script:selectedEvents=0
$select.Add_SelectedIndexChanged({$script:selectedEvents++})
$list.Add_DrawItem({param($sender,$e)
    $script:drawn+= $e.Index
    [Windows.Forms.TextRenderer]::DrawText($e.Graphics,[string]$sender.Items[$e.Index],$sender.Font,$e.Bounds,$sender.ForeColor,$sender.BackColor)
})
function VisibleRows {
    $script:drawn=@();$bitmap=[Drawing.Bitmap]::new($list.Width,$list.Height)
    try{$list.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$list.Width,$list.Height));return @($script:drawn)}finally{$bitmap.Dispose()}
}
try {
    for($i=0;$i -lt 5;$i++){$list.Items.Add("Phone $i")};$list.SelectedIndex=0
    $form.Show();[Windows.Forms.Application]::DoEvents()
    $flags=[Reflection.BindingFlags]'Instance,NonPublic'
    $list.GetType().GetMethod('OnMouseWheel',$flags).Invoke($list,@([Windows.Forms.MouseEventArgs]::new('None',0,80,80,-120)))
    $rows=@(VisibleRows);if($rows[0] -ne 1 -or $list.SelectedIndex -ne 0){throw 'Wheel did not scroll independently of selection'}
    $list.BeginUpdate();$list.Items.Clear();for($i=0;$i -lt 5;$i++){$list.Items.Add("Phone $i")};$list.SelectedIndex=0;$list.EndUpdate()
    $rows=@(VisibleRows);if($rows[0] -ne 1){throw 'Directory refresh reset scroll position'}
    $list.GetType().GetMethod('OnKeyDown',$flags).Invoke($list,@([Windows.Forms.KeyEventArgs]::new('End')))
    $rows=@(VisibleRows);if($list.SelectedIndex -ne 4 -or $rows -notcontains 4){throw 'Last phone is unreachable with keyboard'}
    $select.GetType().GetMethod('OpenMenu',$flags).Invoke($select,@())
    [Windows.Forms.Application]::DoEvents()
    $menu=$select.GetType().GetField('activeMenu',$flags).GetValue($select)
    if(!$menu.Visible -or $menu.BackColor.R -gt 60){throw 'Dark selector menu did not open'}
    if($menu.Width -lt $select.Width){throw 'Dropdown is narrower than its field'}
    $fieldBitmap=[Drawing.Bitmap]::new($select.Width,$select.Height)
    try{
        $select.DrawToBitmap($fieldBitmap,[Drawing.Rectangle]::new(0,0,$select.Width,$select.Height))
        foreach($point in @([Drawing.Point]::new(10,1),[Drawing.Point]::new(10,($select.Height-2)),[Drawing.Point]::new(1,10),[Drawing.Point]::new(($select.Width-2),10))){
            if($fieldBitmap.GetPixel($point.X,$point.Y).ToArgb() -ne [Drawing.Color]::FromArgb(98,231,188).ToArgb()){throw 'Selector outline is incomplete while menu is open'}
        }
        $fieldBitmap.Save((Join-Path $PSScriptRoot '../desktop-select-preview.png'))
    }finally{$fieldBitmap.Dispose()}
    $bitmap=[Drawing.Bitmap]::new($menu.Width,$menu.Height)
    try{$menu.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$menu.Width,$menu.Height));$bitmap.Save((Join-Path $PSScriptRoot '../desktop-menu-preview.png'))}finally{$bitmap.Dispose()}
    $menu.Items[1].PerformClick()
    if($select.SelectedIndex -ne 1 -or $script:selectedEvents -ne 1){throw 'Selector did not change mode exactly once'}
    if(!$menu.IsDisposed){$menu.Close()}
    $list.ShowBotActions=$true;$list.Width=700;$list.ItemHeight=100;$list.Height=200;$list.SelectedIndex=4
    $list.SetBotActions(4,$true,$true,'running')
    if($list.ActionEnabled(4,0) -or !$list.ActionEnabled(4,1) -or !$list.ActionEnabled(4,2)){throw 'Running bot action availability is wrong'}
    $script:rowAction=$null;$list.Add_RowAction({param($sender,$event)$script:rowAction=$event})
    $taskBounds=$list.ActionBounds(4,1)
    $list.GetType().GetMethod('OnMouseDown',$flags).Invoke($list,@([Windows.Forms.MouseEventArgs]::new('Left',1,($taskBounds.X+3),($taskBounds.Y+3),0)))
    if(!$script:rowAction -or $script:rowAction.Index -ne 4 -or $script:rowAction.Action -ne 'pause'){throw 'Scrolled row action targets the wrong phone'}
    $list.SetBotActions(4,$false,$true,'running')
    if($list.ActionEnabled(4,0) -or $list.ActionEnabled(4,1) -or $list.ActionEnabled(4,2) -or !$list.ActionEnabled(4,3)){throw 'Offline action availability is unsafe'}
    $list.SetBotActions(4,$true,$false,'')
    if($list.ActionEnabled(4,0) -or !$list.ActionEnabled(4,3)){throw 'Unassigned phone should expose settings only'}
    $list.SetPhoneHeader(4,250,'Не в сети','VMOS')
    $taskBounds=$list.ActionBounds(4,3)
    if($taskBounds.X -ne 250){throw 'Settings button did not move after country'}
    $list.GetType().GetMethod('OnMouseDown',$flags).Invoke($list,@([Windows.Forms.MouseEventArgs]::new('Left',1,($taskBounds.X+3),($taskBounds.Y+3),0)))
    if($script:rowAction.Index -ne 4 -or $script:rowAction.Action -ne 'settings'){throw 'Header settings action targets the wrong phone'}
    $taskStatusY=$taskBounds.Y+[int][Math]::Round(48*[PhoneExit.DesktopDpi]::Scale)
    $list.GetType().GetMethod('OnMouseMove',$flags).Invoke($list,@([Windows.Forms.MouseEventArgs]::new('None',0,([int][Math]::Round(26*[PhoneExit.DesktopDpi]::Scale)),$taskStatusY,0)))
    if($list.GetType().GetField('tipText',$flags).GetValue($list) -ne 'Не в сети'){throw 'Connection indicator tooltip missing'}
    $check=[PhoneExit.DarkCheckBox]::new();$check.Text='Проверка';$check.Size=[Drawing.Size]::new(240,40);$check.BackColor=[Drawing.Color]::FromArgb(17,19,21);$form.Controls.Add($check)
    $script:checkEvents=0;$check.Add_CheckedChanged({$script:checkEvents++})
    $check.GetType().GetMethod('OnClick',$flags).Invoke($check,@([EventArgs]::Empty))
    if(!$check.Checked -or $script:checkEvents -ne 1){throw 'Dark checkbox did not toggle exactly once'}
    $checkBitmap=[Drawing.Bitmap]::new($check.Width,$check.Height)
    try{$check.DrawToBitmap($checkBitmap,[Drawing.Rectangle]::new(0,0,$check.Width,$check.Height));if($checkBitmap.GetPixel(1,[int]($check.Height/2)).ToArgb() -ne [Drawing.Color]::FromArgb(98,231,188).ToArgb()){throw 'Dark checkbox missing mint checked state'}}finally{$checkBitmap.Dispose()}
    Write-Output 'PASS: dark dropdown, checkbox, scrolling, correct row action target and offline/unassigned controls'
}finally{$form.Close();$form.Dispose()}
