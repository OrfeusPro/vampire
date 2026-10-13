function SetDesktopDialogStyle($window, $header, $stretchControl, $primaryButton) {
    $surface=[Drawing.ColorTranslator]::FromHtml('#202428')
    $window.SetLayoutDpi($form.MonitorDpi)
    $foreground=[Drawing.ColorTranslator]::FromHtml('#eef1f4')
    $background=[Drawing.ColorTranslator]::FromHtml('#111315')
    $shift=UiPixel 36
    $stretchBottom=if($stretchControl){$stretchControl.Bottom+$shift}else{[int]::MaxValue}
    $window.SuspendLayout()
    $window.BackColor=$background;$window.ForeColor=$foreground
    $window.ClientSize=[Drawing.Size]::new($window.ClientSize.Width,($window.ClientSize.Height+$shift))
    foreach($control in $window.Controls){
        $control.Top+=$shift
        $control.Anchor='Top, Left, Right'
        if($control -eq $stretchControl){$control.Anchor='Top, Bottom, Left, Right'}
        elseif($control.Top -gt $stretchBottom){$control.Anchor='Bottom, Left, Right'}
        if($control -is [Windows.Forms.Button]){
            $control.BackColor=$surface;$control.ForeColor=$foreground;$control.Cursor='Hand'
            $control.FlatStyle='Flat';$control.FlatAppearance.BorderSize=1
            $control.FlatAppearance.BorderColor=[Drawing.ColorTranslator]::FromHtml('#34393f')
            $control.FlatAppearance.MouseOverBackColor=[Drawing.ColorTranslator]::FromHtml('#30363a')
            $control.Anchor=if($control.Top -gt $stretchBottom){'Bottom, Left'}else{'Top, Left'}
        }elseif($control -is [Windows.Forms.TextBox]){
            $control.BackColor=$surface;$control.ForeColor=$foreground;$control.BorderStyle='FixedSingle'
        }elseif($control -is [PhoneExit.DarkPhoneList]){
            $control.BackColor=[Drawing.ColorTranslator]::FromHtml('#191c1f');$control.ForeColor=$foreground
        }elseif($control -is [Windows.Forms.Label]){$control.BackColor=$background}
    }
    if($primaryButton){
        $updatePrimary={param($sender,$event)$sender.BackColor=if($sender.Enabled){[Drawing.ColorTranslator]::FromHtml('#62e7bc')}else{[Drawing.ColorTranslator]::FromHtml('#202428')};$sender.ForeColor=if($sender.Enabled){[Drawing.ColorTranslator]::FromHtml('#10251e')}else{[Drawing.ColorTranslator]::FromHtml('#9daabc')}}
        $primaryButton.Add_EnabledChanged($updatePrimary);& $updatePrimary $primaryButton $null;$window.AcceptButton=$primaryButton
    }
    $header.Font.Dispose();$header.Font=[Drawing.Font]::new('Segoe UI Semibold',(13*$form.LayoutScale))
    $bar=[Windows.Forms.Panel]::new();$bar.SetBounds(0,0,$window.ClientSize.Width,(UiPixel 36));$bar.Anchor='Top, Left, Right';$bar.BackColor=$surface
    $caption=[Windows.Forms.Label]::new();$caption.Text='Phone Exit';$caption.ForeColor=$foreground;$caption.TextAlign='MiddleLeft';$caption.SetBounds((UiPixel 16),0,($window.ClientSize.Width-(UiPixel 64)),(UiPixel 36));$caption.Anchor='Top, Left, Right'
    $close=[PhoneExit.CaptionButton]::new();$close.Icon='close';$close.AccessibleName='Закрыть';$close.SetBounds(($window.ClientSize.Width-(UiPixel 44)),0,(UiPixel 44),(UiPixel 36));$close.Anchor='Top, Right';$close.BackColor=$surface;$close.ForeColor=$foreground;$close.FlatStyle='Flat';$close.FlatAppearance.BorderSize=0;$close.FlatAppearance.MouseOverBackColor=[Drawing.ColorTranslator]::FromHtml('#8c343b')
    $close.Add_Click({$this.FindForm().Close()})
    $tip=[Windows.Forms.ToolTip]::new();$tip.SetToolTip($close,'Закрыть');$window.Add_FormClosed({$tip.Dispose()}.GetNewClosure())
    $caption.Add_MouseDown({param($sender,$event)if($event.Button -eq 'Left'){$null=[PhoneExit.WindowChrome]::ReleaseCapture();$null=[PhoneExit.WindowChrome]::SendMessage($sender.FindForm().Handle,0xA1,[IntPtr]2,[IntPtr]0)}})
    $bar.Controls.AddRange([Windows.Forms.Control[]]@($caption,$close));$window.Controls.Add($bar);$bar.BringToFront()
    $window.MinimumSize=$window.Size
    $window.ResumeLayout()
}

function DialogPixel($control,[double]$value){return [int][Math]::Round($value*[PhoneExit.DesktopDpi]::ForControl($control))}

function TestDesktopDialogBounds($window) {
    foreach($control in $window.Controls){
        if($control.Visible -and ($control.Left -lt 0 -or $control.Top -lt 0 -or $control.Right -gt $window.ClientSize.Width -or $control.Bottom -gt $window.ClientSize.Height)){
            throw ('Dialog clips control: '+$window.Text+' / '+$control.Text)
        }
    }
    $controls=@($window.Controls | Where-Object {$_.Visible})
    for($i=0;$i -lt $controls.Count;$i++){
        for($j=$i+1;$j -lt $controls.Count;$j++){
            if($controls[$i].Bounds.IntersectsWith($controls[$j].Bounds)){throw ('Dialog overlaps controls: '+$window.Text+' / '+$controls[$i].Text+' / '+$controls[$j].Text)}
        }
    }
}

function SaveDesktopDialogPreview($window,[string]$name) {
    $original=$window.ClientSize
    $position=$window.Location
    try{
        foreach($extra in @(0,120)){
            $window.ClientSize=[Drawing.Size]::new(($original.Width+(UiPixel $extra)),($original.Height+(UiPixel $extra)))
            $window.PerformLayout();[Windows.Forms.Application]::DoEvents();TestDesktopDialogBounds $window
            $bitmap=[Drawing.Bitmap]::new($window.Width,$window.Height)
            $suffix=if($extra){'-wide'}else{''}
            try{$window.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$window.Width,$window.Height));$bitmap.Save((Join-Path $PSScriptRoot ('../.tools/'+$name+$suffix+'-preview.png')))}finally{$bitmap.Dispose()}
        }
        foreach($screen in [Windows.Forms.Screen]::AllScreens){
            $window.Location=[Drawing.Point]::new(($screen.WorkingArea.Left+30),($screen.WorkingArea.Top+30));[Windows.Forms.Application]::DoEvents()
            TestDesktopDialogBounds $window
            $bitmap=[Drawing.Bitmap]::new($window.Width,$window.Height)
            try{$window.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$window.Width,$window.Height));$bitmap.Save((Join-Path $PSScriptRoot "../.tools/$name-dpi-$($window.MonitorDpi).png"))}finally{$bitmap.Dispose()}
        }
    }finally{$window.Location=$position;[Windows.Forms.Application]::DoEvents();$window.ClientSize=$original}
}
