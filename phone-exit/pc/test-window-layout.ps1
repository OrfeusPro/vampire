function TestWindowLayout {
    $originalSize=$form.ClientSize;$originalMode=$mode.SelectedIndex;$originalView=$script:desktopView
    try{
        $savedBotBadges=$script:botPhoneBadges
        try{
            $script:botPhoneBadges=@{}
            foreach($testPhone in $script:phoneRows){$script:botPhoneBadges[[string]$testPhone.id]=[pscustomobject]@{profile=[pscustomobject]@{identity=[pscustomobject]@{characterName='Orfeus';provider='VMOS'};botId='lordnine'};bot=[pscustomobject]@{botId='lordnine';status='running'};botStatusStale=$false}}
            $script:botBadgeLast=[DateTime]::UtcNow
            $form.ClientSize=[Drawing.Size]::new((UiPixel 1100),(UiPixel 780));UpdateWindowLayout;[Windows.Forms.Application]::DoEvents()
            SetDesktopView 'devices';RefreshFleet
            if($fleet.VisibleCount -ne $script:phoneRows.Count){throw 'Fleet did not project all directory phones'}
            $badgeBitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
            try{$form.DrawToBitmap($badgeBitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height));$badgeBitmap.Save((Join-Path $PSScriptRoot '../.tools/main-bot-badges-preview.png'))}finally{$badgeBitmap.Dispose()}
        }finally{$script:botPhoneBadges=$savedBotBadges}
        SetDesktopView 'connection'
        $savedApps=$script:appPaths
        try{$script:appPaths=@((Get-Command curl.exe).Source,(TransportRuntime));ShowApplicationList -Preview}finally{$script:appPaths=$savedApps}
        ShowAccountTransfer -Preview
        ShowTcpDiagnostics -Preview
        $null=ShowRunningApplications -Preview
        $previousStart=$start.Enabled;$previousStop=$stopButton.Enabled
        try{
            $start.Enabled=$false;$stopButton.Enabled=$true;UpdateConnectionButtons
            if($start.BackColor.ToArgb() -eq $accent.ToArgb() -or $stopButton.ForeColor.ToArgb() -ne $accent.ToArgb()){throw 'Connected button colors are misleading'}
            $buttonBitmap=[Drawing.Bitmap]::new($start.Width+$stopButton.Width+16,[Math]::Max($start.Height,$stopButton.Height))
            try{
                $start.DrawToBitmap($buttonBitmap,[Drawing.Rectangle]::new(0,0,$start.Width,$start.Height))
                $stopButton.DrawToBitmap($buttonBitmap,[Drawing.Rectangle]::new(($start.Width+16),0,$stopButton.Width,$stopButton.Height))
                $buttonBitmap.Save((Join-Path $PSScriptRoot '../desktop-buttons-preview.png'))
            }finally{$buttonBitmap.Dispose()}
            $start.Enabled=$true;$stopButton.Enabled=$false;UpdateConnectionButtons
            if($start.BackColor.ToArgb() -ne $accent.ToArgb()){throw 'Disconnected connect button lost active style'}
        }finally{$start.Enabled=$previousStart;$stopButton.Enabled=$previousStop;UpdateConnectionButtons}
        $mode.SelectedIndex=1
        foreach($testSize in @([Drawing.Size]::new((UiPixel 960),(UiPixel 700)),[Drawing.Size]::new((UiPixel 1300),(UiPixel 880)))){
            $form.ClientSize=$testSize;[Windows.Forms.Application]::DoEvents()
            if($safetyLabel.Bottom -gt $hint.Top -or $start.Top -lt $appNote.Bottom){throw 'Resize overlaps connection controls'}
            if($phoneList.Bottom -ge $removePhone.Top -or $phoneList.Right -ge $form.ClientSize.Width){throw 'Resize breaks phone list bounds'}
            if($closeWindow.Right -gt $form.ClientSize.Width -or $detail.Bottom -gt $form.ClientSize.Height){throw 'Resize clips chrome or footer'}
            if($form.MaximumSize -ne [Drawing.Size]::Empty){throw 'Window resizing still restricted'}
            $layoutBitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
            try{
                $form.DrawToBitmap($layoutBitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height))
                $previewName=if($testSize.Width -eq (UiPixel 960)){'desktop-compact-preview.png'}else{'desktop-wide-preview.png'}
                $layoutBitmap.Save((Join-Path $PSScriptRoot ('../'+$previewName)))
            }finally{$layoutBitmap.Dispose()}
            SetDesktopView 'devices'
            if($fleet.Bottom -gt $selectionLabel.Top -or $fleetSearch.Right -gt $fleetGame.Left -or $fleetSort.Right -gt $form.ClientSize.Width){throw 'Fleet layout overlaps toolbar or footer'}
            if($fleetSearch.Height -ne $fleetGame.Height -or $fleetSearch.Top -ne $fleetGame.Top -or $fleetSearch.Width -gt (UiPixel 326)){throw 'Search field differs from Figma dimensions or filter alignment'}
            if($bulkSettings.Bounds.IntersectsWith($gridButton.Bounds)){throw 'Fleet selection toolbar overlaps view switch'}
            $fleetBitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
            try{$form.DrawToBitmap($fleetBitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height));$fleetBitmap.Save((Join-Path $PSScriptRoot ('../.tools/fleet-'+$testSize.Width+'-preview.png')))}finally{$fleetBitmap.Dispose()}
            SetDesktopView 'connection'
        }
        $screenCorner=$form.PointToScreen([Drawing.Point]::new(($form.ClientSize.Width-2),($form.ClientSize.Height-2)))
        $packed=[int64](($screenCorner.Y -band 65535)*65536+($screenCorner.X -band 65535))
        $hit=[PhoneExit.WindowChrome]::SendMessage($form.Handle,0x84,[IntPtr]::Zero,[IntPtr]$packed)
        if($hit.ToInt32() -ne 17){throw 'Bottom-right edge does not allow native resizing'}
        $form.WindowState='Maximized';[Windows.Forms.Application]::DoEvents()
        $work=[Windows.Forms.Screen]::FromHandle($form.Handle).WorkingArea
        if($form.Bounds.Left -lt $work.Left -or $form.Bounds.Top -lt $work.Top -or $form.Bounds.Right -gt $work.Right -or $form.Bounds.Bottom -gt $work.Bottom){throw 'Maximize covers taskbar or leaves screen bounds'}
        $form.WindowState='Normal';[Windows.Forms.Application]::DoEvents()
        foreach($flagFile in Get-ChildItem (Join-Path $PSScriptRoot 'assets/flags') -Filter '*.png'){
            $flagCheck=[Drawing.Image]::FromFile($flagFile.FullName);$flagCheck.Dispose()
        }
        Write-Host 'PASS: resizable layouts, native edge hit-testing, maximize inside work area, local flag assets'
    }finally{$form.WindowState='Normal';$mode.SelectedIndex=$originalMode;$form.ClientSize=$originalSize;SetDesktopView $originalView;[Windows.Forms.Application]::DoEvents()}
}
