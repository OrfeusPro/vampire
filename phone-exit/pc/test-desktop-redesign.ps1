function TestDesktopRedesign {
    $savedIndex=$phoneList.SelectedIndex
    try{
        SetDesktopView 'devices';RefreshFleet
        if($fleet.VisibleCount -ne $script:phoneRows.Count){throw 'Directory phones missing from grid'}
        $fleet.SelectAll($true)
        if($fleet.SelectedCount -ne $script:phoneRows.Count){throw 'Select all failed'}
        $fleetSort.SelectedIndex=1
        if($fleet.SelectedCount -ne $script:phoneRows.Count){throw 'Sort lost selection'}
        $savedRows=$script:phoneRows
        try{
            $stableKey=$fleet.SelectedKeys[0];$script:phoneRows=@($savedRows|Sort-Object name -Descending)
            $resolved=FindFleetPhone $stableKey
            if($resolved -lt 0 -or [string]$script:phoneRows[$resolved].id -ne $stableKey){throw 'Directory reorder changes fleet action target'}
        }finally{$script:phoneRows=$savedRows}
        $fleetSearch.Text='fixture-name-not-in-real-directory'
        if($fleet.VisibleCount -ne 0 -or $fleet.SelectedCount -ne 0){throw 'Search failed or retained hidden targets'}
        $fleetSearch.Clear();$fleetState.SelectedIndex=2
        if($fleet.VisibleCount -ne @($script:phoneRows|Where-Object {!$_.online}).Count){throw 'Offline filter is inaccurate'}
        $fleetState.SelectedIndex=0;$fleetSort.SelectedIndex=0
        SetFleetAdvanced $true
        foreach($field in @('Country','ApkVersion','Provider','BotVersion')){
            $control=$fleetExtra[$field]
            if($control.Items.Count -gt 1){
                $control.SelectedIndex=1;RefreshFleet
                $visible=$fleet.GetType().GetField('rows',[Reflection.BindingFlags]'Instance,NonPublic').GetValue($fleet)
                $expected=if($field -eq 'Country'){$script:fleetCountryCodes[[string]$control.SelectedItem]}elseif([string]$control.SelectedItem -eq 'Не указано'){''}else{[string]$control.SelectedItem}
                foreach($row in $visible){if([string]$row.$field -ne $expected){throw "Fleet $field filter ignored"}}
                $before=$control.SelectedItem;RefreshFleet;if($control.SelectedItem -ne $before){throw 'Refresh resets active filter'}
                $control.SelectedIndex=0
            }
        }
        SetFleetAdvanced $false
        if($fleetExtra.BotVersion.Visible -or $fleetExtra.Provider.Visible){throw 'Advanced filters visible by default'}
        SetFleetAdvanced $true;$fleetExtra.Connection.SelectedIndex=2;SetFleetAdvanced $false
        if($fleetExtra.Connection.SelectedIndex -ne 0 -or $fleet.VisibleCount -ne $script:phoneRows.Count){throw 'Hidden advanced filter still limits devices'}
        $countries=@($fleetExtra.Country.Items|Select-Object -Skip 1)
        if(($countries -join '|') -ne (@($countries|Sort-Object) -join '|')){throw 'Country menu is not alphabetical'}
        foreach($name in $countries){if(!$fleetExtra.Country.ItemImages.ContainsKey($name)){throw 'Country flag missing from filter'}}
        foreach($size in @([Drawing.Size]::new((UiPixel 960),(UiPixel 700)),[Drawing.Size]::new((UiPixel 1440),(UiPixel 1000)))){
            $form.ClientSize=$size;UpdateWindowLayout
            $filters=@(@($fleetSearch,$fleetGame,$fleetState,$fleetSort)+@($fleetExtra.Values)|Where-Object {$_.Visible})
            foreach($control in $filters){if($control.Right -gt $form.ClientSize.Width -or $control.Bottom -gt $bulkStart.Top){throw 'Fleet filter escapes toolbar'};foreach($other in $filters){if($other -ne $control -and $other.Bounds.IntersectsWith($control.Bounds)){throw 'Fleet filters overlap'}}}
            if($viewSwitch.Top -ne $fleetSearch.Top -or $gridButton.Parent -ne $viewSwitch -or $tableButton.Parent -ne $viewSwitch){throw 'View switch left filter toolbar'}
            if($fleet.Height -lt (UiPixel 324)){throw 'Two compact phone rows do not fit'}
            foreach($table in @($false,$true)){
                $fleet.Table=$table;UpdateWindowLayout;[Windows.Forms.Application]::DoEvents()
                $bitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
                $name=if($table){'table'}else{'grid'}
                try{$form.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height));$bitmap.Save((Join-Path $PSScriptRoot ('../.tools/redesign-'+$name+'-'+$size.Width+'.png')))}finally{$bitmap.Dispose()}
            }
            $fleet.Table=$false;$fleet.Compact=$false;$densityButton.Text='M';UpdateWindowLayout;[Windows.Forms.Application]::DoEvents()
            if(2*$fleet.CardBounds(0).Height+(UiPixel 8) -gt $fleet.Height){throw 'Two normal phone rows do not fit'}
            $bitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
            try{$form.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height));$bitmap.Save((Join-Path $PSScriptRoot ('../.tools/redesign-normal-'+$size.Width+'.png')))}finally{$bitmap.Dispose()}
            $fleet.Compact=$true;$densityButton.Text='XS'
        }
        $form.ClientSize=[Drawing.Size]::new((UiPixel 1600),(UiPixel 1000));UpdateWindowLayout
        if($fleetSearch.Width -ne (UiPixel 326) -or $fleetGame.Width -ne (UiPixel 144) -or $viewSwitch.Width -ne (UiPixel 128)){throw 'Controls differ from canonical Figma widths'}
        if(!$navDevices.Borderless -or !$bulkStart.CenterContent -or $bulkStart.NavigationIcon -ne 'play'){throw 'Canonical button styling missing'}
        foreach($view in @('table','compact','normal')){
            $fleet.Table=$view -eq 'table';$fleet.Compact=$view -ne 'normal';$densityButton.Text=if($fleet.Compact){'XS'}else{'M'}
            UpdateWindowLayout;[Windows.Forms.Application]::DoEvents()
            if($view -eq 'compact' -and $fleet.VisibleCount -ge 10 -and $fleet.CardBounds(9).Top -ne $fleet.CardBounds(0).Top){throw 'Compact mode has fewer than ten columns at Figma width'}
            $bitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
            try{$form.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height));$bitmap.Save((Join-Path $PSScriptRoot "../docs/redesign-2026-10-13/audit-app-$view.png"))}finally{$bitmap.Dispose()}
        }
        $fleet.Compact=$true;$densityButton.Text='XS'
        $fleet.Table=$false;$phoneList.SelectedIndex=0;SetDesktopView 'connection'
        if(!$start.Visible -or $fleet.Visible -or !$selectedPhoneLabel.Text.Contains([string]$script:phoneRows[0].name)){throw 'Connection view selection failed'}
        $savedActive=$script:selectedPhone;$savedWanted=$script:connectionWanted
        try{
            $script:selectedPhone=[string]$script:phoneRows[-1].id;$script:connectionWanted=$true;RefreshFleet
            if(!$selectedPhoneLabel.Text.Contains([string]$script:phoneRows[-1].name)){throw 'Connection details describe list selection instead of active phone'}
        }finally{$script:selectedPhone=$savedActive;$script:connectionWanted=$savedWanted;RefreshFleet}
        $bitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
        try{$form.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height));$bitmap.Save((Join-Path $PSScriptRoot '../.tools/redesign-connection.png'))}finally{$bitmap.Dispose()}
        . (Join-Path $PSScriptRoot 'test-window-layout.ps1')
        TestWindowLayout
        $originalLocation=$form.Location
        foreach($screen in [Windows.Forms.Screen]::AllScreens){
            $form.Location=[Drawing.Point]::new(($screen.WorkingArea.Left+30),($screen.WorkingArea.Top+30));[Windows.Forms.Application]::DoEvents()
            if($form.MonitorDpi -ne [PhoneExit.DesktopDpi]::WindowDpi($form)){throw 'Main window did not adopt monitor DPI'}
            foreach($view in @('devices','connection')){
                SetDesktopView $view;[Windows.Forms.Application]::DoEvents()
                $bitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
                try{$form.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height));$bitmap.Save((Join-Path $PSScriptRoot "../.tools/main-$view-dpi-$($form.MonitorDpi).png"))}finally{$bitmap.Dispose()}
            }
        }
        $form.Location=$originalLocation;[Windows.Forms.Application]::DoEvents()
        Write-Host "PASS: real directory $($script:phoneRows.Count) phones; live bot badges; search, filter, sort, selection, two sizes, grid/table, connection and auxiliary windows. No bot commands or VPN started."
    }finally{$phoneList.SelectedIndex=$savedIndex}
}
