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
        foreach($size in @([Drawing.Size]::new((UiPixel 960),(UiPixel 700)),[Drawing.Size]::new((UiPixel 1440),(UiPixel 1000)))){
            $form.ClientSize=$size;UpdateWindowLayout
            foreach($table in @($false,$true)){
                $fleet.Table=$table;UpdateWindowLayout;[Windows.Forms.Application]::DoEvents()
                $bitmap=[Drawing.Bitmap]::new($form.Width,$form.Height)
                $name=if($table){'table'}else{'grid'}
                try{$form.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height));$bitmap.Save((Join-Path $PSScriptRoot ('../.tools/redesign-'+$name+'-'+$size.Width+'.png')))}finally{$bitmap.Dispose()}
            }
        }
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
        Write-Host "PASS: real directory $($script:phoneRows.Count) phones; live bot badges; search, filter, sort, selection, two sizes, grid/table, connection and auxiliary windows. No bot commands or VPN started."
    }finally{$phoneList.SelectedIndex=$savedIndex}
}
