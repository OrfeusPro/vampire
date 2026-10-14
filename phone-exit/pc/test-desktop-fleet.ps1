$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-controls.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-fleet.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Core,Accessibility
[PhoneExit.DesktopDpi]::Enable()
$flags=[Reflection.BindingFlags]'Instance,NonPublic'
foreach($scale in @(1.0,1.5)){
    $window=[Windows.Forms.Form]::new();$view=[PhoneExit.FleetView]::new();$view.UiScale=$scale
    $window.ClientSize=[Drawing.Size]::new([int](1000*$scale),[int](450*$scale));$view.Dock='Fill';$window.Controls.Add($view)
    $rows=[PhoneExit.FleetPhone[]]@(for($i=0;$i -lt 50;$i++){
        $p=[PhoneExit.FleetPhone]::new();$p.Key='fixture-'+$i;$p.Index=100+$i;$p.Name='Fixture '+$i;$p.Model='Pixel 2';$p.Country='FR';$p.Online=$i -ne 0;$p.Fresh=$p.Online;$p.BotId='lordnine';$p.BotState=if($i%2){'running'}else{'paused'};$p.BotText=$p.BotState;$p
    })
    try{
        $window.Show();$view.SetPhones($rows);[Windows.Forms.Application]::DoEvents()
        foreach($compact in @($true,$false)){
            $view.Compact=$compact
            $card=$view.CardBounds(0);$start=$view.ActionBounds(0,0);$settings=$view.ActionBounds(0,1);$menu=$view.ActionBounds(0,2)
            if($settings.Right -gt $menu.Left -or $start.Right -ge $settings.Left -or $menu.Right -gt $card.Right){throw 'Card footer actions overlap'}
            if($settings.Left -ne $card.Right-[int][Math]::Round(60*$scale) -or $menu.Left -ne $card.Right-[int][Math]::Round(32*$scale)){throw 'Settings and menu are not grouped at card right edge'}
            if($start.Top -ne $settings.Top -or $settings.Top -ne $menu.Top){throw 'Footer icons are not vertically aligned'}
        }
        $view.Compact=$true
        $accent=$view.GetType().GetMethod('StatusAccent',$flags)
        foreach($case in @(
            @{online=$true;fresh=$true;state='running';pending=$false;bot='lordnine';rgb=@(98,231,188)},
            @{online=$true;fresh=$true;state='paused';pending=$false;bot='lordnine';rgb=@(240,198,127)},
            @{online=$true;fresh=$true;state='error';pending=$false;bot='lordnine';rgb=@(242,141,157)},
            @{online=$false;fresh=$false;state='running';pending=$false;bot='lordnine';rgb=@(242,141,157)},
            @{online=$true;fresh=$false;state='running';pending=$false;bot='lordnine';rgb=@(78,88,94)},
            @{online=$true;fresh=$true;state='stopped';pending=$true;bot='lordnine';rgb=@(240,198,127)},
            @{online=$true;fresh=$true;state='running';pending=$false;bot='';rgb=@(78,88,94)}
        )){
            $p=[PhoneExit.FleetPhone]::new();$p.Online=$case.online;$p.Fresh=$case.fresh;$p.BotState=$case.state;$p.Pending=$case.pending;$p.BotId=$case.bot
            $color=$accent.Invoke($view,@($p));$expected=[Drawing.Color]::FromArgb($case.rgb[0],$case.rgb[1],$case.rgb[2])
            if($color.ToArgb() -ne $expected.ToArgb()){throw "Incorrect status accent: $($case.state)"}
        }
        $stripeShot=[Drawing.Bitmap]::new($view.Width,$view.Height)
        try{
            $view.DrawToBitmap($stripeShot,[Drawing.Rectangle]::new(0,0,$view.Width,$view.Height))
            foreach($i in 0..2){$r=$view.CardBounds($i);$color=$stripeShot.GetPixel(($r.X+[int]($r.Width/2)),($r.Y+1));$expected=$accent.Invoke($view,@($rows[$i]));if($color.ToArgb() -ne $expected.ToArgb()){throw 'Status stripe missing from card pixels'}}
            $stripeShot.Save((Join-Path $PSScriptRoot "../.tools/fleet-status-stripes-$scale.png"))
        }finally{$stripeShot.Dispose()}
        $script:fleetTestAction=$null
        $view.Add_Action({param($sender,$e)$script:fleetTestAction=$e})
        $r=$view.ActionBounds(3,1)
        $mouse=[Windows.Forms.MouseEventArgs]::new([Windows.Forms.MouseButtons]::Left,1,($r.X+3),($r.Y+3),0)
        $view.GetType().GetMethod('OnMouseDown',$flags).Invoke($view,@($mouse.PSObject.BaseObject))
        if($script:fleetTestAction.Index -ne 103 -or $script:fleetTestAction.Action -ne 'settings' -or $script:fleetTestAction.Key -ne 'fixture-3'){throw 'Card action lost stable identity'}
        if($view.AccessibilityObject.GetChildCount() -ne 50 -or !$view.AccessibilityObject.GetChild(3).Name.Contains('Fixture 3')){throw 'Screen reader cannot inspect cards'}
        $view.SelectAll($true)
        if($view.SelectedCount -ne 50 -or $view.ActionIndexes('pause').Count -ne 25 -or $view.ActionIndexes('resume').Count -ne 24){throw 'Bulk action availability includes offline or wrong-state devices'}
        $rows[1].Pending=$true;$view.SetPhones($rows)
        if($view.ActionIndexes('pause').Count -ne 24){throw 'Pending action can be sent again'}
        $keys=[Windows.Forms.KeyEventArgs]::new([Windows.Forms.Keys]::End)
        $view.GetType().GetMethod('OnKeyDown',$flags).Invoke($view,@($keys.PSObject.BaseObject))
        if($view.ScrollOffset -le 0){throw 'Keyboard cannot reach last card'}
        $offset=$view.ScrollOffset;$view.SetPhones($rows)
        if($view.ScrollOffset -ne $offset -or $view.SelectedCount -ne 50){throw 'Refresh resets scroll or selection'}
        $view.SetPhones([PhoneExit.FleetPhone[]]@($rows|Sort-Object Index -Descending))
        if($view.SelectedIndexes -notcontains 103){throw 'Sorting changed selection identity'}
        $view.SetPhones([PhoneExit.FleetPhone[]]@($rows[0..4]))
        if($view.SelectedCount -ne 5){throw 'Hidden filtered devices remain selected'}
        $view.Table=$true
        $rows[3].ApkVersion='0.8.8';$rows[3].Provider='VMOS';$rows[3].BotVersion='1.1.18';$rows[3].Group='Фарм / A';$rows[3].VpnState='active';$view.SetPhones([PhoneExit.FleetPhone[]]@($rows[0..4]))
        $filter=[PhoneExit.FleetFilter]::new();$filter.Provider='VMOS';$filter.ApkVersion='0.8.8';$filter.BotVersion='1.1.18';$filter.Group='Фарм / A';$filter.VpnState='active';$filter.State='running';$filter.Connection=1
        if(!$filter.Matches($rows[3]) -or $filter.Matches($rows[2])){throw 'Combined fleet filters failed'}
        $rows[3].Fresh=$false;if($filter.Matches($rows[3])){throw 'Stale bot matches current-state filter'};$rows[3].Fresh=$true
        $filter.Provider='UgPhone';if($filter.Matches($rows[3])){throw 'Provider filter ignored'}
        $rows[3].Provider='LDCloud';$filter.Provider='LDCloud';if(!$filter.Matches($rows[3])){throw 'LDCloud provider filter failed'}
        $providerLogo=[Drawing.Image]::FromFile((Join-Path $PSScriptRoot 'assets/providers/ldcloud.png'))
        try{
            if($providerLogo.Width -ne 40 -or $providerLogo.Height -ne 40){throw 'LDCloud official logo dimensions changed'}
            $rows[3].ProviderIcon=$providerLogo;$view.SetPhones([PhoneExit.FleetPhone[]]@($rows[0..4]))
            foreach($tableMode in @($true,$false)){$view.Table=$tableMode;$bitmap=[Drawing.Bitmap]::new($view.Width,$view.Height);try{$view.DrawToBitmap($bitmap,$view.ClientRectangle)}finally{$bitmap.Dispose()}}
        }finally{$rows[3].ProviderIcon=$null;$providerLogo.Dispose();$view.Table=$true}
        foreach($width in @(720,1000,1360)){
            $view.Width=[int]($width*$scale)
            $previous=0
            foreach($column in 0..9){$bounds=$view.ColumnBounds($column);if($bounds.X -lt $previous -or $bounds.Width -le 0 -or $bounds.Right -gt $view.CardBounds(0).Right){throw 'Table columns overlap or escape content'};$previous=$bounds.Right}
            if($view.ColumnBounds(2).Width -gt [Math]::Ceiling(70*$scale) -or $view.ColumnBounds(5).Width -gt [Math]::Ceiling(64*$scale)){throw 'Country or APK column expands unnecessarily'}
        }
        $view.Dock='Fill';$window.PerformLayout()
        $horizontal=$view.GetType().GetField('horizontal',$flags).GetValue($view)
        if(!$horizontal.Visible){throw 'Narrow table cannot scroll horizontally'}
        $horizontal.Value=100
        if($view.ColumnBounds(0).X -ne -100 -or $view.CardBounds(0).X -ne -100){throw 'Horizontal scroll separates columns from rows'}
        $horizontal.Value=100000
        $settings=$view.ActionBounds(3,1)
        if($settings.Right -gt $view.Width){throw 'Horizontal scroll cannot reach action column'}
        $script:fleetTestAction=$null
        $mouse=[Windows.Forms.MouseEventArgs]::new([Windows.Forms.MouseButtons]::Left,1,($settings.X+3),($settings.Y+3),0)
        $view.GetType().GetMethod('OnMouseDown',$flags).Invoke($view,@($mouse.PSObject.BaseObject))
        if($script:fleetTestAction.Key -ne 'fixture-3'){throw 'Horizontal scroll changed action target'}
        $horizontal.Value=0
        if(!$view.AccessibilityObject.GetChild(3).Name.Contains('APK 0.8.8')){throw 'APK version missing from accessibility'}
        $headerHit=$view.GetType().GetMethod('Hit',$flags).Invoke($view,@([Drawing.Point]::new(10,10)))
        if($headerHit -ne -1){throw 'Table header selects a phone'}
        foreach($i in 0..4){foreach($action in 0..2){if(!$view.CardBounds($i).Contains($view.ActionBounds($i,$action))){throw 'Table action clips its row'}}}
        $tableShot=[Drawing.Bitmap]::new($window.Width,$window.Height)
        try{$window.DrawToBitmap($tableShot,[Drawing.Rectangle]::new(0,0,$window.Width,$window.Height));$tableShot.Save((Join-Path $PSScriptRoot "../.tools/fleet-table-$scale.png"))}finally{$tableShot.Dispose()}
        if($view.CardBounds(1).X -ne 0 -or $view.CardBounds(1).Y -le $view.CardBounds(0).Y){throw 'Table view failed'}
        $view.SelectAll($true)
        $empty=[Windows.Forms.MouseEventArgs]::new([Windows.Forms.MouseButtons]::Left,1,10,($view.CardBounds(4).Bottom+5),0)
        $view.GetType().GetMethod('OnMouseDown',$flags).Invoke($view,@($empty.PSObject.BaseObject))
        if($view.SelectedCount -ne 0 -or $view.GetType().GetField('focus',$flags).GetValue($view) -ne -1){throw 'Empty-space click retains selection highlight'}
        $view.Table=$false;$view.Compact=$false;$view.SetPhones($rows)
        $bitmap=[Drawing.Bitmap]::new($window.Width,$window.Height)
        try{$window.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$window.Width,$window.Height));$bitmap.Save((Join-Path $PSScriptRoot ('../.tools/fleet-fixture-'+$scale+'-preview.png')))}finally{$bitmap.Dispose()}
    }finally{$window.Close();$window.Dispose()}
}
Write-Output 'PASS: 50 fixture cards, 100%/150% layout, original action indexes, fresh/offline/pending guards, sorting, selection, table, keyboard and retained scroll.'
