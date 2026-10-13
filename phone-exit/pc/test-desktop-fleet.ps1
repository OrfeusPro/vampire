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
        $rows[3].ApkVersion='0.8.8';$view.SetPhones([PhoneExit.FleetPhone[]]@($rows[0..4]))
        if(!$view.AccessibilityObject.GetChild(3).Name.Contains('APK 0.8.8')){throw 'APK version missing from accessibility'}
        $headerHit=$view.GetType().GetMethod('Hit',$flags).Invoke($view,@([Drawing.Point]::new(10,10)))
        if($headerHit -ne -1){throw 'Table header selects a phone'}
        foreach($i in 0..4){foreach($action in 0..2){if(!$view.CardBounds($i).Contains($view.ActionBounds($i,$action))){throw 'Table action clips its row'}}}
        $tableShot=[Drawing.Bitmap]::new($window.Width,$window.Height)
        try{$window.DrawToBitmap($tableShot,[Drawing.Rectangle]::new(0,0,$window.Width,$window.Height));$tableShot.Save((Join-Path $PSScriptRoot "../.tools/fleet-table-$scale.png"))}finally{$tableShot.Dispose()}
        if($view.CardBounds(1).X -ne 0 -or $view.CardBounds(1).Y -le $view.CardBounds(0).Y){throw 'Table view failed'}
        $view.Table=$false;$view.Compact=$false;$view.SetPhones($rows)
        $bitmap=[Drawing.Bitmap]::new($window.Width,$window.Height)
        try{$window.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$window.Width,$window.Height));$bitmap.Save((Join-Path $PSScriptRoot ('../.tools/fleet-fixture-'+$scale+'-preview.png')))}finally{$bitmap.Dispose()}
    }finally{$window.Close();$window.Dispose()}
}
Write-Output 'PASS: 50 fixture cards, 100%/150% layout, original action indexes, fresh/offline/pending guards, sorting, selection, table, keyboard and retained scroll.'
