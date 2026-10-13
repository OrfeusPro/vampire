param([ValidateRange(0,120)][int]$PreviewSeconds=0)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing,System.Security,System.Net.Http,System.Web.Extensions
. (Join-Path $PSScriptRoot 'profile.ps1')
Add-Type -Path @((Join-Path $PSScriptRoot 'desktop-controls.cs'),(Join-Path $PSScriptRoot 'desktop-bots.cs')) -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
[PhoneExit.DesktopDpi]::Enable()
$secret=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path (GetPhoneExitProfileDirectory) 'control-api.bin')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
$catalog=Invoke-RestMethod 'http://127.0.0.1:17842/bot/v1/phones' -Headers @{Authorization="Bearer $secret"} -TimeoutSec 10
$phone=@($catalog.phones|Where-Object {$_.country -eq 'SG'})[0]
if(!$phone){$phone=@($catalog.phones)[-1]}
$flags=[Reflection.BindingFlags]'NonPublic,Instance'
function GetDarkFlows($root){if($root -is [PhoneExit.DarkFlowPanel]){Write-Output -NoEnumerate $root};foreach($child in $root.Controls){GetDarkFlows $child}}
foreach($id in @([string]$phone.id,'missing-test-device')) {
    $panel=New-Object PhoneExit.BotPanel($secret,([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../bots'))))
    $panel.DevicePhoneId=$id
    try {
        $panel.Show();$deadline=[DateTime]::UtcNow.AddSeconds(20)
        $captions=@($panel.Controls|ForEach-Object {$_.Controls}|Where-Object {$_ -is [PhoneExit.CaptionButton]})
        $close=@($captions|Where-Object {$_.Icon -eq 'close'})[0]
        $maximize=@($captions|Where-Object {$_.Icon -eq 'maximize'})[0]
        $minimize=@($captions|Where-Object {$_.Icon -eq 'minimize'})[0]
        if($captions.Count -ne 3 -or $close.Left -le $maximize.Left -or $maximize.Left -le $minimize.Left){throw 'Window caption icons have incorrect order'}
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
            $gameSelect=$panel.GetType().GetField('gameSelect',$flags).GetValue($panel)
            if($gameSelect.SelectedItem -ne 'Lord Nine'){throw 'Assigned game is not selected from the catalog'}
            $originalSettings=$profile['settings']
            $originalDirty=$panel.GetType().GetField('dirty',$flags).GetValue($panel)
            $panel.GetType().GetField('chosenGame',$flags).SetValue($panel,'future-game')
            $panel.GetType().GetMethod('UpdateGameView',$flags).Invoke($panel,@())
            $tabs.SelectedIndex=1
            if($tabs.SelectedIndex -eq 1 -or $panel.GetType().GetField('farm',$flags).GetValue($panel).Visible){throw 'Another game exposes LordNine farm controls'}
            foreach($action in $panel.GetType().GetField('actions',$flags).GetValue($panel)){if($action.Text -eq 'Сохранить и отправить настройки' -and $action.Enabled){throw 'Another game can save LordNine settings'}}
            if($profile['settings'] -ne $originalSettings -or $panel.GetType().GetField('dirty',$flags).GetValue($panel) -ne $originalDirty){throw 'Game preview mutated the profile'}
            $panel.GetType().GetField('chosenGame',$flags).SetValue($panel,'lordnine')
            $panel.GetType().GetMethod('UpdateGameView',$flags).Invoke($panel,@())
            $points=$panel.GetType().GetField('points',$flags).GetValue($panel)
            $before=$points.Count
            foreach($width in @(1200,1440)){
                $panel.Size=[Drawing.Size]::new($width,900)
                foreach($action in $panel.GetType().GetField('actions',$flags).GetValue($panel)){
                    if($action.Text -eq 'Сохранить и отправить настройки'){
                        foreach($button in $action.Parent.Controls){if($button.Right -gt $button.Parent.ClientSize.Width -or $button.Bottom -gt $button.Parent.ClientSize.Height){throw 'Footer button overflows its container'}}
                    }
                }
                for($tab=0;$tab -lt 4;$tab++){
                    $tabs.SelectedIndex=$tab;[Windows.Forms.Application]::DoEvents()
                    foreach($flow in @(GetDarkFlows $tabs.TabPages[$tab])){
                        $flow.PerformLayout();$tops=@($flow.Controls|ForEach-Object {$_.Top})
                        for($pass=0;$pass -lt 10;$pass++){$flow.PerformLayout()}
                        for($i=0;$i -lt $tops.Count;$i++){if($flow.Controls[$i].Top -ne $tops[$i]){throw "Tab $tab has unstable repeated layout"}}
                    }
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
            $tabs.SelectedIndex=1;[Windows.Forms.Application]::DoEvents()
            $spots=$panel.GetType().GetField('spots',$flags).GetValue($panel)
            $originalSpot=$spots.SelectedIndex
            $spots.SelectedIndex=0;[Windows.Forms.Application]::DoEvents()
            $pointList=$panel.GetType().GetField('pointList',$flags).GetValue($panel)
            $moveRows=@($pointList.Controls|Where-Object {$_ -is [PhoneExit.MoveRowButton]})
            if($moveRows.Count -ne 3){throw "Bundled Ulan image must show its three nonempty Move rows; got $($moveRows.Count)"}
            foreach($width in @(1200,1440)){$panel.Size=[Drawing.Size]::new($width,900);[Windows.Forms.Application]::DoEvents();if($pointList.HorizontalScroll.Visible){throw 'Fast Travel panel requires horizontal scrolling'}}
            $picture=$panel.GetType().GetField('picture',$flags).GetValue($panel)
            $picture.Image.Save((Join-Path $PSScriptRoot '../.tools/ulan-map-crop.png'))
            for($row=0;$row -lt $moveRows.Count;$row++){$moveRows[$row].Image.Save((Join-Path $PSScriptRoot "../.tools/ulan-move-$row.png"))}
            $ulanPreview=[Drawing.Bitmap]::new($panel.Width,$panel.Height)
            try{$panel.DrawToBitmap($ulanPreview,[Drawing.Rectangle]::new(0,0,$panel.Width,$panel.Height));$ulanPreview.Save((Join-Path $PSScriptRoot '../.tools/ulan-editor-preview.png'))}finally{$ulanPreview.Dispose()}
            $panel.GetType().GetMethod('SelectTeleportRow',$flags).Invoke($panel,@(2))
            $teleport=$points[0]['teleport_point']
            if([Math]::Abs($teleport[0]-.85297) -gt .00001 -or [Math]::Abs($teleport[1]-.314) -gt .00001){throw 'Fast Travel selection changed original full-frame coordinates'}
            $panel.GetType().GetMethod('UndoPointEdit',$flags).Invoke($panel,@())
            $spots.SelectedIndex=$originalSpot;[Windows.Forms.Application]::DoEvents()
            $moveRows=@($pointList.Controls|Where-Object {$_ -is [PhoneExit.MoveRowButton]})
            if($moveRows.Count -ne 1 -or $moveRows[0].Enabled){throw 'Tyriosa must show only its locked route row'}
            $picture.Image.Save((Join-Path $PSScriptRoot '../.tools/tyriosa-map-crop.png'))
            $moveRows[0].Image.Save((Join-Path $PSScriptRoot '../.tools/tyriosa-move-1.png'))
            $spot=$points[$originalSpot];$count=@($spot['map_points']).Count
            $panel.GetType().GetMethod('SetPointTool',$flags).Invoke($panel,@('add'))
            $rect=$panel.GetType().GetMethod('ImageRect',$flags).Invoke($panel,@())
            $click=[Windows.Forms.MouseEventArgs]::new('Left',1,($rect.X+[int]($rect.Width*.2)),($rect.Y+[int]($rect.Height*.25)),0)
            $panel.GetType().GetMethod('PlacePoint',$flags).Invoke($panel,@($click))
            if(@($spot['map_points']).Count -ne $count+1){throw 'Add tool did not add a point'}
            $added=@($spot['map_points'])[-1]
            $panel.GetType().GetMethod('PlacePoint',$flags).Invoke($panel,@($click))
            if(@($spot['map_points']).Count -ne $count+1){throw 'Add tool removed or duplicated a nearby point'}
            $panel.GetType().GetMethod('SetPointTool',$flags).Invoke($panel,@('move'))
            $panel.GetType().GetMethod('BeginPointMove',$flags).Invoke($panel,@($click))
            $end=[Windows.Forms.MouseEventArgs]::new('Left',1,($rect.X+[int]($rect.Width*.4)),($rect.Y+[int]($rect.Height*.35)),0)
            $panel.GetType().GetMethod('EndPointMove',$flags).Invoke($panel,@($end))
            if(@($spot['map_points']).Count -ne $count+1 -or [Math]::Abs(@($spot['map_points'])[-1][0]-$added[0]) -lt .01){throw 'Move tool did not relocate the same point'}
            $panel.GetType().GetMethod('UndoPointEdit',$flags).Invoke($panel,@())
            if([Math]::Abs(@($spot['map_points'])[-1][0]-$added[0]) -gt .00001){throw 'Undo did not restore moved coordinates'}
            $panel.GetType().GetMethod('SetPointTool',$flags).Invoke($panel,@('delete'))
            $panel.GetType().GetMethod('PlacePoint',$flags).Invoke($panel,@($click))
            if(@($spot['map_points']).Count -ne $count){throw 'Delete tool did not remove the hit point'}
            $panel.GetType().GetMethod('UndoPointEdit',$flags).Invoke($panel,@())
            $panel.GetType().GetMethod('UndoPointEdit',$flags).Invoke($panel,@())
            if(@($spot['map_points']).Count -ne $count){throw 'Undo did not restore original point count'}
            $snapshot=ConvertTo-Json $spot['map_points'] -Compress -Depth 10
            $viewport=$picture.Parent
            $panel.GetType().GetMethod('ZoomMapAt',$flags).Invoke($panel,@([Drawing.Point]::new(100,100),[int]120))
            if($panel.GetType().GetField('zoom',$flags).GetValue($panel) -le 1){throw 'Mouse wheel did not zoom the map'}
            $panel.GetType().GetMethod('SetZoom',$flags).Invoke($panel,@([double]2))
            $previousLocation=$picture.Location
            $panel.GetType().GetMethod('PositionMap',$flags).Invoke($panel,@([Drawing.Point]::new(($previousLocation.X-40),($previousLocation.Y-40))))
            if($picture.Location -eq $previousLocation -or $viewport.AutoScroll){throw 'Map panning or scrollbar-free viewport is broken'}
            if((ConvertTo-Json $spot['map_points'] -Compress -Depth 10) -ne $snapshot){throw 'Panning or mouse-wheel zoom changed saved points'}
            $panel.GetType().GetMethod('SetZoom',$flags).Invoke($panel,@([double]1))
            $compactMap=$picture.Size
            $panel.Size=[Drawing.Size]::new(2400,1400);[Windows.Forms.Application]::DoEvents()
            if($picture.Height -le $compactMap.Height+100){throw 'Map does not grow with the editor viewport'}
            if($picture.Height -gt $picture.Parent.ClientSize.Height -or $picture.Width -gt $picture.Parent.ClientSize.Width){throw 'Fit map overflows viewport'}
            $panel.GetType().GetMethod('SetZoom',$flags).Invoke($panel,@([double]2))
            $panel.Size=[Drawing.Size]::new(1200,900);[Windows.Forms.Application]::DoEvents()
            $panel.GetType().GetField('wholeMap',$flags).SetValue($panel,$true)
            $panel.GetType().GetMethod('LoadMap',$flags).Invoke($panel,@())
            if((ConvertTo-Json $spot['map_points'] -Compress -Depth 10) -ne $snapshot){throw 'Zoom, resize or full-frame view changed saved coordinates'}
            $panel.GetType().GetField('wholeMap',$flags).SetValue($panel,$false)
            $panel.GetType().GetMethod('LoadMap',$flags).Invoke($panel,@())
            $panel.GetType().GetMethod('SetPointTool',$flags).Invoke($panel,@('add'))
            $panel.GetType().GetField('dirty',$flags).SetValue($panel,$false)
            $twilightIndex=-1
            for($i=0;$i -lt $mapItems.Count;$i++){if($mapItems[$i]['label'] -eq 'Twilight Hill'){$twilightIndex=$i;break}}
            if($twilightIndex -lt 0){throw 'Twilight Hill catalog entry missing'}
            $countBeforePreview=$points.Count
            $panel.GetType().GetMethod('SelectCatalogMap',$flags).Invoke($panel,@($twilightIndex))
            if($points.Count -ne $countBeforePreview -or $panel.GetType().GetField('dirty',$flags).GetValue($panel)){throw 'Catalog navigation changed the profile'}
            $mapNav=$panel.GetType().GetField('mapNavigation',$flags).GetValue($panel)
            if($mapNav.Controls.Count -ne 4){throw 'Lindris navigation must show all four maps'}
            $fixture=[Web.Script.Serialization.JavaScriptSerializer]::new().DeserializeObject('{"id":"ui-twilight-fixture","label":"Twilight Hill","enabled":true,"run_after_teleport":true,"map_points":[[0.505,0.562]],"teleport_point":null}')
            $fixture['map_id']=$mapItems[$twilightIndex]['id']
            $points.Add($fixture);$panel.GetType().GetMethod('RefreshSpots',$flags).Invoke($panel,@($points.Count-1));$panel.Size=[Drawing.Size]::new(1440,900);[Windows.Forms.Application]::DoEvents()
            $moveRows=@($pointList.Controls|Where-Object {$_ -is [PhoneExit.MoveRowButton]})
            if($moveRows.Count -ne 11){throw "Twilight Hill must show all eleven Move rows; got $($moveRows.Count)"}
            $pointList.GetType().GetMethod('OnMouseWheel',$flags).Invoke($pointList,@([Windows.Forms.MouseEventArgs]::new('None',0,10,10,-120)))
            if($pointList.AutoScrollPosition.Y -ge 0){throw 'Custom list scrollbar does not respond to the wheel'}
            $positions=@($pointList.Controls|ForEach-Object {$_.Top})
            for($pass=0;$pass -lt 20;$pass++){$pointList.PerformLayout()}
            for($i=0;$i -lt $positions.Count;$i++){if($pointList.Controls[$i].Top -ne $positions[$i]){throw 'Repeated list layout accumulates scroll displacement'}}
            for($i=1;$i -lt $pointList.Controls.Count;$i++){if($pointList.Controls[$i].Top -lt $pointList.Controls[$i-1].Bottom){throw 'Right-side list controls overlap'}}
            $pointList.AutoScrollPosition=[Drawing.Point]::Empty
            $regionNav=$panel.GetType().GetField('regionNavigation',$flags).GetValue($panel)
            for($pass=0;$pass -lt 3;$pass++){
                $panel.GetType().GetMethod('SelectCatalogMap',$flags).Invoke($panel,@(0))
                $panel.GetType().GetMethod('SelectCatalogMap',$flags).Invoke($panel,@($twilightIndex))
                if($mapNav.Controls.Count -ne 4 -or @($regionNav.Controls|Group-Object Text|Where-Object Count -gt 1).Count -gt 0){throw 'Catalog refresh duplicates navigation rows'}
            }
            $moveRows=@($pointList.Controls|Where-Object {$_ -is [PhoneExit.MoveRowButton]})
            $marker=[Drawing.Bitmap]::new($picture.Width,$picture.Height)
            $markerGraphics=[Drawing.Graphics]::FromImage($marker)
            try{
                $panel.GetType().GetMethod('PaintPoints',$flags).Invoke($panel,@($markerGraphics))
                $rect=$panel.GetType().GetMethod('ImageRect',$flags).Invoke($panel,@())
                $crop=$panel.GetType().GetField('mapCrop',$flags).GetValue($panel)
                $mx=[int]($rect.X+(.505-$crop.X)/$crop.Width*$rect.Width)
                $my=[int]($rect.Y+(.562-$crop.Y)/$crop.Height*$rect.Height)
                if($marker.GetPixel($mx+10,$my-27).G -lt 180 -or $marker.GetPixel($mx,$my+8).A -ne 0){throw 'Triangle marker is not anchored by its lower tip at the saved coordinate'}
            }finally{$markerGraphics.Dispose();$marker.Dispose()}
            if($pointList.HorizontalScroll.Visible -or $mapNav.HorizontalScroll.Visible){throw 'Farm navigation or Move list needs horizontal scrolling'}
            $regionNav=$panel.GetType().GetField('regionNavigation',$flags).GetValue($panel)
            for($i=0;$i -lt $regionNav.Controls.Count;$i++){if(!$regionNav.Controls[$i].Image){throw 'Region icon missing'};$regionNav.Controls[$i].Image.Save((Join-Path $PSScriptRoot "../.tools/region-icon-$i.png"))}
            for($i=0;$i -lt $mapNav.Controls.Count;$i++){if(!$mapNav.Controls[$i].Image){throw 'Location icon missing'};$mapNav.Controls[$i].Image.Save((Join-Path $PSScriptRoot "../.tools/lindris-icon-$i.png"))}
            $picture.Image.Save((Join-Path $PSScriptRoot '../.tools/twilight-map-crop.png'))
            for($i=0;$i -lt $moveRows.Count;$i++){$moveRows[$i].Image.Save((Join-Path $PSScriptRoot "../.tools/twilight-move-$i.png"))}
            $pointList.AutoScrollPosition=[Drawing.Point]::Empty
            $preview=[Drawing.Bitmap]::new($panel.Width,$panel.Height)
            try{$panel.DrawToBitmap($preview,[Drawing.Rectangle]::new(0,0,$panel.Width,$panel.Height));$preview.Save((Join-Path $PSScriptRoot '../.tools/farm-twilight-preview.png'))}finally{$preview.Dispose()}
            if($PreviewSeconds -gt 0){$until=[DateTime]::UtcNow.AddSeconds($PreviewSeconds);do{[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 20}while([DateTime]::UtcNow -lt $until)}
            $points.RemoveAt($points.Count-1);$panel.GetType().GetMethod('RefreshSpots',$flags).Invoke($panel,@($originalSpot))
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
