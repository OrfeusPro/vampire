$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
Add-Type -Path @((Join-Path $PSScriptRoot 'desktop-controls.cs'),(Join-Path $PSScriptRoot 'desktop-bots.cs')) -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
$taskRoot=Join-Path $PSScriptRoot 'assets/maps/rfonlinenext'
$taskParser=New-Object Web.Script.Serialization.JavaScriptSerializer
$taskSettings=$taskParser.DeserializeObject('{"farm_map_spots":[],"active_farm_map_spot_id":null}')
$taskEditor=New-Object PhoneExit.RfMapEditor($taskRoot,$taskSettings)
$taskFlags=[Reflection.BindingFlags]'Instance,NonPublic'
try {
 $taskEditor.Show();[Windows.Forms.Application]::DoEvents()
 $taskCanvas=$taskEditor.GetType().GetField('canvas',$taskFlags).GetValue($taskEditor)
 $taskList=$taskEditor.GetType().GetField('locationList',$taskFlags).GetValue($taskEditor)
 if($taskList.Items.Count -lt 80){throw 'Novus location catalog incomplete'}
 $taskSearch=$taskEditor.GetType().GetField('search',$taskFlags).GetValue($taskEditor)
 $taskSearch.Text='Чёрная равнина';if($taskList.Items.Count -ne 1){throw 'Location search failed'}
 $taskList.SelectedIndex=0;[Windows.Forms.Application]::DoEvents()
 $taskMonsters=$taskEditor.GetType().GetField('monsterList',$taskFlags).GetValue($taskEditor)
 if($taskMonsters.Items.Count -ne 14){throw 'Black Plain monster list is incomplete'}
 if($taskMonsters.Height -lt 100 -or $taskMonsters.Parent.Bounds.IntersectsWith($taskList.Bounds)){throw 'Monster panel is hidden behind location list'}
 $taskMonsters.SelectedIndex=13;[Windows.Forms.Application]::DoEvents()
 if(!$taskCanvas.SelectedMonster){throw 'Selecting a scrolled monster did not highlight it'}
 $taskEditor.GetType().GetMethod('AddMonsterPoint',$taskFlags).Invoke($taskEditor,@())
 if($taskEditor.Spots.Count -ne 1 -or !$taskEditor.Spots[0].ContainsKey('npc_index') -or !$taskEditor.Spots[0].ContainsKey('catalog_monster_id')){throw 'Monster assignment was not preserved in the profile point'}
 $taskSerialized=$taskParser.Serialize($taskEditor.Spots)
 if(!$taskSerialized.Contains('target_world_xyz')){throw 'Native monster coordinates were lost on serialization'}
 $taskPoint=$taskCanvas.ScreenPoint(.31,.61)
 $taskRoundtrip=$taskCanvas.MapPoint([Drawing.Point]::Round($taskPoint))
 if(!$taskRoundtrip -or [Math]::Abs($taskRoundtrip[0]-.31) -gt .002 -or [Math]::Abs($taskRoundtrip[1]-.61) -gt .002){throw 'Zoomed coordinate conversion failed'}
 $taskCanvas.AddMode=$true
 $taskClick=New-Object Windows.Forms.MouseEventArgs([Windows.Forms.MouseButtons]::Left,1,([int]$taskPoint.X),([int]$taskPoint.Y),0)
 Add-Type -TypeDefinition 'public static class MapTestClick { public static void Click(System.Windows.Forms.Control c,int x,int y){var f=System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic;var e=new System.Windows.Forms.MouseEventArgs(System.Windows.Forms.MouseButtons.Left,1,x,y,0);c.GetType().GetMethod("OnMouseDown",f).Invoke(c,new object[]{e});c.GetType().GetMethod("OnMouseUp",f).Invoke(c,new object[]{e});}}' -ReferencedAssemblies System.Windows.Forms
 [MapTestClick]::Click($taskCanvas,[int]$taskPoint.X,[int]$taskPoint.Y)
 if($taskEditor.Spots.Count -ne 2){throw 'Map click did not create profile point'}
 if($taskSettings['farm_map_spots'].Length -ne 0){throw 'Canceled editor mutated original settings'}
 $taskCanvas.ZoomAt(.8,300,200);$taskCanvas.Fit();[Windows.Forms.Application]::DoEvents()
 $taskBitmap=New-Object Drawing.Bitmap($taskEditor.Width,$taskEditor.Height)
 try{$taskEditor.DrawToBitmap($taskBitmap,(New-Object Drawing.Rectangle(0,0,$taskEditor.Width,$taskEditor.Height)));$taskBitmap.Save([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.tools/rf-map-editor-preview.png')))}finally{$taskBitmap.Dispose()}
 'RF map editor: catalog/search, zoom coordinates, profile point, cancel isolation and render passed'
} finally {$taskEditor.GetType().GetField('changed',$taskFlags).SetValue($taskEditor,$false);$taskEditor.Close();$taskEditor.Dispose()}
