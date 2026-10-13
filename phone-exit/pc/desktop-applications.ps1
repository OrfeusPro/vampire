function MergeApplicationPaths($existing,$added) {
    $paths=[Collections.Generic.List[string]]::new()
    foreach($path in @($existing)+@($added)){
        if(!$path -or ![IO.Path]::IsPathRooted($path) -or [IO.Path]::GetExtension($path) -ine '.exe'){continue}
        $full=[IO.Path]::GetFullPath($path)
        if(!@($paths | Where-Object {$_ -ieq $full}).Count){$paths.Add($full)}
    }
    if($paths.Count -gt 64){throw 'Можно добавить не больше 64 приложений.'}
    return $paths.ToArray()
}
function NormalizeApplicationGroups($groups,$paths) {
    $used=@();$names=@()
    foreach($group in @($groups)){
        $name=[string]$group.name
        if(!$name.Trim() -or $name.Length -gt 80 -or $names -contains $name){continue}
        $members=@(MergeApplicationPaths @() @($group.paths|ForEach-Object{$_})|Where-Object {$paths -contains $_ -and $used -notcontains $_})
        if(!$members.Count){continue};$used+=$members;$names+=$name
        Write-Output ([PSCustomObject]@{name=$name;paths=$members;enabled=($group.enabled -ne $false)})
    }
}
function ReadApplicationGroups($paths) {
    $file=Join-Path $script:profileDirectory 'application-groups.json'
    if([IO.File]::Exists($file)){
        try {if(([IO.FileInfo]::new($file)).Length -gt 262144){return};$decoded=@([IO.File]::ReadAllText($file)|ConvertFrom-Json|ForEach-Object{$_});$all=@(MergeApplicationPaths $paths @($decoded|ForEach-Object {$_.paths}|ForEach-Object{$_}));NormalizeApplicationGroups $decoded $all}catch{}
    }
}
function SaveApplicationSelection($paths,$groups) {
    $selected=@(MergeApplicationPaths @() $paths)
    $normalized=@(NormalizeApplicationGroups $groups $selected)
    $disabled=@($normalized|Where-Object {$_.enabled -eq $false}|ForEach-Object {$_.paths}|ForEach-Object{$_})
    $active=@($selected|Where-Object {$disabled -notcontains $_})
    $null=[IO.Directory]::CreateDirectory($script:profileDirectory)
    foreach($spec in @(@('applications.json',(ConvertTo-Json -InputObject @($active) -Depth 8 -Compress)),@('application-groups.json',(ConvertTo-Json -InputObject @($normalized) -Depth 8 -Compress)))){
        $target=Join-Path $script:profileDirectory $spec[0];$temp=$target+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
        try{[IO.File]::WriteAllText($temp,$spec[1],[Text.UTF8Encoding]::new($false));if([IO.File]::Exists($target)){[IO.File]::Replace($temp,$target,[NullString]::Value)}else{[IO.File]::Move($temp,$target)}}finally{if([IO.File]::Exists($temp)){[IO.File]::Delete($temp)}}
    }
    $script:appPaths=$active
}
function AddApplicationGroup($paths,$groups,$group) {
    $all=@(MergeApplicationPaths $paths @($group.paths|ForEach-Object{$_}))
    $remaining=@()
    foreach($old in @($groups)){
        if($old.name -ieq $group.name){$group=[PSCustomObject]@{name=$group.name;paths=@(MergeApplicationPaths @($old.paths|ForEach-Object{$_}) @($group.paths|ForEach-Object{$_}));enabled=($old.enabled -ne $false)};continue}
        $remaining+=[PSCustomObject]@{name=$old.name;paths=@($old.paths|Where-Object {$group.paths -notcontains $_});enabled=($old.enabled -ne $false)}
    }
    return [PSCustomObject]@{paths=$all;groups=@(NormalizeApplicationGroups (@($group)+$remaining) $all)}
}
function ShowApplicationList([switch]$Preview) {
    $window=[PhoneExit.DesktopWindow]::new();$window.Text='Приложения Phone Exit';$window.FormBorderStyle='None';$window.StartPosition='CenterParent';$window.BackColor=$form.BackColor;$window.ForeColor=$form.ForeColor;$window.Font=$form.Font
    $window.ClientSize=[Drawing.Size]::new((UiPixel 760),(UiPixel 590))
    $list=[PhoneExit.DarkPhoneList]::new();$list.BackColor=[Drawing.ColorTranslator]::FromHtml('#192231');$list.ForeColor=$form.ForeColor;$list.Font=$form.Font;$list.ItemHeight=UiPixel 58
    $list.SetBounds((UiPixel 24),(UiPixel 154),(UiPixel 712),(UiPixel 235));$list.AccessibleName='Группы игр и приложения для VPN'
    $header=[Windows.Forms.Label]::new();$header.Text='Игры и приложения';$header.Font=[Drawing.Font]::new('Segoe UI Semibold',16);$header.SetBounds((UiPixel 24),(UiPixel 20),(UiPixel 712),(UiPixel 35))
    $note=[Windows.Forms.Label]::new();$note.Text="Добавьте запущенную игру вместе с лаунчером в одну группу.`r`nНовые дочерние EXE обнаруживаются после запуска; первые пакеты могут уйти раньше.";$note.SetBounds((UiPixel 24),(UiPixel 60),(UiPixel 712),(UiPixel 46));$note.ForeColor=$muted
    $details=[Windows.Forms.Label]::new();$details.ForeColor=$muted;$details.AutoEllipsis=$true;$details.SetBounds((UiPixel 24),(UiPixel 404),(UiPixel 712),(UiPixel 103))
    $state=@{paths=@($script:appPaths);groups=@(ReadApplicationGroups $script:appPaths);rows=@()}
    $state.paths=@(MergeApplicationPaths $state.paths @($state.groups|ForEach-Object {$_.paths}|ForEach-Object{$_}))
    $tip=[Windows.Forms.ToolTip]::new();$buttons=@()
    foreach($spec in @(@('Запущенная игра…',24,250,110),@('Добавить EXE…',286,220,110),@('Удалить',24,130,529),@('Готово',556,180,529),@('VPN вкл/выкл',166,176,529),@('Только эта',354,190,529))){
        $b=[PhoneExit.DarkButton]::new();$b.Text=$spec[0];$b.SetBounds((UiPixel $spec[1]),(UiPixel $spec[3]),(UiPixel $spec[2]),(UiPixel 40));$b.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$b.ForeColor=$form.ForeColor;$b.FlatStyle='Flat';$b.FlatAppearance.BorderSize=0;$window.Controls.Add($b);$buttons+=$b
    }
    $buttons[2].Enabled=$false;$buttons[4].Enabled=$false;$buttons[5].Enabled=$false;$buttons[3].BackColor=$accent;$buttons[3].ForeColor=[Drawing.ColorTranslator]::FromHtml('#10251e')
    $refresh={
        $state.groups=@(NormalizeApplicationGroups $state.groups $state.paths);$state.rows=@($state.groups);$grouped=@($state.groups|ForEach-Object {$_.paths}|ForEach-Object{$_})
        foreach($path in $state.paths){if($grouped -notcontains $path){$state.rows+=[PSCustomObject]@{name=[IO.Path]::GetFileName($path);paths=@($path);enabled=$true}}}
        $list.BeginUpdate();$list.Items.Clear();foreach($row in $state.rows){$null=$list.Items.Add($row.name)};$list.EndUpdate();$details.Text='Выберите группу. «Только эта» оставляет VPN лишь для её приложений.';foreach($i in @(2,4,5)){$buttons[$i].Enabled=$false}
    }
    $list.Add_DrawItem({param($sender,$e)
        if($e.Index -lt 0){return};$row=$state.rows[$e.Index];$bg=if(($e.State -band [Windows.Forms.DrawItemState]::Selected) -ne 0){[Drawing.ColorTranslator]::FromHtml('#263e34')}else{$sender.BackColor}
        $brush=[Drawing.SolidBrush]::new($bg);$e.Graphics.FillRectangle($brush,$e.Bounds);$brush.Dispose();$x=$e.Bounds.X+(DialogPixel $sender 12);$width=$e.Bounds.Width-(DialogPixel $sender 24)
        $flags=[Windows.Forms.TextFormatFlags]::EndEllipsis -bor [Windows.Forms.TextFormatFlags]::VerticalCenter
        $caption=$row.name+$(if($row.enabled){' · VPN'}else{' · обычная сеть'})
        [Windows.Forms.TextRenderer]::DrawText($e.Graphics,$caption,$sender.Font,[Drawing.Rectangle]::new($x,$e.Bounds.Y+(DialogPixel $sender 5),$width,(DialogPixel $sender 25)),$sender.ForeColor,$bg,$flags)
        $summary=(@($row.paths|ForEach-Object {[IO.Path]::GetFileName($_)}) -join ' · ')
        [Windows.Forms.TextRenderer]::DrawText($e.Graphics,$summary,$sender.Font,[Drawing.Rectangle]::new($x,$e.Bounds.Y+(DialogPixel $sender 30),$width,(DialogPixel $sender 22)),$muted,$bg,$flags)
    })
    $list.Add_SelectedIndexChanged({foreach($i in @(2,4,5)){$buttons[$i].Enabled=$list.SelectedIndex -ge 0};if($list.SelectedIndex -ge 0){$row=$state.rows[$list.SelectedIndex];$details.Text=($row.name+' · EXE: '+@($row.paths).Count+"`r`n"+(@($row.paths|ForEach-Object {[IO.Path]::GetFileName($_)}) -join "`r`n"));$tip.SetToolTip($details,(@($row.paths) -join "`r`n"))}})
    $buttons[4].Add_Click({if($list.SelectedIndex -ge 0){$row=$state.rows[$list.SelectedIndex];$updated=AddApplicationGroup $state.paths $state.groups $row;$state.groups=@($updated.groups);foreach($group in $state.groups){if($group.name -eq $row.name){$group.enabled=!$row.enabled}};& $refresh}})
    $buttons[5].Add_Click({if($list.SelectedIndex -ge 0){$row=$state.rows[$list.SelectedIndex];foreach($item in $state.rows){$updated=AddApplicationGroup $state.paths $state.groups $item;$state.groups=@($updated.groups)};foreach($group in $state.groups){$group.enabled=$group.name -eq $row.name};& $refresh}})
    $buttons[0].Add_Click({try{$group=ShowRunningApplications;if($group){$added=AddApplicationGroup $state.paths $state.groups $group;$state.paths=@($added.paths);$state.groups=@($added.groups);& $refresh}}catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,'Phone Exit')|Out-Null}})
    $buttons[1].Add_Click({
        $dialog=[Windows.Forms.OpenFileDialog]::new();$dialog.Filter='Программы (*.exe)|*.exe';$dialog.Multiselect=$true;$dialog.Title='Добавить EXE'
        try{if($dialog.ShowDialog($window) -eq 'OK'){try{
            if($list.SelectedIndex -ge 0 -and @($state.groups|Where-Object name -eq $state.rows[$list.SelectedIndex].name).Count){$row=$state.rows[$list.SelectedIndex];$added=AddApplicationGroup $state.paths $state.groups ([PSCustomObject]@{name=$row.name;paths=@($dialog.FileNames)});$state.paths=@($added.paths);$state.groups=@($added.groups)}
            else{$state.paths=@(MergeApplicationPaths $state.paths $dialog.FileNames)};& $refresh
        }catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,'Phone Exit')|Out-Null}}}finally{$dialog.Dispose()}
    })
    $buttons[2].Add_Click({if($list.SelectedIndex -ge 0){$row=$state.rows[$list.SelectedIndex];$state.paths=@($state.paths|Where-Object {$row.paths -notcontains $_});& $refresh}})
    $buttons[3].Add_Click({try{SaveApplicationSelection $state.paths $state.groups;if($script:appPaths.Count){$mode.SelectedIndex=1};$appNote.Text="Приложений: $($script:appPaths.Count) · дочерние EXE автоматически";$window.DialogResult='OK';$window.Close()}catch{$details.Text='Не удалось сохранить список приложений.'}})
    $window.Controls.AddRange([Windows.Forms.Control[]]@($header,$note,$list,$details));$window.KeyPreview=$true;$window.Add_KeyDown({param($sender,$e)if($e.KeyCode -eq 'Escape'){$window.Close()}});& $refresh
    SetDesktopDialogStyle $window $header $list $buttons[3]
    $buttons[3].Anchor='Bottom, Right'
    $previewTimer=$null
    if($Preview){$previewTimer=[Windows.Forms.Timer]::new();$previewTimer.Interval=400;$previewTimer.Add_Tick({$previewTimer.Stop();SaveDesktopDialogPreview $window 'applications';$window.Close()});$previewTimer.Start()}
    try{$null=$window.ShowDialog($form)}finally{if($previewTimer){$previewTimer.Dispose()};$tip.Dispose();$header.Font.Dispose();$window.Dispose()}
}
