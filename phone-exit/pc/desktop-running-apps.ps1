if(!('PhoneExit.ProcessTree' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'process-tree.cs')}
function ShowRunningApplications([switch]$Preview) {
    $window=[PhoneExit.DesktopWindow]::new();$window.Text='Запущенные игры и приложения';$window.FormBorderStyle='None';$window.StartPosition='CenterParent'
    $window.BackColor=$form.BackColor;$window.ForeColor=$form.ForeColor;$window.Font=$form.Font;$window.ClientSize=[Drawing.Size]::new((UiPixel 760),(UiPixel 570))
    $header=[Windows.Forms.Label]::new();$header.Text='Выберите запущенную игру';$header.Font=[Drawing.Font]::new('Segoe UI Semibold',16);$header.SetBounds((UiPixel 24),(UiPixel 20),(UiPixel 712),(UiPixel 36))
    $note=[Windows.Forms.Label]::new();$note.Text='Будут предложены игра, её лаунчер и связанные процессы запуска.';$note.ForeColor=$muted;$note.SetBounds((UiPixel 24),(UiPixel 63),(UiPixel 712),(UiPixel 28))
    $search=[PhoneExit.SearchField]::new();$search.Font=$form.Font;$search.Placeholder='Поиск EXE или пути';$search.SetBounds((UiPixel 24),(UiPixel 94),(UiPixel 508),(UiPixel 36));$search.AccessibleName='Поиск по имени EXE или пути'
    $list=[PhoneExit.DarkPhoneList]::new();$list.BackColor=[Drawing.ColorTranslator]::FromHtml('#192231');$list.ForeColor=$form.ForeColor;$list.Font=$form.Font;$list.ItemHeight=UiPixel 52;$list.SetBounds((UiPixel 24),(UiPixel 140),(UiPixel 712),(UiPixel 206));$list.AccessibleName='Запущенные приложения'
    $details=[Windows.Forms.Label]::new();$details.ForeColor=$muted;$details.AutoEllipsis=$true;$details.SetBounds((UiPixel 24),(UiPixel 383),(UiPixel 712),(UiPixel 62));$details.AccessibleName='Связанные EXE для VPN'
    $groupLabel=[Windows.Forms.Label]::new();$groupLabel.Text='Группа';$groupLabel.ForeColor=$muted;$groupLabel.SetBounds((UiPixel 24),(UiPixel 461),(UiPixel 90),(UiPixel 28))
    $groupName=[Windows.Forms.TextBox]::new();$groupName.MaxLength=80;$groupName.BackColor=$search.BackColor;$groupName.ForeColor=$form.ForeColor;$groupName.SetBounds((UiPixel 118),(UiPixel 458),(UiPixel 618),(UiPixel 30));$groupName.AccessibleName='Название группы игры'
    $related=[PhoneExit.DarkCheckBox]::new();$related.Text='Добавить лаунчер и связанные процессы';$related.Checked=$true;$related.SetBounds((UiPixel 24),(UiPixel 352),(UiPixel 712),(UiPixel 28))
    $buttons=@()
    foreach($spec in @(@('Обновить',544,192,94,36),@('Добавить в список',24,240,514,36),@('Отмена',556,180,514,36))){
        $b=[PhoneExit.DarkButton]::new();$b.Text=$spec[0];$b.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$b.ForeColor=$form.ForeColor;$b.FlatStyle='Flat';$b.FlatAppearance.BorderSize=0;$b.SetBounds((UiPixel $spec[1]),(UiPixel $spec[3]),(UiPixel $spec[2]),(UiPixel $spec[4]));$window.Controls.Add($b);$buttons+=$b
    }
    $buttons[1].Enabled=$false;$buttons[1].BackColor=$accent;$buttons[1].ForeColor=[Drawing.ColorTranslator]::FromHtml('#10251e')
    $state=@{snapshot=@();rows=@();paths=@();result=$null}
    $select={
        $state.paths=@();if($list.SelectedIndex -ge 0){$row=$state.rows[$list.SelectedIndex];$state.paths=if($related.Checked){@([PhoneExit.ProcessTree]::RelatedPaths([PhoneExit.ProcessRecord[]]$state.snapshot,$row.Id))}else{@($row.Path)}}
        if($list.SelectedIndex -ge 0){$groupName.Text=[IO.Path]::GetFileNameWithoutExtension($row.Path);if(@($state.paths|Where-Object {[IO.Path]::GetFileName($_) -ieq 'VAMPIR.exe'}).Count){$groupName.Text='Vampire'}}
        $buttons[1].Enabled=@($state.paths).Count -gt 0;$details.Text=@($state.paths|ForEach-Object {[IO.Path]::GetFileName($_)}) -join ' · '
    }
    $filter={
        $state.rows=@($state.snapshot|Where-Object {$_.Path -and [IO.Path]::GetExtension($_.Path) -ieq '.exe' -and (([IO.Path]::GetFileName($_.Path)).IndexOf($search.Text,[StringComparison]::OrdinalIgnoreCase) -ge 0 -or ($search.Text -match '[:\\/]' -and $_.Path.IndexOf($search.Text,[StringComparison]::OrdinalIgnoreCase) -ge 0))}|Sort-Object Path -Unique)
        $list.BeginUpdate();$list.Items.Clear();foreach($row in $state.rows){$null=$list.Items.Add($row.Path)};$list.EndUpdate();$details.Text='';$buttons[1].Enabled=$false
    }
    $refresh={try{$state.snapshot=@([PhoneExit.ProcessTree]::Snapshot());& $filter;$note.Text='Выберите EXE. Ниже показаны связанные процессы для добавления.'}catch{$note.Text='Не удалось прочитать процессы. Можно добавить EXE вручную.'}}
    $list.Add_DrawItem({param($sender,$e)
        if($e.Index -lt 0){return};$bg=if(($e.State -band [Windows.Forms.DrawItemState]::Selected) -ne 0){[Drawing.ColorTranslator]::FromHtml('#263e34')}else{$sender.BackColor}
        $brush=[Drawing.SolidBrush]::new($bg);$e.Graphics.FillRectangle($brush,$e.Bounds);$brush.Dispose();$path=[string]$sender.Items[$e.Index]
        $flags=[Windows.Forms.TextFormatFlags]::EndEllipsis -bor [Windows.Forms.TextFormatFlags]::VerticalCenter
        [Windows.Forms.TextRenderer]::DrawText($e.Graphics,[IO.Path]::GetFileName($path),$sender.Font,[Drawing.Rectangle]::new($e.Bounds.X+(DialogPixel $sender 12),$e.Bounds.Y+(DialogPixel $sender 3),$e.Bounds.Width-(DialogPixel $sender 24),(DialogPixel $sender 24)),$sender.ForeColor,$bg,$flags)
        [Windows.Forms.TextRenderer]::DrawText($e.Graphics,$path,$sender.Font,[Drawing.Rectangle]::new($e.Bounds.X+(DialogPixel $sender 12),$e.Bounds.Y+(DialogPixel $sender 26),$e.Bounds.Width-(DialogPixel $sender 24),(DialogPixel $sender 23)),$muted,$bg,([Windows.Forms.TextFormatFlags]::PathEllipsis -bor [Windows.Forms.TextFormatFlags]::VerticalCenter))
    })
    $list.Add_SelectedIndexChanged($select);$related.Add_CheckedChanged($select);$search.Add_TextChanged($filter);$buttons[0].Add_Click($refresh)
    $buttons[1].Add_Click({if(!$groupName.Text.Trim()){$note.Text='Введите название группы.';return};$state.result=[PSCustomObject]@{name=$groupName.Text.Trim();paths=@($state.paths)};$window.DialogResult='OK';$window.Close()});$buttons[2].Add_Click({$window.Close()})
    $window.Controls.AddRange([Windows.Forms.Control[]]@($header,$note,$search,$list,$details,$related,$groupLabel,$groupName));$window.KeyPreview=$true;$window.Add_KeyDown({param($sender,$e)if($e.KeyCode -eq 'Escape'){$window.Close()}})
    & $refresh
    SetDesktopDialogStyle $window $header $list $buttons[1]
    $buttons[0].Anchor='Top, Right';$buttons[2].Anchor='Bottom, Right'
    $groupLabel.Anchor='Bottom, Left'
    $previewTimer=$null
    if($Preview){$search.Clear();if($list.Items.Count){$list.SelectedIndex=0};$previewTimer=[Windows.Forms.Timer]::new();$previewTimer.Interval=400;$previewTimer.Add_Tick({$previewTimer.Stop();SaveDesktopDialogPreview $window 'running-apps';$window.Close()});$previewTimer.Start()}
    try{$null=$window.ShowDialog($form);if($state.result){Write-Output $state.result}}finally{if($previewTimer){$previewTimer.Dispose()};$header.Font.Dispose();$window.Dispose()}
}
