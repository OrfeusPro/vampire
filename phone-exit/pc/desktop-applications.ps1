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
function ShowApplicationList([switch]$Preview) {
    $window=[PhoneExit.DesktopWindow]::new();$window.Text='Приложения Phone Exit'
    $window.FormBorderStyle='None';$window.StartPosition='CenterParent';$window.BackColor=$form.BackColor;$window.ForeColor=$form.ForeColor;$window.Font=$form.Font
    $window.ClientSize=[Drawing.Size]::new((UiPixel 700),(UiPixel 440))
    $list=[PhoneExit.DarkPhoneList]::new();$list.BackColor=[Drawing.ColorTranslator]::FromHtml('#192231');$list.ForeColor=$form.ForeColor;$list.Font=$form.Font;$list.ItemHeight=UiPixel 58
    $list.SetBounds((UiPixel 24),(UiPixel 120),(UiPixel 652),(UiPixel 223));$list.AccessibleName='Выбранные приложения и игры'
    foreach($path in $script:appPaths){$list.Items.Add($path)}
    $list.Add_DrawItem({param($sender,$e)
        $selected=($e.State -band [Windows.Forms.DrawItemState]::Selected) -ne 0
        $bg=if($selected){[Drawing.ColorTranslator]::FromHtml('#2d3b50')}else{$sender.BackColor}
        $brush=[Drawing.SolidBrush]::new($bg);$e.Graphics.FillRectangle($brush,$e.Bounds);$brush.Dispose()
        $path=[string]$sender.Items[$e.Index];$x=$e.Bounds.X+(UiPixel 12);$width=$e.Bounds.Width-(UiPixel 24)
        [Windows.Forms.TextRenderer]::DrawText($e.Graphics,[IO.Path]::GetFileName($path),$sender.Font,[Drawing.Rectangle]::new($x,$e.Bounds.Y+(UiPixel 5),$width,(UiPixel 25)),$sender.ForeColor,$bg,([Windows.Forms.TextFormatFlags]::EndEllipsis -bor [Windows.Forms.TextFormatFlags]::VerticalCenter))
        [Windows.Forms.TextRenderer]::DrawText($e.Graphics,$path,$sender.Font,[Drawing.Rectangle]::new($x,$e.Bounds.Y+(UiPixel 30),$width,(UiPixel 22)),[Drawing.ColorTranslator]::FromHtml('#9daabc'),$bg,([Windows.Forms.TextFormatFlags]::PathEllipsis -bor [Windows.Forms.TextFormatFlags]::VerticalCenter))
    })
    $header=[Windows.Forms.Label]::new();$header.Text='Приложения и игры';$header.Font=[Drawing.Font]::new('Segoe UI Semibold',16);$header.SetBounds((UiPixel 24),(UiPixel 20),(UiPixel 600),(UiPixel 35))
    $note=[Windows.Forms.Label]::new();$note.Text="Дочерние EXE обнаруживаются после запуска. Чтобы первые соединения игры`r`nтоже шли через VPN, добавьте её EXE и лаунчер в список заранее.";$note.SetBounds((UiPixel 24),(UiPixel 60),(UiPixel 652),(UiPixel 52));$note.ForeColor=$muted
    $tip=[Windows.Forms.ToolTip]::new();$list.Add_SelectedIndexChanged({if($list.SelectedIndex -ge 0){$tip.SetToolTip($list,[string]$list.Items[$list.SelectedIndex])}})
    $buttons=@()
    foreach($spec in @(@('Добавить EXE…',24,180),@('Удалить',216,150),@('Готово',496,180))){
        $b=[PhoneExit.DarkButton]::new();$b.Text=$spec[0];$b.SetBounds((UiPixel $spec[1]),(UiPixel 368),(UiPixel $spec[2]),(UiPixel 44));$b.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$b.ForeColor=$form.ForeColor;$b.FlatStyle='Flat';$b.FlatAppearance.BorderSize=0;$window.Controls.Add($b);$buttons+=$b
    }
    $buttons[1].Enabled=$false
    $list.Add_SelectedIndexChanged({$buttons[1].Enabled=$list.SelectedIndex -ge 0})
    $buttons[0].Add_Click({
        $dialog=[Windows.Forms.OpenFileDialog]::new();$dialog.Filter='Программы (*.exe)|*.exe';$dialog.Multiselect=$true;$dialog.Title='Добавить игры и приложения в список VPN'
        try{if($dialog.ShowDialog($window) -eq 'OK'){
            try{$paths=@(MergeApplicationPaths @($list.Items) $dialog.FileNames);$list.BeginUpdate();$list.Items.Clear();foreach($path in $paths){$list.Items.Add($path)};$list.EndUpdate()}
            catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,'Phone Exit')|Out-Null}
        }}finally{$dialog.Dispose()}
    })
    $buttons[1].Add_Click({if($list.SelectedIndex -ge 0){$list.Items.RemoveAt($list.SelectedIndex);$buttons[1].Enabled=$list.SelectedIndex -ge 0}})
    $buttons[2].BackColor=$accent;$buttons[2].ForeColor=[Drawing.ColorTranslator]::FromHtml('#10251e')
    $buttons[2].Add_Click({
        $script:appPaths=@($list.Items|ForEach-Object{[string]$_})
        [IO.Directory]::CreateDirectory($script:profileDirectory)|Out-Null
        [IO.File]::WriteAllText($appFile,(ConvertTo-Json -InputObject @($script:appPaths) -Compress),[Text.UTF8Encoding]::new($false))
        $appNote.Text="Приложений: $($script:appPaths.Count) · дочерние EXE автоматически"
        $window.DialogResult='OK';$window.Close()
    })
    $window.Controls.AddRange([Windows.Forms.Control[]]@($header,$note,$list))
    $window.KeyPreview=$true;$window.Add_KeyDown({param($sender,$e)if($e.KeyCode -eq 'Escape'){$window.Close()}})
    $previewTimer=$null
    if($Preview){$previewTimer=[Windows.Forms.Timer]::new();$previewTimer.Interval=400;$previewTimer.Add_Tick({$previewTimer.Stop();$bitmap=[Drawing.Bitmap]::new($window.Width,$window.Height);try{$window.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$window.Width,$window.Height));$bitmap.Save((Join-Path $PSScriptRoot '../.tools/applications-preview.png'))}finally{$bitmap.Dispose()};$window.Close()});$previewTimer.Start()}
    try{$null=$window.ShowDialog($form)}finally{if($previewTimer){$previewTimer.Dispose()};$tip.Dispose();$header.Font.Dispose();$window.Dispose()}
}
