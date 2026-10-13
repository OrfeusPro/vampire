# The fleet is a projection of the real directory. Filtering never changes VPN indexes.
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-fleet.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Core,Accessibility
$script:redesignReady=$true
$script:desktopView='devices'
$script:fleetSync=$false
$form.BackColor=[Drawing.ColorTranslator]::FromHtml('#111315')
$form.ForeColor=[Drawing.ColorTranslator]::FromHtml('#eef1f4')
$muted=[Drawing.ColorTranslator]::FromHtml('#919ba5')
$surface=[Drawing.ColorTranslator]::FromHtml('#202428')
$buttonSurface=[Drawing.ColorTranslator]::FromHtml('#272c31')
foreach($control in $form.Controls){
    if($control -is [Windows.Forms.Button]){$control.BackColor=$buttonSurface}
    if($control -is [Windows.Forms.Label]){$control.BackColor=$form.BackColor}
}
$title.Font=[Drawing.Font]::new('Segoe UI Semibold',14)
$title.BackColor=[Drawing.ColorTranslator]::FromHtml('#191c1f')
$sub.Text='DESKTOP';$sub.Font=[Drawing.Font]::new('Segoe UI',7,[Drawing.FontStyle]::Bold);$sub.BackColor=$title.BackColor
$badge.Text='ЛИЧНОЕ ПРОСТРАНСТВО';$badge.ForeColor=$muted;$badge.TextAlign='MiddleLeft';$badge.Font=[Drawing.Font]::new('Segoe UI',8,[Drawing.FontStyle]::Bold)
$brandIcon.BackColor=$title.BackColor
$heading.Visible=$false
$phoneList.ShowBotActions=$false;$phoneList.BackColor=$surface
$phoneColumnHeading.Visible=$false;$providerColumnHeading.Visible=$false;$botColumnHeading.Visible=$false
$script:botsButton.Anchor='None';$script:botsButton.Text='Боты и профили'
$accountButton.Anchor='None';$accountButton.Text='Настройки'
$navDevices=ButtonAt 'Устройства' 0 0 160
$navConnection=ButtonAt 'Подключение' 0 0 160
$sidebarNote=LabelAt 'Личные телефоны' 0 0 160 24;$sidebarNote.BackColor=$title.BackColor;$sidebarNote.ForeColor=$muted;$sidebarNote.Font=[Drawing.Font]::new('Segoe UI',8)
$pageTitle=LabelAt 'Устройства' 0 0 600 38;$pageTitle.Font=[Drawing.Font]::new('Segoe UI Semibold',20)
$pageSubtitle=LabelAt 'Все устройства / Личный список' 0 0 600 24;$pageSubtitle.ForeColor=$muted;$pageSubtitle.Font=[Drawing.Font]::new('Segoe UI',9)
$fleetSummary=LabelAt '' 0 0 600 25;$fleetSummary.Font=[Drawing.Font]::new('Segoe UI',9)
$fleet=New-Object PhoneExit.FleetView;$fleet.UiScale=$script:uiScale;$form.Controls.Add($fleet)
$fleetSearch=New-Object PhoneExit.SearchField;$fleetSearch.BackColor=$surface;$fleetSearch.ForeColor=$form.ForeColor;$fleetSearch.Font=[Drawing.Font]::new('Segoe UI',9);$fleetSearch.AccessibleName='Поиск по имени, персонажу, модели или стране';$form.Controls.Add($fleetSearch)
$fleetGame=New-Object PhoneExit.DarkSelect;$fleetGame.AccessibleName='Фильтр по боту';$fleetGame.BackColor=$buttonSurface;$fleetGame.ForeColor=$form.ForeColor
foreach($text in @('Бот: все','Lord Nine','Без бота')){$null=$fleetGame.Items.Add($text)};$fleetGame.SelectedIndex=0;$form.Controls.Add($fleetGame)
$fleetState=New-Object PhoneExit.DarkSelect;$fleetState.AccessibleName='Фильтр состояния';$fleetState.BackColor=$buttonSurface;$fleetState.ForeColor=$form.ForeColor
foreach($text in @('Статус: все','В сети','Не в сети','Бот работает','Ошибка бота')){$null=$fleetState.Items.Add($text)};$fleetState.SelectedIndex=0;$form.Controls.Add($fleetState)
$fleetSort=New-Object PhoneExit.DarkSelect;$fleetSort.AccessibleName='Сортировка устройств';$fleetSort.BackColor=$buttonSurface;$fleetSort.ForeColor=$form.ForeColor
foreach($text in @('Имя ↑','Имя ↓','Сначала в сети','По стране')){$null=$fleetSort.Items.Add($text)};$fleetSort.SelectedIndex=0;$form.Controls.Add($fleetSort)
$gridButton=ButtonAt 'Карточки' 0 0 90;$tableButton=ButtonAt 'Таблица' 0 0 90
$densityButton=ButtonAt 'XS' 0 0 40;$densityButton.AccessibleName='Плотность карточек';$captionTips.SetToolTip($densityButton,'Компактные / крупные карточки')
$selectAll=New-Object Windows.Forms.CheckBox;$selectAll.Text='Выбрать все';$selectAll.ForeColor=$accent;$selectAll.FlatStyle='Flat';$selectAll.AccessibleName='Выбрать все видимые устройства';$form.Controls.Add($selectAll)
$bulkStart=ButtonAt 'Запустить' 0 0 120;$bulkPause=ButtonAt 'Пауза' 0 0 110
$bulkSettings=ButtonAt 'Копировать' 0 0 130
$selectionLabel=LabelAt '' 0 0 200 24;$selectionLabel.ForeColor=$muted;$selectionLabel.Font=[Drawing.Font]::new('Segoe UI',9)
$connectTitle=LabelAt 'Выход через телефон' 0 0 300 26;$connectTitle.Font=[Drawing.Font]::new('Segoe UI Semibold',14)
$selectedPhoneLabel=LabelAt 'Выберите телефон в списке' 0 0 300 52;$selectedPhoneLabel.ForeColor=$muted;$selectedPhoneLabel.Font=[Drawing.Font]::new('Segoe UI',10)
$modeTitle=LabelAt 'РЕЖИМ ТРАФИКА' 0 0 300 24;$modeTitle.ForeColor=$muted;$modeTitle.Font=[Drawing.Font]::new('Segoe UI',8,[Drawing.FontStyle]::Bold)
$safetyLabel=LabelAt 'При потере телефона трафик туннеля блокируется.' 0 0 300 52;$safetyLabel.ForeColor=$muted;$safetyLabel.Font=[Drawing.Font]::new('Segoe UI',9)
$status.TextAlign='MiddleLeft';$status.Font=[Drawing.Font]::new('Segoe UI Semibold',14);$status.BackColor=$form.BackColor
$pingLabel.TextAlign='MiddleLeft';$pingLabel.BackColor=$form.BackColor
$mode.BackColor=$buttonSurface;$appNote.BackColor=$form.BackColor;$appNote.Font=[Drawing.Font]::new('Segoe UI',8)
$detail.Text='Wi-Fi телефона  ·  Шифрование WebRTC';$detail.ForeColor=$muted
function UpdateConnectionButtons {
    $start.BackColor=if($start.Enabled){$accent}else{$surface}
    $start.ForeColor=if($start.Enabled){[Drawing.ColorTranslator]::FromHtml('#10251e')}else{$muted}
    $stopButton.BackColor=$buttonSurface;$stopButton.ForeColor=if($stopButton.Enabled){$accent}else{$muted}
    $start.Invalidate();$stopButton.Invalidate()
}
function DrawConnectionPhone($paintEvent) {
    $phone=$script:phoneRows[$paintEvent.Index];$g=$paintEvent.Graphics;$r=$paintEvent.Bounds
    $selected=($paintEvent.State -band [Windows.Forms.DrawItemState]::Selected) -ne 0
    $brush=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($(if($selected){'#263e34'}else{'#202428'})));$g.FillRectangle($brush,$r);$brush.Dispose()
    $g.DrawImage((CountryFlag $phone.country),[Drawing.Rectangle]::new(($r.X+(UiPixel 12)),($r.Y+(UiPixel 17)),(UiPixel 24),(UiPixel 24)))
    $font=[Drawing.Font]::new('Segoe UI Semibold',(10*$form.LayoutScale));$small=[Drawing.Font]::new('Segoe UI',(8*$form.LayoutScale))
    $flags=[Windows.Forms.TextFormatFlags]::NoPadding -bor [Windows.Forms.TextFormatFlags]::SingleLine -bor [Windows.Forms.TextFormatFlags]::EndEllipsis
    [Windows.Forms.TextRenderer]::DrawText($g,(CountryName $phone.country),$font,[Drawing.Rectangle]::new(($r.X+(UiPixel 48)),($r.Y+(UiPixel 12)),($r.Width-(UiPixel 144)),(UiPixel 24)),$form.ForeColor,$flags)
    [Windows.Forms.TextRenderer]::DrawText($g,([string]$phone.name),$small,[Drawing.Rectangle]::new(($r.X+(UiPixel 48)),($r.Y+(UiPixel 39)),($r.Width-(UiPixel 60)),(UiPixel 24)),$muted,$flags)
    $text=if(!$phone.online){'Не в сети'}elseif($phone.busy){'Занят'}else{'Доступен'}
    $color=if(!$phone.online){$muted}elseif($phone.busy){[Drawing.ColorTranslator]::FromHtml('#f0c67f')}else{$accent}
    [Windows.Forms.TextRenderer]::DrawText($g,$text,$small,[Drawing.Rectangle]::new(($r.Right-(UiPixel 94)),($r.Y+(UiPixel 17)),(UiPixel 84),(UiPixel 22)),$color,$flags)
    $font.Dispose();$small.Dispose()
}
function SetDesktopView([string]$view) {$script:desktopView=$view;UpdateWindowLayout}
function UpdateFleetSelection {
    $script:fleetSync=$true
    $selectAll.Checked=$fleet.VisibleCount -gt 0 -and $fleet.SelectedCount -eq $fleet.VisibleCount
    $script:fleetSync=$false
    $selectionLabel.Text="Выбрано: $($fleet.SelectedCount)"
    $bulkStart.Enabled=($fleet.ActionIndexes('start').Count+$fleet.ActionIndexes('resume').Count) -gt 0
    $bulkPause.Enabled=$fleet.ActionIndexes('pause').Count -gt 0
    $bulkSettings.Enabled=$fleet.SelectedCount -gt 0
}
function RefreshFleet {
    $phones=[Collections.Generic.List[PhoneExit.FleetPhone]]::new();$online=0;$running=0;$errors=0
    for($i=0;$i -lt $script:phoneRows.Count;$i++){
        $phone=$script:phoneRows[$i];$bot=$script:botPhoneBadges[[string]$phone.id]
        $row=[PhoneExit.FleetPhone]::new();$row.Key=[string]$phone.id;$row.Index=$i;$row.Model=[string]$phone.name;$row.Name=$row.Model;$row.Country=[string]$phone.country
        $row.Online=[bool]$phone.online;$row.Busy=[bool]$phone.busy;$row.Flag=CountryFlag $phone.country
        $row.Fresh=$row.Online -and $bot -and !$bot.botStatusStale -and ([DateTime]::UtcNow-$script:botBadgeLast).TotalSeconds -le 15
        $row.Pending=$script:botRowJobs.ContainsKey([string]$phone.id)
        if($bot){$row.BotId=if($bot.bot.botId){[string]$bot.bot.botId}else{[string]$bot.profile.botId};$row.BotState=[string]$bot.bot.status;if($bot.profile.identity.characterName){$row.Name=[string]$bot.profile.identity.characterName}}
        $row.BotText=if(!$row.BotId){'Без бота'}else{switch($row.BotState){'running'{'Работает'}'paused'{'На паузе'}'error'{'Ошибка'}'stopped'{'Остановлен'}'starting'{'Запускается'}'waiting'{'Ожидает'}default{'Назначен'}}}
        if($row.BotId){$row.GameIcon=BotGameIcon $row.BotId;if(!$row.Fresh){$row.BotText='Последнее: '+$row.BotText}}
        if($row.Online){$online++};if($row.Fresh -and $row.BotState -eq 'running'){$running++};if($row.Fresh -and $row.BotState -eq 'error'){$errors++}
        $query=$fleetSearch.Text.Trim();if($query -and ($row.Name+' '+$row.Model+' '+$row.Country+' '+(CountryName $phone.country)).IndexOf($query,[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
        if($fleetGame.SelectedIndex -eq 1 -and $row.BotId -ne 'lordnine'){continue};if($fleetGame.SelectedIndex -eq 2 -and $row.BotId){continue}
        if(($fleetState.SelectedIndex -eq 1 -and !$row.Online) -or ($fleetState.SelectedIndex -eq 2 -and $row.Online) -or ($fleetState.SelectedIndex -eq 3 -and (!$row.Fresh -or $row.BotState -ne 'running')) -or ($fleetState.SelectedIndex -eq 4 -and (!$row.Fresh -or $row.BotState -ne 'error'))){continue}
        $phones.Add($row)
    }
    $sorted=switch($fleetSort.SelectedIndex){1{@($phones|Sort-Object Name -Descending)}2{@($phones|Sort-Object @{Expression='Online';Descending=$true},Name)}3{@($phones|Sort-Object Country,Name)}default{@($phones|Sort-Object Name)}}
    $fleet.SetPhones([PhoneExit.FleetPhone[]]$sorted)
    $fleetSummary.Text="Устройств: $($script:phoneRows.Count)     ·     В сети: $online     ·     Боты работают: $running     ·     Ошибки: $errors"
    $selected=$null
    if($script:selectedPhone -and ($script:client -or $script:connectionWanted)){$selected=@($script:phoneRows|Where-Object {[string]$_.id -eq [string]$script:selectedPhone}|Select-Object -First 1)[0]}
    elseif($phoneList.SelectedIndex -ge 0 -and $phoneList.SelectedIndex -lt $script:phoneRows.Count){$selected=$script:phoneRows[$phoneList.SelectedIndex]}
    if($selected){$selectedPhoneLabel.Text=[string]$selected.name+"`n"+(CountryName $selected.country)}else{$selectedPhoneLabel.Text='Выберите телефон в списке'}
    $sidebarNote.Text=if($script:vpnState -eq 'active'){if($script:transportReady){'VPN активен'}else{'Трафик заблокирован'}}elseif($script:transportReady){'Прокси подключён'}else{'Личные телефоны'}
}
foreach($filter in @($fleetGame,$fleetState,$fleetSort)){$filter.Add_SelectedIndexChanged({RefreshFleet})}
$fleetSearch.Add_TextChanged({RefreshFleet})
$fleet.Add_SelectionChanged({UpdateFleetSelection})
$selectAll.Add_CheckedChanged({if(!$script:fleetSync){$fleet.SelectAll($selectAll.Checked)}})
$gridButton.Add_Click({$fleet.Table=$false;UpdateWindowLayout})
$tableButton.Add_Click({$fleet.Table=$true;UpdateWindowLayout})
$densityButton.Add_Click({$fleet.Compact=!$fleet.Compact;$densityButton.Text=if($fleet.Compact){'XS'}else{'M'}})
$navDevices.Add_Click({SetDesktopView 'devices'})
$navConnection.Add_Click({SetDesktopView 'connection'})
function FindFleetPhone([string]$id) {
    for($index=0;$index -lt $script:phoneRows.Count;$index++){if([string]$script:phoneRows[$index].id -eq $id){return $index}}
    return -1
}
$fleet.Add_Action({param($sender,$event)
    $index=FindFleetPhone $event.Key
    if($index -lt 0){return}
    $phoneList.SelectedIndex=$index
    if($event.Action -eq 'connect'){SetDesktopView 'connection';return}
    InvokePhoneBotAction $index $event.Action;RefreshFleet
})
function InvokeFleetBulk([string]$op) {
    $keys=if($op -eq 'start'){@($fleet.ActionKeys('start'))+@($fleet.ActionKeys('resume'))}else{@($fleet.ActionKeys($op))}
    $targets=@(foreach($id in $keys){$action=$op;if($op -eq 'start' -and $script:botPhoneBadges[$id].bot.status -eq 'paused'){$action='resume'};[pscustomobject]@{id=$id;action=$action}})
    if(!$targets.Count){return}
    $label=if($op -eq 'start'){'Запустить / продолжить'}else{'Приостановить'}
    if([Windows.Forms.MessageBox]::Show($form,"$label ботов на $($targets.Count) устройствах?",'Групповое действие','YesNo','Question') -ne 'Yes'){return}
    # The modal confirmation pumps directory refreshes; resolve stable IDs again afterwards.
    foreach($target in $targets){$index=FindFleetPhone $target.id;if($index -ge 0){InvokePhoneBotAction $index $target.action}}
    RefreshFleet
}
$bulkStart.Add_Click({InvokeFleetBulk 'start'});$bulkPause.Add_Click({InvokeFleetBulk 'pause'})
$bulkSettings.Add_Click({
    $targets=@($fleet.SelectedKeys|Where-Object {(FindFleetPhone $_) -ge 0})
    if($targets.Count){OpenBotPanel $targets[0] @($targets|Select-Object -Skip 1)}
})
$phoneList.Add_SelectedIndexChanged({RefreshFleet})
foreach($button in @($navDevices,$navConnection,$gridButton,$tableButton,$densityButton,$bulkStart,$bulkPause,$bulkSettings)){
    $button.FlatStyle='Flat';$button.FlatAppearance.BorderSize=0;$button.FlatAppearance.MouseOverBackColor=[Drawing.ColorTranslator]::FromHtml('#34393f')
    $button.Font=[Drawing.Font]::new('Segoe UI',9);$button.ForeColor=$form.ForeColor;$button.BackColor=$buttonSurface
}
foreach($button in @($navDevices,$navConnection,$script:botsButton,$accountButton)){$button.Font=[Drawing.Font]::new('Segoe UI',10);$button.TextAlign='MiddleLeft';$button.Padding=[Windows.Forms.Padding]::new((UiPixel 14),0,0,0)}
$navDevices.NavigationIcon='devices';$navConnection.NavigationIcon='connection';$script:botsButton.NavigationIcon='bots';$accountButton.NavigationIcon='settings'
foreach($button in @($minimizeWindow,$maximizeWindow,$closeWindow)){$button.BackColor=$form.BackColor}
$sidebarNote.Cursor='Hand';$sidebarNote.Add_Click({SetDesktopView 'connection'})
$tabIndex=0
foreach($control in @($navDevices,$navConnection,$script:botsButton,$accountButton,$fleetSearch,$fleetGame,$fleetState,$fleetSort,$selectAll,$bulkStart,$bulkPause,$bulkSettings,$gridButton,$tableButton,$densityButton,$fleet,$phoneList,$mode,$chooseApps,$start,$stopButton,$removePhone)){$control.TabIndex=$tabIndex;$tabIndex++}
function UpdateWindowLayout {
    if(!$script:redesignReady -or $form.WindowState -eq 'Minimized'){return}
    $w=$form.ClientSize.Width/$script:uiScale;$h=$form.ClientSize.Height/$script:uiScale
    $x=216;$width=$w-$x-24;$devices=$script:desktopView -eq 'devices'
    $form.SuspendLayout()
    PlaceControl $brandIcon 18 17 36 36;PlaceControl $title 60 16 128 27;PlaceControl $sub 61 43 125 16
    PlaceControl $badge 204 12 ($w-390) 25
    PlaceControl $minimizeWindow ($w-116) 8 32 32;PlaceControl $maximizeWindow ($w-80) 8 32 32;PlaceControl $closeWindow ($w-44) 8 32 32
    $maximizeWindow.RestoredIcon=$form.WindowState -eq 'Maximized'
    foreach($button in @($navDevices,$navConnection,$script:botsButton,$accountButton)){$button.ForeColor=$muted;$button.BackColor=$title.BackColor}
    PlaceControl $navDevices 12 92 168 38;PlaceControl $navConnection 12 136 168 38;PlaceControl $script:botsButton 12 180 168 38;PlaceControl $accountButton 12 ($h-104) 168 38;PlaceControl $sidebarNote 24 ($h-54) 155 24
    $active=if($devices){$navDevices}else{$navConnection};$active.BackColor=[Drawing.ColorTranslator]::FromHtml('#263e34');$active.ForeColor=$accent
    $pageTitle.Text=if($devices){'Устройства'}else{'Подключение'};$pageSubtitle.Text=if($devices){'Все устройства / Личный список'}else{'Интернет через личный телефон'}
    PlaceControl $pageTitle $x 65 $width 38;PlaceControl $pageSubtitle $x 106 $width 25
    $deviceControls=@($fleet,$fleetSummary,$fleetSearch,$fleetGame,$fleetState,$fleetSort,$gridButton,$tableButton,$densityButton,$selectAll,$bulkStart,$bulkPause,$bulkSettings,$selectionLabel)
    foreach($control in $deviceControls){$control.Visible=$devices}
    foreach($control in @($status,$pingLabel,$mode,$start,$stopButton,$phoneList,$removePhone,$connectTitle,$selectedPhoneLabel,$modeTitle,$safetyLabel)){$control.Visible=!$devices}
    $chooseApps.Visible=!$devices -and $mode.SelectedIndex -eq 1;$appNote.Visible=$chooseApps.Visible
    $heading.Visible=$false;$phoneColumnHeading.Visible=$false;$providerColumnHeading.Visible=$false;$botColumnHeading.Visible=$false
    if($script:personalMode){$apkFolder.Visible=!$devices}else{$phoneName.Visible=!$devices;$addPhone.Visible=!$devices}
    $code.Visible=!$script:personalMode -and !$devices;$copy.Visible=$code.Visible
    PlaceControl $fleetSummary $x 139 $width 26
    $searchWidth=[Math]::Min(326,[Math]::Max(140,$width-420))
    PlaceControl $fleetSearch $x 188 $searchWidth 34
    PlaceControl $fleetGame ($x+$searchWidth+8) 188 120 34;PlaceControl $fleetState ($x+$searchWidth+136) 188 140 34;PlaceControl $fleetSort ($x+$searchWidth+284) 188 136 34
    PlaceControl $selectAll $x 235 135 32;PlaceControl $bulkStart ($x+143) 235 110 32;PlaceControl $bulkPause ($x+261) 235 90 32
    PlaceControl $bulkSettings ($x+359) 235 130 32
    PlaceControl $gridButton ($w-250) 235 88 32;PlaceControl $tableButton ($w-158) 235 88 32;PlaceControl $densityButton ($w-66) 235 42 32
    $gridButton.ForeColor=if(!$fleet.Table){$accent}else{$muted};$tableButton.ForeColor=if($fleet.Table){$accent}else{$muted}
    PlaceControl $selectionLabel $x ($h-132) $width 26
    PlaceControl $fleet $x 279 $width ($h-421)
    $leftWidth=$width-330;$right=$x+$leftWidth+24
    $listHeight=if($script:personalMode){$h-370}else{$h-420}
    PlaceControl $phoneList $x 154 $leftWidth $listHeight;$phoneList.ItemHeight=UiPixel 76
    PlaceControl $removePhone $x ($h-204) ([Math]::Floor(($leftWidth-12)/2)) 36
    if($script:personalMode){PlaceControl $apkFolder ($x+[Math]::Floor(($leftWidth-12)/2)+12) ($h-204) ([Math]::Floor(($leftWidth-12)/2)) 36}
    else{PlaceControl $phoneName $x ($h-159) ($leftWidth-170) 30;PlaceControl $addPhone ($x+$leftWidth-158) ($h-159) 158 32;PlaceControl $code $x ($h-252) ($leftWidth-100) 36;PlaceControl $copy ($x+$leftWidth-90) ($h-252) 90 36}
    PlaceControl $connectTitle $right 154 306 28;PlaceControl $selectedPhoneLabel $right 194 306 52
    PlaceControl $status $right 252 306 66;PlaceControl $pingLabel $right 327 306 24
    PlaceControl $modeTitle $right 365 306 24;PlaceControl $mode $right 397 306 36
    PlaceControl $chooseApps $right 445 306 34;PlaceControl $appNote $right 484 306 27
    $buttonY=if($mode.SelectedIndex -eq 1){522}else{454}
    $safetyLabel.Text=switch($mode.SelectedIndex){2{'При потере телефона прокси и открытые потоки закрываются.'}1{'Трафик выбранных EXE блокируется при потере телефона.'}default{'При потере телефона трафик ПК блокируется.'}}
    PlaceControl $start $right $buttonY 177 44;PlaceControl $stopButton ($right+189) $buttonY 117 44
    PlaceControl $safetyLabel $right ($buttonY+58) 306 32
    PlaceControl $hint $x ($h-85) $width 43;PlaceControl $detail $x ($h-35) ($width-165) 24;PlaceControl $versionLabel ($w-180) ($h-35) 156 24
    $form.ResumeLayout();$form.Invalidate()
}
$script:fleetTimer=New-Object Windows.Forms.Timer;$script:fleetTimer.Interval=1000
$script:fleetTimer.Add_Tick({RefreshFleet})
$form.Add_Shown({$script:fleetTimer.Start()})
$form.Add_FormClosed({$script:fleetTimer.Stop();$script:fleetTimer.Dispose()})
if($SelfTest){$script:desktopView='connection'}
UpdateConnectionButtons;RefreshFleet;UpdateWindowLayout
