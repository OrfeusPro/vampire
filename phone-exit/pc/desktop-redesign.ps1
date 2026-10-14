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
$sidebarDivider=New-Object Windows.Forms.Panel;$sidebarDivider.BackColor=[Drawing.ColorTranslator]::FromHtml('#34393f');$form.Controls.Add($sidebarDivider)
$sidebarDot=New-Object Windows.Forms.Panel;$sidebarDot.BackColor=$title.BackColor;$form.Controls.Add($sidebarDot)
$sidebarDot.Add_Paint({param($sender,$e) $ink=if($script:directory -and !$script:directory.HasExited){[Drawing.ColorTranslator]::FromHtml('#62e7bc')}else{$muted};$brush=[Drawing.SolidBrush]::new($ink);try{$e.Graphics.SmoothingMode='AntiAlias';$e.Graphics.FillEllipse($brush,0,0,$sender.Width-1,$sender.Height-1)}finally{$brush.Dispose()}})
$pageTitle=LabelAt 'Устройства' 0 0 600 38;$pageTitle.Font=[Drawing.Font]::new('Segoe UI',20,[Drawing.FontStyle]::Bold)
$pageSubtitle=LabelAt 'Все устройства / Личный список' 0 0 600 24;$pageSubtitle.ForeColor=$muted;$pageSubtitle.Font=[Drawing.Font]::new('Segoe UI',9)
$fleetSummary=New-Object PhoneExit.FleetSummaryControl;$fleetSummary.BackColor=$form.BackColor;$fleetSummary.ForeColor=$form.ForeColor;$fleetSummary.Font=[Drawing.Font]::new('Segoe UI',9);$form.Controls.Add($fleetSummary)
$fleet=New-Object PhoneExit.FleetView;$fleet.UiScale=$script:uiScale;$form.Controls.Add($fleet)
$fleetSearch=New-Object PhoneExit.SearchField;$fleetSearch.BackColor=$surface;$fleetSearch.ForeColor=$form.ForeColor;$fleetSearch.Font=[Drawing.Font]::new('Segoe UI',9);$fleetSearch.AccessibleName='Поиск по имени, персонажу, модели или стране';$form.Controls.Add($fleetSearch)
$fleetGame=New-Object PhoneExit.DarkSelect;$fleetGame.AccessibleName='Фильтр по боту';$fleetGame.BackColor=$buttonSurface;$fleetGame.ForeColor=$form.ForeColor
foreach($text in @('Бот: все','Lord Nine','RF Online Next','Без бота')){$null=$fleetGame.Items.Add($text)};$fleetGame.SelectedIndex=0;$form.Controls.Add($fleetGame)
$fleetState=New-Object PhoneExit.DarkSelect;$fleetState.AccessibleName='Фильтр состояния';$fleetState.BackColor=$buttonSurface;$fleetState.ForeColor=$form.ForeColor
foreach($text in @('Статус: все','В сети','Не в сети','Бот работает','Ошибка бота')){$null=$fleetState.Items.Add($text)};$fleetState.SelectedIndex=0;$form.Controls.Add($fleetState)
$fleetSort=New-Object PhoneExit.DarkSelect;$fleetSort.AccessibleName='Сортировка устройств';$fleetSort.BackColor=$buttonSurface;$fleetSort.ForeColor=$form.ForeColor
foreach($text in @('Имя ↑','Имя ↓','Сначала в сети','По стране')){$null=$fleetSort.Items.Add($text)};$fleetSort.SelectedIndex=0;$form.Controls.Add($fleetSort)
$script:fleetFilterSync=$false;$script:fleetAdvanced=$false;$script:fleetCountryCodes=@{}
$fleetExtra=@{}
foreach($spec in @(@('Country','Страна'),@('Connection','Связь'),@('VpnState','VPN'),@('ApkVersion','APK'),@('BotVersion','Версия бота'),@('Provider','Поставщик'))){
    $control=New-Object PhoneExit.DarkSelect;$control.AccessibleName='Фильтр: '+$spec[1];$control.BackColor=$buttonSurface;$control.ForeColor=$form.ForeColor
    $null=$control.Items.Add($spec[1]+': все');$control.SelectedIndex=0;$form.Controls.Add($control);$fleetExtra[$spec[0]]=$control
}
foreach($text in @('Онлайн','Офлайн')){$null=$fleetExtra.Connection.Items.Add($text)}
foreach($text in @('Включён','Выключен','Трафик заблокирован')){$null=$fleetExtra.VpnState.Items.Add($text)}
foreach($text in @('На паузе','Ожидает','Запускается','Остановлен','Без бота')){$null=$fleetState.Items.Add($text)}
$captionTips.SetToolTip($fleetExtra.VpnState,'VPN через этот ПК; не состояние стороннего VPN на телефоне')
$gridButton=ButtonAt 'Карточки' 0 0 90;$tableButton=ButtonAt 'Таблица' 0 0 90
$densityButton=ButtonAt 'XS' 0 0 40;$densityButton.AccessibleName='Плотность карточек';$captionTips.SetToolTip($densityButton,'Компактные / крупные карточки')
$advancedButton=ButtonAt '' 0 0 34;$advancedButton.NavigationIcon='settings';$advancedButton.IconOnly=$true;$advancedButton.AccessibleName='Расширенные фильтры';$captionTips.SetToolTip($advancedButton,'Показать / скрыть расширенные фильтры')
$gridButton.Text='';$gridButton.NavigationIcon='devices';$gridButton.IconOnly=$true;$gridButton.AccessibleName='Карточки';$captionTips.SetToolTip($gridButton,'Карточки')
$tableButton.Text='';$tableButton.NavigationIcon='list';$tableButton.IconOnly=$true;$tableButton.AccessibleName='Таблица';$captionTips.SetToolTip($tableButton,'Таблица')
foreach($control in $form.Controls){if($control -is [PhoneExit.DarkSelect] -or $control -is [PhoneExit.DarkButton]){$control.Rounded=$true}}
$selectAll=New-Object PhoneExit.DarkCheckBox;$selectAll.Text='Выбрать все';$selectAll.ForeColor=$accent;$selectAll.BackColor=$form.BackColor;$selectAll.AccessibleName='Выбрать все видимые устройства';$form.Controls.Add($selectAll)
$bulkStart=ButtonAt 'Запустить' 0 0 120;$bulkPause=ButtonAt 'Пауза' 0 0 110
$bulkSettings=ButtonAt 'Настроить бота' 0 0 146
$bulkStart.NavigationIcon='play';$bulkPause.NavigationIcon='pause';$bulkSettings.NavigationIcon='settings'
foreach($button in @($bulkStart,$bulkPause,$bulkSettings)){$button.CenterContent=$true;$button.KeepForegroundWhenDisabled=$true}
$viewSwitch=New-Object PhoneExit.SegmentedSurface;$form.Controls.Add($viewSwitch)
foreach($button in @($gridButton,$tableButton,$densityButton)){$viewSwitch.Controls.Add($button);$button.Borderless=$true;$button.Rounded=$true}
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
    $selectAll.CheckState=if($fleet.SelectedCount -eq 0){'Unchecked'}elseif($fleet.SelectedCount -eq $fleet.VisibleCount){'Checked'}else{'Indeterminate'}
    $selectAll.Text=if($fleet.SelectedCount -gt 0){"Выбрано $($fleet.SelectedCount)"}else{'Выбрать все'}
    $script:fleetSync=$false
    $selectionLabel.Text="Выбрано: $($fleet.SelectedCount)"
    $bulkStart.Enabled=($fleet.ActionIndexes('start').Count+$fleet.ActionIndexes('resume').Count) -gt 0
    $bulkPause.Enabled=$fleet.ActionIndexes('pause').Count -gt 0
    $bulkSettings.Enabled=$fleet.SelectedCount -gt 0
    foreach($button in @($bulkStart,$bulkPause,$bulkSettings)){$button.Visible=$script:desktopView -eq 'devices' -and $fleet.SelectedCount -gt 0}
}
function RefreshFleet {
    if($script:fleetFilterSync){return}
    $phones=[Collections.Generic.List[PhoneExit.FleetPhone]]::new();$online=0;$running=0;$errors=0
    for($i=0;$i -lt $script:phoneRows.Count;$i++){
        $phone=$script:phoneRows[$i];$bot=$script:botPhoneBadges[[string]$phone.id]
        $row=[PhoneExit.FleetPhone]::new();$row.Key=[string]$phone.id;$row.Index=$i;$row.Model=[string]$phone.name;$row.Name=$row.Model;$row.Country=[string]$phone.country
        $row.Online=[bool]$phone.online;$row.Busy=[bool]$phone.busy;$row.Flag=CountryFlag $phone.country
        $row.ApkVersion=if($phone.versionName){[string]$phone.versionName}else{''}
        $row.Group=[string]$phone.group
        $row.VpnState=if([string]$script:selectedPhone -eq $row.Key -and $script:vpnState -eq 'active'){if($script:transportReady){'active'}else{'blocked'}}else{'off'}
        $row.Fresh=$row.Online -and $bot -and !$bot.botStatusStale -and ([DateTime]::UtcNow-$script:botBadgeLast).TotalSeconds -le 15
        $row.Pending=$script:botRowJobs.ContainsKey([string]$phone.id)
        if($bot){$row.BotId=if($bot.bot.botId){[string]$bot.bot.botId}else{[string]$bot.profile.botId};$row.BotState=[string]$bot.bot.status;if($bot.profile.identity.characterName){$row.Name=[string]$bot.profile.identity.characterName}}
        if($bot){$row.BotVersion=[string]$bot.bot.version;$row.Provider=[string]$bot.profile.identity.provider;if($bot.profile.identity.group){$row.Group=[string]$bot.profile.identity.group}}
        if($bot.profile.assignmentPending){$row.BotId=[string]$bot.profile.botId;$row.BotState='assigned';$row.BotVersion='';$row.Fresh=$false}
        $row.BotName=switch($row.BotId){'lordnine'{'Lord Nine'}'rfonlinenext'{'RF Online Next'}default{$row.BotId}}
        $row.ProviderIcon=ProviderIcon $row.Provider
        $row.BotText=if(!$row.BotId){'Без бота'}else{switch($row.BotState){'running'{'Работает'}'paused'{'На паузе'}'error'{'Ошибка'}'stopped'{'Остановлен'}'starting'{'Запускается'}'waiting'{'Ожидает'}default{'Назначен'}}}
        if($row.Fresh -and $bot.bot.step -eq 'auto_restart_pending'){$row.BotText='Перезапуск '+$bot.bot.retryCount+'/5'}
        if($row.BotId){$row.GameIcon=BotGameIcon $row.BotId;if(!$row.Fresh){$row.BotText='Последнее: '+$row.BotText}}
        if($bot.profile.assignmentPending){$row.BotText='Назначен на ПК · ожидает передачи'}
        if($row.Online){$online++};if($row.Fresh -and $row.BotState -eq 'running'){$running++};if($row.Fresh -and $row.BotState -eq 'error'){$errors++}
        $phones.Add($row)
    }
    $script:fleetFilterSync=$true
    try{
        foreach($field in @('Country','ApkVersion','BotVersion','Provider')){
            $control=$fleetExtra[$field];$old=[string]$control.SelectedItem
            $oldCode=if($field -eq 'Country'){$script:fleetCountryCodes[$old]}else{''}
            if($field -eq 'Country'){
                $script:fleetCountryCodes=@{};$control.ItemImages.Clear()
                $values=@($phones|ForEach-Object {$code=$_.Country;$label=CountryName $code;$script:fleetCountryCodes[$label]=$code;$control.ItemImages[$label]=CountryFlag $code;$label}|Sort-Object -Unique)
            }else{$values=@($phones|ForEach-Object {if($_.$field){[string]$_.$field}else{'Не указано'}}|Sort-Object -Unique)}
            if($control.SelectedIndex -gt 0 -and $values -notcontains $old){$values=@($values)+$old;if($field -eq 'Country'){$script:fleetCountryCodes[$old]=$oldCode;$control.ItemImages[$old]=CountryFlag $oldCode}}
            $values=@($values|Sort-Object)
            $items=@([string]$control.Items[0])+$values
            if(($items -join "`n") -ne (@($control.Items|ForEach-Object {[string]$_}) -join "`n")){
                $control.SelectedIndex=-1;$control.Items.Clear();foreach($item in $items){$null=$control.Items.Add($item)}
                $control.SelectedIndex=[Math]::Max(0,$control.Items.IndexOf($old))
            }
        }
    }finally{$script:fleetFilterSync=$false}
    $conditions=[PhoneExit.FleetFilter]::new();$conditions.Connection=$fleetExtra.Connection.SelectedIndex
    foreach($field in @('Country','ApkVersion','BotVersion','Provider')){if($fleetExtra[$field].SelectedIndex -gt 0){$value=[string]$fleetExtra[$field].SelectedItem;$conditions.$field=if($field -eq 'Country'){[string]$script:fleetCountryCodes[$value]}elseif($value -eq 'Не указано'){''}else{$value}}}
    if($fleetExtra.VpnState.SelectedIndex -gt 0){$conditions.VpnState=@('','active','off','blocked')[$fleetExtra.VpnState.SelectedIndex]}
    if($fleetGame.SelectedIndex -gt 0){$conditions.BotId=@('','lordnine','rfonlinenext','')[$fleetGame.SelectedIndex]}
    if($fleetState.SelectedIndex -ge 3){$conditions.State=@('','','','running','error','paused','waiting','starting','stopped','none')[$fleetState.SelectedIndex]}
    $query=$fleetSearch.Text.Trim()
    $phones=@($phones|Where-Object {$conditions.Matches($_) -and ($fleetState.SelectedIndex -ne 1 -or $_.Online) -and ($fleetState.SelectedIndex -ne 2 -or !$_.Online) -and (!$query -or ($_.Name+' '+$_.Model+' '+$_.Country+' '+(CountryName $_.Country)+' '+$_.Key+' '+$_.Provider+' '+$_.Group).IndexOf($query,[StringComparison]::OrdinalIgnoreCase) -ge 0)})
    $sorted=switch($fleetSort.SelectedIndex){1{@($phones|Sort-Object Name -Descending)}2{@($phones|Sort-Object @{Expression='Online';Descending=$true},Name)}3{@($phones|Sort-Object Country,Name)}default{@($phones|Sort-Object Name)}}
    $fleet.SetPhones([PhoneExit.FleetPhone[]]$sorted)
    $fleetSummary.SetCounts($script:phoneRows.Count,$online,$running,$errors)
    $selected=$null
    if($script:selectedPhone -and ($script:client -or $script:connectionWanted)){$selected=@($script:phoneRows|Where-Object {[string]$_.id -eq [string]$script:selectedPhone}|Select-Object -First 1)[0]}
    elseif($phoneList.SelectedIndex -ge 0 -and $phoneList.SelectedIndex -lt $script:phoneRows.Count){$selected=$script:phoneRows[$phoneList.SelectedIndex]}
    if($selected){$selectedPhoneLabel.Text=[string]$selected.name+"`n"+(CountryName $selected.country)}else{$selectedPhoneLabel.Text='Выберите телефон в списке'}
    $sidebarNote.Text=if($script:vpnState -eq 'active'){if($script:transportReady){'VPN активен'}else{'Трафик заблокирован'}}elseif($script:transportReady){'Прокси подключён'}elseif($script:directory -and !$script:directory.HasExited){'Каталог телефонов'}else{'Каталог остановлен'}
    $sidebarDot.Invalidate()
}
foreach($filter in @($fleetGame,$fleetState,$fleetSort)){$filter.Add_SelectedIndexChanged({RefreshFleet})}
foreach($filter in $fleetExtra.Values){$filter.Add_SelectedIndexChanged({RefreshFleet})}
$fleetSearch.Add_TextChanged({RefreshFleet})
$fleet.Add_SelectionChanged({UpdateFleetSelection})
$selectAll.Add_CheckedChanged({if(!$script:fleetSync){$fleet.SelectAll($selectAll.Checked)}})
$gridButton.Add_Click({$fleet.Table=$false;UpdateWindowLayout})
$tableButton.Add_Click({$fleet.Table=$true;UpdateWindowLayout})
$densityButton.Add_Click({$fleet.Compact=!$fleet.Compact;$densityButton.Text=if($fleet.Compact){'XS'}else{'M'}})
$advancedButton.Add_Click({SetFleetAdvanced (!$script:fleetAdvanced)})
function SetFleetAdvanced([bool]$enabled){
    $script:fleetAdvanced=$enabled
    if(!$enabled){$script:fleetFilterSync=$true;try{foreach($field in @('Connection','VpnState','ApkVersion','BotVersion','Provider')){$fleetExtra[$field].SelectedIndex=0}}finally{$script:fleetFilterSync=$false};RefreshFleet}
    $advancedButton.ForeColor=if($enabled){$accent}else{$muted};UpdateWindowLayout
}
$form.Add_MouseDown({param($sender,$e)if($script:desktopView -eq 'devices' -and $e.Button -eq 'Left'){$fleet.ClearSelection()}})
foreach($label in @($pageTitle,$pageSubtitle,$fleetSummary,$selectionLabel)){$label.Add_MouseDown({param($sender,$e)if($e.Button -eq 'Left'){$fleet.ClearSelection()}})}
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
    foreach($target in $targets){OpenBotPanel $target}
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
foreach($control in @($fleetGame,$fleetState,$fleetSort)+@($fleetExtra.Values)){$control.Font=[Drawing.Font]::new('Segoe UI',9,[Drawing.FontStyle]::Bold)}
foreach($button in @($bulkStart,$bulkPause,$bulkSettings)){$button.Font=[Drawing.Font]::new('Segoe UI',9,[Drawing.FontStyle]::Bold)}
$selectAll.Font=[Drawing.Font]::new('Segoe UI',9,[Drawing.FontStyle]::Bold)
foreach($control in $form.Controls){if($control -is [PhoneExit.DarkSelect] -or $control -is [PhoneExit.DarkButton]){$control.Rounded=$true}}
foreach($button in @($navDevices,$navConnection,$script:botsButton,$accountButton)){$button.Borderless=$true}
foreach($control in @($navDevices,$navConnection,$script:botsButton,$accountButton,$fleetSearch,$fleetGame,$fleetState,$fleetSort,$advancedButton,$viewSwitch,$selectAll,$bulkStart,$bulkPause,$bulkSettings,$fleet,$phoneList,$mode,$chooseApps,$start,$stopButton,$removePhone)){$control.TabIndex=$tabIndex;$tabIndex++}
$gridButton.TabIndex=0;$tableButton.TabIndex=1;$densityButton.TabIndex=2
foreach($control in $fleetExtra.Values){$control.TabIndex=$tabIndex;$tabIndex++}
function UpdateWindowLayout {
    if(!$script:redesignReady -or $form.WindowState -eq 'Minimized'){return}
    $w=$form.ClientSize.Width/$script:uiScale;$h=$form.ClientSize.Height/$script:uiScale
    $x=216;$width=$w-$x-24;$devices=$script:desktopView -eq 'devices'
    $form.SuspendLayout()
    PlaceControl $brandIcon 18 17 36 36;PlaceControl $title 60 16 128 27;PlaceControl $sub 61 43 125 16
    PlaceControl $badge 204 12 ($w-390) 25
    PlaceControl $minimizeWindow ($w-116) 8 32 32;PlaceControl $maximizeWindow ($w-80) 8 32 32;PlaceControl $closeWindow ($w-44) 8 32 32
    $maximizeWindow.RestoredIcon=$form.WindowState -eq 'Maximized'
    foreach($button in @($navDevices,$navConnection,$script:botsButton,$accountButton)){$button.ForeColor=$muted;$button.BackColor=$title.BackColor;$button.SurroundColor=$title.BackColor}
    PlaceControl $navDevices 12 92 168 38;PlaceControl $navConnection 12 136 168 38;PlaceControl $script:botsButton 12 180 168 38;PlaceControl $accountButton 12 ($h-112) 168 38
    PlaceControl $sidebarDivider 20 ($h-66) 152 1;PlaceControl $sidebarDot 28 ($h-37) 7 7;PlaceControl $sidebarNote 44 ($h-46) 140 24
    $bots=$script:desktopView -eq 'bots';$connection=$script:desktopView -eq 'connection'
    $pageTitle.Visible=!$bots;$pageSubtitle.Visible=!$bots
    $active=if($devices){$navDevices}elseif($bots){$script:botsButton}else{$navConnection};$active.BackColor=[Drawing.ColorTranslator]::FromHtml('#263e34');$active.ForeColor=$accent
    $pageTitle.Text=if($devices){'Устройства'}elseif($bots){'Боты и профили'}else{'Подключение'};$pageSubtitle.Text=if($devices){'Все устройства / Личный список'}elseif($bots){'Игры и настройки личных телефонов'}else{'Интернет через личный телефон'}
    PlaceControl $pageTitle $x 65 $width 38;PlaceControl $pageSubtitle $x 106 $width 25
    $deviceControls=@($fleet,$fleetSummary,$fleetSearch,$fleetGame,$fleetState,$fleetSort,$viewSwitch,$selectAll,$bulkStart,$bulkPause,$bulkSettings,$selectionLabel)
    foreach($control in $deviceControls){$control.Visible=$devices}
    foreach($button in @($bulkStart,$bulkPause,$bulkSettings)){$button.Visible=$devices -and $fleet.SelectedCount -gt 0}
    foreach($control in $fleetExtra.Values){$control.Visible=$devices}
    foreach($field in @('Connection','VpnState','ApkVersion','BotVersion','Provider')){$fleetExtra[$field].Visible=$devices -and $script:fleetAdvanced}
    $advancedButton.Visible=$devices
    foreach($control in @($status,$pingLabel,$mode,$start,$stopButton,$phoneList,$removePhone,$connectTitle,$selectedPhoneLabel,$modeTitle,$safetyLabel)){$control.Visible=$connection}
    $chooseApps.Visible=$connection -and $mode.SelectedIndex -eq 1;$appNote.Visible=$chooseApps.Visible
    $heading.Visible=$false;$phoneColumnHeading.Visible=$false;$providerColumnHeading.Visible=$false;$botColumnHeading.Visible=$false
    if($script:personalMode){$apkFolder.Visible=$connection}else{$phoneName.Visible=$connection;$addPhone.Visible=$connection}
    $code.Visible=!$script:personalMode -and $connection;$copy.Visible=$code.Visible
    PlaceControl $fleetSummary $x 139 $width 26
    $filterX=$x;$filterY=172;$filterRight=$x+$width-172
    $specs=@(@($fleetSearch,326),@($fleetGame,144),@($fleetExtra.Country,170),@($fleetState,160),@($fleetSort,112))
    foreach($spec in $specs){if($filterX -gt $x -and $filterX+$spec[1] -gt $filterRight){$filterX=$x;$filterY+=42;$filterRight=$x+$width};PlaceControl $spec[0] $filterX $filterY $spec[1] 36;$filterX+=$spec[1]+8}
    PlaceControl $advancedButton ($w-196) 172 36 36;PlaceControl $viewSwitch ($w-152) 172 128 36
    PlaceControl $gridButton 4 4 36 28;PlaceControl $tableButton 44 4 36 28;PlaceControl $densityButton 84 4 40 28
    if($script:fleetAdvanced){$filterX=$x;$filterY+=42;foreach($spec in @(@($fleetExtra.Connection,126),@($fleetExtra.VpnState,126),@($fleetExtra.ApkVersion,126),@($fleetExtra.BotVersion,160),@($fleetExtra.Provider,160))){if($filterX -gt $x -and $filterX+$spec[1] -gt $x+$width){$filterX=$x;$filterY+=42};PlaceControl $spec[0] $filterX $filterY $spec[1] 34;$filterX+=$spec[1]+8}}
    $bulkY=$filterY+43
    PlaceControl $selectAll $x $bulkY 145 36;PlaceControl $bulkStart ($x+153) $bulkY 130 36;PlaceControl $bulkPause ($x+291) $bulkY 130 36
    PlaceControl $bulkSettings ($x+429) $bulkY 146 36
    $viewY=$bulkY
    $gridButton.ForeColor=if(!$fleet.Table){$accent}else{$muted};$tableButton.ForeColor=if($fleet.Table){$accent}else{$muted}
    $gridButton.BackColor=if(!$fleet.Table){[Drawing.ColorTranslator]::FromHtml('#263e34')}else{$surface};$tableButton.BackColor=if($fleet.Table){[Drawing.ColorTranslator]::FromHtml('#263e34')}else{$surface};$densityButton.BackColor=$surface
    PlaceControl $selectionLabel $x ($h-56) ($width-180) 26
    $fleetTop=$viewY+44
    PlaceControl $fleet $x $fleetTop $width ([Math]::Max(60,$h-66-$fleetTop))
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
    $hint.Visible=$connection;$detail.Visible=$connection
    if($script:embeddedBotPanel -and !$script:embeddedBotPanel.IsDisposed){
        if($script:embeddedBotPanel.MonitorDpi -ne $form.MonitorDpi){$script:embeddedBotPanel.ApplyMonitorDpi($form.MonitorDpi,[Drawing.Rectangle]::Empty)}
        $script:embeddedBotPanel.Visible=$bots
        if($bots){
            PlaceControl $script:embeddedBotPanel $x 65 $width ($h-131)
            $script:embeddedBotPanel.SetEmbeddedHeaderOffset((UiPixel 89))
            $script:embeddedBotPanel.BringToFront()
            $headerWidth=[Math]::Floor($width*0.52)-16
            PlaceControl $pageTitle $x 65 $headerWidth 38;PlaceControl $pageSubtitle $x 106 $headerWidth 25
            $pageTitle.BringToFront();$pageSubtitle.BringToFront()
        }
    }
    $form.ResumeLayout();$form.Invalidate()
}
$script:fleetTimer=New-Object Windows.Forms.Timer;$script:fleetTimer.Interval=1000
$script:fleetTimer.Add_Tick({RefreshFleet})
$form.Add_Shown({$script:fleetTimer.Start()})
$form.Add_FormClosed({$script:fleetTimer.Stop();$script:fleetTimer.Dispose()})
if($SelfTest){$script:desktopView='connection'}
UpdateConnectionButtons;RefreshFleet;UpdateWindowLayout
