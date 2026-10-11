# Native UI: no local web server, browser, or account capability in rendered content.
$dpiGraphics=[Drawing.Graphics]::FromHwnd([IntPtr]::Zero)
$script:uiScale=[single]($dpiGraphics.DpiX/96.0);$dpiGraphics.Dispose()
function UiPixel([double]$value){return [int][Math]::Round($value*$script:uiScale)}
$form.MaximumSize=[Drawing.Size]::Empty;$form.MinimumSize=[Drawing.Size]::Empty
$form.FormBorderStyle=[Windows.Forms.FormBorderStyle]::None
$form.ClientSize=New-Object Drawing.Size(1100,720)
$form.BackColor=[Drawing.ColorTranslator]::FromHtml('#10151f')
$form.ForeColor=[Drawing.ColorTranslator]::FromHtml('#eff4fa')
$form.Font=New-Object Drawing.Font('Segoe UI',10)
$muted=[Drawing.ColorTranslator]::FromHtml('#9daabc')
$accent=[Drawing.ColorTranslator]::FromHtml('#62e7bc')
foreach($control in $form.Controls){
    if($control -is [Windows.Forms.Label]){$control.Visible=$false;$control.ForeColor=$form.ForeColor}
    if($control -is [Windows.Forms.Button]){
        $control.FlatStyle='Flat';$control.FlatAppearance.BorderSize=0
        $control.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$control.ForeColor=$form.ForeColor
        $control.Cursor='Hand';$control.Font=New-Object Drawing.Font('Segoe UI',10,[Drawing.FontStyle]::Bold)
    }
}
$title.Visible=$true;$title.SetBounds(78,28,350,46);$title.Font=New-Object Drawing.Font('Segoe UI Semibold',24)
$brandIcon=New-Object Windows.Forms.PictureBox;$brandIcon.SetBounds(36,32,38,38);$brandIcon.SizeMode='Zoom';$brandIcon.Image=[Drawing.Image]::FromFile((Join-Path $PSScriptRoot 'assets/phone-exit.png'));$form.Controls.Add($brandIcon)
$form.Add_FormClosed({$brandIcon.Image.Dispose()})
$sub=LabelAt 'Личный интернет. Через твои телефоны.' 38 79 600 30;$sub.ForeColor=$muted
$versionLabel=LabelAt 'Версия 0.4.8' 440 42 170 24;$versionLabel.ForeColor=$muted;$versionLabel.TextAlign='MiddleRight'
$badge=LabelAt 'ПРЯМОЕ ПОДКЛЮЧЕНИЕ' 765 49 293 30;$badge.ForeColor=$accent;$badge.TextAlign='MiddleRight';$badge.Font=New-Object Drawing.Font('Segoe UI Semibold',9)
$form.Add_Paint({param($sender,$paintEvent)
    $g=$paintEvent.Graphics;$g.SmoothingMode='AntiAlias';$g.ScaleTransform($script:uiScale,$script:uiScale)
    $brush=New-Object Drawing.SolidBrush([Drawing.ColorTranslator]::FromHtml('#192231'))
    $left=$script:leftPane;$right=$script:rightPane
    $g.FillRectangle($brush,$left);$g.FillRectangle($brush,$right);$brush.Dispose()
    $center=$left.X+$left.Width/2
    $pen=New-Object Drawing.Pen([Drawing.ColorTranslator]::FromHtml('#314056'),2)
    $offset=$script:connectionOffset
    $g.DrawEllipse($pen,($center-63),(173+$offset),126,126);$pen.Dispose()
    $pen=New-Object Drawing.Pen([Drawing.ColorTranslator]::FromHtml('#62e7bc'),4)
    $g.DrawArc($pen,($center-29),(209+$offset),58,58,-50,280);$g.DrawLine($pen,$center,(201+$offset),$center,(235+$offset));$pen.Dispose()
    if($form.WindowState -eq 'Normal'){
        $pen=New-Object Drawing.Pen([Drawing.ColorTranslator]::FromHtml('#4c5e76'),1)
        $w=$form.ClientSize.Width/$script:uiScale;$h=$form.ClientSize.Height/$script:uiScale
        $g.DrawLine($pen,($w-14),($h-6),($w-6),($h-14));$g.DrawLine($pen,($w-9),($h-6),($w-6),($h-9));$pen.Dispose()
    }
})
$status.Visible=$true;$status.SetBounds(62,319,524,39);$status.TextAlign='MiddleCenter';$status.Font=New-Object Drawing.Font('Segoe UI Semibold',17);$status.BackColor=[Drawing.ColorTranslator]::FromHtml('#192231')
$pingLabel=LabelAt 'Пинг до телефона: —' 94 354 458 22;$pingLabel.TextAlign='MiddleCenter';$pingLabel.ForeColor=$muted;$pingLabel.BackColor=$status.BackColor;$pingLabel.Font=New-Object Drawing.Font('Segoe UI',9)
$mode=New-Object PhoneExit.DarkSelect;$mode.SetBounds(94,377,458,34);$mode.AccessibleName='Режим подключения'
$mode.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$mode.ForeColor=$form.ForeColor
$null=$mode.Items.Add('Весь трафик · VPN');$null=$mode.Items.Add('Выбранные EXE · VPN (тестовый)');$null=$mode.Items.Add('Прокси · TCP');$mode.SelectedIndex=0;$form.Controls.Add($mode)
$chooseApps=ButtonAt 'Список приложений…' 94 421 458;$chooseApps.Height=34;$chooseApps.Visible=$false
$chooseApps.FlatStyle='Flat';$chooseApps.FlatAppearance.BorderSize=0
$chooseApps.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144');$chooseApps.ForeColor=$form.ForeColor
$appNote=LabelAt '' 94 460 458 27;$appNote.ForeColor=$muted;$appNote.BackColor=[Drawing.ColorTranslator]::FromHtml('#192231');$appNote.Visible=$false
$start.SetBounds(94,498,274,52);$start.Text='Подключить VPN';$start.BackColor=$accent;$start.ForeColor=[Drawing.ColorTranslator]::FromHtml('#10251e')
$stopButton.SetBounds(380,498,172,52);$stopButton.Text='Отключить'
function UpdateConnectionButtons {
    $start.BackColor=if($start.Enabled){$accent}else{[Drawing.ColorTranslator]::FromHtml('#202b3b')}
    $start.ForeColor=if($start.Enabled){[Drawing.ColorTranslator]::FromHtml('#10251e')}else{$muted}
    $start.Cursor=if($start.Enabled){'Hand'}else{'Default'}
    $stopButton.BackColor=[Drawing.ColorTranslator]::FromHtml('#263144')
    $stopButton.ForeColor=if($stopButton.Enabled){$accent}else{$muted}
    $stopButton.Cursor=if($stopButton.Enabled){'Hand'}else{'Default'}
    $start.Invalidate();$stopButton.Invalidate()
}
$start.Add_EnabledChanged({UpdateConnectionButtons})
$stopButton.Add_EnabledChanged({UpdateConnectionButtons})
UpdateConnectionButtons
$heading=LabelAt 'Мои телефоны' 664 161 346 35;$heading.Font=New-Object Drawing.Font('Segoe UI Semibold',16);$heading.BackColor=[Drawing.ColorTranslator]::FromHtml('#192231')
$phoneList.SetBounds(662,214,384,258);$phoneList.BackColor=[Drawing.ColorTranslator]::FromHtml('#192231');$phoneList.ForeColor=$form.ForeColor
$phoneList.ItemHeight=80
$script:flagImages=@{}
$flagFolder=Join-Path $PSScriptRoot 'assets/flags'
function CountryFlag($country){
    $key=if($country -match '^[A-Z]{2}$'){$country}else{'unknown'}
    if(!$script:flagImages.ContainsKey($key)){
        $path=Join-Path $flagFolder ($key+'.png')
        if(!(Test-Path -LiteralPath $path)){$path=Join-Path $flagFolder 'unknown.png'}
        $script:flagImages[$key]=[Drawing.Image]::FromFile($path)
    }
    return $script:flagImages[$key]
}
$form.Add_FormClosed({foreach($flagImage in $script:flagImages.Values){$flagImage.Dispose()}})
$phoneList.Add_DrawItem({param($sender,$paintEvent)
    if($paintEvent.Index -lt 0 -or $paintEvent.Index -ge $script:phoneRows.Count){return}
    $phone=$script:phoneRows[$paintEvent.Index];$g=$paintEvent.Graphics;$r=$paintEvent.Bounds
    $selected=($paintEvent.State -band [Windows.Forms.DrawItemState]::Selected) -ne 0
    $bg=if($selected){'#2c3a50'}else{'#192231'};$brush=New-Object Drawing.SolidBrush([Drawing.ColorTranslator]::FromHtml($bg));$g.FillRectangle($brush,$r);$brush.Dispose()
    $country=CountryName $phone.country;$state=if(!$phone.online){'Не в сети'}elseif($phone.busy){'Занят'}else{'Доступен'}
    $small=New-Object Drawing.Font('Segoe UI',9);$large=New-Object Drawing.Font('Segoe UI Semibold',12)
    $flags=[Windows.Forms.TextFormatFlags]::NoPadding -bor [Windows.Forms.TextFormatFlags]::SingleLine -bor [Windows.Forms.TextFormatFlags]::EndEllipsis
    $flagRect=New-Object Drawing.Rectangle(($r.X+(UiPixel 14)),($r.Y+(UiPixel 10)),(UiPixel 34),(UiPixel 34))
    $g.DrawImage((CountryFlag $phone.country),$flagRect)
    $countryRect=New-Object Drawing.Rectangle(($r.X+(UiPixel 60)),($r.Y+(UiPixel 12)),($r.Width-(UiPixel 166)),(UiPixel 28))
    $nameRect=New-Object Drawing.Rectangle(($r.X+(UiPixel 60)),($r.Y+(UiPixel 40)),($r.Width-(UiPixel 76)),(UiPixel 22))
    [Windows.Forms.TextRenderer]::DrawText($g,$country,$large,$countryRect,$form.ForeColor,$flags)
    [Windows.Forms.TextRenderer]::DrawText($g,[string]$phone.name,$small,$nameRect,$muted,$flags)
    $stateColor=if($phone.online -and !$phone.busy){'#62e7bc'}else{'#9daabc'};$dot=New-Object Drawing.SolidBrush([Drawing.ColorTranslator]::FromHtml($stateColor))
    $g.FillEllipse($dot,($r.Right-(UiPixel 98)),($r.Y+(UiPixel 21)),(UiPixel 6),(UiPixel 6))
    $stateRect=New-Object Drawing.Rectangle(($r.Right-(UiPixel 86)),($r.Y+(UiPixel 15)),(UiPixel 82),(UiPixel 24))
    [Windows.Forms.TextRenderer]::DrawText($g,$state,$small,$stateRect,$dot.Color,$flags)
    $small.Dispose();$large.Dispose();$dot.Dispose()
})
$removePhone.SetBounds(664,499,180,40);$removePhone.Text='Удалить телефон'
if($script:personalMode){$apkFolder.SetBounds(856,499,190,40);$apkFolder.Text='APK для телефона'}
else{$phoneName.SetBounds(664,549,160,28);$addPhone.SetBounds(836,545,210,36)}
$hint.Visible=$true;$hint.SetBounds(38,611,1026,50);$hint.ForeColor=$muted;$hint.Font=New-Object Drawing.Font('Segoe UI',10)
$detail.Visible=$true;$detail.SetBounds(38,674,1026,26);$detail.Text='Wi-Fi телефона  •  Шифрование WebRTC  •  Сервер передаёт только параметры связи';$detail.ForeColor=$muted;$detail.Font=New-Object Drawing.Font('Segoe UI',9)
$codeHeading.Visible=$false;$code.Visible=$false;$copy.Visible=$false
$appFile=Join-Path $script:profileDirectory 'applications.json'
. (Join-Path $PSScriptRoot 'desktop-applications.ps1')
if(Test-Path -LiteralPath $appFile){try{$script:appPaths=@(MergeApplicationPaths @() @([IO.File]::ReadAllText($appFile)|ConvertFrom-Json|ForEach-Object{$_}))}catch{}}
$mode.Add_SelectedIndexChanged({$chooseApps.Visible=$mode.SelectedIndex -eq 1;$appNote.Visible=$chooseApps.Visible;$start.Text=if($mode.SelectedIndex -eq 2){'Подключить прокси'}else{'Подключить VPN'};$appNote.Text="Приложений: $($script:appPaths.Count) · дочерние EXE автоматически";UpdateWindowLayout})
$chooseApps.Add_Click({ShowApplicationList})
$phoneList.Add_SelectedIndexChanged({if($phoneList.SelectedIndex -ge 0 -and !$script:client){$phone=$script:phoneRows[$phoneList.SelectedIndex];$hint.Text="Выбран $($phone.name) · $(CountryName $phone.country). Нажмите «Подключить VPN»."}})

# Native caption dragging retains Windows movement across monitors without
# introducing a system caption or bypassing the form's normal close cleanup.
if(!('PhoneExit.WindowChrome' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace PhoneExit {
    public static class WindowChrome {
        [DllImport("user32.dll")] public static extern bool ReleaseCapture();
        [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    }
}
'@
}
$dragCaption={param($sender,$mouseEvent)
    if($mouseEvent.Button -eq [Windows.Forms.MouseButtons]::Left){
        $null=[PhoneExit.WindowChrome]::ReleaseCapture()
        $null=[PhoneExit.WindowChrome]::SendMessage($form.Handle,0xA1,[IntPtr]2,[IntPtr]0)
    }
}
foreach($caption in @($title,$sub,$badge,$brandIcon)){$caption.Add_MouseDown($dragCaption)}
$form.Add_MouseDown({param($sender,$mouseEvent)
    if($mouseEvent.Y -lt (UiPixel 120) -and $mouseEvent.Button -eq [Windows.Forms.MouseButtons]::Left){
        $null=[PhoneExit.WindowChrome]::ReleaseCapture()
        $null=[PhoneExit.WindowChrome]::SendMessage($form.Handle,0xA1,[IntPtr]2,[IntPtr]0)
    }
})
$minimizeWindow=New-Object PhoneExit.CaptionButton;$minimizeWindow.Icon='minimize';$form.Controls.Add($minimizeWindow)
$maximizeWindow=New-Object PhoneExit.CaptionButton;$maximizeWindow.Icon='maximize';$form.Controls.Add($maximizeWindow)
$closeWindow=New-Object PhoneExit.CaptionButton;$closeWindow.Icon='close';$form.Controls.Add($closeWindow)
$captionTips=New-Object Windows.Forms.ToolTip
foreach($captionButton in @($minimizeWindow,$maximizeWindow,$closeWindow)){
    $captionButton.Height=34;$captionButton.FlatStyle='Flat';$captionButton.FlatAppearance.BorderSize=0
    $captionButton.BackColor=$form.BackColor;$captionButton.ForeColor=$form.ForeColor
    $captionButton.FlatAppearance.MouseOverBackColor=[Drawing.ColorTranslator]::FromHtml('#263144')
    $captionButton.Font=New-Object Drawing.Font('Segoe UI',18)
    $captionButton.Cursor='Hand'
}
$minimizeWindow.AccessibleName='Свернуть';$closeWindow.AccessibleName='Закрыть'
$maximizeWindow.AccessibleName='Развернуть';$captionTips.SetToolTip($maximizeWindow,'Развернуть / восстановить размер')
$captionTips.SetToolTip($minimizeWindow,'Свернуть');$captionTips.SetToolTip($closeWindow,'Закрыть')
$closeWindow.FlatAppearance.MouseOverBackColor=[Drawing.ColorTranslator]::FromHtml('#bc3547')
$minimizeWindow.Add_Click({$form.WindowState=[Windows.Forms.FormWindowState]::Minimized})
function ToggleWindowSize {if($form.WindowState -eq 'Maximized'){$form.WindowState='Normal'}else{$form.WindowState='Maximized'}}
$maximizeWindow.Add_Click({ToggleWindowSize})
foreach($caption in @($title,$sub,$badge,$brandIcon)){$caption.Add_DoubleClick({ToggleWindowSize})}
$closeWindow.Add_Click({$form.Close()})
$form.Add_FormClosed({$captionTips.Dispose()})

# Preserve the logical layout while painting text at native monitor resolution.
$form.MinimumSize=[Drawing.Size]::Empty;$form.MaximumSize=[Drawing.Size]::Empty
if($script:uiScale -ne 1){$form.Scale([Drawing.SizeF]::new($script:uiScale,$script:uiScale))}
$phoneList.ItemHeight=UiPixel 80
$form.MinimumSize=[Drawing.Size]::new((UiPixel 960),(UiPixel 700))
$form.MaximumSize=[Drawing.Size]::Empty
function PlaceControl($control,$x,$y,$width,$height){$control.SetBounds((UiPixel $x),(UiPixel $y),(UiPixel $width),(UiPixel $height))}
function UpdateWindowLayout {
    if($form.WindowState -eq 'Minimized'){return}
    $w=$form.ClientSize.Width/$script:uiScale;$h=$form.ClientSize.Height/$script:uiScale
    $leftWidth=[Math]::Round(($w-88)*0.577)
    $rightX=32+$leftWidth+24;$rightWidth=$w-$rightX-32;$paneHeight=$h-248
    $script:leftPane=[Drawing.RectangleF]::new(32,137,$leftWidth,$paneHeight)
    $script:rightPane=[Drawing.RectangleF]::new($rightX,137,$rightWidth,$paneHeight)
    $script:connectionOffset=[Math]::Round([Math]::Max(0,$paneHeight-452)/2)
    $padding=[Math]::Min(62,[Math]::Round($leftWidth*0.106));$innerX=32+$padding;$innerWidth=$leftWidth-2*$padding
    $buttonY=$h-201;$leftButtonY=if($mode.SelectedIndex -eq 1){510+$script:connectionOffset}else{451+$script:connectionOffset};$primaryWidth=[Math]::Round(($innerWidth-12)*0.61)
    $form.SuspendLayout()
    PlaceControl $badge ($w-350) 49 308 30
    PlaceControl $status 62 (319+$script:connectionOffset) ($leftWidth-60) 39
    PlaceControl $pingLabel $innerX (355+$script:connectionOffset) $innerWidth 22
    PlaceControl $mode $innerX (389+$script:connectionOffset) $innerWidth 34
    PlaceControl $chooseApps $innerX (433+$script:connectionOffset) $innerWidth 34
    PlaceControl $appNote $innerX (472+$script:connectionOffset) $innerWidth 27
    PlaceControl $start $innerX $leftButtonY $primaryWidth 52
    PlaceControl $stopButton ($innerX+$primaryWidth+12) $leftButtonY ($innerWidth-$primaryWidth-12) 52
    PlaceControl $heading ($rightX+24) 161 ($rightWidth-48) 35
    PlaceControl $phoneList ($rightX+22) 214 ($rightWidth-44) ($buttonY-241)
    $phoneList.ItemHeight=UiPixel ([Math]::Min(80,[Math]::Max(64,[Math]::Floor($phoneList.Height/($script:uiScale*4)))))
    $rightButtonWidth=[Math]::Floor(($rightWidth-60)/2)
    PlaceControl $removePhone ($rightX+24) ($buttonY+1) $rightButtonWidth 40
    if($script:personalMode){PlaceControl $apkFolder ($rightX+36+$rightButtonWidth) ($buttonY+1) $rightButtonWidth 40}
    else{PlaceControl $phoneName ($rightX+24) ($buttonY+51) $rightButtonWidth 28;PlaceControl $addPhone ($rightX+36+$rightButtonWidth) ($buttonY+47) $rightButtonWidth 36}
    PlaceControl $hint 38 ($h-104) ($w-76) 58
    PlaceControl $detail 38 ($h-46) ($w-270) 26
    PlaceControl $versionLabel ($w-208) ($h-46) 170 26
    PlaceControl $minimizeWindow ($w-152) 12 42 34
    PlaceControl $maximizeWindow ($w-106) 12 42 34
    PlaceControl $closeWindow ($w-60) 12 42 34
    $maximizeWindow.RestoredIcon=$form.WindowState -eq 'Maximized';$maximizeWindow.Invalidate()
    $form.ResumeLayout();$form.Invalidate()
}
$form.Add_ClientSizeChanged({UpdateWindowLayout})
UpdateWindowLayout
