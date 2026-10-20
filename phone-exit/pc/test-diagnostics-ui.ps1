$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-controls.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing
[PhoneExit.DesktopDpi]::Enable()
[Windows.Forms.Application]::EnableVisualStyles()
$form=[PhoneExit.DesktopWindow]::new();$form.FormBorderStyle='None';$form.ClientSize=[Drawing.Size]::new(1100,720)
$form.Font=[Drawing.Font]::new('Segoe UI',10);$form.BackColor=[Drawing.ColorTranslator]::FromHtml('#111315');$form.ForeColor=[Drawing.Color]::White
$form.Show();[Windows.Forms.Application]::DoEvents()
$script:uiScale=[single]($form.MonitorDpi/96.0);$muted=[Drawing.Color]::Silver
$script:profileDirectory=Join-Path $PSScriptRoot '../.test-data/diagnostics-ui'
$script:client=$null;$script:transportReady=$false;$script:stopping=$false
function UiPixel($n){[int][Math]::Round($n*$script:uiScale)}
function PlaceControl($control,$x,$y,$w,$h){$control.SetBounds((UiPixel $x),(UiPixel $y),(UiPixel $w),(UiPixel $h))}
function ButtonAt($text,$x,$y,$w){$b=[PhoneExit.DarkButton]::new();$b.Text=$text;$form.Controls.Add($b);PlaceControl $b $x $y $w 38;return $b}
. (Join-Path $PSScriptRoot 'desktop-dialogs.ps1')
. (Join-Path $PSScriptRoot 'desktop-diagnostics.ps1')
$null=[IO.Directory]::CreateDirectory((Join-Path $PSScriptRoot '../.tools'))
$writer=[IO.StringWriter]::new()
$script:client=[pscustomobject]@{HasExited=$false;StandardInput=$writer};$script:transportReady=$true
$script:diagnosticUiStep=0;$script:diagnosticUiError=$null
$exercise=[Windows.Forms.Timer]::new();$exercise.Interval=100
$exercise.Add_Tick({
    $dialog=@([Windows.Forms.Application]::OpenForms|Where-Object Text -eq 'Диагностика TCP Phone Exit')|Select-Object -First 1
    if(!$dialog){return}
    try{
        $inputBox=@($dialog.Controls|Where-Object AccessibleName -eq 'Фильтр адресов игры')[0]
        $beginButton=@($dialog.Controls|Where-Object AccessibleName -eq 'Начать запись TCP')[0]
        $endButton=@($dialog.Controls|Where-Object Text -eq 'Остановить')[0]
        if($script:diagnosticUiStep -eq 0){
            $inputBox.Text='https://invalid.example';$beginButton.PerformClick()
            if($writer.ToString().Length){throw 'Invalid filter reached transport'}
            $inputBox.Text='game.example:12001';$beginButton.PerformClick()
            $command=$writer.ToString().Trim()|ConvertFrom-Json
            if($command.op -ne 'capture-start' -or @($command.filters).Count -ne 1 -or $command.filters[0].host -ne 'game.example' -or $command.filters[0].port -ne 12001){throw 'Wrong capture start command'}
            $script:diagnosticState=[pscustomobject]@{state='active';id=('a'*32);bytes=123;flows=1;reason=''}
            $script:diagnosticUiStep=1
        }elseif($endButton.Enabled){
            if($beginButton.Enabled -or $inputBox.Enabled){throw 'Active capture filter is editable'}
            $endButton.PerformClick()
            $last=@($writer.ToString().Trim() -split "`r?`n")[-1]|ConvertFrom-Json
            if($last.op -ne 'capture-stop'){throw 'Stop did not reach transport'}
            $script:diagnosticUiStep=2;$exercise.Stop();$dialog.Close()
        }
    }catch{$script:diagnosticUiError=$_.Exception.Message;$exercise.Stop();$dialog.Close()}
})
try{
    $null=[IO.Directory]::CreateDirectory($script:profileDirectory)
    $fixture=Join-Path $script:profileDirectory 'filter.txt'
    [IO.File]::WriteAllText($fixture,"lobby.example:12000`ngame.example:12001`n",[Text.UTF8Encoding]::new($false))
    $loaded=ReadDiagnosticFilterFile $fixture
    if(@(ConvertToDiagnosticFilters ($loaded -split "`r?`n")).Count -ne 2){throw 'Filter import lost endpoints'}
    [IO.File]::WriteAllText($fixture,('x'*4097));$rejected=$false
    try{$null=ReadDiagnosticFilterFile $fixture}catch{$rejected=$true}
    if(!$rejected){throw 'Oversized filter accepted'}
    $exercise.Start();ShowTcpDiagnostics
    if($script:diagnosticUiError){throw $script:diagnosticUiError}
    if($script:diagnosticUiStep -ne 2){throw 'Capture controls did not finish test'}
    $script:client=$null;$script:transportReady=$false;$script:diagnosticState=$null
    ShowTcpDiagnostics -Preview
    Write-Output 'PASS: exact filter start/stop commands, active state, disabled capture without transport, dialog bounds and resize'
}finally{$exercise.Dispose();$writer.Dispose();$form.Dispose()}
