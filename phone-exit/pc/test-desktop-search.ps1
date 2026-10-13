$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
Add-Type -Path (Join-Path $PSScriptRoot 'desktop-controls.cs') -ReferencedAssemblies System.Windows.Forms,System.Drawing
[PhoneExit.DesktopDpi]::Enable()
$form=New-Object Windows.Forms.Form
$search=New-Object PhoneExit.SearchField
$form.Controls.Add($search)
$script:changes=0
$search.Add_TextChanged({$script:changes++})
try {
    $form.Show()
    $flags=[Reflection.BindingFlags]'Instance,NonPublic'
    $input=$search.GetType().GetField('input',$flags).GetValue($search)
    $clear=$search.GetType().GetField('clear',$flags).GetValue($search)
    foreach($scale in @(1.0,1.5)) {
        [PhoneExit.DesktopDpi]::Scale=$scale
        $search.SetBounds(10,10,[int](326*$scale),[int](34*$scale))
        $search.Text='Orfeus'
        [Windows.Forms.Application]::DoEvents()
        if($search.Height -ne [int](34*$scale) -or !$clear.Visible){throw 'Search height or clear state is incorrect'}
        if($input.Left -lt [int](30*$scale) -or $input.Right -gt $clear.Left){throw 'Search text overlaps its icons'}
        if([Math]::Abs(($input.Top+$input.Height/2)-$search.Height/2) -gt 1){throw 'Search text is not vertically centered'}
        $clear.PerformClick()
        if($search.Text -ne '' -or $clear.Visible){throw 'Clear button did not reset search'}
        $search.Text='missing'
        $input.GetType().GetMethod('OnKeyDown',$flags).Invoke($input,@([Windows.Forms.KeyEventArgs]::new('Escape')))
        if($search.Text -ne ''){throw 'Escape did not clear search'}
    }
    if($script:changes -ne 8){throw 'Search TextChanged was lost or duplicated'}
    'PASS: search sizes, vertical alignment, icon spacing, clear, Escape, TextChanged at 100%/150%'
} finally {$form.Dispose()}
