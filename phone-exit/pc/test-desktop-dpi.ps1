$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
Add-Type -Path @((Join-Path $PSScriptRoot 'desktop-controls.cs'),(Join-Path $PSScriptRoot 'desktop-bots.cs')) -ReferencedAssemblies System.Windows.Forms,System.Drawing,System.Net.Http,System.Web.Extensions
[PhoneExit.DesktopDpi]::Enable()
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DpiTestNative {
 [DllImport("user32.dll")] public static extern IntPtr GetWindowDpiAwarenessContext(IntPtr h);
 [DllImport("user32.dll")] public static extern bool AreDpiAwarenessContextsEqual(IntPtr a,IntPtr b);
 [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,int m,IntPtr w,IntPtr l);
}
'@
foreach($type in @('PhoneExit.DesktopWindow','PhoneExit.BotWindow')) {
    $window=New-Object $type
    $other=New-Object PhoneExit.DesktopWindow
    try {
        $window.StartPosition='Manual';$window.Size=[Drawing.Size]::new(900,550)
        $window.MinimumSize=[Drawing.Size]::new(600,400)
        $label=[Windows.Forms.Label]::new();$label.Text='Phone Exit DPI';$label.Font=[Drawing.Font]::new('Segoe UI',12);$label.SetBounds(24,100,350,40);$window.Controls.Add($label)
        $window.Show();$other.Show();[Windows.Forms.Application]::DoEvents()
        if(![DpiTestNative]::AreDpiAwarenessContextsEqual([DpiTestNative]::GetWindowDpiAwarenessContext($window.Handle),[IntPtr](-4))){throw 'Window is not per-monitor-v2 aware'}
        $initial=$window.MonitorDpi;$originalFont=$label.Font.Size;$originalBounds=$label.Bounds;$originalMinimum=$window.MinimumSize;$otherDpi=$other.MonitorDpi
        for($cycle=0;$cycle -lt 5;$cycle++) {
            foreach($dpi in @(96,120,144,192,$initial)) {
                $factor=$dpi/[double]$initial
                $rect=[int[]]@(100,100,(100+[int](900*$factor)),(100+[int](550*$factor)))
                $ptr=[Runtime.InteropServices.Marshal]::AllocHGlobal(16)
                try {[Runtime.InteropServices.Marshal]::Copy($rect,0,$ptr,4);$null=[DpiTestNative]::SendMessage($window.Handle,0x2e0,[IntPtr]($dpi -bor ($dpi -shl 16)),$ptr)} finally {[Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)}
                if($window.MonitorDpi -ne $dpi -or [Math]::Abs($label.Font.Size-$originalFont*$factor) -gt .02){throw 'DPI or native font size did not change'}
                if($other.MonitorDpi -ne $otherDpi){throw 'DPI leaked into another window'}
                if($label.Right -gt $window.ClientSize.Width -or $label.Bottom -gt $window.ClientSize.Height){throw 'Label clipped after DPI change'}
            }
        }
        if([Math]::Abs($label.Width-$originalBounds.Width) -gt 3 -or [Math]::Abs($label.Left-$originalBounds.Left) -gt 3 -or [Math]::Abs($window.MinimumSize.Width-$originalMinimum.Width) -gt 3){throw 'Repeated DPI transitions accumulated layout drift'}
        Write-Output "PASS: $type PMv2; native WM_DPICHANGED 96/120/144/192; fonts, bounds and independent windows"
        foreach($screen in [Windows.Forms.Screen]::AllScreens) {
            $window.Location=[Drawing.Point]::new(($screen.WorkingArea.Left+40),($screen.WorkingArea.Top+40))
            [Windows.Forms.Application]::DoEvents()
            $nativeDpi=[PhoneExit.DesktopDpi]::WindowDpi($window)
            if($window.MonitorDpi -ne $nativeDpi){throw 'Moving between physical monitors did not update the window DPI'}
            $image=[Drawing.Bitmap]::new($window.Width,$window.Height)
            try {$window.DrawToBitmap($image,[Drawing.Rectangle]::new(0,0,$window.Width,$window.Height));$image.Save((Join-Path $PSScriptRoot "../.tools/dpi-$($window.GetType().Name)-$nativeDpi.png"))} finally {$image.Dispose()}
            Write-Output "PASS: physical monitor $($screen.Bounds.Width)x$($screen.Bounds.Height), DPI=$nativeDpi"
        }
    } finally {$window.Close();$window.Dispose();$other.Close();$other.Dispose()}
}
