$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadLine() | ConvertFrom-Json
$library = [string]$request.library
$env:PATH = $library + ';' + $env:PATH
Add-Type -AssemblyName System.Windows.Forms
Add-Type -Path (Join-Path $library 'Microsoft.Web.WebView2.Core.dll')
Add-Type -Path (Join-Path $library 'Microsoft.Web.WebView2.WinForms.dll')
Add-Type -Path (Join-Path $PSScriptRoot 'verification-browser.cs') -ReferencedAssemblies @(
    'System.Windows.Forms', 'System.Drawing', 'System.Web.Extensions',
    (Join-Path $library 'Microsoft.Web.WebView2.Core.dll'),
    (Join-Path $library 'Microsoft.Web.WebView2.WinForms.dll')
)
if ($request.compile_only) {
    [Console]::WriteLine('compiled')
    return
}
$script = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'verification-form.js') -Raw -Encoding UTF8
$result = [VerificationBrowser]::Run([string]$request.url, [string]$request.purpose, [string]$request.game_code,
    [string]$request.email, [string]$request.directory, [int]$request.port, $script, [bool]$request.manual_code)
[Console]::WriteLine($result)
