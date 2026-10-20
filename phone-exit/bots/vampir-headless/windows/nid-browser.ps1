$ErrorActionPreference = 'Stop'
# Request/response use anonymous stdin/stdout pipes. Never echo the request.
$requestText = [Console]::In.ReadToEnd()
$request = $requestText | ConvertFrom-Json
$requestText = $null
$library = [string]$request.library
$env:PATH = $library + ';' + $env:PATH
Add-Type -AssemblyName System.Windows.Forms
Add-Type -Path (Join-Path $library 'Microsoft.Web.WebView2.Core.dll')
Add-Type -Path (Join-Path $library 'Microsoft.Web.WebView2.WinForms.dll')
Add-Type -Path (Join-Path $PSScriptRoot 'nid-browser.cs') -ReferencedAssemblies @(
    'System.Windows.Forms', 'System.Drawing',
    (Join-Path $library 'Microsoft.Web.WebView2.Core.dll'),
    (Join-Path $library 'Microsoft.Web.WebView2.WinForms.dll')
)
try {
    [NidBrowserHost]::Run([string]$request.url, [string]$request.game_code,
        [string]$request.data_directory, [int]$request.timeout, [bool]$request.smoke, [string]$request.account_hint)
    @{status=[NidBrowserHost]::Status; callback=[NidBrowserHost]::Callback;
      blocked_external=[NidBrowserHost]::BlockedExternal; blocked_popups=[NidBrowserHost]::BlockedPopups;
      blocked_scheme=[NidBrowserHost]::LastBlockedScheme} |
        ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.Write($_) }
} finally {
    $request = $null
    [NidBrowserHost]::Callback = $null
}
