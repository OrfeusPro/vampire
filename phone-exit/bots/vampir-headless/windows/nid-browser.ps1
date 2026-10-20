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
    $signInScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'nid-sign-in.js') -Raw -Encoding UTF8
    $emailJson = ConvertTo-Json -InputObject ([string]$request.account_hint) -Compress
    $passwordJson = ConvertTo-Json -InputObject ([string]$request.sign_in_password) -Compress
    [NidBrowserHost]::Run([string]$request.url, [string]$request.game_code,
        [string]$request.data_directory, [int]$request.timeout, [bool]$request.smoke, [string]$request.account_hint,
        $signInScript, $emailJson, $passwordJson, [int]$request.socks_port)
    @{status=[NidBrowserHost]::Status; callback=[NidBrowserHost]::Callback;
      blocked_external=[NidBrowserHost]::BlockedExternal; blocked_popups=[NidBrowserHost]::BlockedPopups;
      blocked_scheme=[NidBrowserHost]::LastBlockedScheme; sign_in_step=[NidBrowserHost]::SignInStep} |
        ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.Write($_) }
} finally {
    $request = $null
    $emailJson = $null
    $passwordJson = $null
    [NidBrowserHost]::Callback = $null
}
