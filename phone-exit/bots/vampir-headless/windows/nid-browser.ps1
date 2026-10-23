$ErrorActionPreference = 'Stop'
# Request/response use anonymous stdin/stdout pipes. Never echo the request.
$requestText = [Console]::In.ReadLine()
$request = $requestText | ConvertFrom-Json
$requestText = $null
$library = [string]$request.library
$env:PATH = $library + ';' + $env:PATH
Add-Type -AssemblyName System.Windows.Forms
Add-Type -Path (Join-Path $library 'Microsoft.Web.WebView2.Core.dll')
Add-Type -Path (Join-Path $library 'Microsoft.Web.WebView2.WinForms.dll')
Add-Type -Path @((Join-Path $PSScriptRoot 'nid-browser.cs'), (Join-Path $PSScriptRoot 'nid-http-diagnostics.cs')) -ReferencedAssemblies @(
    'System.Windows.Forms', 'System.Drawing', 'System.Web.Extensions',
    (Join-Path $library 'Microsoft.Web.WebView2.Core.dll'),
    (Join-Path $library 'Microsoft.Web.WebView2.WinForms.dll')
)
try {
    $signInScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'nid-sign-in.js') -Raw -Encoding UTF8
    $statusScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'nid-page-status.js') -Raw -Encoding UTF8
    $registrationScript = ''
    if ($request.register_account) {
        $registrationScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'nid-register.js') -Raw -Encoding UTF8
    }
    $emailJson = ConvertTo-Json -InputObject ([string]$request.account_hint) -Compress
    $passwordJson = ConvertTo-Json -InputObject ([string]$request.sign_in_password) -Compress
    [NidBrowserHost]::Run([string]$request.url, [string]$request.game_code,
        [string]$request.data_directory, [int]$request.timeout, [bool]$request.smoke, [string]$request.account_hint,
        $signInScript, $emailJson, $passwordJson, [int]$request.socks_port, $registrationScript, $statusScript)
    @{status=[NidBrowserHost]::Status; callback=[NidBrowserHost]::Callback;
      blocked_external=[NidBrowserHost]::BlockedExternal; blocked_popups=[NidBrowserHost]::BlockedPopups;
      blocked_scheme=[NidBrowserHost]::LastBlockedScheme; sign_in_step=[NidBrowserHost]::SignInStep;
      nid_http_status=[NidBrowserHost]::NidHttpStatus; nid_error_code=[NidBrowserHost]::NidErrorCode;
      nid_response_state=[NidBrowserHost]::NidResponseState;
      nid_error_hint=[NidBrowserHost]::NidErrorHint; nid_response_shape=[NidBrowserHost]::NidResponseShape} |
        ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.Write($_) }
} finally {
    $request = $null
    $emailJson = $null
    $passwordJson = $null
    [NidBrowserHost]::Callback = $null
}
