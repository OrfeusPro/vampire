using System;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

public static class NidBrowserHost {
    public static string Callback;
    public static string Status;
    public static int BlockedExternal;
    public static int BlockedPopups;
    public static string LastBlockedScheme;
    public static string SignInStep;
    public static int NidHttpStatus;
    public static int? NidErrorCode;
    public static string NidResponseState;

    public static void Run(string startUrl, string gameCode, string dataDirectory, int timeoutSeconds, bool smoke, string accountHint,
            string signInScript, string emailJson, string passwordJson, int socksPort, string registrationScript, string statusScript) {
        Callback = null; Status = "cancelled"; BlockedExternal = 0; BlockedPopups = 0; LastBlockedScheme = "";
        SignInStep = "manual";
        NidHttpStatus = 0; NidErrorCode = null;
        NidResponseState = "not_observed";
        if (socksPort != 0 && (socksPort < 1024 || socksPort > 65535)) throw new ArgumentException("Invalid SOCKS port");
        if (timeoutSeconds < 1 || timeoutSeconds > 900) throw new ArgumentException("Invalid timeout");
        if (String.IsNullOrEmpty(gameCode) || gameCode.Length > 64) throw new ArgumentException("Invalid game scope");
        foreach (char c in gameCode) if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-') throw new ArgumentException("Invalid game scope");
        Uri initial;
        if (!smoke && (!Uri.TryCreate(startUrl, UriKind.Absolute, out initial) || initial.Scheme != "https" ||
            initial.Host != "members.netmarble.com" || initial.AbsolutePath != "/auth" || initial.UserInfo != "" || !initial.IsDefaultPort))
            throw new ArgumentException("Invalid initial auth endpoint");

        Application.EnableVisualStyles();
        using (Form form = new Form())
        using (WebView2 view = new WebView2())
        using (Timer timer = new Timer()) {
            form.Text = "Vampir — вход в аккаунт Netmarble";
            form.Width = 1050; form.Height = 800; form.StartPosition = FormStartPosition.CenterScreen;
            view.Dock = DockStyle.Fill;
            view.CreationProperties = new CoreWebView2CreationProperties { UserDataFolder = dataDirectory, IsInPrivateModeEnabled = true };
            view.CreationProperties.AdditionalBrowserArguments = socksPort == 0
                ? "--no-proxy-server --disable-quic"
                : "--proxy-server=socks5://127.0.0.1:" + socksPort.ToString(System.Globalization.CultureInfo.InvariantCulture) + " --disable-quic";
            form.Controls.Add(view);
            if (!String.IsNullOrEmpty(accountHint)) {
                Label hint = new Label { Dock = DockStyle.Top, Height = 42, AutoEllipsis = true,
                    Padding = new Padding(10), Text = "Войдите в тестовый аккаунт: " + accountHint };
                form.Controls.Add(hint);
            }
            if (smoke) { form.ShowInTaskbar = false; form.Opacity = 0; }
            bool done = false;
            bool signInBusy = false, emailOpened = false, filled = false;
            bool autoSignIn = !smoke && passwordJson != "\"\"" && !String.IsNullOrEmpty(passwordJson);
            bool registering = !smoke && !String.IsNullOrEmpty(registrationScript);
            string registrationState = "{}", previousRegistrationResult = "";
            string verificationCode = "";
            int pendingDiagnostics = 0;
            DateTime? failureSeenAt = null;
            System.Threading.Tasks.Task<string> codeRead = null;
            if (autoSignIn) SignInStep = "waiting";
            Action<string> finish = status => { if (!done) { done = true; Status = status; form.Close(); } };
            Action<string> custom = uri => {
                BlockedExternal++;
                if (done || uri == null || uri.Length > 32768) return;
                Uri result;
                if (Uri.TryCreate(uri, UriKind.Absolute, out result)) LastBlockedScheme = result.Scheme;
                if (!Uri.TryCreate(uri, UriKind.Absolute, out result) || result.Scheme != "nm" + gameCode ||
                    result.Host != "nmidprovider" || result.AbsolutePath != "/result" || result.UserInfo != "" || result.Fragment != "") return;
                Uri source;
                bool trusted = smoke || (Uri.TryCreate(view.CoreWebView2.Source, UriKind.Absolute, out source) &&
                    source.Scheme == "https" && source.Host == "members.netmarble.com");
                if (!trusted) { finish("untrusted_callback_origin"); return; }
                Callback = uri;
                finish("callback");
            };
            view.CoreWebView2InitializationCompleted += (sender, args) => {
                if (!args.IsSuccess) { finish("browser_initialization_failed"); return; }
                var core = view.CoreWebView2;
                core.Settings.AreDevToolsEnabled = false;
                core.Settings.AreDefaultContextMenusEnabled = false;
                core.Settings.IsWebMessageEnabled = false;
                core.Settings.IsPasswordAutosaveEnabled = false;
                core.Settings.IsGeneralAutofillEnabled = false;
                const string smokeUrl = "https://members.netmarble.com/__phone_exit_smoke__";
                if (smoke) {
                    // Intercept every resource in this synthetic test: no network login.
                    core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
                    core.WebResourceRequested += (s, e) => {
                        byte[] body = System.Text.Encoding.UTF8.GetBytes("{\"errorCode\":321,\"message\":\"synthetic-private-text\"}");
                        e.Response = core.Environment.CreateWebResourceResponse(new System.IO.MemoryStream(body),
                            e.Request.Uri == smokeUrl ? 400 : 404, "Synthetic",
                            "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: " + body.Length);
                    };
                }
                core.NavigationStarting += (s, e) => {
                    Uri uri;
                    if (!Uri.TryCreate(e.Uri, UriKind.Absolute, out uri)) { e.Cancel = true; return; }
                    if (uri.Scheme != "https" && !(smoke && (uri.Scheme == "about" || uri.Scheme == "data"))) {
                        e.Cancel = true; custom(e.Uri);
                    }
                };
                core.FrameNavigationStarting += (s, e) => {
                    Uri uri;
                    if (!Uri.TryCreate(e.Uri, UriKind.Absolute, out uri) || (uri.Scheme != "https" && uri.Scheme != "about")) e.Cancel = true;
                };
                core.LaunchingExternalUriScheme += (s, e) => { e.Cancel = true; custom(e.Uri); };
                core.NewWindowRequested += (s, e) => { e.Handled = true; BlockedPopups++; };
                core.DownloadStarting += (s, e) => { e.Cancel = true; };
                core.PermissionRequested += (s, e) => { e.State = CoreWebView2PermissionState.Deny; };
                core.ServerCertificateErrorDetected += (s, e) => { e.Action = CoreWebView2ServerCertificateErrorAction.Cancel; };
                core.ProcessFailed += (s, e) => finish("browser_process_failed");
                core.WebResourceResponseReceived += async (s, e) => {
                    // No request body, headers, URL or response text is emitted.
                    if (done || registering || (smoke && e.Request.Uri != smokeUrl) ||
                        !NidHttpDiagnostics.IsEndpoint(e.Request.Uri, e.Request.Method)) return;
                    int status = e.Response.StatusCode;
                    if (status >= 400 && status <= 599) NidHttpStatus = status;
                    pendingDiagnostics++;
                    try {
                        if (!e.Response.Headers.Contains("Content-Type") ||
                            !e.Response.Headers.GetHeader("Content-Type").StartsWith("application/json", StringComparison.OrdinalIgnoreCase)) {
                            if (status >= 400) NidResponseState = "non_json";
                            return;
                        }
                        int? length = null;
                        if (e.Response.Headers.Contains("Content-Length")) {
                            int parsed;
                            if (!Int32.TryParse(e.Response.Headers.GetHeader("Content-Length"), out parsed) || parsed < 0 || parsed > 16384) {
                                if (status >= 400) NidResponseState = "length_limit";
                                return;
                            }
                            length = parsed;
                        }
                        using (var stream = await e.Response.GetContentAsync()) {
                            if (done) return;
                            if (stream == null) {
                                if (status >= 400) NidResponseState = "content_unavailable";
                                return;
                            }
                            var observed = await NidHttpDiagnostics.ReadAsync(stream, length);
                            if (done) return;
                            if (status >= 400 || (observed.Code.HasValue && observed.Code.Value != 0)) NidResponseState = observed.State;
                            if (observed.Code.HasValue && observed.Code.Value != 0) { NidHttpStatus = status; NidErrorCode = observed.Code; }
                        }
                    } catch { if (!done && status >= 400) NidResponseState = "response_observation_failed"; }
                    finally { pendingDiagnostics--; }
                };
                if (smoke) {
                    core.NavigateToString("<html><script>setTimeout(function(){window.open('probe-blocked://ignored'); location.href='probe-blocked://ignored'; fetch('" + smokeUrl + "',{method:'POST'}).then(function(){setTimeout(function(){location.href='nm" + gameCode + "://nmidprovider/result?resultCode=0&accessToken=synthetic-token&refreshToken=&channelKey=mailUserKey&netmarbleId=synthetic-id&joinedCountryCode=KR';},1000);});},200);</script></html>");
                } else core.Navigate(startUrl);
            };
            var started = DateTime.UtcNow;
            timer.Interval = 200;
            timer.Tick += async (s, e) => {
                if ((DateTime.UtcNow - started).TotalSeconds >= timeoutSeconds) { finish("timeout"); return; }
                if (done || smoke || signInBusy || view.CoreWebView2 == null) return;
                Uri source;
                if (!Uri.TryCreate(view.CoreWebView2.Source, UriKind.Absolute, out source) || source.Scheme != "https" ||
                    source.Host != "members.netmarble.com" || !source.IsDefaultPort || source.UserInfo != "") return;
                if (!registering) {
                    signInBusy = true;
                    try {
                        string pageStatus = await view.CoreWebView2.ExecuteScriptAsync(statusScript + "()");
                        if (pageStatus == "\"login_failed\"") {
                            if (!failureSeenAt.HasValue) failureSeenAt = DateTime.UtcNow;
                            // Let a pending bounded response inspection finish; never wait indefinitely.
                            if (pendingDiagnostics > 0 && (DateTime.UtcNow - failureSeenAt.Value).TotalMilliseconds < 1500) return;
                            finish("login_failed"); return;
                        }
                    } catch { /* Optional observation does not change authentication. */ }
                    finally { signInBusy = false; }
                }
                if (done || !autoSignIn) return;
                if (registering) {
                    signInBusy = true;
                    try {
                        if (codeRead != null && codeRead.IsCompleted) {
                            string code = codeRead.Result;
                            if (code == null || code.Length != 5 || !System.Text.RegularExpressions.Regex.IsMatch(code, "^[0-9]{5}$")) {
                                finish("invalid_verification_input"); return;
                            }
                            verificationCode = code;
                            codeRead = null;
                        }
                        string registrationResult = await view.CoreWebView2.ExecuteScriptAsync(registrationScript +
                            "({email:" + emailJson + ",password:" + passwordJson + ",code:'" + verificationCode +
                            "',state:" + registrationState + "})");
                        if (done) return;
                        if (registrationResult != "null" && registrationResult != previousRegistrationResult) {
                            previousRegistrationResult = registrationResult;
                            Console.Out.WriteLine("{\"registration\":" + registrationResult + "}");
                            Console.Out.Flush();
                        }
                        // The script returns only bounded state flags and UI labels, never values.
                        registrationState = registrationResult == "null" ? "{}" : registrationResult;
                        if (registrationResult.Contains("\"need_code\":true") && codeRead == null && verificationCode == "")
                            codeRead = System.Threading.Tasks.Task.Factory.StartNew<string>(() => Console.In.ReadLine());
                        if (registrationResult.Contains("\"complete\":true")) {
                            registering = false; view.CoreWebView2.Navigate(startUrl);
                        }
                        if (registrationResult.Contains("\"stopped\":")) finish("registration_stopped");
                    } catch { finish("registration_script_failed"); }
                    finally { signInBusy = false; }
                    return;
                }
                if (source.AbsolutePath != "/auth/signin" && source.AbsolutePath != "/auth/signin/email") return;
                signInBusy = true;
                try {
                    string script = signInScript + "({\"email\":" + emailJson + ",\"password\":" + passwordJson +
                        ",\"emailOpened\":" + (emailOpened ? "true" : "false") + ",\"filled\":" + (filled ? "true" : "false") + "})";
                    string result = await view.CoreWebView2.ExecuteScriptAsync(script);
                    script = null;
                    if (done) return;
                    if (result == "\"opened_email\"") { emailOpened = true; SignInStep = "opened_email"; }
                    else if (result == "\"filled\"") { filled = true; SignInStep = "filled"; }
                    else if (result == "\"submitted\"" || result == "\"form_changed\"") {
                        SignInStep = result == "\"submitted\"" ? "submitted" : "form_changed";
                        autoSignIn = false; passwordJson = null; emailJson = null;
                    }
                } catch { autoSignIn = false; passwordJson = null; emailJson = null; SignInStep = "script_failed"; }
                finally { signInBusy = false; }
            };
            form.Shown += async (s, e) => { timer.Start(); try { await view.EnsureCoreWebView2Async(); } catch { finish("browser_initialization_failed"); } };
            Application.Run(form);
            timer.Stop();
        }
    }
}
