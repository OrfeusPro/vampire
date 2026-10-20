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

    public static void Run(string startUrl, string gameCode, string dataDirectory, int timeoutSeconds, bool smoke, string accountHint,
            string signInScript, string emailJson, string passwordJson, int socksPort) {
        Callback = null; Status = "cancelled"; BlockedExternal = 0; BlockedPopups = 0; LastBlockedScheme = "";
        SignInStep = "manual";
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
            if (socksPort != 0) view.CreationProperties.AdditionalBrowserArguments =
                "--proxy-server=socks5://127.0.0.1:" + socksPort.ToString(System.Globalization.CultureInfo.InvariantCulture) + " --disable-quic";
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
                if (smoke) {
                    core.NavigateToString("<html><script>setTimeout(function(){window.open('probe-blocked://ignored'); location.href='probe-blocked://ignored'; setTimeout(function(){location.href='nm" + gameCode + "://nmidprovider/result?resultCode=0&accessToken=synthetic-token&refreshToken=&channelKey=mailUserKey&netmarbleId=synthetic-id&joinedCountryCode=KR';},200);},200);</script></html>");
                } else core.Navigate(startUrl);
            };
            var started = DateTime.UtcNow;
            timer.Interval = 200;
            timer.Tick += async (s, e) => {
                if ((DateTime.UtcNow - started).TotalSeconds >= timeoutSeconds) { finish("timeout"); return; }
                if (done || !autoSignIn || signInBusy || view.CoreWebView2 == null) return;
                Uri source;
                if (!Uri.TryCreate(view.CoreWebView2.Source, UriKind.Absolute, out source) || source.Scheme != "https" ||
                    source.Host != "members.netmarble.com" || !source.IsDefaultPort || source.UserInfo != "" ||
                    (source.AbsolutePath != "/auth/signin" && source.AbsolutePath != "/auth/signin/email")) return;
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
