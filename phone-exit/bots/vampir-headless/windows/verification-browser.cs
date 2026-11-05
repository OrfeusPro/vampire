using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

public static class VerificationBrowser {
    const string Host = "profile-auth-view.netmarble.com";
    const string Mail = "/api/v2/notification/email";

    static Uri Trusted(string url) {
        Uri uri;
        return Uri.TryCreate(url, UriKind.Absolute, out uri) && uri.Scheme == "https" &&
            uri.Host == Host && uri.IsDefaultPort && uri.UserInfo == "" ? uri : null;
    }

    static bool Accepted(Dictionary<string, object> body) {
        object value;
        bool known = false;
        if (body.TryGetValue("errorCode", out value)) {
            if (!(value is int) || (int)value != 0) return false;
            known = true;
        }
        if (body.TryGetValue("resultCode", out value)) {
            if (!(value is int) || (int)value != 200) return false;
            known = true;
        }
        return known;
    }

    static async Task<Dictionary<string, object>> Response(CoreWebView2WebResourceResponseView response) {
        if (response.StatusCode < 200 || response.StatusCode >= 300) return null;
        using (var stream = await response.GetContentAsync()) {
            if (stream == null) return null;
            return await Task.Run(() => {
                var bytes = new byte[16385];
                var chunk = new byte[4096];
                int used = 0, read;
                try {
                    // The WebView2 COM stream accepts reads only at offset zero.
                    while (used < bytes.Length &&
                            (read = stream.Read(chunk, 0, Math.Min(chunk.Length, bytes.Length - used))) > 0) {
                        Buffer.BlockCopy(chunk, 0, bytes, used, read);
                        used += read;
                    }
                    if (used == bytes.Length) return null;
                    var json = new JavaScriptSerializer { MaxJsonLength = 16384, RecursionLimit = 12 };
                    return json.Deserialize<Dictionary<string, object>>(new UTF8Encoding(false, true).GetString(bytes, 0, used));
                } finally {
                    Array.Clear(bytes, 0, bytes.Length);
                    Array.Clear(chunk, 0, chunk.Length);
                }
            });
        }
    }

    public static string Run(string url, string purpose, string game, string email, string directory, int port, string script) {
        bool device = purpose == "device-registration";
        string root = device ? "/secure/device" : "/restriction";
        string callback = "nm" + game + "://nmwebview/" + (device ?
            "device-registration?ExecutionType=register&IsConnected=true" : "restriction?ExecutionType=success");
        string completePath = device ? "/api/v2/secure/device" : "/api/v2/restriction/workplace/release/email";
        Uri initial = Trusted(url);
        if ((!device && purpose != "workplace") || initial == null || initial.AbsolutePath != root ||
            initial.Fragment != "" || game != "thered" || port < 0 || port > 65535) return "invalid_context";

        Application.EnableVisualStyles();
        using (var form = new Form())
        using (var view = new WebView2())
        using (var timer = new Timer()) {
            form.Text = "Vampir · " + (device ? "регистрация устройства" : "защита аккаунта");
            form.Width = 1040;
            form.Height = 760;
            form.StartPosition = FormStartPosition.CenterScreen;
            view.Dock = DockStyle.Fill;
            view.CreationProperties = new CoreWebView2CreationProperties {
                UserDataFolder = directory, IsInPrivateModeEnabled = true,
                AdditionalBrowserArguments = port == 0 ? "--no-proxy-server --disable-quic" :
                    "--proxy-server=socks5://127.0.0.1:" + port + " --disable-quic"
            };
            form.Controls.Add(view);
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var actions = new HashSet<string>();
            var json = new JavaScriptSerializer();
            string result = "cancelled", code = "";
            bool done = false, busy = false, sent = false, mutation = false, success = false;
            int mailReplies = 0;
            Task<string> codeRead = null;
            Action<string> finish = status => {
                if (done) return;
                done = true;
                result = status;
                form.Close();
            };
            Action<string> external = target => {
                Uri current = Trusted(view.CoreWebView2.Source);
                if (current == null || !current.AbsolutePath.StartsWith(root + "/", StringComparison.Ordinal)) return;
                if (String.Equals(target, callback, StringComparison.Ordinal)) {
                    success = true;
                    if (mutation) finish("verified");
                }
            };
            view.CoreWebView2InitializationCompleted += (sender, args) => {
                if (!args.IsSuccess) { finish("browser_failed"); return; }
                var core = view.CoreWebView2;
                core.Settings.AreDevToolsEnabled = false;
                core.Settings.AreDefaultContextMenusEnabled = false;
                core.Settings.IsPasswordAutosaveEnabled = false;
                core.Settings.IsGeneralAutofillEnabled = false;
                core.Settings.IsWebMessageEnabled = false;
                core.NavigationStarting += (s, e) => {
                    Uri next = Trusted(e.Uri);
                    if (next != null && (next.AbsolutePath == root ||
                            next.AbsolutePath.StartsWith(root + "/", StringComparison.Ordinal))) return;
                    e.Cancel = true;
                    external(e.Uri);
                };
                core.LaunchingExternalUriScheme += (s, e) => { e.Cancel = true; external(e.Uri); };
                core.NewWindowRequested += (s, e) => { e.Handled = true; };
                core.DownloadStarting += (s, e) => { e.Cancel = true; };
                core.PermissionRequested += (s, e) => { e.State = CoreWebView2PermissionState.Deny; };
                core.ServerCertificateErrorDetected += (s, e) => { e.Action = CoreWebView2ServerCertificateErrorAction.Cancel; };
                core.ProcessFailed += (s, e) => finish("browser_failed");
                core.WebResourceResponseReceived += async (s, e) => {
                    Uri request = Trusted(e.Request.Uri);
                    if (done || request == null || e.Request.Method != "POST") return;
                    string path = request.AbsolutePath;
                    if (path != Mail && path != Mail + "/verify" && path != completePath) return;
                    if (path == Mail && ++mailReplies != 1) { finish("multiple_mail_requests"); return; }
                    try {
                        var body = await Response(e.Response);
                        if (done) return;
                        if (body == null || !Accepted(body)) { finish("server_rejected"); return; }
                        if (path == Mail) {
                            sent = true;
                            actions.Add("mail_requested");
                            Console.WriteLine("mail_sent");
                            Console.Out.Flush();
                            codeRead = Task.Factory.StartNew(() => Console.In.ReadLine());
                        } else if (path == completePath) {
                            mutation = true;
                            if (success) finish("verified");
                        }
                    } catch { if (!done) finish("response_unknown"); }
                };
                core.Navigate(url);
            };
            timer.Interval = 250;
            timer.Tick += async (s, e) => {
                if (clock.Elapsed.TotalSeconds >= 600) { finish("timeout"); return; }
                if (done || busy || view.CoreWebView2 == null || Trusted(view.CoreWebView2.Source) == null) return;
                if (codeRead != null && codeRead.IsCompleted) {
                    code = codeRead.Result;
                    codeRead = null;
                    if (code == null || !System.Text.RegularExpressions.Regex.IsMatch(code, "^[0-9]{5}$")) {
                        finish("mail_unavailable"); return;
                    }
                }
                busy = true;
                try {
                    string value = await view.CoreWebView2.ExecuteScriptAsync(script + "(" + json.Serialize(new {
                        purpose = purpose, email = email, code = sent ? code : "", actions = actions
                    }) + ")");
                    if (done || value == "null") return;
                    string action = json.Deserialize<string>(value);
                    if (action == "abnormal_pattern" || action == "captcha_required") { finish(action); return; }
                    if (action != "waiting") actions.Add(action);
                    if (action == "code_submitted") code = "";
                } catch { if (!done) finish("form_unknown"); }
                finally { busy = false; }
            };
            form.Shown += async (s, e) => {
                timer.Start();
                try { await view.EnsureCoreWebView2Async(); } catch { finish("browser_failed"); }
            };
            Application.Run(form);
            done = true;
            timer.Stop();
            return result;
        }
    }
}
