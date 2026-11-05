using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Script.Serialization;

// Official NID PCV2 external-browser return. No OS protocol registration or token logs.
public sealed class NidGoogleBridge : IDisposable {
    TcpListener listener;
    string path, host, expectedEmail;
    public Task<string> Response { get; private set; }
    public bool AccountMatched { get; private set; }

    public static string ExternalUrl(string target, string game) {
        Uri uri;
        if (!Uri.TryCreate(target, UriKind.Absolute, out uri) || uri.Scheme != "nm" + game ||
                uri.Host != "nmwebview" || uri.AbsolutePath != "/showExternalBrowser" ||
                uri.UserInfo != "" || uri.Fragment != "") return null;
        var query = HttpUtility.ParseQueryString(uri.Query);
        if (query.Count != 2 || query.GetValues("url") == null || query.GetValues("url").Length != 1 ||
                query.GetValues("callback") == null || query.GetValues("callback").Length != 1 ||
                query["callback"] != "onIDPResponse") return null;
        Uri next;
        if (!Uri.TryCreate(query["url"], UriKind.Absolute, out next) || next.Scheme != "https" ||
                next.Host != "members.netmarble.com" || !next.IsDefaultPort || next.UserInfo != "" ||
                next.AbsolutePath != "/auth/idp/start/external-browser/google" || next.Fragment != "") return null;
        var fields = HttpUtility.ParseQueryString(next.Query);
        if (fields["webViewType"] != "sdk" || String.IsNullOrEmpty(fields["clientId"]) ||
                fields["redirectUrl"] != null || String.IsNullOrEmpty(fields["encodedIdpUrl"])) return null;
        return next.AbsoluteUri;
    }

    public static bool MatchesGoogleAccount(string query, string expectedEmail) {
        try {
            if (query == null || query.Length > 32768) return false;
            var fields = HttpUtility.ParseQueryString(query);
            string token = fields["idToken"] ?? fields["googleIdToken"];
            if (String.IsNullOrEmpty(token)) return false;
            string[] parts = token.Split('.');
            if (parts.Length != 3 || parts[1].Length > 16384) return false;
            string value = parts[1].Replace('-', '+').Replace('_', '/');
            value += new string('=', (4 - value.Length % 4) % 4);
            var json = new JavaScriptSerializer { MaxJsonLength = 16384, RecursionLimit = 8 };
            var claims = json.Deserialize<Dictionary<string, object>>(new UTF8Encoding(false, true).GetString(Convert.FromBase64String(value)));
            object email, issuer, verified, audience;
            return claims.TryGetValue("email", out email) && email is string &&
                String.Equals((string)email, expectedEmail, StringComparison.OrdinalIgnoreCase) &&
                claims.TryGetValue("iss", out issuer) && (Equals(issuer,"https://accounts.google.com") || Equals(issuer,"accounts.google.com")) &&
                claims.TryGetValue("email_verified", out verified) && (Equals(verified,true) || Equals(verified,"true")) &&
                claims.TryGetValue("aud", out audience) && audience is string && !String.IsNullOrEmpty((string)audience);
            // This binds the account only. NID /idp/google/token still verifies the ID token.
        } catch { return false; }
    }

    public void Start(string url, string email, Action<string> openBrowser = null) {
        if (listener != null) throw new InvalidOperationException("External sign-in already started");
        byte[] random = new byte[32];
        using (var generator = RandomNumberGenerator.Create()) generator.GetBytes(random);
        path = "/" + BitConverter.ToString(random).Replace("-", "").ToLowerInvariant() + "/";
        Array.Clear(random, 0, random.Length);
        expectedEmail = email;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(4);
        host = "127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
        Response = Receive();
        string redirect = "http://" + host + path;
        string external = url + "&redirectUrl=" + Uri.EscapeDataString(redirect);
        if (openBrowser == null) Process.Start(new ProcessStartInfo(external) { UseShellExecute = true });
        else openBrowser(external);
    }

    async Task<string> Receive() {
        while (listener != null) {
            using (var client = await listener.AcceptTcpClientAsync()) {
                client.ReceiveTimeout = 3000;
                using (var stream = client.GetStream()) {
                    var bytes = new byte[40960];
                    int used = 0;
                    try {
                        using (var limit = new System.Threading.CancellationTokenSource(3000)) {
                            while (used < bytes.Length) {
                                int count = await stream.ReadAsync(bytes, used, bytes.Length - used, limit.Token);
                                if (count == 0) break;
                                used += count;
                                if (Encoding.ASCII.GetString(bytes, 0, used).Contains("\r\n\r\n")) break;
                            }
                        }
                        string request = Encoding.ASCII.GetString(bytes, 0, used);
                        int lineEnd = request.IndexOf("\r\n", StringComparison.Ordinal);
                        bool valid = used < bytes.Length && lineEnd > 0 && lineEnd < 33000;
                        string query = null;
                        if (valid) {
                            string[] first = request.Substring(0,lineEnd).Split(' ');
                            valid = first.Length == 3 && first[0] == "GET" && first[2] == "HTTP/1.1" &&
                                first[1].StartsWith(path + "?",StringComparison.Ordinal) &&
                                request.IndexOf("\r\nHost: " + host + "\r\n",StringComparison.OrdinalIgnoreCase) >= 0;
                            if (valid) query = first[1].Substring(path.Length);
                        }
                        valid = valid && MatchesGoogleAccount(query, expectedEmail);
                        byte[] reply = Encoding.ASCII.GetBytes("HTTP/1.1 " + (valid ? "200 OK" : "403 Forbidden") +
                            "\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n");
                        await stream.WriteAsync(reply, 0, reply.Length);
                        if (valid) { AccountMatched = true; return query.Substring(1); }
                    } catch (IOException) {} catch (OperationCanceledException) {}
                    finally { Array.Clear(bytes,0,bytes.Length); }
                }
            }
        }
        return null;
    }

    public void Dispose() {
        var owned = listener;
        listener = null;
        if (owned != null) owned.Stop();
        expectedEmail = null;
    }
}
