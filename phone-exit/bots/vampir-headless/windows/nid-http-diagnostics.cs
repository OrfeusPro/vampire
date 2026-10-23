using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

// Diagnostics only: never use this optional field to authorize an action or retry.
public static class NidHttpDiagnostics {
    public sealed class Result {
        public int? Code;
        public string State;
        public string Hint = "unknown";
        public string Shape = "unknown";
    }
    public static bool IsEndpoint(string value, string method) {
        Uri uri;
        return method == "POST" && Uri.TryCreate(value, UriKind.Absolute, out uri) &&
            uri.Scheme == "https" && uri.Host == "members.netmarble.com" && uri.IsDefaultPort && uri.UserInfo == "";
    }

    public static int? ParseCode(string body) {
        if (body == null || body.Length > 16384) return null;
        try {
            var parser = new JavaScriptSerializer { MaxJsonLength = 16384, RecursionLimit = 16 };
            var obj = parser.DeserializeObject(body) as Dictionary<string, object>;
            if (obj == null) return null;
            object value;
            foreach (string key in new[] { "errorCode", "code", "resultCode" }) {
                if (obj.TryGetValue(key, out value)) {
                    int? parsed = IntegerCode(value);
                    if (parsed.HasValue) return parsed;
                }
            }
            object error;
            if (obj.TryGetValue("error", out error)) {
                var nested = error as Dictionary<string, object>;
                if (nested != null && nested.TryGetValue("code", out value)) return IntegerCode(value);
            }
        } catch { }
        return null;
    }

    private static int? IntegerCode(object value) {
        if (value is int) return (int)value;
        string text = value as string;
        int number;
        if (text != null && text.Length <= 11 && System.Text.RegularExpressions.Regex.IsMatch(text, "^-?(0|[1-9][0-9]{0,9})$") &&
            Int32.TryParse(text, System.Globalization.NumberStyles.AllowLeadingSign,
                System.Globalization.CultureInfo.InvariantCulture, out number)) return number;
        return null;
    }

    // Fixed labels only. Never return a provider string, identifier or body.
    // A hint is an optional observation, not an authentication decision.
    public static Result Describe(string body) {
        int? code = ParseCode(body);
        var result = new Result { Code = code, State = code.HasValue ? "numeric_code" : "no_numeric_code" };
        if (body == null || body.Length > 16384) return result;
        try {
            var parser = new JavaScriptSerializer { MaxJsonLength = 16384, RecursionLimit = 16 };
            var obj = parser.DeserializeObject(body) as Dictionary<string, object>;
            if (obj == null) { result.Shape = "not_object"; return result; }
            var messages = new List<string>();
            bool hasCode = false;
            foreach (string key in new[] { "errorCode", "code", "resultCode" }) {
                object value;
                if (obj.TryGetValue(key, out value)) {
                    hasCode = true;
                    AddText(messages, value);
                }
            }
            bool hasMessage = AddMessages(messages, obj);
            object error;
            bool nested = obj.TryGetValue("error", out error) && error is Dictionary<string, object>;
            if (nested) {
                var map = (Dictionary<string, object>)error;
                object value;
                if (map.TryGetValue("code", out value)) AddText(messages, value);
                AddMessages(messages, map);
            } else AddText(messages, error);
            result.Shape = code.HasValue ? "numeric_code" : nested ? "nested_error" :
                hasCode ? "nonnumeric_code" : hasMessage ? "message_only" : "unrecognized_object";
            string[] labels = { "invalid_credentials", "account_not_found", "rate_limited",
                "captcha_required", "device_confirmation", "region_restricted", "session_invalid" };
            string[] patterns = {
                @"invalid[ _-]*(credentials|password)|incorrect password|wrong password|email or password|username or password|password mismatch",
                @"account not found|email (is )?not registered|account[ _-]*not[ _-]*found",
                @"too[ _-]*many|rate[ _-]*limit|try again later|temporarily locked",
                @"captcha",
                @"device verification|verify (your |the )?device|device confirmation",
                @"not allowed country|region (is )?not supported",
                @"session expired|invalid session|invalid signature|invalid nonce|expired token"
            };
            var matches = new HashSet<string>();
            foreach (string text in messages)
                for (int i = 0; i < labels.Length; i++)
                    if (System.Text.RegularExpressions.Regex.IsMatch(text, patterns[i],
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
                        matches.Add(labels[i]);
            if (matches.Count == 1) foreach (string label in matches) result.Hint = label;
        } catch { result.Shape = "invalid_json"; }
        return result;
    }

    private static void AddText(List<string> target, object value) {
        string text = value as string;
        if (text != null && text.Length <= 1024) target.Add(text);
    }

    private static bool AddMessages(List<string> target, Dictionary<string, object> obj) {
        bool found = false;
        foreach (string key in new[] { "message", "errorMessage", "error_description", "description" }) {
            object value;
            if (obj.TryGetValue(key, out value)) { found = true; AddText(target, value); }
        }
        return found;
    }

    public static Task<Result> ReadAsync(Stream stream, int? length) {
        // Keep blocking COM stream reads off the UI thread.
        return Task.Run(() => Read(stream, length));
    }

    private static Result Read(Stream stream, int? length) {
        if (length.HasValue && (length.Value < 0 || length.Value > 16384)) return new Result { State = "length_limit" };
        byte[] buffer = new byte[16385];
        byte[] chunk = new byte[4096];
        try {
            int total = 0, read;
            // WebView2 COMStreamWrapper.Read rejects a nonzero buffer offset.
            // Always read at zero, then append into the bounded result buffer.
            while (total < buffer.Length && (read = stream.Read(chunk, 0, Math.Min(chunk.Length, buffer.Length - total))) > 0) {
                Buffer.BlockCopy(chunk, 0, buffer, total, read);
                total += read;
            }
            if (total > 16384) return new Result { State = "body_limit" };
            if (length.HasValue && total != length.Value) return new Result { State = "length_mismatch" };
            string body = new System.Text.UTF8Encoding(false, true).GetString(buffer, 0, total);
            Result result = Describe(body);
            body = null;
            return result;
        } catch (System.Text.DecoderFallbackException) { return new Result { State = "invalid_utf8" }; }
        catch { return new Result { State = "read_failed" }; }
        finally { Array.Clear(buffer, 0, buffer.Length); Array.Clear(chunk, 0, chunk.Length); }
    }
}
