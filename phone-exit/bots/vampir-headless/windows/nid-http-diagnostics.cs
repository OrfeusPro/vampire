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
            int? code = ParseCode(body);
            body = null;
            return new Result { Code = code, State = code.HasValue ? "numeric_code" : "no_numeric_code" };
        } catch (System.Text.DecoderFallbackException) { return new Result { State = "invalid_utf8" }; }
        catch { return new Result { State = "read_failed" }; }
        finally { Array.Clear(buffer, 0, buffer.Length); Array.Clear(chunk, 0, chunk.Length); }
    }
}
