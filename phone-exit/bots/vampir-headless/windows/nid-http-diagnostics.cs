using System;
using System.Collections.Generic;
using System.Web.Script.Serialization;

// Diagnostics only: never use this optional field to authorize an action or retry.
public static class NidHttpDiagnostics {
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
            foreach (string key in new[] { "errorCode", "code" }) {
                if (obj.TryGetValue(key, out value) && value is int) return (int)value;
            }
            object error;
            if (obj.TryGetValue("error", out error)) {
                var nested = error as Dictionary<string, object>;
                if (nested != null && nested.TryGetValue("code", out value) && value is int) return (int)value;
            }
        } catch { }
        return null;
    }
}
