package net.phoneexit;

import java.net.URL;
import org.json.JSONObject;

final class Pairing {
    final URL endpoint; final String token;
    private Pairing(URL endpoint,String token) { this.endpoint = endpoint; this.token = token; }
    static Pairing parse(String raw) throws Exception {
        if (raw.length() > 2048) throw new Exception("слишком длинный");
        JSONObject value = new JSONObject(raw);
        if (value.getInt("version") != 1) throw new Exception("версия");
        String token = value.getString("token");
        if (!token.matches("[0-9a-f]{64}")) throw new Exception("ключ");
        URL url = new URL(value.getString("signal"));
        // First build talks only to the previously verified hosting endpoint.
        if (!url.getProtocol().equals("https") || !url.getHost().equals("demochko.com") || url.getPort() != -1 ||
            !(url.getPath().equals("/hosting-webrtc-probe/signal.php") || url.getPath().equals("/phone-exit/signal.php")) || url.getUserInfo() != null || url.getQuery() != null || url.getRef() != null)
            throw new Exception("неподдерживаемый сервер сигнализации");
        return new Pairing(url,token);
    }
}
