package net.phoneexit;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.util.Base64;
import java.nio.charset.StandardCharsets;

/** Debug-only, protected by DUMP permission (ADB shell/system), not the launcher. */
public final class UsbTestActivity extends Activity {
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        try {
            String raw=new String(Base64.decode(getIntent().getStringExtra("testPairingBase64"),Base64.DEFAULT),StandardCharsets.UTF_8);
            if(new org.json.JSONObject(raw).optInt("version")==2) DirectoryConfig.parse(raw).save(this);
            else Pairing.parse(raw);
            startForegroundService(new Intent(this,ExitService.class).putExtra("pairing",raw));
        } catch(Exception e) { ExitService.update("Ошибка USB-сопряжения"); }
        startActivity(new Intent(this,MainActivity.class));
        finish();
    }
}
