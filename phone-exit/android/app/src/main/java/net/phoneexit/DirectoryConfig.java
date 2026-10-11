package net.phoneexit;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

final class DirectoryConfig {
    final String raw, id, name, token;
    final Pairing pairing;
    final PersonalAccount account;
    private DirectoryConfig(String raw, JSONObject value, Pairing pairing) throws Exception {
        this.raw=raw; this.pairing=pairing;
        id=value.getString("id"); name=value.getString("name"); token=pairing.token;
        account=PersonalAccount.parse(value.optJSONObject("account"));
        if(!id.matches("[0-9a-f]{32}")||name.isEmpty()||name.length()>40) throw new Exception("имя устройства");
    }
    static DirectoryConfig parse(String raw) throws Exception {
        if(raw==null||raw.length()>2048) throw new Exception("код привязки");
        JSONObject value=new JSONObject(raw);
        if(value.getInt("version")!=2||!"directory".equals(value.getString("mode"))) throw new Exception("версия привязки");
        Pairing pairing=Pairing.parse(new JSONObject().put("version",1).put("signal",value.getString("signal")).put("token",value.getString("token")).toString());
        return new DirectoryConfig(raw,value,pairing);
    }
    private static SecretKey key() throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore"); store.load(null);
        String alias="phone-exit-enrollment-v1";
        if(!store.containsAlias(alias)) {
            KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
            generator.generateKey();
        }
        return (SecretKey)store.getKey(alias,null);
    }
    void save(Context context) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE,key());
        String iv=Base64.encodeToString(cipher.getIV(),Base64.NO_WRAP);
        String data=Base64.encodeToString(cipher.doFinal(raw.getBytes(StandardCharsets.UTF_8)),Base64.NO_WRAP);
        if(!context.getSharedPreferences("enrollment",Context.MODE_PRIVATE).edit().putString("iv",iv).putString("data",data).commit()) throw new Exception("сохранение привязки");
    }
    static DirectoryConfig load(Context context) throws Exception {
        android.content.SharedPreferences prefs=context.getSharedPreferences("enrollment",Context.MODE_PRIVATE);
        if(!prefs.contains("data")) return null;
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,Base64.decode(prefs.getString("iv",""),Base64.NO_WRAP)));
        return parse(new String(cipher.doFinal(Base64.decode(prefs.getString("data",""),Base64.NO_WRAP)),StandardCharsets.UTF_8));
    }
    static void forget(Context context) { context.getSharedPreferences("enrollment",Context.MODE_PRIVATE).edit().clear().apply(); }
}
