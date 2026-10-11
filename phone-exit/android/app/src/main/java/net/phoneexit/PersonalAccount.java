package net.phoneexit;

import android.content.Context;
import android.util.Base64;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.json.*;

final class PersonalAccount {
    final JSONObject value;
    final String feedToken;
    final PublicKey publicKey;
    private PersonalAccount(JSONObject value) throws Exception {
        this.value=value;
        if(value.getInt("version")!=1) throw new Exception("account version");
        feedToken=value.getString("feedToken");
        if(!feedToken.matches("[0-9a-f]{64}")) throw new Exception("account key");
        Pairing.parse(new JSONObject().put("version",1).put("signal",value.getString("signal")).put("token",feedToken).toString());
        String encoded=value.getString("publicKey"); if(encoded.length()>256) throw new Exception("account public key");
        publicKey=KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.decode(encoded,Base64.NO_WRAP)));
        if(!(((java.security.interfaces.ECPublicKey)publicKey).getParams().getCurve().getField().getFieldSize()==256)) throw new Exception("account curve");
    }
    static PersonalAccount parse(JSONObject value) throws Exception { return value==null?null:new PersonalAccount(value); }
    static PersonalAccount asset(Context context) throws Exception {
        try(InputStream input=context.getAssets().open("phone-exit-account.json")) {
            ByteArrayOutputStream out=new ByteArrayOutputStream(); byte[] buf=new byte[1024]; int n;
            while((n=input.read(buf))!=-1) { if(out.size()+n>2048) throw new IOException("account size"); out.write(buf,0,n); }
            return parse(new JSONObject(out.toString("UTF-8")));
        } catch(FileNotFoundException e) { return null; }
    }
    static DirectoryConfig prepare(Context context,boolean force) throws Exception {
        PersonalAccount account=asset(context); if(account==null) return DirectoryConfig.load(context);
        if(!force&&context.getSharedPreferences("runtime",Context.MODE_PRIVATE).getBoolean("ignorePersonal",false)) return null;
        DirectoryConfig saved=DirectoryConfig.load(context);
        JSONObject phone=saved==null?new JSONObject().put("version",2).put("mode","directory")
            .put("signal",account.value.getString("signal")).put("id",randomHex(16)).put("token",randomHex(32))
            .put("name",(android.os.Build.MANUFACTURER+" "+android.os.Build.MODEL).trim().substring(0,Math.min(40,(android.os.Build.MANUFACTURER+" "+android.os.Build.MODEL).trim().length())))
            :new JSONObject(saved.raw);
        phone.put("account",account.value); saved=DirectoryConfig.parse(phone.toString()); saved.save(context);
        context.getSharedPreferences("runtime",Context.MODE_PRIVATE).edit().putBoolean("ignorePersonal",false).apply();
        return saved;
    }
    private static String randomHex(int count) {
        byte[] bytes=new byte[count]; new SecureRandom().nextBytes(bytes);
        StringBuilder out=new StringBuilder(); for(byte b:bytes) out.append(String.format(java.util.Locale.ROOT,"%02x",b&255)); return out.toString();
    }
    String roomKey(long bucket) throws Exception {
        byte[] key=new byte[32]; for(int i=0;i<32;i++) key[i]=(byte)Integer.parseInt(feedToken.substring(i*2,i*2+2),16);
        Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key,"HmacSHA256"));
        byte[] result=mac.doFinal(("phone-exit-registration-v1:"+bucket).getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder(); for(byte b:result) out.append(String.format(java.util.Locale.ROOT,"%02x",b&255)); return out.toString();
    }
    String catalogKey() throws Exception {
        byte[] key=new byte[32];for(int i=0;i<32;i++)key[i]=(byte)Integer.parseInt(feedToken.substring(i*2,i*2+2),16);
        Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key,"HmacSHA256"));
        byte[] result=mac.doFinal("phone-exit-catalog-v1".getBytes(StandardCharsets.UTF_8));
        StringBuilder hex=new StringBuilder();for(byte b:result)hex.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return hex.toString();
    }
    static JSONObject openRequest(String token,JSONObject box) throws Exception {
        String ivText=box.getString("iv"),dataText=box.getString("data");
        if(ivText.length()>32||dataText.length()>4096)throw new Exception("request size");
        byte[] iv=Base64.decode(ivText,Base64.NO_WRAP),data=Base64.decode(dataText,Base64.NO_WRAP);
        if(iv.length!=12||data.length<16)throw new Exception("request frame");
        MessageDigest hash=MessageDigest.getInstance("SHA-256");byte[] label="phone-exit-connect-v1".getBytes(StandardCharsets.UTF_8);hash.update(label);
        byte[] bytes=new byte[32];for(int i=0;i<32;i++)bytes[i]=(byte)Integer.parseInt(token.substring(i*2,i*2+2),16);hash.update(bytes);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(hash.digest(),"AES"),new GCMParameterSpec(128,iv));cipher.updateAAD(label);
        return new JSONObject(new String(cipher.doFinal(data),StandardCharsets.UTF_8));
    }
    JSONObject seal(JSONObject registration) throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("EC"); generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair=generator.generateKeyPair();
        KeyAgreement agreement=KeyAgreement.getInstance("ECDH"); agreement.init(pair.getPrivate()); agreement.doPhase(publicKey,true);
        byte[] key=MessageDigest.getInstance("SHA-256").digest(agreement.generateSecret());
        byte[] iv=new byte[12]; new SecureRandom().nextBytes(iv);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));
        cipher.updateAAD("phone-exit-registration-v1".getBytes(StandardCharsets.UTF_8));
        return new JSONObject().put("ephemeral",Base64.encodeToString(pair.getPublic().getEncoded(),Base64.NO_WRAP))
            .put("iv",Base64.encodeToString(iv,Base64.NO_WRAP))
            .put("data",Base64.encodeToString(cipher.doFinal(registration.toString().getBytes(StandardCharsets.UTF_8)),Base64.NO_WRAP));
    }
}
