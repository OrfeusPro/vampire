package net.phoneexit;

import android.content.Context;
import android.net.Network;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import org.json.*;

/** Private per-device presence and connection requests over the existing bounded PHP signal. */
final class DirectoryAgent implements AutoCloseable {
    final Network wifi;
    private final Context context;
    private final DirectoryConfig config;
    private final Runnable retryWifi;
    private final ScheduledExecutorService loop=Executors.newSingleThreadScheduledExecutor();
    private final Map<String,Integer> cursors=new HashMap<>();
    private final Set<String> requests=new LinkedHashSet<>();
    private volatile boolean closed;
    private volatile ExitEngine engine;
    private volatile ControlAgent control;
    private boolean directWasOpen;
    private String country="";
    private long lastPresence;
    private long nextAttempt;
    private int failures;
    DirectoryAgent(Context context,Network wifi,DirectoryConfig config,Runnable retryWifi) { this.context=context; this.wifi=wifi; this.config=config; this.retryWifi=retryWifi; }
    void start() {
        loop.execute(() -> {
            if(!WifiBinding.acquire(context,wifi,this)) {
                closed=true; loop.shutdown();
                ExitService.update("Ошибка: Android запретил Wi-Fi. Проверьте активный VPN или AdGuard.");
                retryWifi.run(); return;
            }
            country=country(); synchronized(this){if(!closed) { waiting(); control=new ControlAgent(context,wifi,config);control.start(); }}
        });
        try { loop.scheduleWithFixedDelay(this::tick,0,3,TimeUnit.SECONDS); } catch(RejectedExecutionException ignored) {}
    }
    private void waiting() {
        if(control!=null&&control.directConnected())ExitService.update("Прямое управление подключено"+(failures>0?" · каталог временно недоступен":""));
        else if(failures>0)ExitService.update("Каталог недоступен · ожидаю восстановления");
        else ExitService.update("Доступен для своего ПК · "+config.name+" · "+(country.isEmpty()?"страна неизвестна":country));
    }
    private String country() {
        HttpsURLConnection connection=null;
        try {
            connection=(HttpsURLConnection)wifi.openConnection(new URL("https://www.cloudflare.com/cdn-cgi/trace"));
            connection.setInstanceFollowRedirects(false); connection.setConnectTimeout(8000); connection.setReadTimeout(8000);
            if(connection.getResponseCode()!=200) return "";
            String body=read(connection,8192);
            for(String line:body.split("\n")) if(line.matches("loc=[A-Z]{2}")) return line.substring(4);
        } catch(Exception ignored) {} finally { if(connection!=null) connection.disconnect(); }
        return "";
    }
    private static String read(HttpsURLConnection connection,int limit) throws Exception {
        ByteArrayOutputStream result=new ByteArrayOutputStream();
        try(InputStream input=connection.getInputStream()) {
            byte[] buffer=new byte[4096]; int n;
            while((n=input.read(buffer))!=-1) { if(result.size()+n>limit) throw new IOException("response size"); result.write(buffer,0,n); }
        }
        return result.toString("UTF-8");
    }
    static String roomKey(String key,long bucket) throws Exception {
        byte[] bytes=new byte[32];
        for(int i=0;i<32;i++) bytes[i]=(byte)Integer.parseInt(key.substring(i*2,i*2+2),16);
        Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(bytes,"HmacSHA256"));
        byte[] result=mac.doFinal(("phone-exit-directory-v1:"+bucket).getBytes(StandardCharsets.UTF_8));
        StringBuilder hex=new StringBuilder(); for(byte b:result) hex.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return hex.toString();
    }
    private JSONObject api(String key,String op,JSONObject message) throws Exception {
        HttpsURLConnection connection=(HttpsURLConnection)wifi.openConnection(config.pairing.endpoint);
        connection.setInstanceFollowRedirects(false); connection.setRequestMethod("POST");
        connection.setConnectTimeout(8000); connection.setReadTimeout(8000); connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type","application/json");
        byte[] body=ExitEngine.json("token",key,"role","phone","op",op,"after",cursors.getOrDefault(key,0),"message",message==null?JSONObject.NULL:message).toString().getBytes(StandardCharsets.UTF_8);
        connection.setFixedLengthStreamingMode(body.length);
        try {
            try(OutputStream output=connection.getOutputStream()) { output.write(body); }
            if(connection.getResponseCode()!=200) throw new IOException("directory HTTP");
            return new JSONObject(read(connection,262144));
        } finally { connection.disconnect(); }
    }
    private void tick() {
        if(closed) return;
        boolean directOpen=control!=null&&control.directConnected();
        if(engine==null&&directOpen!=directWasOpen){directWasOpen=directOpen;waiting();}
        if(System.nanoTime()<nextAttempt) return;
        long now=System.currentTimeMillis(), bucket=now/300000;
        try {
            if(config.account!=null){catalogTick(now);boolean recovered=failures>0;failures=0;nextAttempt=0;if(recovered&&engine==null)waiting();return;}
            String current=roomKey(config.token,bucket), previous=roomKey(config.token,bucket-1);
            if(now-lastPresence>=15000) {
                api(current,"send",ExitEngine.json("type","candidate","value",ExitEngine.json("directory",1,"type","presence","at",now,"country",country,"busy",engine!=null)));
                if(config.account!=null) {
                    JSONObject registration=ExitEngine.json("id",config.id,"name",config.name,"token",config.token,"at",now,"country",country,"busy",engine!=null);
                    api(config.account.roomKey(bucket),"send",ExitEngine.json("type","candidate","value",ExitEngine.json("directory",2,"type","register","box",config.account.seal(registration))));
                }
                lastPresence=now;
            }
            for(String key:Arrays.asList(previous,current)) {
                JSONArray messages=api(key,"poll",null).getJSONArray("messages");
                for(int i=0;i<messages.length();i++) {
                    JSONObject item=messages.getJSONObject(i), message=item.getJSONObject("message"), value=message.optJSONObject("value");
                    cursors.put(key,Math.max(cursors.getOrDefault(key,0),item.getInt("id")));
                    if(value==null||!"candidate".equals(message.optString("type"))||value.optInt("directory")!=1||!"connect".equals(value.optString("type"))) continue;
                    String request=value.optString("request");
                    long at=value.optLong("at",0);
                    if(!request.matches("[0-9a-f]{32}")||at<now-45000||at>now+45000||requests.contains(request)) continue;
                    requests.add(request); while(requests.size()>64) requests.remove(requests.iterator().next());
                    if(engine!=null) continue;
                    Pairing pairing=Pairing.parse(value.getJSONObject("pairing").toString());
                    synchronized(this) {
                        if(closed) return;
                        engine=new ExitEngine(context,wifi,pairing,ExitService::update,this::finished);
                        ExitService.update("Подключаю свой ПК · "+country); engine.start(); lastPresence=0;
                    }
                }
            }
            cursors.keySet().retainAll(new HashSet<>(Arrays.asList(previous,current)));
            boolean recovered=failures>0;failures=0;nextAttempt=0;if(recovered&&engine==null)waiting();
        } catch(Exception ignored) {
            failures=Math.min(failures+1,5);
            long delay=Math.min(30,1L<<failures);
            nextAttempt=System.nanoTime()+TimeUnit.SECONDS.toNanos(delay);
            if(!closed&&engine==null) waiting();
        }
    }
    private void catalogTick(long now) throws Exception {
        if(now-lastPresence<15000)return;
        JSONObject registration=ExitEngine.json("id",config.id,"name",config.name,"token",config.token,"at",now,"country",country,"busy",engine!=null);
        registration.put("signal","https://demochko.com/phone-exit/signal.php");
        registration.put("versionName",BuildConfig.VERSION_NAME).put("versionCode",BuildConfig.VERSION_CODE);
        registration.put("control",ControlAgent.capabilities(context)).put("update",AppUpdater.state(context));
        JSONObject body=ExitEngine.json("version",1,"token",config.account.catalogKey(),"op","pulse","id",config.id,"box",config.account.seal(registration));
        HttpsURLConnection connection=(HttpsURLConnection)wifi.openConnection(new URL("https://demochko.com/phone-exit/directory.php"));
        connection.setInstanceFollowRedirects(false);connection.setRequestMethod("POST");connection.setConnectTimeout(8000);connection.setReadTimeout(8000);connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type","application/json");byte[] encoded=body.toString().getBytes(StandardCharsets.UTF_8);connection.setFixedLengthStreamingMode(encoded.length);
        JSONObject response;
        try{try(OutputStream output=connection.getOutputStream()){output.write(encoded);}if(connection.getResponseCode()!=200)throw new IOException("catalog HTTP");response=new JSONObject(read(connection,8192));}
        finally{connection.disconnect();}
        lastPresence=now;
        JSONObject box=response.optJSONObject("request");if(box==null)return;
        JSONObject value;try{value=PersonalAccount.openRequest(config.token,box);}catch(Exception invalid){return;}
        long at=value.optLong("at",0);String request=value.optString("request");
        if(!request.matches("[0-9a-f]{32}")||Math.abs(at-now)>45000||requests.contains(request))return;
        requests.add(request);while(requests.size()>64)requests.remove(requests.iterator().next());if(engine!=null)return;
        Pairing pairing=Pairing.parse(value.getJSONObject("pairing").toString());
        synchronized(this){if(closed)return;engine=new ExitEngine(context,wifi,pairing,ExitService::update,this::finished);ExitService.update("Подключаю свой ПК · "+country);engine.start();lastPresence=0;}
    }
    private void finished() {
        if(closed) return;
        try { loop.execute(() -> {
            synchronized(this) { if(engine!=null) engine.close(); engine=null; lastPresence=0; if(!closed) waiting(); }
        }); }
        catch(RejectedExecutionException ignored) {}
    }
    @Override public synchronized void close() {
        closed=true; loop.shutdownNow();
        if(control!=null)control.close();control=null;
        if(engine!=null) engine.close(); engine=null;
        WifiBinding.release(context,this);
    }
}
