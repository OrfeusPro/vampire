package net.phoneexit;

import android.content.*;
import android.net.*;
import android.os.*;
import android.util.Base64;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.HttpsURLConnection;
import org.json.*;

final class ControlAgent implements AutoCloseable {
    static final String ENDPOINT="https://demochko.com/hosting-webrtc-probe/phone-exit-api/control.php",LABEL="phone-exit-control-v1";
    final Context context;final Network wifi;final DirectoryConfig config;
    private final boolean updateOnly;
    private final ScheduledExecutorService loop=Executors.newSingleThreadScheduledExecutor();
    private volatile ControlPeer direct;private volatile boolean closed;private JSONObject pending;private String pendingId;private long pendingAt,nextPoll;private int failures;
    private org.webrtc.PeerConnectionFactory peerFactory;
    private volatile JSONObject lastConnectDiagnostic;
    ControlAgent(Context c,Network wifi,DirectoryConfig config){this(c,wifi,config,false);}
    ControlAgent(Context c,Network wifi,DirectoryConfig config,boolean updateOnly){this.context=c;this.wifi=wifi;this.config=config;this.updateOnly=updateOnly;}
    synchronized org.webrtc.PeerConnectionFactory peerFactory()throws Exception{
        if(closed)throw new Exception("wifi_lost");
        if(peerFactory==null){
            // Retain binding for the lifetime of this shared factory, including
            // the gaps between peers. Do not invalidate its network monitor.
            if(!WifiBinding.acquire(context,wifi,this))throw new Exception("wifi_binding_denied");
            WebRtcRuntime.initialize(context);
            org.webrtc.PeerConnectionFactory.Options options=new org.webrtc.PeerConnectionFactory.Options();
            // Keep Android's native network discovery enabled. Disabling it
            // passed USB tests but regressed remote ICE bootstrap in 0.7.2/3.
            options.disableNetworkMonitor=false;
            // Virtual phones can expose the selected Wi-Fi through a tun/virtual
            // adapter. Restrict egress by Network binding, not guessed adapter type.
            options.networkIgnoreMask=org.webrtc.PeerConnectionFactory.Options.ADAPTER_TYPE_LOOPBACK;
            peerFactory=org.webrtc.PeerConnectionFactory.builder().setOptions(options).createPeerConnectionFactory();
        }return peerFactory;
    }
    private synchronized void disposeFactory(){try{if(peerFactory!=null){peerFactory.dispose();peerFactory=null;}}finally{WifiBinding.release(context,this);}}
    void start(){if(config.account!=null)loop.scheduleWithFixedDelay(this::tick,0,1,TimeUnit.SECONDS);}
    static JSONObject capabilities(Context c)throws Exception{
        boolean su=false;for(String path:new String[]{"/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su","/system_ext/bin/su"})if(new File(path).exists())su=true;
        return new JSONObject().put("api",4).put("botApi",1).put("botDiagnostics",1).put("bot",BotStore.status(c)).put("directControl",true).put("enabled",ControlAccessibility.allowed(c)).put("accessibility",ControlAccessibility.current!=null).put("screenshot",Build.VERSION.SDK_INT>=30)
            .put("shell",false).put("forceStop",false).put("reboot",false).put("textInput",ControlAccessibility.current!=null).put("gesture",ControlAccessibility.current!=null)
            .put("androidSdk",Build.VERSION.SDK_INT).put("processUid",android.os.Process.myUid()).put("processRoot",android.os.Process.myUid()==0).put("rootGranted",JSONObject.NULL).put("suPresent",su).put("rootProbe","passive_only");
    }
    boolean directConnected(){ControlPeer p=direct;return p!=null&&p.open();}
    boolean active(){NetworkCapabilities caps=context.getSystemService(ConnectivityManager.class).getNetworkCapabilities(wifi);return !closed&&(updateOnly||ExitService.enabled(context))&&PeerDirectory.clientUplink(caps);}
    HttpsURLConnection connection(JSONObject body)throws Exception{
        HttpsURLConnection c=(HttpsURLConnection)new ExitNetwork(context,wifi).connection(new URL(ENDPOINT));c.setInstanceFollowRedirects(false);c.setRequestMethod("POST");c.setDoOutput(true);c.setConnectTimeout(8000);c.setReadTimeout(10000);c.setRequestProperty("Content-Type","application/json");
        body.put("version",1).put("token",config.account.catalogKey());byte[] bytes=body.toString().getBytes(StandardCharsets.UTF_8);c.setFixedLengthStreamingMode(bytes.length);try(OutputStream out=c.getOutputStream()){out.write(bytes);}return c;
    }
    JSONObject api(JSONObject body)throws Exception{HttpsURLConnection c=connection(body);try{if(c.getResponseCode()!=200)throw new IOException("control_http");return new JSONObject(read(c.getInputStream(),3000000));}finally{c.disconnect();}}
    static String read(InputStream input,int max)throws Exception{try(InputStream in=input;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1){if(out.size()+n>max)throw new IOException("response_limit");out.write(b,0,n);}return out.toString("UTF-8");}}
    static JSONObject crypt(String token,JSONObject value,boolean encrypt)throws Exception{
        byte[] label=LABEL.getBytes(StandardCharsets.UTF_8),bytes=new byte[32];for(int i=0;i<32;i++)bytes[i]=(byte)Integer.parseInt(token.substring(i*2,i*2+2),16);
        MessageDigest hash=MessageDigest.getInstance("SHA-256");hash.update(label);hash.update(bytes);
        byte[] iv;if(encrypt){iv=new byte[12];new SecureRandom().nextBytes(iv);}else{if(value.getString("iv").length()!=16||value.getString("data").length()>16384)throw new Exception("invalid_frame");iv=Base64.decode(value.getString("iv"),Base64.NO_WRAP);if(iv.length!=12)throw new Exception("invalid_frame");}
        Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(hash.digest(),"AES"),new GCMParameterSpec(128,iv));c.updateAAD(label);
        if(encrypt)return new JSONObject().put("iv",Base64.encodeToString(iv,Base64.NO_WRAP)).put("data",Base64.encodeToString(c.doFinal(value.toString().getBytes(StandardCharsets.UTF_8)),Base64.NO_WRAP));
        return new JSONObject(new String(c.doFinal(Base64.decode(value.getString("data"),Base64.NO_WRAP)),StandardCharsets.UTF_8));
    }
    private void tick(){
        if(!active()||System.currentTimeMillis()<nextPoll)return;
        try{
            if(pending!=null&&System.currentTimeMillis()-pendingAt>110000)pending=null;
            if(pending!=null){api(new JSONObject().put("op","result").put("id",config.id).put("request",pendingId).put("box",pending));pending=null;}
            JSONObject job=api(new JSONObject().put("op","poll").put("id",config.id)).optJSONObject("job");
            if(job!=null&&active()){
                JSONObject v=crypt(config.token,job.getJSONObject("box"),false);String request=v.getString("request");long at=v.getLong("at"),now=System.currentTimeMillis();
                if(!config.id.equals(v.optString("id"))||!request.equals(job.optString("request"))||!request.matches("[0-9a-f]{32}")||at<now-60000||at>now+45000)return;
                JSONObject result=process(v);
                pendingId=request;pendingAt=now;pending=crypt(config.token,result,true);
                if(active()){api(new JSONObject().put("op","result").put("id",config.id).put("request",request).put("box",pending));pending=null;}
            }
            failures=0;nextPoll=System.currentTimeMillis()+(direct!=null&&direct.open()?15000:4000);
        }catch(Exception ignored){failures=Math.min(5,failures+1);nextPoll=System.currentTimeMillis()+Math.min(30000,1000L<<failures);/* Never log payloads, screenshots or keys. */}
    }
    JSONObject process(JSONObject v)throws Exception{
        String request=v.getString("request");long now=System.currentTimeMillis(),at=v.getLong("at");
        if(!config.id.equals(v.optString("id"))||!request.matches("[0-9a-f]{32}")||at<now-60000||at>now+45000)throw new Exception("invalid_request");
        JSONObject result=new JSONObject().put("id",config.id).put("request",request).put("at",now);
        synchronized(this){
            android.content.SharedPreferences prefs=context.getSharedPreferences("control_seen",Context.MODE_PRIVATE);
            if(prefs.contains(request))return result.put("ok",false).put("error","already_delivered_unknown_outcome");
            android.content.SharedPreferences.Editor edit=prefs.edit();int retained=0;
            for(java.util.Map.Entry<String,?> e:prefs.getAll().entrySet())if(e.getValue() instanceof Long&&(Long)e.getValue()<now-180000)edit.remove(e.getKey());else retained++;
            if(retained>=4096)throw new IOException("dedup_limit");
            if(!edit.putLong(request,now).commit())throw new IOException("dedup_storage");
        }
        try{result.put("result",execute(v.getString("command"),v.optJSONObject("args"))).put("ok",true);}catch(Exception e){result.put("ok",false).put("error",safeError(e));if(v.optString("command").equals("connectControl")&&lastConnectDiagnostic!=null)result.put("diagnostics",lastConnectDiagnostic);}
        return result;
    }
    private JSONObject execute(String command,JSONObject args)throws Exception{
        if(!active())throw new Exception("wifi_lost");
        if(command.equals("connectControl")){
            lastConnectDiagnostic=null;
            if(!ControlAccessibility.allowed(context))throw new Exception("control_disabled");
            String offer=args.getString("sdp");if(offer.length()>11000||!offer.startsWith("v=0"))throw new Exception("invalid_offer");
            // Only retry an empty initial ICE answer. No DataChannel has been
            // handed to the caller and no control action can have run yet.
            for(int attempt=0;attempt<2;attempt++){
                ControlPeer old=direct;if(old!=null){old.close();old.awaitClosed();}
                ControlPeer created=new ControlPeer(this);direct=created;
                try{return created.connect(offer);}catch(Exception failure){
                    lastConnectDiagnostic=created.diagnostics().put("bootstrapAttempt",attempt+1);
                    if(attempt!=0||!"ice_no_candidates".equals(failure.getMessage()))throw failure;
                    created.close();created.awaitClosed();
                    // An empty answer can persist across peers of the same
                    // native network monitor. Reset it only after full cleanup.
                    disposeFactory();Thread.sleep(500);
                    if(!active())throw new Exception("wifi_lost");
                }
            }
            throw new Exception("ice_no_candidates");
        }
        if(command.equals("status"))return capabilities(context);
        if(command.equals("bot"))return BotManager.execute(this,args==null?new JSONObject():args);
        if(command.equals("checkUpdate")||command.equals("installUpdate")){AppUpdater.check(this);if(command.equals("installUpdate"))AppUpdater.notifyReady(context);return AppUpdater.state(context);}
        if(!ControlAccessibility.allowed(context))throw new Exception("control_disabled");
        if(command.equals("deviceInfo")){JSONObject info=DeviceControl.info(context);ControlPeer p=direct;if(p!=null)info.put("controlDiagnostics",p.diagnostics());return info;}
        if(command.equals("apps"))return DeviceControl.apps(context,args==null?new JSONObject():args);
        ControlAccessibility service=ControlAccessibility.current;if(service==null)throw new Exception("accessibility_permission_required");
        if(java.util.Arrays.asList("tap","swipe","longPress","gesture","back","home","launch","keyevent","inputText").contains(command))BotManager.manualPause(context);
        return service.execute(command,args==null?new JSONObject():args,this::active);
    }
    private String safeError(Exception e){String m=e.getMessage();return m!=null&&m.matches("[a-z0-9_]{1,80}")?m:"action_failed_or_timeout";}
    @Override public synchronized void close(){
        if(closed)return;closed=true;loop.shutdownNow();pending=null;ControlPeer old=direct;
        if(old!=null)old.close();
        ExecutorService cleanup=Executors.newSingleThreadExecutor();
        cleanup.execute(()->{try{if(old!=null)old.awaitClosed();disposeFactory();}catch(Exception ignored){/* Do not dispose a factory while an old peer can still use it. */}});cleanup.shutdown();
    }
}
