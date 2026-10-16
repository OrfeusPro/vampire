package net.phoneexit.fixture;

import android.app.Activity;
import android.os.Bundle;
import android.net.*;
import android.widget.TextView;
import org.json.*;
import java.net.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.HttpsURLConnection;

/** Separate UID: normal app traffic must enter the real VPN, with no proxy or Network binding. */
public final class NetworkProbeActivity extends Activity {
    private TextView output;
    private boolean netmarble;
    @Override public void onCreate(Bundle state){
        super.onCreate(state);getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        output=new TextView(this);output.setTextSize(18);output.setPadding(24,24,24,24);setContentView(output);
        String label=getIntent().getStringExtra("label");if(label==null||!label.matches("baseline|vpn|blocked|restored")){finish();return;}
        output.setText("Проверка сети: "+label);
        netmarble=getIntent().getBooleanExtra("netmarble",false);
        final String selected=label;new Thread(()->runProbe(selected),"NetworkProbe").start();
    }
    private void save(String label,JSONObject result){try(FileOutputStream out=openFileOutput("network-"+label+".json",MODE_PRIVATE)){out.write(result.toString().getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new IllegalStateException(e);}}
    private JSONObject https(){
        HttpsURLConnection c=null;try{
            c=(HttpsURLConnection)new URL("https://www.cloudflare.com/cdn-cgi/trace").openConnection(java.net.Proxy.NO_PROXY);
            c.setConnectTimeout(6000);c.setReadTimeout(6000);c.setUseCaches(false);c.setInstanceFollowRedirects(false);
            if(c.getResponseCode()!=200)throw new IOException();
            ByteArrayOutputStream data=new ByteArrayOutputStream();try(InputStream in=c.getInputStream()){byte[] b=new byte[1024];int n;while((n=in.read(b))!=-1){if(data.size()+n>8192)throw new IOException();data.write(b,0,n);}}
            String country="",ip="";for(String line:data.toString("UTF-8").split("\n")){if(line.startsWith("loc="))country=line.substring(4);if(line.startsWith("ip="))ip=line.substring(3);}
            if(ip.isEmpty())throw new IOException();byte[] hash=MessageDigest.getInstance("SHA-256").digest(ip.getBytes(StandardCharsets.US_ASCII));StringBuilder hex=new StringBuilder();for(byte b:hash)hex.append(String.format(Locale.ROOT,"%02x",b&255));
            return new JSONObject().put("ok",true).put("country",country).put("ipHash",hex.toString());
        }catch(Exception e){return error(e);}finally{if(c!=null)c.disconnect();}
    }
    private static JSONObject error(Exception e){try{return new JSONObject().put("ok",false).put("error",e.getClass().getSimpleName());}catch(JSONException ignored){throw new IllegalStateException();}}
    private JSONObject netmarble(int family){
        final String host="profile-auth-view.netmarble.com";
        try{
            Socket raw=new Socket();raw.setSoTimeout(6000);
            try{
                InetAddress selected=null;for(InetAddress address:InetAddress.getAllByName(host))if((family==4&&address instanceof Inet4Address)||(family==6&&address instanceof Inet6Address)){selected=address;break;}
                if(selected==null)return new JSONObject().put("available",false).put("family",family);
                raw.connect(new InetSocketAddress(selected,443),6000);
                try(javax.net.ssl.SSLSocket tls=(javax.net.ssl.SSLSocket)((javax.net.ssl.SSLSocketFactory)javax.net.ssl.SSLSocketFactory.getDefault()).createSocket(raw,host,443,true)){
                    tls.setSoTimeout(6000);javax.net.ssl.SSLParameters parameters=tls.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(parameters);tls.startHandshake();
                    tls.getOutputStream().write(("GET /restriction HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: Mozilla/5.0 (Linux; Android 12; wv) AppleWebKit/537.36 Version/4.0 Chrome/130.0.0.0 Mobile Safari/537.36\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    ByteArrayOutputStream line=new ByteArrayOutputStream();int b;while(line.size()<256&&(b=tls.getInputStream().read())!=-1&&b!='\n')line.write(b);
                    String status=line.toString("US-ASCII").trim();if(!status.matches("HTTP/1\\.[01] [1-5][0-9]{2}.*"))throw new IOException();
                    return new JSONObject().put("ok",true).put("family",family).put("http",Integer.parseInt(status.substring(9,12)));
                }
            }finally{raw.close();}
        }catch(Exception e){try{return error(e).put("family",family);}catch(JSONException ignored){throw new IllegalStateException();}}
    }
    private JSONObject netmarbleWebView(){
        CompletableFuture<JSONObject> done=new CompletableFuture<>();
        final android.webkit.WebView[] view=new android.webkit.WebView[1];
        runOnUiThread(()->{
            try{
                view[0]=new android.webkit.WebView(this);setContentView(view[0]);
                view[0].getSettings().setJavaScriptEnabled(true);
                view[0].getSettings().setCacheMode(android.webkit.WebSettings.LOAD_NO_CACHE);
                view[0].setWebViewClient(new android.webkit.WebViewClient(){
                    @Override public void onPageFinished(android.webkit.WebView v,String url){try{done.complete(new JSONObject().put("ok",true));}catch(JSONException ignored){}}
                    @Override public void onReceivedError(android.webkit.WebView v,android.webkit.WebResourceRequest request,android.webkit.WebResourceError e){if(request.isForMainFrame())try{done.complete(new JSONObject().put("ok",false).put("webViewError",e.getErrorCode()));}catch(JSONException ignored){}}
                    @Override public void onReceivedHttpError(android.webkit.WebView v,android.webkit.WebResourceRequest request,android.webkit.WebResourceResponse response){if(request.isForMainFrame())try{done.complete(new JSONObject().put("ok",false).put("http",response.getStatusCode()));}catch(JSONException ignored){}}
                    @Override public void onReceivedSslError(android.webkit.WebView v,android.webkit.SslErrorHandler handler,android.net.http.SslError e){handler.cancel();try{done.complete(new JSONObject().put("ok",false).put("sslError",e.getPrimaryError()));}catch(JSONException ignored){}}
                });
                // Fixed public page only: never accept a game/session URL from an Intent.
                view[0].loadUrl("https://profile-auth-view.netmarble.com/restriction");
            }catch(Exception e){done.complete(error(e));}
        });
        try{return done.get(25,TimeUnit.SECONDS);}catch(Exception e){return error(e);}
        finally{runOnUiThread(()->{if(view[0]!=null){view[0].stopLoading();view[0].destroy();}setContentView(output);});}
    }
    private JSONObject dns(){try(DatagramSocket socket=new DatagramSocket()){
        byte[] request={0x32,0x16,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
        socket.connect(InetAddress.getByName("1.1.1.1"),53);socket.setSoTimeout(2000);
        for(int i=0;i<3;i++)try{socket.send(new DatagramPacket(request,request.length));DatagramPacket p=new DatagramPacket(new byte[1400],1400);socket.receive(p);byte[] b=p.getData();if(p.getLength()>=12&&b[0]==0x32&&b[1]==0x16&&(b[2]&128)!=0)return new JSONObject().put("ok",true);}catch(SocketTimeoutException ignored){}
        throw new SocketTimeoutException();
    }catch(Exception e){return error(e);}}
    private JSONObject stun(){try(DatagramSocket socket=new DatagramSocket()){
        byte[] transaction=new byte[12];new SecureRandom().nextBytes(transaction);ByteBuffer b=ByteBuffer.allocate(20);b.putShort((short)1).putShort((short)0).putInt(0x2112a442).put(transaction);
        socket.connect(InetAddress.getByName("stun.cloudflare.com"),3478);socket.setSoTimeout(2000);
        for(int i=0;i<3;i++)try{socket.send(new DatagramPacket(b.array(),20));DatagramPacket p=new DatagramPacket(new byte[1400],1400);socket.receive(p);ByteBuffer reply=ByteBuffer.wrap(p.getData(),0,p.getLength());
            if(p.getLength()<20||reply.getShort()!=0x0101)continue;reply.getShort();if(reply.getInt()!=0x2112a442)continue;byte[] id=new byte[12];reply.get(id);if(Arrays.equals(id,transaction))return new JSONObject().put("ok",true);
        }catch(SocketTimeoutException ignored){}
        throw new SocketTimeoutException();
    }catch(Exception e){return error(e);}}
    private void runProbe(String label){
        JSONObject result=new JSONObject();ExecutorService tasks=Executors.newFixedThreadPool(5);long started=android.os.SystemClock.elapsedRealtime();
        try{
            result.put("label",label).put("status","running");save(label,result);
            ConnectivityManager manager=getSystemService(ConnectivityManager.class);NetworkCapabilities caps=manager.getNetworkCapabilities(manager.getActiveNetwork());
            result.put("vpn",caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
            if(netmarble){
                Future<JSONObject> v4=tasks.submit(()->netmarble(4)),v6=tasks.submit(()->netmarble(6)),web=tasks.submit(this::netmarbleWebView);
                result.put("netmarble4",v4.get(25,TimeUnit.SECONDS)).put("netmarble6",v6.get(25,TimeUnit.SECONDS)).put("webView",web.get(30,TimeUnit.SECONDS));
                result.put("status","done").put("elapsedMs",android.os.SystemClock.elapsedRealtime()-started);return;
            }
            List<Future<JSONObject>> https=new ArrayList<>();for(int i=0;i<3;i++)https.add(tasks.submit(this::https));Future<JSONObject> dns=tasks.submit(this::dns),stun=tasks.submit(this::stun);
            JSONArray responses=new JSONArray();for(Future<JSONObject> f:https)try{responses.put(f.get(25,TimeUnit.SECONDS));}catch(Exception e){responses.put(error(e));f.cancel(true);}
            result.put("https",responses);try{result.put("dns",dns.get(10,TimeUnit.SECONDS));}catch(Exception e){result.put("dns",error(e));}
            try{result.put("stun",stun.get(10,TimeUnit.SECONDS));}catch(Exception e){result.put("stun",error(e));}
            result.put("status","done").put("elapsedMs",android.os.SystemClock.elapsedRealtime()-started);
        }catch(Exception e){try{result.put("status","failed").put("error",e.getClass().getSimpleName());}catch(JSONException ignored){}}
        finally{tasks.shutdownNow();save(label,result);runOnUiThread(()->output.setText("Проверка сети завершена: "+label));}
    }
}
