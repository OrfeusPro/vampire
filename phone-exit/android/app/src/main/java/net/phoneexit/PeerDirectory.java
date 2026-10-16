package net.phoneexit;

import android.net.*;
import android.content.Context;
import org.json.*;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/** Uses only the account capability already present in the personal APK. */
final class PeerDirectory {
    /** Explicitly enabled personal clients and exits may use Wi-Fi or cellular. */
    static Network clientNetwork(Context c) throws IOException {return internetNetwork(c);}
    static Network internetNetwork(Context c) throws IOException {
        ConnectivityManager cm=c.getSystemService(ConnectivityManager.class);
        Network active=cm.getActiveNetwork();
        NetworkCapabilities activeCaps=active==null?null:cm.getNetworkCapabilities(active);
        if(clientUplink(activeCaps)&&activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))return active;
        Network cellular=clientUplink(activeCaps)&&activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)?active:null;
        for(Network n:cm.getAllNetworks()){
            NetworkCapabilities caps=cm.getNetworkCapabilities(n);
            if(!clientUplink(caps))continue;
            if(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))return n;
            if(cellular==null)cellular=n;
        }
        if(cellular!=null)return cellular;
        throw new IOException("internet_required");
    }
    static boolean clientUplink(NetworkCapabilities caps){
        return caps!=null&&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            &&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            &&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            &&(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)||caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
    }
    static Network wifi(Context c) throws IOException {
        ConnectivityManager cm=c.getSystemService(ConnectivityManager.class);
        for(Network n:cm.getAllNetworks()){
            NetworkCapabilities caps=cm.getNetworkCapabilities(n);
            if(caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)&&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)&&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))return n;
        }
        throw new IOException("wifi_required");
    }
    static JSONObject post(Network wifi,URL url,JSONObject body,int limit) throws Exception {
        HttpsURLConnection c=(HttpsURLConnection)wifi.openConnection(url);
        c.setInstanceFollowRedirects(false);c.setRequestMethod("POST");c.setConnectTimeout(8000);c.setReadTimeout(8000);c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json");
        byte[] data=body.toString().getBytes(StandardCharsets.UTF_8);c.setFixedLengthStreamingMode(data.length);
        try{
            try(OutputStream out=c.getOutputStream()){out.write(data);}
            if(c.getResponseCode()!=200)throw new IOException("catalog_http");
            try(InputStream in=c.getInputStream()){
                ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[4096];int n;
                while((n=in.read(buffer))!=-1){if(out.size()+n>limit)throw new IOException("response_size");out.write(buffer,0,n);}
                return new JSONObject(out.toString("UTF-8"));
            }
        }finally{c.disconnect();}
    }
    static JSONObject api(Network wifi,PersonalAccount account,String op,JSONObject extra) throws Exception {
        JSONObject body=new JSONObject(extra.toString()).put("version",1).put("token",account.catalogKey()).put("op",op);
        return post(wifi,new URL("https://demochko.com/phone-exit/directory.php"),body,2097152);
    }
    static List<JSONObject> list(Network wifi,DirectoryConfig config) throws Exception {
        if(config==null||config.account==null)throw new IOException("personal_required");
        JSONArray devices=api(wifi,config.account,"list",new JSONObject()).getJSONArray("devices");
        return decode(devices,config.id,config.account.feedToken,System.currentTimeMillis());
    }
    static List<JSONObject> decode(JSONArray devices,String ownId,String feedToken,long now) throws Exception {
        if(devices.length()>256)throw new IOException("device_limit");
        List<JSONObject> result=new ArrayList<>();Set<String> ids=new HashSet<>();
        for(int i=0;i<devices.length();i++)try{
            JSONObject entry=devices.getJSONObject(i);
            JSONObject value=PersonalAccount.secretBox(feedToken,"phone-exit-peer-directory-v1",null,entry.getJSONObject("box").getJSONObject("peer"));
            String id=value.getString("id"),name=value.getString("name");long at=value.getLong("at");
            if(!id.matches("[0-9a-f]{32}")||!entry.getString("id").equals(id)||id.equals(ownId)||!ids.add(id)||at<now-45000||at>now+45000||!"exit".equals(value.optString("role"))||!(value.opt("busy") instanceof Boolean)||name.isEmpty()||name.length()>40)continue;
            Pairing.parse(ExitEngine.json("version",1,"signal",value.getString("signal"),"token",value.getString("token")).toString());
            if(!value.optString("country").matches("[A-Z]{2}"))value.put("country","");
            result.add(value);
        }catch(Exception invalid){/* Unreadable/old announcements are not targets. */}
        result.sort(Comparator.comparing(v->v.optString("name")));return result;
    }
    static String random(int size){byte[] data=new byte[size];new SecureRandom().nextBytes(data);StringBuilder b=new StringBuilder();for(byte v:data)b.append(String.format(Locale.ROOT,"%02x",v&255));return b.toString();}
    static final class Connection {
        final Pairing pairing;final String name;
        Connection(Pairing pairing,String name){this.pairing=pairing;this.name=name;}
    }
    static Connection connect(Network wifi,DirectoryConfig config,String id) throws Exception {
        JSONObject target=null;for(JSONObject v:list(wifi,config))if(v.getString("id").equals(id))target=v;
        if(target==null||target.optBoolean("busy"))throw new IOException("device_unavailable");
        JSONObject pairing=ExitEngine.json("version",1,"signal",target.getString("signal"),"token",random(32));
        JSONObject request=ExitEngine.json("request",random(16),"at",System.currentTimeMillis(),"pairing",pairing);
        api(wifi,config.account,"connect",ExitEngine.json("id",id,"request",PersonalAccount.secretBox(target.getString("token"),"phone-exit-connect-v1",request,null)));
        return new Connection(Pairing.parse(pairing.toString()),target.getString("name"));
    }
}
