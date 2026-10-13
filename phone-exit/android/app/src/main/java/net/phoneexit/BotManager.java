package net.phoneexit;

import android.content.*;
import android.util.Base64;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.zip.*;
import javax.net.ssl.HttpsURLConnection;

final class BotManager {
    private static final int MAX_SETTINGS=1048576;
    private static String id(String value)throws Exception{if(!value.matches("[a-z][a-z0-9_-]{0,40}"))throw new Exception("invalid_bot_id");return value;}
    static String hash(byte[] data)throws Exception{StringBuilder s=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(data))s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString();}
    static synchronized JSONObject execute(ControlAgent agent,JSONObject args)throws Exception{
        Context c=agent.context;String op=args.getString("op");JSONObject state=BotStore.read(c,"state");
        if(op.equals("status"))return BotStore.status(c);
        if(op.equals("diagnosticsList"))return BotDiagnostics.list(c);
        if(op.equals("diagnosticsGet"))return BotDiagnostics.get(c,args.getString("id"));
        if(op.equals("catalog"))return agent.api(new JSONObject().put("op","botCatalog").put("id",agent.config.id));
        if(op.equals("assign")){
            if("running".equals(state.optString("desired")))throw new Exception("bot_stop_before_assign");
            String bot=id(args.getString("botId"));
            // Keep a profile per game; assigning never starts a bot or deletes settings.
            state=new JSONObject().put("botId",bot).put("desired","stopped").put("status","assigned").put("generation",UUID.randomUUID().toString());
            BotStore.write(c,"state",state);return BotStore.status(c);
        }
        if(op.equals("install")||op.equals("rollback")){
            if("running".equals(state.optString("desired")))throw new Exception("bot_stop_before_install");
            String bot=id(state.getString("botId"));File base=new File(BotStore.root(c),bot);base.mkdirs();
            if(op.equals("rollback")){
                JSONObject previous=BotStore.read(c,bot+"-previous");if(!previous.has("directory"))throw new Exception("bot_no_previous_version");
                JSONObject current=BotStore.read(c,bot+"-installed");BotStore.write(c,bot+"-installed",previous);BotStore.write(c,bot+"-previous",current);
                state.put("version",previous.getString("version")).put("status","installed").put("desired","stopped");state.remove("error");state.remove("reason");BotStore.write(c,"state",state);return BotStore.status(c);
            }
            String wanted=args.getString("version");JSONObject catalog=agent.api(new JSONObject().put("op","botCatalog").put("id",agent.config.id));
            JSONObject signed=null;JSONArray items=catalog.getJSONArray("bots");for(int i=0;i<items.length();i++){
                JSONObject item=items.getJSONObject(i),p=new JSONObject(item.getString("payload"));if(bot.equals(p.optString("id"))&&wanted.equals(p.optString("version")))signed=item;
            }if(signed==null)throw new Exception("bot_release_unavailable");
            JSONObject meta=verify(c,signed);if(meta.getInt("engineVersion")<1||meta.getInt("engineVersion")>3)throw new Exception("bot_engine_incompatible");if(meta.getInt("settingsVersion")!=1)throw new Exception("bot_settings_incompatible");
            long size=meta.getLong("size");if(size<1||size>60000000)throw new Exception("bot_package_size");
            state.put("status","downloading");BotStore.write(c,"state",state);
            File tmp=new File(base,"download.tmp");HttpsURLConnection conn=agent.connection(new JSONObject().put("op","botPackage").put("id",agent.config.id).put("botId",bot).put("sha256",meta.getString("sha256")));
            conn.setReadTimeout(15000);MessageDigest digest=MessageDigest.getInstance("SHA-256");long total=0,start=android.os.SystemClock.elapsedRealtime();
            try{
                if(conn.getResponseCode()!=200)throw new Exception("bot_download_http");
                try(InputStream in=conn.getInputStream();OutputStream out=new FileOutputStream(tmp)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1){
                    if(!agent.active())throw new Exception("wifi_lost");if(android.os.SystemClock.elapsedRealtime()-start>120000)throw new Exception("bot_download_timeout");
                    total+=n;if(total>size)throw new Exception("bot_package_size");digest.update(b,0,n);out.write(b,0,n);
                }}if(total!=size||!hex(digest.digest()).equals(meta.getString("sha256")))throw new Exception("bot_hash_mismatch");
                File dest=new File(base,meta.getString("sha256"));File stage=new File(base,"stage-"+UUID.randomUUID());stage.mkdirs();
                try{
                    extract(tmp,stage);
                    JSONObject manifest=new JSONObject(read(new File(stage,"manifest.json"),16384));
                    if(!bot.equals(manifest.getString("id"))||!wanted.equals(manifest.getString("version"))||manifest.getInt("engineVersion")!=meta.getInt("engineVersion")||manifest.getInt("settingsVersion")!=meta.getInt("settingsVersion")||!manifest.getString("entrypoint").equals("bot.py"))throw new Exception("bot_manifest_mismatch");
                    if(!new File(stage,"bot.py").isFile())throw new Exception("bot_entrypoint_missing");
                    if(!dest.exists()&&!stage.renameTo(dest))throw new Exception("bot_storage");
                    JSONObject current=BotStore.read(c,bot+"-installed");if(current.has("directory")&&!dest.getAbsolutePath().equals(current.optString("directory")))BotStore.write(c,bot+"-previous",current);
                    BotStore.write(c,bot+"-installed",meta.put("directory",dest.getAbsolutePath()));
                }finally{delete(stage);}
                state.put("version",wanted).put("status","installed").put("desired","stopped").remove("error");BotStore.write(c,"state",state);
            }catch(Exception failure){state.put("status","error").put("error",safe(failure));BotStore.write(c,"state",state);throw failure;}
            finally{conn.disconnect();tmp.delete();}return BotStore.status(c);
        }
        String bot=id(state.getString("botId"));
        if(op.equals("settingsBegin")){
            int revision=args.getInt("revision"),size=args.getInt("size");String sha=args.getString("sha256");
            if(revision<=BotStore.read(c,bot+"-settings").optInt("revision",0)||size<2||size>MAX_SETTINGS||!sha.matches("[a-f0-9]{64}"))throw new Exception("bot_settings_revision_or_size");
            File f=new File(BotStore.root(c),"settings-upload.tmp");try(OutputStream out=new FileOutputStream(f)){}
            BotStore.write(c,"upload",new JSONObject().put("botId",bot).put("revision",revision).put("size",size).put("sha256",sha).put("received",0).put("at",System.currentTimeMillis()));
            state.put("receivedRevision",revision).put("settingsStatus","receiving");BotStore.write(c,"state",state);return BotStore.status(c);
        }
        if(op.equals("settingsChunk")||op.equals("settingsCommit")){
            JSONObject upload=BotStore.read(c,"upload");if(!bot.equals(upload.optString("botId"))||args.getInt("revision")!=upload.getInt("revision")||System.currentTimeMillis()-upload.getLong("at")>120000)throw new Exception("bot_settings_upload_expired");
            File file=new File(BotStore.root(c),"settings-upload.tmp");
            if(op.equals("settingsChunk")){
                byte[] bytes=Base64.decode(args.getString("data"),Base64.NO_WRAP);int offset=args.getInt("offset");
                if(bytes.length<1||bytes.length>4096||offset!=upload.getInt("received")||offset+bytes.length>upload.getInt("size"))throw new Exception("bot_settings_chunk_order");
                try(RandomAccessFile out=new RandomAccessFile(file,"rw")){out.seek(offset);out.write(bytes);}
                upload.put("received",offset+bytes.length).put("at",System.currentTimeMillis());BotStore.write(c,"upload",upload);return new JSONObject().put("received",offset+bytes.length);
            }
            byte[] bytes;try(InputStream in=new FileInputStream(file)){bytes=readBytes(in,MAX_SETTINGS);}
            if(bytes.length!=upload.getInt("size")||!hash(bytes).equals(upload.getString("sha256")))throw new Exception("bot_settings_hash");
            JSONObject value=new JSONObject(new String(bytes,StandardCharsets.UTF_8));validateSettings(value);
            JSONObject installed=BotStore.read(c,bot+"-installed");if(installed.has("settingsVersion")&&value.getInt("settingsVersion")!=installed.getInt("settingsVersion"))throw new Exception("bot_settings_incompatible");
            BotStore.write(c,bot+"-settings",new JSONObject().put("revision",upload.getInt("revision")).put("value",value));file.delete();
            state.put("settingsStatus","received").put("receivedRevision",upload.getInt("revision")).put("settingsSha256",upload.getString("sha256"));BotStore.write(c,"state",state);return BotStore.status(c);
        }
        if(op.equals("start")||op.equals("resume")){
            JSONObject installed=BotStore.read(c,bot+"-installed"),settings=BotStore.read(c,bot+"-settings");
            if(!installed.has("directory"))throw new Exception("bot_not_installed");if(!settings.has("value"))throw new Exception("bot_settings_required");
            if(!ControlAccessibility.allowed(c)||ControlAccessibility.current==null)throw new Exception("accessibility_permission_required");
            state.put("desired","running").put("status","starting").put("generation",UUID.randomUUID().toString()).put("version",installed.getString("version"));state.remove("error");BotStore.write(c,"state",state);resumeWanted(c);
        }else if(op.equals("pause")||op.equals("stop")){
            state.put("desired",op.equals("pause")?"paused":"stopped").put("status",op.equals("pause")?"paused":"stopped").put("generation",UUID.randomUUID().toString());BotStore.write(c,"state",state);
            if(op.equals("stop"))c.stopService(new Intent(c,BotService.class));
        }else throw new Exception("unsupported_bot_operation");return BotStore.status(c);
    }
    static synchronized void manualPause(Context c)throws Exception{JSONObject s=BotStore.read(c,"state");if(s.optString("desired").equals("running")){s.put("desired","paused").put("status","paused").put("reason","manual_control").put("generation",UUID.randomUUID().toString());BotStore.write(c,"state",s);}}
    static void resumeWanted(Context c){try{if(BotStore.read(c,"state").optString("desired").equals("running"))c.startForegroundService(new Intent(c,BotService.class));}catch(Exception ignored){}}
    static synchronized boolean valid(Context c,String generation)throws Exception{JSONObject s=BotStore.read(c,"state");return s.optString("desired").equals("running")&&s.optString("generation").equals(generation)&&ControlAccessibility.allowed(c);}
    static synchronized void report(Context c,String generation,JSONObject report)throws Exception{
        JSONObject state=BotStore.read(c,"state");if(!state.optString("generation").equals(generation)||!state.optString("desired").equals("running"))return;
        for(String field:new String[]{"status","step","error","reason","activePoint","appliedRevision","tickMs","hostTimingsMs"})if(report.has(field))state.put(field,report.get(field));
        if(report.has("settingsStatus")&&report.optInt("appliedRevision")==state.optInt("receivedRevision"))state.put("settingsStatus",report.get("settingsStatus"));
        if(report.optBoolean("pause"))state.put("desired",report.optString("reason").equals("phone_stop")?"stopped":"paused");state.put("updatedAt",System.currentTimeMillis());BotStore.write(c,"state",state);
    }
    static void validateSettings(JSONObject value)throws Exception{
        if(value.optInt("settingsVersion")!=1)throw new Exception("bot_settings_incompatible");
        JSONArray spots=value.optJSONArray("farm_map_spots");if(spots==null||spots.length()>256)throw new Exception("bot_invalid_points");Set<String> ids=new HashSet<>();
        for(String key:new String[]{"farm_enabled","recovery_enabled","auto_dismantle_enabled","autostart_enabled"})if(!(value.opt(key) instanceof Boolean))throw new Exception("bot_invalid_switch");
        for(int i=0;i<spots.length();i++){JSONObject spot=spots.getJSONObject(i);if(!ids.add(spot.getString("id"))||spot.getString("id").length()>128||spot.getString("map_id").length()>128)throw new Exception("bot_invalid_points");
            JSONArray points=spot.optJSONArray("map_points");if(points==null)throw new Exception("bot_invalid_points");if(points.length()>256)throw new Exception("bot_invalid_points");for(int j=0;j<points.length();j++)point(points.getJSONArray(j));
            JSONArray teleport=spot.optJSONArray("teleport_point");if(teleport!=null)point(teleport);
        }
        if(!value.isNull("active_farm_map_spot_id")&&!value.optString("active_farm_map_spot_id").isEmpty()&&!ids.contains(value.optString("active_farm_map_spot_id")))throw new Exception("bot_invalid_active_point");
    }
    static void point(JSONArray p)throws Exception{if(p.length()!=2)throw new Exception("bot_invalid_point");for(int i=0;i<2;i++){double v=p.getDouble(i);if(!Double.isFinite(v)||v<0||v>=1)throw new Exception("bot_invalid_point");}}
    private static JSONObject verify(Context c,JSONObject signed)throws Exception{
        JSONObject publisher=new JSONObject(ControlAgent.read(c.getAssets().open("bot-publisher.json"),4096));String payload=signed.getString("payload");if(payload.length()>4096)throw new Exception("bot_signature_invalid");
        Signature verifier=Signature.getInstance("SHA256withRSA");verifier.initVerify(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(publisher.getString("publicKey"),Base64.NO_WRAP))));verifier.update(payload.getBytes(StandardCharsets.UTF_8));
        if(!verifier.verify(Base64.decode(signed.getString("signature"),Base64.NO_WRAP)))throw new Exception("bot_signature_invalid");JSONObject meta=new JSONObject(payload);id(meta.getString("id"));if(!meta.getString("sha256").matches("[a-f0-9]{64}")||!meta.getString("version").matches("[0-9]+\\.[0-9]+\\.[0-9]+"))throw new Exception("bot_invalid_release");return meta;
    }
    static void extract(File zip,File dir)throws Exception{
        long total=0;int count=0;Set<String> names=new HashSet<>();try(ZipInputStream in=new ZipInputStream(new FileInputStream(zip))){ZipEntry entry;byte[] b=new byte[65536];
            while((entry=in.getNextEntry())!=null){String name=entry.getName();File out=new File(dir,name);if(++count>4096||!names.add(name)||name.contains("\\")||name.startsWith("/")||!out.getCanonicalPath().startsWith(dir.getCanonicalPath()+File.separator))throw new Exception("bot_invalid_archive");
                if(entry.isDirectory()){out.mkdirs();continue;}out.getParentFile().mkdirs();try(OutputStream file=new FileOutputStream(out)){int n;while((n=in.read(b))!=-1){total+=n;if(total>120000000)throw new Exception("bot_expanded_limit");file.write(b,0,n);}}
            }
        }
    }
    static String safe(Exception e){String s=e.getMessage();return s!=null&&s.matches("[a-z0-9_]{1,80}")?s:"bot_operation_failed";}
    static String read(File f,int max)throws Exception{try(InputStream in=new FileInputStream(f)){return ControlAgent.read(in,max);}}
    static byte[] readBytes(InputStream in,int max)throws Exception{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];int n;while((n=in.read(b))!=-1){if(out.size()+n>max)throw new Exception("bot_size_limit");out.write(b,0,n);}return out.toByteArray();}
    private static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format(Locale.ROOT,"%02x",v&255));return s.toString();}
    private static void delete(File file){if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)delete(child);}file.delete();}
}
