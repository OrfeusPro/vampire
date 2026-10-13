package net.phoneexit;
import android.content.Context;
import android.util.Base64;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded private error records. No settings, account keys or full stack traces. */
final class BotDiagnostics {
    static final long TTL=12*60*60*1000L,INTERVAL=3*60*60*1000L;
    static final int MAX_COUNT=100,MAX_IMAGE=1048576;static final long MAX_BYTES=64*1024*1024L;
    private static long nextPrune;
    private static String lastSignature="";
    static File root(Context c){File f=new File(c.getFilesDir(),"bot-errors");f.mkdirs();return f;}
    private static void remove(File f){if(f.isDirectory()){File[] children=f.listFiles();if(children!=null)for(File child:children)remove(child);}f.delete();}
    static synchronized void prune(Context c,boolean force){long now=System.currentTimeMillis();if(!force&&now<nextPrune)return;nextPrune=now+INTERVAL;File[] entries=root(c).listFiles();if(entries==null)return;List<File> keep=new ArrayList<>();
        for(File f:entries){if(!f.getName().matches("[0-9]{13}-[a-f0-9]{32}(\\.tmp)?"))continue;long at=Long.parseLong(f.getName().substring(0,13));if(now-at>TTL||f.getName().endsWith(".tmp")){remove(f);continue;}keep.add(f);}
        keep.sort((a,b)->b.getName().compareTo(a.getName()));long bytes=0;for(int i=0;i<keep.size();i++){File f=keep.get(i);bytes+=new File(f,"report.json").length()+new File(f,"screen.jpg").length();if(i>=MAX_COUNT||bytes>MAX_BYTES)remove(f);}
    }
    private static void write(File file,byte[] data)throws Exception{try(FileOutputStream out=new FileOutputStream(file)){out.write(data);out.getFD().sync();}}
    static synchronized String save(Context c,JSONObject state,JSONObject report,byte[] image,long frameAt)throws Exception{
        String signature=state.optString("generation")+":"+report.optString("error")+":"+report.optString("step");if(signature.equals(lastSignature))return null;
        long now=System.currentTimeMillis();String id=String.format(Locale.ROOT,"%013d",now)+"-"+UUID.randomUUID().toString().replace("-","");File parent=root(c),temp=new File(parent,id+".tmp");if(!temp.mkdir())throw new IOException("diagnostic_storage_unavailable");
        JSONObject value=new JSONObject().put("id",id).put("capturedAt",now).put("frameCapturedAt",frameAt).put("source","phone_error_frame");
        for(String field:new String[]{"botId","version","appliedRevision"})if(state.has(field))value.put(field,state.get(field));
        for(String field:new String[]{"step","error","reason","activePoint","appliedRevision"})if(report.has(field))value.put(field,report.get(field));
        try{if(image!=null&&image.length<=MAX_IMAGE){write(new File(temp,"screen.jpg"),image);value.put("hasScreenshot",true);}else value.put("hasScreenshot",false).put("screenshotUnavailable",image==null?"no_error_frame":"frame_too_large");
            write(new File(temp,"report.json"),value.toString().getBytes(StandardCharsets.UTF_8));if(!temp.renameTo(new File(parent,id)))throw new IOException("diagnostic_commit_failed");lastSignature=signature;prune(c,true);return id;
        }finally{if(temp.exists())remove(temp);}
    }
    static synchronized JSONObject list(Context c)throws Exception{prune(c,false);JSONArray records=new JSONArray();File[] entries=root(c).listFiles();if(entries!=null){Arrays.sort(entries,(a,b)->b.getName().compareTo(a.getName()));for(File f:entries)if(f.getName().matches("[0-9]{13}-[a-f0-9]{32}")){try{records.put(new JSONObject(BotManager.read(new File(f,"report.json"),16384)));}catch(Exception ignored){}}}return new JSONObject().put("records",records).put("retentionHours",12).put("cleanupHours",3);}
    static synchronized JSONObject get(Context c,String id)throws Exception{if(!id.matches("[0-9]{13}-[a-f0-9]{32}"))throw new Exception("invalid_diagnostic_id");prune(c,false);File f=new File(root(c),id);JSONObject value=new JSONObject(BotManager.read(new File(f,"report.json"),16384));File image=new File(f,"screen.jpg");if(image.isFile()&&image.length()<=MAX_IMAGE){byte[] data=new byte[(int)image.length()];try(DataInputStream in=new DataInputStream(new FileInputStream(image))){in.readFully(data);}value.put("image",Base64.encodeToString(data,Base64.NO_WRAP));}return value;}
}
