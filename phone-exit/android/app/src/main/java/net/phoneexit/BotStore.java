package net.phoneexit;

import android.content.Context;
import android.util.AtomicFile;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

final class BotStore {
    static File root(Context c){File f=new File(c.getFilesDir(),"bots");f.mkdirs();return f;}
    static JSONObject read(Context c,String name)throws Exception{
        AtomicFile f=new AtomicFile(new File(root(c),name+".json"));
        if(!f.getBaseFile().exists())return new JSONObject();
        // AtomicFile.openRead can remove a writer's .new file. The worker process
        // reads only the committed base; finishWrite atomically replaces it.
        try(InputStream in=new FileInputStream(f.getBaseFile())){return new JSONObject(ControlAgent.read(in,1100000));}
    }
    static void write(Context c,String name,JSONObject value)throws Exception{
        AtomicFile file=new AtomicFile(new File(root(c),name+".json"));FileOutputStream out=null;
        try{out=file.startWrite();out.write(value.toString().getBytes(StandardCharsets.UTF_8));file.finishWrite(out);}
        catch(Exception e){if(out!=null)file.failWrite(out);throw e;}
    }
    static JSONObject status(Context c)throws Exception{
        JSONObject s=read(c,"state");BotRetry.expire(s,System.currentTimeMillis());s.put("apiVersion",1).put("engineVersion",3).put("lastSeenAt",System.currentTimeMillis());return s;
    }
}
