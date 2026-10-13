package net.phoneexit;
import android.app.Service;
import android.content.*;
import android.os.*;
import org.json.*;
import java.io.File;
import java.util.concurrent.*;

public final class BotBridgeService extends Service {
    private final ExecutorService worker=Executors.newSingleThreadExecutor();private BotVision vision;private String visionGeneration="";
    private final Messenger messenger=new Messenger(new Handler(Looper.getMainLooper(),message->{
        final Message request=Message.obtain(message);worker.execute(()->{
            JSONObject result;try{JSONObject input=new JSONObject(request.getData().getString("json"));result=call(input);}catch(Exception e){result=new JSONObject();try{result.put("error",BotManager.safe(e));}catch(Exception ignored){}}
            try{Message reply=Message.obtain(null,request.what);Bundle b=new Bundle();b.putString("json",result.toString());reply.setData(b);request.replyTo.send(reply);}catch(Exception ignored){}finally{request.recycle();}
        });return true;
    }));
    @Override public IBinder onBind(Intent intent){return messenger.getBinder();}
    private JSONObject call(JSONObject input)throws Exception{
        String generation=input.getString("generation"),command=input.getString("command");if(command.equals("report")){JSONObject report=input.getJSONObject("args"),state=BotStore.read(this,"state");
            if(!report.optString("error","").isEmpty()&&!report.isNull("error")&&state.optString("generation").equals(generation)&&state.optString("desired").equals("running")){
                try{boolean frame=vision!=null&&generation.equals(visionGeneration);String id=BotDiagnostics.save(this,state,report,frame?vision.diagnosticJpeg():null,frame?vision.frameCapturedAt:0);if(id!=null)report.put("diagnosticId",id);}catch(Exception ignored){/* Recording must not prevent pausing a failed bot. */}
            }
            BotManager.report(this,generation,report);return new JSONObject();}
        if(command.equals("ready"))return new JSONObject().put("ready",ControlAccessibility.current!=null&&ControlAccessibility.allowed(this));
        if(!BotManager.valid(this,generation))throw new Exception("bot_cancelled");
        if(command.equals("match")){
            JSONObject s=BotStore.read(this,"state"),installed=BotStore.read(this,s.getString("botId")+"-installed");File dir=new File(installed.getString("directory"));
            JSONObject args=input.getJSONObject("args");if(vision==null)throw new Exception("bot_capture_required");return vision.match(dir,args.getString("name"),args.getJSONObject("spec"));
        }
        ControlAccessibility control=ControlAccessibility.current;if(control==null)throw new Exception("accessibility_permission_required");
        JSONObject args=input.optJSONObject("args");if(args==null)args=new JSONObject();
        String bot=BotStore.read(this,"state").getString("botId");File dir=new File(BotStore.read(this,bot+"-installed").getString("directory"));
        JSONObject manifest=new JSONObject(BotManager.read(new File(dir,"manifest.json"),16384));JSONArray packages=manifest.getJSONArray("packages");
        if(command.equals("launch")){boolean found=false;for(int i=0;i<packages.length();i++)if(packages.getString(i).equals(args.optString("package")))found=true;if(!found)throw new Exception("bot_package_not_allowed");}
        if(!command.equals("capture")&&!command.equals("foreground")&&!command.equals("launch")){
            JSONObject foreground=control.execute("foreground",new JSONObject(),()->valid(generation));boolean found=false;for(int i=0;i<packages.length();i++)if(packages.getString(i).equals(foreground.optString("package")))found=true;if(!found)throw new Exception("bot_game_not_foreground");
        }
        if(command.equals("capture")){if(vision==null)vision=new BotVision();JSONObject frame=vision.capture(control.captureLocal(()->valid(generation)));visionGeneration=generation;return frame;}
        if(!java.util.Arrays.asList("foreground","launch","tap","swipe","back").contains(command))throw new Exception("unsupported_bot_host_command");
        return control.execute(command,args,()->valid(generation));
    }
    private boolean valid(String g){try{return BotManager.valid(this,g);}catch(Exception e){return false;}}
    @Override public void onDestroy(){worker.execute(()->{if(vision!=null){vision.close();vision=null;}});worker.shutdown();super.onDestroy();}
}
