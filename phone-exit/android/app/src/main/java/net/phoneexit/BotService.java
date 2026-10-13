package net.phoneexit;

import android.app.*;
import android.content.*;
import android.os.*;
import com.chaquo.python.*;
import com.chaquo.python.android.AndroidPlatform;
import org.json.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public final class BotService extends Service {
    private volatile Messenger bridge;private volatile boolean closed;private Thread runner;
    private final AtomicInteger ids=new AtomicInteger();private final ConcurrentHashMap<Integer,CompletableFuture<String>> pending=new ConcurrentHashMap<>();
    private final Messenger replies=new Messenger(new Handler(Looper.getMainLooper(),m->{CompletableFuture<String> f=pending.remove(m.what);if(f!=null)f.complete(m.getData().getString("json"));return true;}));
    private final ServiceConnection connection=new ServiceConnection(){public void onServiceConnected(ComponentName n,IBinder binder){bridge=new Messenger(binder);}public void onServiceDisconnected(ComponentName n){bridge=null;for(CompletableFuture<String> f:pending.values())f.completeExceptionally(new Exception("bot_bridge_lost"));pending.clear();}};
    public final class Host {
        private final String generation;Host(String g){generation=g;}
        public String call(String command,String args)throws Exception{
            if(closed||bridge==null)throw new Exception("bot_bridge_lost");int id=ids.incrementAndGet();CompletableFuture<String> future=new CompletableFuture<>();pending.put(id,future);
            try{Message m=Message.obtain(null,id);Bundle b=new Bundle();b.putString("json",new JSONObject().put("generation",generation).put("command",command).put("args",new JSONObject(args)).toString());m.setData(b);m.replyTo=replies;bridge.send(m);return future.get(10,TimeUnit.SECONDS);}finally{pending.remove(id);}
        }
    }
    @Override public IBinder onBind(Intent intent){return null;}
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        NotificationManager nm=getSystemService(NotificationManager.class);nm.createNotificationChannel(new NotificationChannel("bots","Бот на телефоне",NotificationManager.IMPORTANCE_LOW));
        PendingIntent stop=PendingIntent.getService(this,80,new Intent(this,BotService.class).setAction("stop"),PendingIntent.FLAG_IMMUTABLE);
        startForeground(80,new Notification.Builder(this,"bots").setSmallIcon(R.drawable.ic_exit_notification).setContentTitle("Phone Exit — бот").setContentText("Автономное выполнение на телефоне").addAction(new Notification.Action.Builder(null,"Остановить бот",stop).build()).build());
        if(intent!=null&&"stop".equals(intent.getAction())){new Thread(()->{try{JSONObject state=BotStore.read(this,"state");if(bridge!=null)new Host(state.optString("generation")).call("report",new JSONObject().put("pause",true).put("status","stopped").put("reason","phone_stop").toString());}catch(Exception ignored){}stopSelf();}).start();return START_NOT_STICKY;}
        if(runner==null){bindService(new Intent(this,BotBridgeService.class),connection,BIND_AUTO_CREATE);runner=new Thread(this::run,"PhoneExitBot");runner.start();}return START_STICKY;
    }
    private void run(){
        try{
            if(!Python.isStarted())Python.start(new AndroidPlatform(this));PyObject runtime=Python.getInstance().getModule("bot_runtime");
            String permittedGeneration=null;
            while(!closed){long started=SystemClock.elapsedRealtime();JSONObject state=BotStore.read(this,"state");String generation=state.optString("generation");
                if(!state.optString("desired").equals("running")){if(state.optString("desired").equals("stopped")){stopSelf();return;}Thread.sleep(500);continue;}
                if(state.optLong("retryAt",0)>System.currentTimeMillis()){Thread.sleep(500);continue;}
                if(bridge==null){Thread.sleep(500);continue;}Host host=new Host(generation);
                try{
                    if(!new JSONObject(host.call("ready","{}")).optBoolean("ready")){
                        boolean lost=generation.equals(permittedGeneration);
                        host.call("report",new JSONObject().put("status",lost?"paused":"waiting").put("reason","accessibility_permission_required").put("pause",lost).toString());Thread.sleep(1000);continue;
                    }
                    permittedGeneration=generation;
                    if(getSystemService(KeyguardManager.class).isKeyguardLocked()||!getSystemService(PowerManager.class).isInteractive()){
                        host.call("report",new JSONObject().put("status","waiting").put("reason","screen_locked").toString());Thread.sleep(1000);continue;
                    }
                    String bot=state.getString("botId");JSONObject installed=BotStore.read(this,bot+"-installed"),settings=BotStore.read(this,bot+"-settings");
                    String result=runtime.callAttr("tick",installed.getString("directory"),generation,host,settings.getJSONObject("value").toString()).toString();
                    JSONObject report=new JSONObject(result).put("appliedRevision",settings.getInt("revision")).put("settingsStatus","applied").put("tickMs",SystemClock.elapsedRealtime()-started);host.call("report",report.toString());
                }catch(Exception error){String safe="bot_execution_failed";String message=error.getMessage();if(message!=null)for(String reason:new String[]{"accessibility_permission_required","bot_game_not_foreground","bot_cancelled","bot_bridge_lost","screenshot_too_large","control_disabled_or_screen_locked"})if(message.contains(reason))safe=reason;try{host.call("report",new JSONObject().put("status","error").put("error",safe).put("pause",true).toString());}catch(Exception ignored){}}
                long wait=1000-(SystemClock.elapsedRealtime()-started);if(wait>0)Thread.sleep(wait);
            }
        }catch(InterruptedException e){Thread.currentThread().interrupt();}catch(Exception e){/* Do not log settings or Python stack payloads. */}
    }
    @Override public void onDestroy(){closed=true;if(runner!=null)runner.interrupt();for(CompletableFuture<String> f:pending.values())f.cancel(false);pending.clear();try{unbindService(connection);}catch(Exception ignored){}super.onDestroy();}
}
