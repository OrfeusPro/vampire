package net.phoneexit;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;

public final class ExitService extends Service {
    static volatile String status="Остановлено";
    static void update(String text) { status=text; android.util.Log.i("PhoneExit",text); }
    static boolean enabled(Context c) { return c.getSharedPreferences("runtime",MODE_PRIVATE).getBoolean("enabled",false); }
    static void stopEnabled(Context c) {
        c.getSharedPreferences("runtime",MODE_PRIVATE).edit().putBoolean("enabled",false).apply();
        c.stopService(new Intent(c,ExitService.class));
    }
    private final Handler handler=new Handler(Looper.getMainLooper());
    private ExitEngine engine;
    private DirectoryAgent directory;
    private DirectoryConfig config;
    private Pairing pairing;
    private Network selectedWifi;
    private boolean destroyed;
    private ConnectivityManager manager;
    private ConnectivityManager.NetworkCallback callback;
    private ConnectivityManager.NetworkCallback defaultCallback;
    private long retryAt;
    private int sessionGeneration;
    private final Runnable reconcile=new Runnable() {
        public void run() {
            if(destroyed) return;
            BotDiagnostics.prune(ExitService.this,false);
            if(config!=null)reconcileNetwork();
            handler.postDelayed(this,5000);
        }
    };
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public int onStartCommand(Intent intent,int flags,int id) {
        if(ClientVpnService.active||ClientVpnService.requested(this)) { stopSelf(); return START_NOT_STICKY; }
        if(intent!=null&&"stop".equals(intent.getAction())) { stopEnabled(this); return START_NOT_STICKY; }
        if(callback!=null) {
            if(intent!=null&&"reconnect".equals(intent.getAction())){
                closeSession();selectedWifi=null;retryAt=0;
                update("Переподключаю доступ · сначала Wi-Fi");reconcileNetwork();
            }
            return config==null?START_NOT_STICKY:START_STICKY;
        }
        try {
            String raw=intent==null?null:intent.getStringExtra("pairing");
            if(raw==null) {
                if(!enabled(this)) { stopSelf(); return START_NOT_STICKY; }
                config=DirectoryConfig.load(this);
                if(config==null) { stopSelf(); return START_NOT_STICKY; }
            } else if(new org.json.JSONObject(raw).optInt("version")==2) {
                config=DirectoryConfig.parse(raw); config.save(this);
                getSharedPreferences("runtime",MODE_PRIVATE).edit().putBoolean("enabled",true).apply();
            } else pairing=Pairing.parse(raw);
            NotificationManager nm=getSystemService(NotificationManager.class);
            nm.createNotificationChannel(new NotificationChannel("exit","Выход через телефон",NotificationManager.IMPORTANCE_LOW));
            PendingIntent activity=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE);
            PendingIntent stop=PendingIntent.getService(this,1,new Intent(this,ExitService.class).setAction("stop"),PendingIntent.FLAG_IMMUTABLE);
            startForeground(1,new Notification.Builder(this,"exit").setContentTitle("Phone Exit")
                .setContentText("Доступ через Wi-Fi или мобильный интернет включён")
                .setSmallIcon(R.drawable.ic_exit_notification).setContentIntent(activity)
                .addAction(new Notification.Action.Builder(null,"Остановить",stop).build()).setOngoing(true).build());
            BotManager.resumeWanted(this);
            manager=getSystemService(ConnectivityManager.class);
            callback=new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { reconcileNetwork(); }
                @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities caps) {
                    if(PeerDirectory.clientUplink(caps))reconcileNetwork();
                    else if(network.equals(selectedWifi)){closeSession();selectedWifi=null;update("Сеть недоступна · жду восстановления интернета");}
                }
                @Override public void onLost(Network network) {
                    if(!network.equals(selectedWifi)) return;
                    closeSession(); selectedWifi=null;
                    update("Нет интернета · жду Wi-Fi или мобильную сеть");
                    if(config==null) stopSelf();else reconcileNetwork();
                }
            };
            update("Ожидаю Wi-Fi или мобильный интернет · подключение автоматическое");
            manager.registerNetworkCallback(new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),callback,handler);
            defaultCallback=new ConnectivityManager.NetworkCallback(){
                @Override public void onAvailable(Network network){reconcileNetwork();}
                @Override public void onLost(Network network){reconcileNetwork();}
                @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities caps){reconcileNetwork();}
            };
            manager.registerDefaultNetworkCallback(defaultCallback,handler);
            if(config!=null) handler.post(reconcile);
        } catch(Exception e) { update("Ошибка: не удалось включить доступ"); stopSelf(); return START_NOT_STICKY; }
        return config==null?START_NOT_STICKY:START_STICKY;
    }
    private void reconcileNetwork(){
        if(destroyed)return;
        if(WifiBinding.compatible(selectedWifi)&&!WifiBinding.canUseDefault(this,selectedWifi)){
            closeSession();selectedWifi=null;retryAt=0;
            update("Текущая сеть изменилась · переподключаю доступ");
        }
        try{
            Network network=PeerDirectory.internetNetwork(this);
            if(selectedWifi!=null&&!network.equals(selectedWifi)){
                closeSession();selectedWifi=null;retryAt=0;
                if(config==null){stopSelf();return;}
            }
            useWifi(network,manager.getNetworkCapabilities(network));
        }catch(java.io.IOException ignored){
            if(selectedWifi!=null&&!PeerDirectory.clientUplink(manager.getNetworkCapabilities(selectedWifi))){closeSession();selectedWifi=null;}
            if(directory==null&&engine==null)update("Ожидаю Wi-Fi или мобильный интернет · подключение автоматическое");
        }
    }
    private void useWifi(Network network,NetworkCapabilities caps) {
        if(destroyed||engine!=null||directory!=null) return;
        if(SystemClock.uptimeMillis()<retryAt)return;
        if(!PeerDirectory.clientUplink(caps)) return;
        selectedWifi=network;
        int attempt=++sessionGeneration;
        if(config!=null) {
            directory=new DirectoryAgent(getApplicationContext(),network,config,() -> handler.post(() -> {
                if(destroyed||attempt!=sessionGeneration||!network.equals(selectedWifi)) return;
                // DirectoryAgent already reports whether Android denied binding
                // or another live Network still owns it; keep that useful reason.
                closeSession();
                retryAt=SystemClock.uptimeMillis()+15000;
            }));
            directory.start();
        } else {
            engine=new ExitEngine(getApplicationContext(),network,pairing,ExitService::update,this::stopSelf); engine.start();
        }
    }
    private void closeSession() {
        sessionGeneration++;
        if(engine!=null) engine.close(); engine=null;
        if(directory!=null) directory.close(); directory=null;
    }
    @Override public void onDestroy() {
        destroyed=true; handler.removeCallbacksAndMessages(null); closeSession(); selectedWifi=null;
        if(callback!=null) { try { manager.unregisterNetworkCallback(callback); } catch(Exception ignored) {} }
        if(defaultCallback!=null) { try { manager.unregisterNetworkCallback(defaultCallback); } catch(Exception ignored) {} }
        callback=null; status="Остановлено"; super.onDestroy();
    }
}
