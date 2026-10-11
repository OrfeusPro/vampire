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
    private final Runnable reconcile=new Runnable() {
        public void run() {
            if(destroyed) return;
            if(config!=null&&directory==null) {
                for(Network network:manager.getAllNetworks()) {
                    NetworkCapabilities caps=manager.getNetworkCapabilities(network);
                    if(caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                        &&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        &&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) { useWifi(network,caps); break; }
                }
            }
            handler.postDelayed(this,5000);
        }
    };
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public int onStartCommand(Intent intent,int flags,int id) {
        if(intent!=null&&"stop".equals(intent.getAction())) { stopEnabled(this); return START_NOT_STICKY; }
        if(callback!=null) return config==null?START_NOT_STICKY:START_STICKY;
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
                .setContentText("Автоматический доступ через Wi-Fi включён")
                .setSmallIcon(R.drawable.ic_exit_notification).setContentIntent(activity)
                .addAction(new Notification.Action.Builder(null,"Остановить",stop).build()).setOngoing(true).build());
            manager=getSystemService(ConnectivityManager.class);
            callback=new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { useWifi(network,manager.getNetworkCapabilities(network)); }
                @Override public void onCapabilitiesChanged(Network network,NetworkCapabilities caps) {
                    if(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) useWifi(network,caps);
                }
                @Override public void onLost(Network network) {
                    if(!network.equals(selectedWifi)) return;
                    closeSession(); selectedWifi=null;
                    update("Нет Wi-Fi · жду восстановления сети");
                    if(config==null) stopSelf();
                }
            };
            update("Ожидаю Wi-Fi · подключение автоматическое");
            manager.requestNetwork(new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),callback,handler);
            if(config!=null) handler.post(reconcile);
        } catch(Exception e) { update("Ошибка: не удалось включить доступ"); stopSelf(); return START_NOT_STICKY; }
        return config==null?START_NOT_STICKY:START_STICKY;
    }
    private void useWifi(Network network,NetworkCapabilities caps) {
        if(destroyed||engine!=null||directory!=null) return;
        if(caps==null||!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return;
        selectedWifi=network;
        if(config!=null) {
            directory=new DirectoryAgent(getApplicationContext(),network,config,() -> handler.post(() -> {
                if(destroyed||!network.equals(selectedWifi)) return;
                closeSession(); update("Wi-Fi недоступен для приложения · повторю подключение");
                handler.postDelayed(() -> { if(!destroyed&&network.equals(selectedWifi)) useWifi(network,manager.getNetworkCapabilities(network)); },15000);
            }));
            directory.start();
        } else {
            engine=new ExitEngine(getApplicationContext(),network,pairing,ExitService::update,this::stopSelf); engine.start();
        }
    }
    private void closeSession() {
        if(engine!=null) engine.close(); engine=null;
        if(directory!=null) directory.close(); directory=null;
    }
    @Override public void onDestroy() {
        destroyed=true; handler.removeCallbacksAndMessages(null); closeSession(); selectedWifi=null;
        if(callback!=null) { try { manager.unregisterNetworkCallback(callback); } catch(Exception ignored) {} }
        callback=null; status="Остановлено"; super.onDestroy();
    }
}
