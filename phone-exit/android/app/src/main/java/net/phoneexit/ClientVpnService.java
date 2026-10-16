package net.phoneexit;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import hev.htproxy.TProxyService;

/** Holds the default TUN routes when the transport fails; only explicit Stop removes them. */
public final class ClientVpnService extends VpnService {
    static volatile boolean active;
    static volatile boolean stopping;
    static volatile String status="VPN выключен";
    private final ScheduledExecutorService worker=Executors.newSingleThreadScheduledExecutor();
    private volatile boolean destroyed;
    private volatile ParcelFileDescriptor tun;
    private final Object tunnelLock=new Object();
    private boolean ownsSession;
    private ClientTransport transport;
    private ClientSocks socks;
    private File configFile;
    private boolean nativeStarted,blocked;
    private ConnectivityManager manager;
    private ConnectivityManager.NetworkCallback callback;
    private Network uplink;
    private String targetName="Личный телефон";
    static boolean requested(Context c){return c.getSharedPreferences("runtime",MODE_PRIVATE).getBoolean("vpnRequested",false);}
    static void stop(Context c){c.startService(new Intent(c,ClientVpnService.class).setAction("stop"));}
    private void update(String text){status=text;getSystemService(NotificationManager.class).notify(4,notification());}
    private Notification notification(){
        PendingIntent open=PendingIntent.getActivity(this,40,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop=PendingIntent.getService(this,41,new Intent(this,ClientVpnService.class).setAction("stop"),PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this,"client-vpn").setContentTitle("Phone Exit · VPN")
            .setContentText(status).setSmallIcon(R.drawable.ic_exit_notification).setContentIntent(open)
            .addAction(new Notification.Action.Builder(null,"Отключить VPN",stop).build()).setOngoing(true).build();
    }
    @Override public int onStartCommand(Intent intent,int flags,int id){
        if(intent==null||"stop".equals(intent.getAction())){
            if(!ownsSession&&!active&&!stopping){getSharedPreferences("runtime",MODE_PRIVATE).edit().putBoolean("vpnRequested",false).apply();status="VPN выключен";}
            stopSession();stopSelf();return START_NOT_STICKY;
        }
        if(active)return START_NOT_STICKY;
        if(stopping){stopSelf();return START_NOT_STICKY;}
        String target=intent.getStringExtra("target");
        if(Build.VERSION.SDK_INT<29||target==null||!target.matches("[0-9a-f]{32}")||VpnService.prepare(this)!=null){stopSelf();return START_NOT_STICKY;}
        ownsSession=true;active=true;status="Подключение · трафик блокируется до готовности";
        getSharedPreferences("runtime",MODE_PRIVATE).edit().putBoolean("vpnRequested",true).apply();
        ExitService.stopEnabled(this);
        NotificationManager nm=getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("client-vpn","VPN через личный телефон",NotificationManager.IMPORTANCE_LOW));
        startForeground(4,notification());
        try{
            tun=configureTunnel(new Builder(),getPackageName()).establish();
            if(tun==null)throw new IOException("consent");
            worker.schedule(()->connect(target),1,TimeUnit.SECONDS);
        }catch(Exception e){update("Не удалось включить системный VPN");stopSelf();}
        return START_NOT_STICKY;
    }
    private void connect(String target){
        if(destroyed||blocked)return;
        try{
            android.util.Log.w("PhoneExitClient","directory start");
            uplink=PeerDirectory.clientNetwork(this);setUnderlyingNetworks(new Network[]{uplink});
            manager=getSystemService(ConnectivityManager.class);
            callback=new ConnectivityManager.NetworkCallback(){
                @Override public void onLost(Network n){if(n.equals(uplink)){android.util.Log.w("PhoneExitClient","uplink lost");fail();}}
                @Override public void onCapabilitiesChanged(Network n,NetworkCapabilities caps){if(n.equals(uplink)&&!PeerDirectory.clientUplink(caps)){android.util.Log.w("PhoneExitClient","uplink unavailable");fail();}}
            };
            manager.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),callback);
            DirectoryConfig account=DirectoryConfig.load(this);if(account==null||target.equals(account.id))throw new IOException("account");
            PeerDirectory.Connection connection=PeerDirectory.connect(uplink,account,target);targetName=connection.name;
            android.util.Log.w("PhoneExitClient","directory accepted");
            if(destroyed||blocked)return;
            transport=new ClientTransport(getApplicationContext(),uplink,connection.pairing,()->enqueue(this::connected),this::fail);
            transport.start();
        }catch(Exception e){android.util.Log.w("PhoneExitClient","directory "+e.getClass().getSimpleName());block("Нет связи с телефоном · трафик заблокирован. Отключите VPN и проверьте мобильный интернет или Wi-Fi и доступность телефона.");}
    }
    private void connected(){
        if(destroyed||blocked)return;
        try{
            socks=new ClientSocks(transport);socks.start();
            configFile=new File(getFilesDir(),"client-tun.yml");
            String yaml=tunnelConfig(socks.port());
            try(FileOutputStream out=new FileOutputStream(configFile)){out.write(yaml.getBytes(StandardCharsets.UTF_8));}
            synchronized(tunnelLock){
                if(destroyed||tun==null)return;
                if(!TProxyService.TProxyStartService(configFile.getAbsolutePath(),tun.getFd()))throw new IOException("native");
                nativeStarted=true;
            }
            // JNI start is asynchronous; report connected only after the worker survives startup.
            worker.schedule(()->{
                if(!destroyed&&!blocked){if(!TProxyService.TProxyIsRunning())fail();else update("Подключено · "+targetName+" · TCP и UDP");}
            },1,TimeUnit.SECONDS);
            worker.scheduleWithFixedDelay(()->{if(!destroyed&&!blocked&&!TProxyService.TProxyIsRunning())fail();},3,3,TimeUnit.SECONDS);
        }catch(Exception|LinkageError e){block("Ошибка VPN · трафик заблокирован. Нажмите «Отключить VPN».");}
    }
    private void enqueue(Runnable r){try{worker.execute(()->{if(!destroyed)r.run();});}catch(RejectedExecutionException ignored){}}
    static Builder configureTunnel(Builder builder,String ownPackage)throws android.content.pm.PackageManager.NameNotFoundException{
        // Do not advertise IPv6 without a verified IPv6 exit. Android blocks a
        // family with no address/route/DNS; never allowFamily(AF_INET6), which
        // would let that traffic fall through outside the VPN.
        return builder.setSession("Phone Exit").setMtu(1280).addAddress("198.18.0.1",30)
            .addRoute("0.0.0.0",0).addDnsServer("1.1.1.1")
            .addDisallowedApplication(ownPackage).setBlocking(false);
    }
    static String tunnelConfig(int port){
        return "tunnel:\n  mtu: 1280\n  ipv4: 198.18.0.1\nsocks5:\n  address: 127.0.0.1\n  port: "+port+"\n  udp: 'udp'\nmisc:\n  max-session-count: 160\n  connect-timeout: 10000\n  tcp-read-write-timeout: 300000\n  udp-read-write-timeout: 60000\n  log-level: error\n";
    }
    private void fail(){enqueue(()->block(nativeStarted?"Связь потеряна · трафик заблокирован. Для обычной сети отключите VPN.":"Прямая связь с телефоном не установлена · трафик заблокирован. Для обычной сети отключите VPN."));}
    private void block(String message){
        if(destroyed||blocked)return;blocked=true;closeTransport();update(message);
    }
    private void closeTransport(){
        if(nativeStarted){TProxyService.TProxyStopService();nativeStarted=false;}
        if(socks!=null){socks.close();socks=null;}
        if(transport!=null){transport.close();transport=null;}
    }
    private void stopSession(){
        if(destroyed)return;destroyed=true;
        if(ownsSession){
            stopping=true;active=false;
            getSharedPreferences("runtime",MODE_PRIVATE).edit().putBoolean("vpnRequested",false).apply();
            // Android keeps an established VpnService bound. stopSelf/stopService alone
            // cannot reach onDestroy while that binding and the TUN remain alive.
            // Close the TUN on the explicit stop path, before waiting for any HTTPS/RTC work.
            synchronized(tunnelLock){if(tun!=null)try{tun.close();}catch(IOException ignored){}tun=null;}
            status="VPN выключен";stopForeground(STOP_FOREGROUND_REMOVE);
        }
        if(manager!=null&&callback!=null)try{manager.unregisterNetworkCallback(callback);}catch(Exception ignored){}
        worker.execute(()->{
            try{closeTransport();}
            finally{
                if(manager!=null&&callback!=null)try{manager.unregisterNetworkCallback(callback);}catch(Exception ignored){}
                if(configFile!=null)configFile.delete();
                if(ownsSession)stopping=false;
            }
        });worker.shutdown();
    }
    @Override public void onRevoke(){stopSession();stopSelf();}
    @Override public void onDestroy(){stopSession();super.onDestroy();}
}
