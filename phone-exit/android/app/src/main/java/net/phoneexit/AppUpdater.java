package net.phoneexit;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import java.io.*;
import java.security.*;
import java.util.*;
import javax.net.ssl.HttpsURLConnection;
import org.json.*;

final class AppUpdater {
    private static final long MAX=60000000;
    static JSONObject state(Context c)throws Exception{
        android.content.SharedPreferences p=c.getSharedPreferences("update",Context.MODE_PRIVATE);
        boolean ready=p.getInt("code",0)>BuildConfig.VERSION_CODE&&new File(c.getCacheDir(),"phone-exit-update.apk").isFile();
        String status=p.getString("status","idle");if(!ready&&status.equals("ready_for_confirmation"))status="current";
        return new JSONObject().put("status",ready?"ready_for_confirmation":status).put("availableVersion",ready?p.getString("name",""):JSONObject.NULL).put("autoDownload",c.getSharedPreferences("control",Context.MODE_PRIVATE).getBoolean("autoUpdate",true)).put("silentInstall",false);
    }
    static void check(ControlAgent agent)throws Exception{
        Context c=agent.context;android.content.SharedPreferences p=c.getSharedPreferences("update",Context.MODE_PRIVATE);
        try{
            JSONObject meta;
            HttpsURLConnection m=agent.connection(new JSONObject().put("op","manifest"));
            try{int status=m.getResponseCode();if(status==404){p.edit().putString("status","no_release").apply();return;}if(status!=200)throw new IOException("update_http");meta=new JSONObject(ControlAgent.read(m.getInputStream(),4096));}finally{m.disconnect();}
            int code=meta.getInt("versionCode");String name=meta.getString("versionName"),hash=meta.getString("sha256");long size=meta.getLong("size");
            if(code<=BuildConfig.VERSION_CODE){p.edit().putString("status","current").remove("code").apply();new File(c.getCacheDir(),"phone-exit-update.apk").delete();return;}
            if(!hash.matches("[a-f0-9]{64}")||size<1||size>MAX||name.length()>32)throw new IOException("invalid_update_manifest");
            File ready=new File(c.getCacheDir(),"phone-exit-update.apk");
            if(p.getInt("code",0)==code&&hash.equals(p.getString("sha256",""))&&ready.isFile()&&ready.length()==size){verify(c,ready,code,hash);return;}
            p.edit().putString("status","downloading").apply();File tmp=new File(c.getCacheDir(),"phone-exit-update.tmp");
            HttpsURLConnection download=agent.connection(new JSONObject().put("op","package").put("sha256",hash));download.setReadTimeout(15000);
            try{
                if(download.getResponseCode()!=200)throw new IOException("update_http");
                try(InputStream in=download.getInputStream();OutputStream out=new FileOutputStream(tmp)){
                    byte[] buffer=new byte[65536];long total=0,started=System.nanoTime();int n;
                    while((n=in.read(buffer))!=-1){if(!agent.active())throw new IOException("wifi_lost");if(System.nanoTime()-started>java.util.concurrent.TimeUnit.SECONDS.toNanos(90))throw new IOException("update_timeout");total+=n;if(total>size||total>MAX)throw new IOException("update_size");out.write(buffer,0,n);}
                    if(total!=size)throw new IOException("update_size");
                }
                verify(c,tmp,code,hash);
                if(!agent.active())throw new IOException("wifi_lost");
                if(!tmp.renameTo(ready))throw new IOException("update_storage");
                p.edit().putInt("code",code).putString("name",name).putString("sha256",hash).putString("status","ready_for_confirmation").apply();notifyReady(c);
            }finally{download.disconnect();tmp.delete();}
        }catch(Exception e){p.edit().putString("status","check_or_download_failed").apply();throw e;}
    }
    private static String sha(File file)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");try(InputStream in=new FileInputStream(file)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)d.update(b,0,n);}
        StringBuilder out=new StringBuilder();for(byte b:d.digest())out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();
    }
    @SuppressWarnings("deprecation") private static void verify(Context c,File file,int code,String hash)throws Exception{
        if(!sha(file).equals(hash))throw new IOException("update_hash");
        PackageManager pm=c.getPackageManager();int flags=Build.VERSION.SDK_INT>=28?PackageManager.GET_SIGNING_CERTIFICATES:PackageManager.GET_SIGNATURES;
        PackageInfo apk=pm.getPackageArchiveInfo(file.getAbsolutePath(),flags),installed=pm.getPackageInfo(c.getPackageName(),flags);
        if(apk==null||!c.getPackageName().equals(apk.packageName)||apk.versionCode!=code||code<=BuildConfig.VERSION_CODE)throw new IOException("update_package");
        android.content.pm.Signature[] a=Build.VERSION.SDK_INT>=28?apk.signingInfo.getApkContentsSigners():apk.signatures,b=Build.VERSION.SDK_INT>=28?installed.signingInfo.getApkContentsSigners():installed.signatures;
        if(a==null||b==null||a.length!=1||b.length!=1||!a[0].equals(b[0]))throw new IOException("update_signature");
    }
    static void notifyReady(Context c)throws Exception{
        if(!state(c).optString("status").equals("ready_for_confirmation"))return;
        NotificationManager nm=c.getSystemService(NotificationManager.class);nm.createNotificationChannel(new NotificationChannel("updates","Обновления Phone Exit",NotificationManager.IMPORTANCE_DEFAULT));
        PendingIntent open=PendingIntent.getActivity(c,52,new Intent(c,MainActivity.class).putExtra("update",true),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        nm.notify(52,new Notification.Builder(c,"updates").setSmallIcon(net.phoneexit.R.drawable.ic_exit_notification).setContentTitle("Обновление Phone Exit готово")
            .setContentText("Откройте приложение и подтвердите установку новой версии").setContentIntent(open).setAutoCancel(true).build());
    }
    static void install(Activity activity)throws Exception{
        android.content.SharedPreferences p=activity.getSharedPreferences("update",Context.MODE_PRIVATE);File file=new File(activity.getCacheDir(),"phone-exit-update.apk");
        verify(activity,file,p.getInt("code",0),p.getString("sha256",""));
        if(!activity.getPackageManager().canRequestPackageInstalls()){
            activity.startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,Uri.parse("package:"+activity.getPackageName())));return;
        }
        Intent intent=new Intent(Intent.ACTION_VIEW).setDataAndType(Uri.parse("content://"+activity.getPackageName()+".updates/apk"),"application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        activity.startActivity(intent);
    }
}
