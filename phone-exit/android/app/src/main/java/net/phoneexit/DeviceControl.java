package net.phoneexit;
import android.content.*;
import android.content.pm.*;
import android.graphics.Point;
import android.os.Build;
import android.view.WindowManager;
import org.json.*;
import java.util.*;

final class DeviceControl {
    static JSONObject info(Context c)throws Exception{
        Point size=new Point();c.getSystemService(WindowManager.class).getDefaultDisplay().getRealSize(size);
        return new JSONObject().put("manufacturer",Build.MANUFACTURER).put("model",Build.MODEL).put("androidVersion",Build.VERSION.RELEASE).put("androidSdk",Build.VERSION.SDK_INT)
            .put("versionName",BuildConfig.VERSION_NAME).put("versionCode",BuildConfig.VERSION_CODE).put("width",size.x).put("height",size.y)
            .put("frameWidth",Math.round(size.x*Math.min(1f,1280f/Math.max(size.x,size.y)))).put("frameHeight",Math.round(size.y*Math.min(1f,1280f/Math.max(size.x,size.y))))
            .put("screenLocked",c.getSystemService(android.app.KeyguardManager.class).isKeyguardLocked()).put("screenOn",c.getSystemService(android.os.PowerManager.class).isInteractive())
            .put("capabilities",ControlAgent.capabilities(c)).put("networkDiagnostics",networkDiagnostics(c));
    }
    static JSONObject networkDiagnostics(Context c){return NetworkDiagnostics.snapshot(c);}
    static JSONObject apps(Context c,JSONObject args)throws Exception{
        String filter=args.optString("package","");if(!filter.isEmpty()&&!filter.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+"))throw new Exception("invalid_package");
        List<PackageInfo> packages=c.getPackageManager().getInstalledPackages(0);packages.sort(Comparator.comparing(p->p.packageName));JSONArray out=new JSONArray();
        int offset=args.optInt("offset",0),limit=args.optInt("limit",256);if(offset<0||offset>8192||limit<1||limit>256)throw new Exception("invalid_pagination");int total=0;
        for(PackageInfo p:packages){
            if(!filter.isEmpty()&&!p.packageName.equals(filter))continue;int index=total++;
            if(index<offset||out.length()>=limit)continue;
            Intent launch=c.getPackageManager().getLaunchIntentForPackage(p.packageName);
            out.put(new JSONObject().put("package",p.packageName).put("versionName",p.versionName==null?JSONObject.NULL:p.versionName).put("versionCode",Build.VERSION.SDK_INT>=28?p.getLongVersionCode():p.versionCode)
                .put("launchable",launch!=null).put("activity",launch!=null&&launch.getComponent()!=null?launch.getComponent().getClassName():JSONObject.NULL));
        }
        return new JSONObject().put("apps",out).put("total",total).put("offset",offset).put("nextOffset",offset+out.length()<total?offset+out.length():JSONObject.NULL);
    }
}
