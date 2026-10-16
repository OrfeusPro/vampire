package net.phoneexit;

import android.content.Context;
import android.net.*;
import java.util.*;

/** Native ICE sockets share one process binding; release only the final owner.
 * Both explicitly enabled roles may select Wi-Fi or cellular. */
final class WifiBinding {
    enum Result { ACQUIRED, PREVIOUS_NETWORK, ANDROID_DENIED }
    private static final Set<Object> owners=Collections.newSetFromMap(new IdentityHashMap<>());
    private static Network network;
    private static boolean defaultRoute;
    static synchronized boolean acquire(Context context,Network wifi,Object owner){
        return acquireResult(context,wifi,owner)==Result.ACQUIRED;
    }
    static synchronized Result acquireResult(Context context,Network wifi,Object owner){
        return acquireResult(context,wifi,owner,false);
    }
    /** Exit-only compatibility for cloud Android which cannot bind a Network. */
    static synchronized Result acquireExitResult(Context context,Network wifi,Object owner){
        return acquireResult(context,wifi,owner,true);
    }
    private static Result acquireResult(Context context,Network wifi,Object owner,boolean allowDefault){
        if(network!=null&&network.equals(wifi)&&defaultRoute&&!canUseDefault(context,wifi))return Result.ANDROID_DENIED;
        if(owners.contains(owner))return wifi.equals(network)?Result.ACQUIRED:Result.PREVIOUS_NETWORK;
        ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);
        if(network!=null&&!network.equals(wifi)){
            // Old native factories may finish disposing after Android has removed
            // their Network. Do not let their stale reference count block recovery.
            if(cm.getNetworkCapabilities(network)!=null)return Result.PREVIOUS_NETWORK;
            if(!bind(context,cm,wifi,allowDefault))return Result.ANDROID_DENIED;
            owners.clear();network=wifi;
        }else if(network==null){
            if(!bind(context,cm,wifi,allowDefault))return Result.ANDROID_DENIED;
            network=wifi;
        }
        owners.add(owner);return Result.ACQUIRED;
    }
    private static boolean bind(Context context,ConnectivityManager cm,Network wifi,boolean allowDefault){
        if(cm.bindProcessToNetwork(wifi)){defaultRoute=false;return true;}
        if(!allowDefault||!canUseDefault(context,wifi))return false;
        defaultRoute=true;return true;
    }
    static boolean canUseDefault(Context context,Network selected){
        ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);
        if(selected==null||!selected.equals(cm.getActiveNetwork())||cm.getBoundNetworkForProcess()!=null)return false;
        if(!PeerDirectory.clientUplink(cm.getNetworkCapabilities(selected)))return false;
        Network[] networks=cm.getAllNetworks();if(networks==null)return false;
        for(Network n:networks){NetworkCapabilities caps=cm.getNetworkCapabilities(n);
            if(caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return false;
        }
        return true;
    }
    static synchronized boolean usesDefaultRoute(Context context,Network selected)throws java.io.IOException{
        if(!defaultRoute||!selected.equals(network))return false;
        if(!canUseDefault(context,selected))throw new java.io.IOException("default_network_changed");
        return true;
    }
    static synchronized boolean compatible(Network selected){return defaultRoute&&selected!=null&&selected.equals(network);}
    static synchronized void release(Context context,Object owner){
        if(owners.remove(owner)&&owners.isEmpty()){
            if(!defaultRoute)context.getSystemService(ConnectivityManager.class).bindProcessToNetwork(null);
            network=null;defaultRoute=false;
        }
    }
}
