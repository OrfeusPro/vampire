package net.phoneexit;

import android.content.Context;
import android.net.*;
import java.util.*;

/** Native ICE sockets share one process binding; release only the final owner. */
final class WifiBinding {
    private static final Set<Object> owners=Collections.newSetFromMap(new IdentityHashMap<>());
    private static Network network;
    static synchronized boolean acquire(Context context,Network wifi,Object owner){
        if(owners.contains(owner))return wifi.equals(network);
        if(network!=null&&!network.equals(wifi))return false;
        if(network==null&&!context.getSystemService(ConnectivityManager.class).bindProcessToNetwork(wifi))return false;
        network=wifi;owners.add(owner);return true;
    }
    static synchronized void release(Context context,Object owner){
        if(owners.remove(owner)&&owners.isEmpty()){
            context.getSystemService(ConnectivityManager.class).bindProcessToNetwork(null);network=null;
        }
    }
}
