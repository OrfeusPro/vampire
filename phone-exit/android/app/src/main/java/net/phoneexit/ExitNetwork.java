package net.phoneexit;

import android.content.Context;
import android.net.Network;
import java.io.IOException;
import java.net.*;
import javax.net.ssl.HttpsURLConnection;

/** Physical Network by default. A denied cloud binding may use the same OS
 * default, only while it remains validated, selected and free of visible VPNs. */
final class ExitNetwork {
    private final Context context;
    private final Network network;
    ExitNetwork(Context context,Network network){this.context=context;this.network=network;}
    void check()throws IOException{WifiBinding.usesDefaultRoute(context,network);}
    HttpsURLConnection connection(URL url)throws IOException{
        return (HttpsURLConnection)(WifiBinding.usesDefaultRoute(context,network)
            ?url.openConnection(Proxy.NO_PROXY):network.openConnection(url));
    }
    InetAddress[] resolve(String host)throws IOException{
        boolean ordinary=WifiBinding.usesDefaultRoute(context,network);
        InetAddress[] addresses=ordinary?InetAddress.getAllByName(host):network.getAllByName(host);
        check();return PublicAddress.ipv4Addresses(addresses);
    }
    Socket socket()throws IOException{
        return WifiBinding.usesDefaultRoute(context,network)?new Socket(Proxy.NO_PROXY):network.getSocketFactory().createSocket();
    }
    void bind(DatagramSocket socket)throws IOException{
        if(!WifiBinding.usesDefaultRoute(context,network))network.bindSocket(socket);
    }
}
