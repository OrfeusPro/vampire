package net.phoneexit;

import android.content.Context;
import android.net.*;
import java.io.IOException;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class ClientNetworkTest {
    private NetworkCapabilities caps(int transport,boolean validated,boolean physical){
        NetworkCapabilities c=mock(NetworkCapabilities.class);
        when(c.hasTransport(transport)).thenReturn(true);
        when(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)).thenReturn(true);
        when(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)).thenReturn(validated);
        when(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)).thenReturn(physical);
        return c;
    }
    @Test public void bothRolesCanUseCellularWithoutWifi()throws Exception{
        Context context=mock(Context.class);ConnectivityManager cm=mock(ConnectivityManager.class);Network cell=mock(Network.class);
        when(context.getSystemService(ConnectivityManager.class)).thenReturn(cm);
        when(cm.getActiveNetwork()).thenReturn(cell);when(cm.getAllNetworks()).thenReturn(new Network[]{cell});
        doReturn(caps(NetworkCapabilities.TRANSPORT_CELLULAR,true,true)).when(cm).getNetworkCapabilities(cell);
        assertSame(cell,PeerDirectory.clientNetwork(context));
        assertSame(cell,PeerDirectory.internetNetwork(context));
        assertThrows(IOException.class,()->PeerDirectory.wifi(context));
    }
    @Test public void clientIgnoresOwnVpnAndUnvalidatedNetworks()throws Exception{
        Context context=mock(Context.class);ConnectivityManager cm=mock(ConnectivityManager.class);
        Network vpn=mock(Network.class),wifi=mock(Network.class),cell=mock(Network.class);
        when(context.getSystemService(ConnectivityManager.class)).thenReturn(cm);
        when(cm.getActiveNetwork()).thenReturn(vpn);when(cm.getAllNetworks()).thenReturn(new Network[]{vpn,wifi,cell});
        doReturn(caps(NetworkCapabilities.TRANSPORT_CELLULAR,true,false)).when(cm).getNetworkCapabilities(vpn);
        doReturn(caps(NetworkCapabilities.TRANSPORT_WIFI,false,true)).when(cm).getNetworkCapabilities(wifi);
        doReturn(caps(NetworkCapabilities.TRANSPORT_CELLULAR,true,true)).when(cm).getNetworkCapabilities(cell);
        assertSame(cell,PeerDirectory.clientNetwork(context));
        when(cm.getNetworkCapabilities(cell)).thenReturn(null);
        assertThrows(IOException.class,()->PeerDirectory.clientNetwork(context));
    }
    @Test public void wifiHasPriorityEvenWhenAndroidDefaultIsCellular()throws Exception{
        Context context=mock(Context.class);ConnectivityManager cm=mock(ConnectivityManager.class);
        Network wifi=mock(Network.class),cell=mock(Network.class);
        when(context.getSystemService(ConnectivityManager.class)).thenReturn(cm);
        when(cm.getActiveNetwork()).thenReturn(cell);when(cm.getAllNetworks()).thenReturn(new Network[]{cell,wifi});
        doReturn(caps(NetworkCapabilities.TRANSPORT_WIFI,true,true)).when(cm).getNetworkCapabilities(wifi);
        doReturn(caps(NetworkCapabilities.TRANSPORT_CELLULAR,true,true)).when(cm).getNetworkCapabilities(cell);
        assertSame(wifi,PeerDirectory.clientNetwork(context));assertSame(wifi,PeerDirectory.internetNetwork(context));
        when(cm.getActiveNetwork()).thenReturn(null);
        assertSame(wifi,PeerDirectory.clientNetwork(context));assertSame(wifi,PeerDirectory.wifi(context));
        doReturn(caps(NetworkCapabilities.TRANSPORT_WIFI,false,true)).when(cm).getNetworkCapabilities(wifi);
        assertSame(cell,PeerDirectory.internetNetwork(context));
    }
}
