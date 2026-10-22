package net.phoneexit;

import android.content.Context;
import android.net.*;
import java.util.*;
import org.json.*;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class NetworkDiagnosticsTest {
    @Test public void duplicateInterfaceNetworksKeepTheirOwnRolesAndValidation()throws Exception{
        Context c=mock(Context.class);ConnectivityManager cm=mock(ConnectivityManager.class);
        Network stale=mock(Network.class),live=mock(Network.class);NetworkCapabilities bad=caps(false),good=caps(true);
        when(c.getSystemService(ConnectivityManager.class)).thenReturn(cm);
        when(cm.getActiveNetwork()).thenReturn(live);when(cm.getBoundNetworkForProcess()).thenReturn(live);
        when(cm.getAllNetworks()).thenReturn(new Network[]{stale,live});
        when(cm.getNetworkCapabilities(stale)).thenReturn(bad);when(cm.getNetworkCapabilities(live)).thenReturn(good);
        for(Network n:new Network[]{stale,live}){
            LinkProperties properties=mock(LinkProperties.class);when(properties.getInterfaceName()).thenReturn("wlan0");
            when(properties.getLinkAddresses()).thenReturn(Collections.emptyList());when(properties.getDnsServers()).thenReturn(Collections.emptyList());
            when(properties.getRoutes()).thenReturn(Collections.emptyList());when(cm.getLinkProperties(n)).thenReturn(properties);
        }
        JSONObject result=NetworkDiagnostics.snapshot(c);assertTrue(result.getBoolean("available"));
        JSONArray rows=result.getJSONArray("networks");assertEquals(2,rows.length());
        assertEquals(rows.getJSONObject(0).getString("interface"),rows.getJSONObject(1).getString("interface"));
        assertFalse(rows.getJSONObject(0).getBoolean("preferred"));assertFalse(rows.getJSONObject(0).getBoolean("eligible"));
        assertTrue(rows.getJSONObject(1).getBoolean("preferred"));assertTrue(rows.getJSONObject(1).getBoolean("processBound"));
        assertTrue(rows.getJSONObject(1).getBoolean("systemDefault"));
        String text=NetworkDiagnostics.describe(result);assertTrue(text.contains("Сеть №1"));assertTrue(text.contains("Сеть №2"));
        assertFalse(result.toString().contains("ssid"));assertFalse(result.toString().contains("iceSession"));
    }
    private NetworkCapabilities caps(boolean validated){
        NetworkCapabilities c=mock(NetworkCapabilities.class);when(c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)).thenReturn(true);
        when(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)).thenReturn(true);
        when(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)).thenReturn(true);
        when(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)).thenReturn(validated);return c;
    }
}
