package net.phoneexit;

import android.content.Context;
import android.net.*;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class WifiBindingTest {
    private NetworkCapabilities wifiCaps(){
        NetworkCapabilities caps=mock(NetworkCapabilities.class);
        when(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)).thenReturn(true);
        when(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)).thenReturn(true);
        when(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)).thenReturn(true);
        when(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)).thenReturn(true);
        return caps;
    }
    @Test public void deniedExitBindingCanUseOnlySamePhysicalDefaultAndStopsOnChange()throws Exception{
        Context c=mock(Context.class);ConnectivityManager cm=mock(ConnectivityManager.class);
        Network wifi=mock(Network.class),cell=mock(Network.class);Object owner=new Object(),peer=new Object();
        when(c.getSystemService(ConnectivityManager.class)).thenReturn(cm);
        when(cm.getActiveNetwork()).thenReturn(wifi);when(cm.getAllNetworks()).thenReturn(new Network[]{wifi});
        NetworkCapabilities valid=wifiCaps();when(cm.getNetworkCapabilities(wifi)).thenReturn(valid);
        try{
            // The client never initiates an unbound fallback.
            assertFalse(WifiBinding.acquire(c,wifi,owner));
            assertEquals(WifiBinding.Result.ACQUIRED,WifiBinding.acquireExitResult(c,wifi,owner));
            assertTrue(WifiBinding.usesDefaultRoute(c,wifi));
            assertTrue(WifiBinding.acquire(c,wifi,peer));
            when(cm.getActiveNetwork()).thenReturn(cell);
            assertThrows(java.io.IOException.class,()->new ExitNetwork(c,wifi).check());
            assertEquals(WifiBinding.Result.ANDROID_DENIED,WifiBinding.acquireExitResult(c,wifi,new Object()));
        }finally{WifiBinding.release(c,peer);WifiBinding.release(c,owner);}
        verify(cm,never()).bindProcessToNetwork(null);
        assertFalse(WifiBinding.compatible(wifi));
    }
    @Test public void defaultFallbackRejectsVpnUnvalidatedAndDifferentDefault(){
        Context c=mock(Context.class);ConnectivityManager cm=mock(ConnectivityManager.class);
        Network wifi=mock(Network.class),vpn=mock(Network.class);Object owner=new Object();
        when(c.getSystemService(ConnectivityManager.class)).thenReturn(cm);
        when(cm.getActiveNetwork()).thenReturn(wifi);when(cm.getAllNetworks()).thenReturn(new Network[]{wifi,vpn});
        NetworkCapabilities caps=wifiCaps(),vpnCaps=mock(NetworkCapabilities.class);
        when(cm.getNetworkCapabilities(wifi)).thenReturn(caps);when(cm.getNetworkCapabilities(vpn)).thenReturn(vpnCaps);
        when(vpnCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)).thenReturn(true);
        try{
            assertEquals(WifiBinding.Result.ANDROID_DENIED,WifiBinding.acquireExitResult(c,wifi,owner));
            when(cm.getAllNetworks()).thenReturn(new Network[]{wifi});
            when(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)).thenReturn(false);
            assertEquals(WifiBinding.Result.ANDROID_DENIED,WifiBinding.acquireExitResult(c,wifi,owner));
            when(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)).thenReturn(true);
            when(cm.getActiveNetwork()).thenReturn(vpn);
            assertEquals(WifiBinding.Result.ANDROID_DENIED,WifiBinding.acquireExitResult(c,wifi,owner));
            when(cm.getActiveNetwork()).thenReturn(wifi);when(cm.getBoundNetworkForProcess()).thenReturn(vpn);
            assertEquals(WifiBinding.Result.ANDROID_DENIED,WifiBinding.acquireExitResult(c,wifi,owner));
        }finally{WifiBinding.release(c,owner);}
        assertFalse(WifiBinding.compatible(wifi));
    }
    @Test public void lostNetworkOwnersCannotBlockNewNetworkOrUnbindItLater(){
        Context c=mock(Context.class);ConnectivityManager cm=mock(ConnectivityManager.class);
        Network old=mock(Network.class),next=mock(Network.class);Object a=new Object(),b=new Object();
        when(c.getSystemService(ConnectivityManager.class)).thenReturn(cm);
        when(cm.bindProcessToNetwork(old)).thenReturn(true);when(cm.bindProcessToNetwork(next)).thenReturn(true);
        try{
            assertTrue(WifiBinding.acquire(c,old,a));
            when(cm.getNetworkCapabilities(old)).thenReturn(null);
            assertEquals(WifiBinding.Result.ACQUIRED,WifiBinding.acquireResult(c,next,b));
            WifiBinding.release(c,a);verify(cm,never()).bindProcessToNetwork(null);
            WifiBinding.release(c,b);verify(cm,times(1)).bindProcessToNetwork(null);
        }finally{WifiBinding.release(c,a);WifiBinding.release(c,b);}
    }
    @Test public void liveNetworkRemainsOwnedAndAndroidDenialDoesNotReplaceBinding(){
        Context c=mock(Context.class);ConnectivityManager cm=mock(ConnectivityManager.class);
        Network old=mock(Network.class),next=mock(Network.class);Object a=new Object(),b=new Object();
        when(c.getSystemService(ConnectivityManager.class)).thenReturn(cm);
        when(cm.bindProcessToNetwork(old)).thenReturn(true);
        NetworkCapabilities present=mock(NetworkCapabilities.class);
        try{
            assertTrue(WifiBinding.acquire(c,old,a));when(cm.getNetworkCapabilities(old)).thenReturn(present);
            assertEquals(WifiBinding.Result.PREVIOUS_NETWORK,WifiBinding.acquireResult(c,next,b));
            verify(cm,never()).bindProcessToNetwork(next);
            when(cm.getNetworkCapabilities(old)).thenReturn(null);
            assertEquals(WifiBinding.Result.ANDROID_DENIED,WifiBinding.acquireResult(c,next,b));
            WifiBinding.release(c,b);verify(cm,never()).bindProcessToNetwork(null);
        }finally{WifiBinding.release(c,a);WifiBinding.release(c,b);}
    }
}
