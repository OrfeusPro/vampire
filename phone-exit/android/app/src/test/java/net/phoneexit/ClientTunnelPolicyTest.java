package net.phoneexit;

import android.net.VpnService;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class ClientTunnelPolicyTest {
    @Test public void exitUsesOnlyIpv4DestinationsAndStillRejectsPrivateAddresses()throws Exception{
        java.net.InetAddress v4=java.net.InetAddress.getByAddress(new byte[]{1,1,1,1});
        byte[] v6=new byte[16];v6[0]=0x26;v6[1]=6;v6[15]=1;
        java.net.InetAddress ipv6=java.net.InetAddress.getByAddress(v6);
        assertArrayEquals(new java.net.InetAddress[]{v4},PublicAddress.ipv4Addresses(new java.net.InetAddress[]{ipv6,v4}));
        assertEquals(0,PublicAddress.ipv4Addresses(new java.net.InetAddress[]{ipv6}).length);
        assertFalse(PublicAddress.allowed(java.net.InetAddress.getByAddress(new byte[]{10,0,0,1})));
    }
    @Test public void unverifiedIpv6IsNotAdvertisedOrAllowedToBypassVpn()throws Exception{
        VpnService.Builder builder=mock(VpnService.Builder.class,RETURNS_SELF);
        assertSame(builder,ClientVpnService.configureTunnel(builder,"net.phoneexit"));
        verify(builder).addAddress("198.18.0.1",30);verify(builder).addRoute("0.0.0.0",0);
        verify(builder).addDnsServer("1.1.1.1");verify(builder).addDisallowedApplication("net.phoneexit");
        verify(builder,never()).addAddress(eq("fdfe:7065::1"),anyInt());
        verify(builder,never()).addRoute(eq("::"),anyInt());
        verify(builder,never()).allowFamily(anyInt());verify(builder,never()).allowBypass();
        assertFalse(ClientVpnService.tunnelConfig(12345).contains("ipv6:"));
    }
}
