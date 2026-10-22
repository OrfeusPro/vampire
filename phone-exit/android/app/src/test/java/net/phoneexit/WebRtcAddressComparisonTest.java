package net.phoneexit;

import android.net.Network;
import java.net.*;
import org.json.*;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class WebRtcAddressComparisonTest {
    private static final long AT=1_000_000_000L;
    private String candidate(String address,int port,String type){return "a=candidate:fixture 1 udp 123 "+address+" "+port+" typ "+type+"\r\n";}
    private InetSocketAddress endpoint(int last,int port)throws Exception{return new InetSocketAddress(InetAddress.getByAddress(new byte[]{8,8,8,(byte)last}),port);}
    @Test public void sameAddressOnDifferentSocketPortsMatchesWithoutLeakingEndpoints()throws Exception{
        Network network=mock(Network.class);
        WebRtcAddressComparison snapshot=new WebRtcAddressComparison(candidate("8.8.8.8",30000,"srflx"),network,AT);
        JSONObject result=snapshot.compare(new InetSocketAddress[]{endpoint(8,40000),endpoint(8,40000),endpoint(8,40000)},network,AT+1_000_000);
        assertEquals("match",result.getString("result"));assertEquals(3,result.getInt("matchedResponses"));assertEquals(0,result.getInt("unmatchedWebRtcIpv4Count"));
        String json=result.toString();assertFalse(json.contains("8.8.8.8"));assertFalse(json.contains("30000"));assertFalse(json.contains("40000"));
    }
    @Test public void changedNetworkAndStaleSnapshotCannotClaimAddressMismatch()throws Exception{
        Network network=mock(Network.class),other=mock(Network.class);
        WebRtcAddressComparison snapshot=new WebRtcAddressComparison(candidate("8.8.8.8",30000,"srflx"),network,AT);
        InetSocketAddress[] mapped={endpoint(4,50000)};
        assertEquals("different_network",snapshot.compare(mapped,other,AT).getString("result"));
        assertEquals("network_unknown",snapshot.compare(mapped,null,AT).getString("result"));
        assertEquals("stale",snapshot.compare(mapped,network,AT+(WebRtcAddressComparison.MAX_AGE_MS+1)*1_000_000).getString("result"));
        assertEquals("no_stun_response",snapshot.compare(new InetSocketAddress[]{null},network,AT).getString("result"));
        assertEquals("different",snapshot.compare(mapped,network,AT).getString("result"));
        assertEquals("mixed",snapshot.compare(new InetSocketAddress[]{endpoint(4,50000),endpoint(8,40000)},network,AT).getString("result"));
    }
    @Test public void onlyAnnouncedPublicUdpSrflxIpv4IsUsedWithoutDnsResolution()throws Exception{
        String sdp=candidate("8.8.8.8",30000,"srflx")+candidate("8.8.8.8",30001,"srflx")
            +candidate("1.1.1.1",20000,"host")+candidate("10.0.0.1",30000,"srflx")+candidate("100.64.1.1",30000,"srflx")
            +candidate("localhost",30000,"srflx")+candidate("8.8.8.999",30000,"srflx")+candidate("08.8.8.8",30000,"srflx")
            +candidate("2001:4860:4860::8888",30000,"srflx")+candidate("9.9.9.9",30000,"srflx").replace(" udp "," tcp ");
        assertEquals(1,WebRtcAddressComparison.parse(sdp).size());
        Network network=mock(Network.class);WebRtcAddressComparison empty=new WebRtcAddressComparison("",network,AT);
        assertEquals("no_public_candidate",empty.compare(new InetSocketAddress[]{endpoint(8,40000)},network,AT).getString("result"));
    }
    @Test public void candidateAddressSetIsBounded()throws Exception{
        StringBuilder sdp=new StringBuilder();for(int i=1;i<=20;i++)sdp.append(candidate("8.8.8."+i,30000,"srflx"));
        assertEquals(8,WebRtcAddressComparison.parse(sdp.toString()).size());
    }
}
