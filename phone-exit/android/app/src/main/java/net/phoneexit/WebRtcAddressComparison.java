package net.phoneexit;

import android.net.Network;
import java.net.*;
import java.util.*;
import org.json.*;

/** Compare IPv4 addresses across different sockets; never compare their ports. */
final class WebRtcAddressComparison {
    static final long MAX_AGE_MS=120_000;
    final Set<InetAddress> addresses;
    final Network network;
    final long capturedNs;
    WebRtcAddressComparison(String sdp,Network network,long capturedNs){
        this.addresses=parse(sdp);this.network=network;this.capturedNs=capturedNs;
    }
    static Set<InetAddress> parse(String sdp){
        LinkedHashSet<InetAddress> values=new LinkedHashSet<>();
        for(String line:sdp.split("\\r?\\n")){
            if(values.size()>=8)break;
            if(!line.startsWith("a=candidate:"))continue;
            String[] fields=line.trim().split("\\s+");
            if(fields.length<8||!fields[1].equals("1")||!fields[2].equalsIgnoreCase("udp")||!fields[6].equals("typ")||!fields[7].equals("srflx"))continue;
            // Numeric IPv4 only. Never resolve candidate hostnames through DNS.
            String[] parts=fields[4].split("\\.",-1);if(parts.length!=4)continue;
            byte[] bytes=new byte[4];boolean valid=true;
            for(int i=0;i<4;i++)try{if(!parts[i].matches("0|[1-9][0-9]{0,2}"))throw new Exception();int n=Integer.parseInt(parts[i]);if(n>255)throw new Exception();bytes[i]=(byte)n;}catch(Exception e){valid=false;break;}
            if(valid)try{InetAddress address=InetAddress.getByAddress(bytes);if(PublicAddress.allowed(address))values.add(address);}catch(Exception ignored){}
        }
        return Collections.unmodifiableSet(values);
    }
    JSONObject compare(InetSocketAddress[] mapped,Network probeNetwork,long nowNs)throws JSONException{
        long age=Math.max(0,(nowNs-capturedNs)/1_000_000);
        JSONObject result=new JSONObject().put("ageMs",age).put("maxAgeMs",MAX_AGE_MS);
        if(age>MAX_AGE_MS)return result.put("result","stale");
        result.put("publicIpv4Count",addresses.size());
        if(addresses.isEmpty())return result.put("result","no_public_candidate");
        if(network==null||probeNetwork==null)return result.put("result","network_unknown");
        if(!network.equals(probeNetwork))return result.put("result","different_network");
        int compared=0,matched=0;Set<InetAddress> observed=new HashSet<>();
        for(InetSocketAddress endpoint:mapped)if(endpoint!=null){compared++;observed.add(endpoint.getAddress());if(addresses.contains(endpoint.getAddress()))matched++;}
        int absent=0;for(InetAddress address:addresses)if(!observed.contains(address))absent++;
        return result.put("comparedResponses",compared).put("matchedResponses",matched)
            .put("unmatchedWebRtcIpv4Count",absent).put("result",compared==0?"no_stun_response":matched==compared?"match":matched==0?"different":"mixed");
    }
}
