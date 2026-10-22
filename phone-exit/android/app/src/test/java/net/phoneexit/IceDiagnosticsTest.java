package net.phoneexit;

import java.util.*;
import org.json.*;
import org.webrtc.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class IceDiagnosticsTest {
    @Test public void statsContainOnlyAllowedCountersAndStates()throws Exception{
        Map<String,Object> members=new HashMap<>();members.put("requestsSent",7);members.put("responsesReceived",0);members.put("state","failed");
        members.put("remoteCandidateId","private-id");members.put("address","private-address");members.put("port",54321);members.put("bytesReceived",-1);
        Map<String,RTCStats> stats=new LinkedHashMap<>();for(int i=0;i<40;i++)stats.put("pair"+i,new RTCStats(1,"candidate-pair","secret-id",members));
        stats.put("candidate",new RTCStats(1,"remote-candidate","secret",members));
        JSONObject result=IceDiagnostics.summarize(new RTCStatsReport(1,stats));assertEquals(40,result.getInt("pairCount"));assertEquals(32,result.getJSONArray("pairs").length());
        JSONObject pair=result.getJSONArray("pairs").getJSONObject(0);assertEquals(7,pair.getInt("requestsSent"));assertFalse(pair.has("bytesReceived"));
        assertFalse(result.toString().contains("private"));assertFalse(result.toString().contains("secret"));assertFalse(result.toString().contains("54321"));
    }
}
