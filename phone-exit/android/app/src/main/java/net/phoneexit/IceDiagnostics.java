package net.phoneexit;

import java.util.*;
import org.json.*;
import org.webrtc.*;

/** Allowlist only; never serialize RTCStats IDs, addresses or raw members. */
final class IceDiagnostics {
    static JSONObject summarize(RTCStatsReport report)throws JSONException{
        JSONObject result=new JSONObject();JSONArray pairs=new JSONArray();int total=0;
        for(RTCStats stat:report.getStatsMap().values())if("candidate-pair".equals(stat.getType())){
            total++;if(pairs.length()>=32)continue;
            Map<String,Object> members=stat.getMembers();JSONObject pair=new JSONObject();
            Object state=members.get("state");if(Arrays.asList("frozen","waiting","in-progress","failed","succeeded").contains(state))pair.put("state",state);
            Object nominated=members.get("nominated");if(nominated instanceof Boolean)pair.put("nominated",nominated);
            for(String key:new String[]{"requestsSent","requestsReceived","responsesSent","responsesReceived","consentRequestsSent","bytesSent","bytesReceived"}){
                Object value=members.get(key);if(value instanceof Number&&((Number)value).doubleValue()>=0)pair.put(key,value);
            }
            pairs.put(pair);
        }
        return result.put("pairCount",total).put("pairs",pairs);
    }
}
