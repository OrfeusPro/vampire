package net.phoneexit;

import org.json.*;
import java.util.*;

/** Bounded, session-scoped ICE mailbox; returned only through encrypted control. */
final class ControlIce {
    final String session=PeerDirectory.random(16);
    private final List<JSONObject> items=new ArrayList<>();
    private final Set<String> known=new HashSet<>();
    private boolean closed;
    synchronized void add(String candidate,String mid,int line)throws Exception{
        if(closed||items.size()>=32||candidate.length()>2048||line<0||line>8||mid==null||mid.length()>32)return;
        String key=line+":"+mid+":"+candidate;
        if(!known.add(key))return;
        items.add(new JSONObject().put("candidate",candidate).put("sdpMid",mid).put("sdpMLineIndex",line));
    }
    synchronized JSONObject snapshot(String requested)throws Exception{
        if(!session.equals(requested))throw new Exception("ice_session_changed");
        JSONArray candidates=new JSONArray();for(JSONObject item:items)candidates.put(new JSONObject(item.toString()));
        return new JSONObject().put("iceSession",session).put("closed",closed).put("candidates",candidates);
    }
    synchronized void close(){closed=true;items.clear();known.clear();}
}
