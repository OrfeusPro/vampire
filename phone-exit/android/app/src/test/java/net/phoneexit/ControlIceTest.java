package net.phoneexit;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;

public class ControlIceTest {
    @Test public void lateCandidatesAreBoundedUniqueAndSessionScoped()throws Exception{
        ControlIce ice=new ControlIce();
        ice.add("candidate:first","0",0);
        assertEquals(1,ice.snapshot(ice.session).getJSONArray("candidates").length());
        ice.add("candidate:first","0",0);ice.add("candidate:late","0",0);
        assertEquals(2,ice.snapshot(ice.session).getJSONArray("candidates").length());
        assertThrows(Exception.class,()->ice.snapshot("other_session"));
        JSONArray copy=ice.snapshot(ice.session).getJSONArray("candidates");copy.getJSONObject(0).put("candidate","changed");
        assertEquals("candidate:first",ice.snapshot(ice.session).getJSONArray("candidates").getJSONObject(0).getString("candidate"));
        for(int i=0;i<100;i++)ice.add("candidate:"+i,"0",0);
        assertEquals(32,ice.snapshot(ice.session).getJSONArray("candidates").length());
        ice.close();ice.add("candidate:after_close","0",0);
        assertTrue(ice.snapshot(ice.session).getBoolean("closed"));
        assertEquals(0,ice.snapshot(ice.session).getJSONArray("candidates").length());
    }
}
