package net.phoneexit;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.util.*;

public class PeerProtocolTest {
    private static final String KEY="a1".repeat(32),LABEL="phone-exit-peer-directory-v1";
    @Test public void encryptedDiscoveryRoundTripAndRandomIv()throws Exception{
        JSONObject value=new JSONObject().put("name","Личный телефон").put("token","b2".repeat(32));
        JSONObject one=PersonalAccount.secretBox(KEY,LABEL,value,null),two=PersonalAccount.secretBox(KEY,LABEL,value,null);
        assertNotEquals(one.getString("iv"),two.getString("iv"));assertFalse(one.toString().contains("Личный"));
        assertEquals(value.toString(),PersonalAccount.secretBox(KEY,LABEL,null,one).toString());
    }
    @Test public void wrongAccountTamperingAndProtocolConfusionRejected()throws Exception{
        JSONObject box=PersonalAccount.secretBox(KEY,LABEL,new JSONObject().put("id","c3".repeat(16)),null);
        assertThrows(Exception.class,()->PersonalAccount.secretBox("b2".repeat(32),LABEL,null,box));
        assertThrows(Exception.class,()->PersonalAccount.secretBox(KEY,"phone-exit-connect-v1",null,box));
        byte[] data=Base64.getDecoder().decode(box.getString("data"));data[0]^=1;
        box.put("data",Base64.getEncoder().encodeToString(data));assertThrows(Exception.class,()->PersonalAccount.secretBox(KEY,LABEL,null,box));
    }
    @Test public void connectRequestUsesExistingExitDecryption()throws Exception{
        // Java crypto independently verifies the exact old request key/AAD contract.
        String label="phone-exit-connect-v1";
        JSONObject box=PersonalAccount.secretBox(KEY,label,new JSONObject().put("request","42"),null);
        java.security.MessageDigest hash=java.security.MessageDigest.getInstance("SHA-256");hash.update(label.getBytes(java.nio.charset.StandardCharsets.UTF_8));byte[] key=new byte[32];Arrays.fill(key,(byte)0xa1);hash.update(key);
        javax.crypto.Cipher cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE,new javax.crypto.spec.SecretKeySpec(hash.digest(),"AES"),new javax.crypto.spec.GCMParameterSpec(128,Base64.getDecoder().decode(box.getString("iv"))));cipher.updateAAD(label.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertEquals("42",new JSONObject(new String(cipher.doFinal(Base64.getDecoder().decode(box.getString("data"))),java.nio.charset.StandardCharsets.UTF_8)).getString("request"));
    }
    @Test public void malformedBoxesAreBounded()throws Exception{
        assertThrows(Exception.class,()->PersonalAccount.secretBox(KEY,LABEL,null,new JSONObject().put("iv","A".repeat(33)).put("data","AAAA")));
        assertThrows(Exception.class,()->PersonalAccount.secretBox(KEY,LABEL,null,new JSONObject().put("iv","AAAA").put("data","A".repeat(4097))));
        assertThrows(Exception.class,()->PersonalAccount.secretBox("bad",LABEL,new JSONObject(),null));
    }
    @Test public void datagramBoundariesAddressFamiliesAndFragments(){
        byte[] ipv4={0,0,0,1,1,1,1,1,0,53,9};assertTrue(SocksDatagram.valid(ipv4));
        byte[] ipv6=new byte[23];ipv6[3]=4;ipv6[20]=1;assertTrue(SocksDatagram.valid(ipv6));
        byte[] name={0,0,0,3,3,'a','.','b',0,53,9};assertTrue(SocksDatagram.valid(name));
        for(int i=0;i<ipv4.length;i++)assertFalse(SocksDatagram.valid(Arrays.copyOf(ipv4,i)));
        ipv4[2]=1;assertFalse(SocksDatagram.valid(ipv4));ipv4[2]=0;ipv4[9]=0;assertFalse(SocksDatagram.valid(ipv4));
        name[5]=(byte)0xff;assertFalse(SocksDatagram.valid(name));assertFalse(SocksDatagram.valid(new byte[1401]));
    }
    private JSONObject record(String id,long at)throws Exception{return new JSONObject().put("id",id).put("name","Личный телефон").put("role","exit").put("busy",false).put("at",at).put("signal","https://demochko.com/phone-exit/signal.php").put("token","b2".repeat(32)).put("country","UA");}
    private JSONObject entry(JSONObject value)throws Exception{return new JSONObject().put("id",value.getString("id")).put("box",new JSONObject().put("peer",PersonalAccount.secretBox(KEY,LABEL,value,null)));}
    @Test public void discoveryFiltersSelfStaleFutureOldAndOtherAccount()throws Exception{
        long now=1770000000000L;String own="11".repeat(16),other="22".repeat(16);
        JSONArray array=new JSONArray().put(entry(record(own,now))).put(entry(record(other,now)))
            .put(entry(record("33".repeat(16),now-45001))).put(entry(record("44".repeat(16),now+45001)))
            .put(entry(record("55".repeat(16),Long.MIN_VALUE))).put(new JSONObject().put("id","66".repeat(16)).put("box",new JSONObject()));
        assertEquals(other,PeerDirectory.decode(array,own,KEY,now).get(0).getString("id"));assertEquals(1,PeerDirectory.decode(array,own,KEY,now).size());
        assertTrue(PeerDirectory.decode(array,own,"00".repeat(32),now).isEmpty());
    }
    @Test public void mismatchedIdBadEndpointTokenAndRoleRejected()throws Exception{
        long now=1770000000000L;JSONObject good=record("22".repeat(16),now);
        for(JSONObject bad:new JSONObject[]{new JSONObject(good.toString()).put("role","client"),new JSONObject(good.toString()).put("token","short"),new JSONObject(good.toString()).put("signal","https://evil.example/signal.php"),new JSONObject(good.toString()).put("signal","http://demochko.com/phone-exit/signal.php"),new JSONObject(good.toString()).put("name","a".repeat(41))})
            assertTrue(PeerDirectory.decode(new JSONArray().put(entry(bad)),"11".repeat(16),KEY,now).isEmpty());
        assertTrue(PeerDirectory.decode(new JSONArray().put(entry(good).put("id","33".repeat(16))),"11".repeat(16),KEY,now).isEmpty());
    }
    @Test public void busyRetainedUnknownCountryNormalizedAndLimitEnforced()throws Exception{
        long now=1770000000000L;JSONObject good=record("22".repeat(16),now).put("busy",true).put("country","unknown");
        JSONObject result=PeerDirectory.decode(new JSONArray().put(entry(good)),"11".repeat(16),KEY,now).get(0);assertTrue(result.getBoolean("busy"));assertEquals("",result.getString("country"));
        JSONArray huge=new JSONArray();for(int i=0;i<257;i++)huge.put(new JSONObject());assertThrows(Exception.class,()->PeerDirectory.decode(huge,"11".repeat(16),KEY,now));
    }
}
