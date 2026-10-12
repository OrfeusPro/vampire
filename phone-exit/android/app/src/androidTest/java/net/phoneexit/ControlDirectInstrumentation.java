package net.phoneexit;

import android.content.*;
import android.net.*;
import android.app.Instrumentation;
import android.os.Bundle;
import java.io.*;
import java.nio.charset.StandardCharsets;
import org.json.*;

/** USB supplies SDP only; all commands/results still cross real native WebRTC. */
public final class ControlDirectInstrumentation extends Instrumentation {
    @Override public void onCreate(Bundle b){super.onCreate(b);start();}
    @Override public void onStart(){Bundle result=new Bundle();try{testDirectChannel();result.putString("stream","PASS native Android control test");finish(0,result);}catch(Exception e){String message=e.getMessage();result.putString("stream","FAIL "+e.getClass().getSimpleName()+" "+(message!=null&&message.matches("[a-z_]{1,80}")?message:""));finish(1,result);}}
    private void assertNotNull(Object v){if(v==null)throw new IllegalStateException();}
    private void assertTrue(boolean v){if(!v)throw new IllegalStateException();}
    public void testDirectChannel()throws Exception{
        Context c=getTargetContext();
        DirectoryConfig config=DirectoryConfig.load(c);assertNotNull(config);assertTrue(ExitService.enabled(c));
        Network wifi=null;ConnectivityManager cm=c.getSystemService(ConnectivityManager.class);
        for(Network n:cm.getAllNetworks()){NetworkCapabilities caps=cm.getNetworkCapabilities(n);if(caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)&&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)){wifi=n;break;}}
        assertNotNull(wifi);
        c.startForegroundService(new Intent(c,ExitService.class));
        long permissionDeadline=System.currentTimeMillis()+10000;
        while(ControlAccessibility.current==null&&System.currentTimeMillis()<permissionDeadline)Thread.sleep(100);
        assertNotNull(ControlAccessibility.current);
        File offer=new File(c.getFilesDir(),"control-test-offer.json"),output=new File(c.getFilesDir(),"control-test-answer.json"),stop=new File(c.getFilesDir(),"control-test-stop");
        ControlAgent agent=new ControlAgent(c,wifi,config);ControlPeer peer=new ControlPeer(agent);
        DirectoryAgent statusAgent=new DirectoryAgent(c,wifi,config,()->{});
        java.lang.reflect.Field peerField=ControlAgent.class.getDeclaredField("direct");peerField.setAccessible(true);peerField.set(agent,peer);
        java.lang.reflect.Field controlField=DirectoryAgent.class.getDeclaredField("control");controlField.setAccessible(true);controlField.set(statusAgent,agent);
        java.lang.reflect.Field failures=DirectoryAgent.class.getDeclaredField("failures");failures.setAccessible(true);
        java.lang.reflect.Method waiting=DirectoryAgent.class.getDeclaredMethod("waiting");waiting.setAccessible(true);
        boolean statusChecked=false;
        try{
            JSONObject value;try(FileInputStream in=new FileInputStream(offer)){value=new JSONObject(ControlAgent.read(in,12000));}
            JSONObject answer=peer.connect(value.getString("sdp"));answer.put("id",config.id);
            try(FileOutputStream out=new FileOutputStream(output)){out.write(answer.toString().getBytes(StandardCharsets.UTF_8));}
            File reoffer=new File(c.getFilesDir(),"control-test-reoffer.json");
            long deadline=System.currentTimeMillis()+180000;
            while(!stop.exists()&&System.currentTimeMillis()<deadline){
                if(reoffer.exists()){
                    JSONObject next;try(FileInputStream in=new FileInputStream(reoffer)){next=new JSONObject(ControlAgent.read(in,12000));}reoffer.delete();
                    JSONObject response=agent.process(new JSONObject().put("id",config.id).put("request",java.util.UUID.randomUUID().toString().replace("-","")).put("at",System.currentTimeMillis()).put("command","connectControl").put("args",next));
                    if(!response.getBoolean("ok"))throw new IllegalStateException(response.optString("error","reconnect_failed"));JSONObject nextAnswer=response.getJSONObject("result").put("id",config.id);
                    try(FileOutputStream out=new FileOutputStream(output)){out.write(nextAnswer.toString().getBytes(StandardCharsets.UTF_8));}
                }
                if(peer.open()&&!statusChecked){
                    failures.setInt(statusAgent,1);waiting.invoke(statusAgent);assertTrue(ExitService.status.contains("Прямое управление подключено")&&ExitService.status.contains("каталог временно недоступен"));
                    failures.setInt(statusAgent,0);waiting.invoke(statusAgent);assertTrue(ExitService.status.equals("Прямое управление подключено"));statusChecked=true;
                }Thread.sleep(100);
            }
            assertTrue(statusChecked);
            assertTrue(stop.exists());
        }finally{statusAgent.close();peer.close();agent.close();offer.delete();output.delete();stop.delete();new File(c.getFilesDir(),"control-test-reoffer.json").delete();}
    }
}
