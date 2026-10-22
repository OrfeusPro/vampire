package net.phoneexit;

import android.app.Instrumentation;
import android.content.*;
import android.net.VpnService;
import android.os.Bundle;
import java.io.File;
import org.json.JSONObject;

/** ADB-only test runner: retains actual VPN while a separate UID probes its routes. */
public final class SystemVpnInstrumentation extends Instrumentation {
    private String targetName="realme RMX3830",targetCountry="JP";
    @Override public void onCreate(Bundle args){super.onCreate(args);
        if(args!=null){targetName=args.getString("phone",targetName);targetCountry=args.getString("country",targetCountry);}start();}
    @Override public void onStart(){
        Context c=getTargetContext();Bundle result=new Bundle();boolean restore=ExitService.enabled(c),started=false;
        File stop=new File(c.getFilesDir(),"system-vpn-test-stop");stop.delete();
        try{
            if(ClientVpnService.active||ClientVpnService.requested(c))throw new IllegalStateException("session_busy");
            if(VpnService.prepare(c)!=null)throw new IllegalStateException("vpn_consent_required");
            DirectoryConfig config=DirectoryConfig.load(c);JSONObject selected=null;
            int matches=0;
            for(JSONObject phone:PeerDirectory.list(PeerDirectory.clientNetwork(c),config))if(targetName.equals(phone.optString("name"))&&targetCountry.equals(phone.optString("country"))&&!phone.optBoolean("busy")){selected=phone;matches++;}
            if(matches>1)throw new IllegalStateException("ambiguous_exit");
            if(selected==null)throw new IllegalStateException("exit_unavailable");
            c.startForegroundService(new Intent(c,ClientVpnService.class).putExtra("target",selected.getString("id")));
            started=true;
            long deadline=android.os.SystemClock.elapsedRealtime()+65000;
            while(android.os.SystemClock.elapsedRealtime()<deadline&&!ClientVpnService.status.startsWith("Подключено")){
                if(ClientVpnService.status.contains("не установлена")||ClientVpnService.status.startsWith("Нет связи"))throw new IllegalStateException("vpn_failed");
                Thread.sleep(200);
            }
            if(!ClientVpnService.status.startsWith("Подключено"))throw new IllegalStateException("vpn_timeout");
            Bundle ready=new Bundle();ready.putString("stream","READY actual Android VPN via selected phone");sendStatus(1,ready);
            deadline=android.os.SystemClock.elapsedRealtime()+90000;
            while(!stop.exists()&&android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(200);
            if(!stop.exists())throw new IllegalStateException("probe_timeout");
            result.putString("stream","PASS system VPN test session completed");
        }catch(Exception e){String reason=e.getMessage();result.putString("stream","FAIL "+e.getClass().getSimpleName()+" "+(reason!=null&&reason.matches("[a-z_]{1,40}")?reason:""));}
        finally{
            if(started)ClientVpnService.stop(c);stop.delete();
            try{long deadline=android.os.SystemClock.elapsedRealtime()+10000;while(started&&(ClientVpnService.active||ClientVpnService.requested(c)||ClientVpnService.stopping)&&android.os.SystemClock.elapsedRealtime()<deadline)Thread.sleep(100);}catch(InterruptedException e){Thread.currentThread().interrupt();}
            if(started&&restore){c.getSharedPreferences("runtime",Context.MODE_PRIVATE).edit().putBoolean("enabled",true).apply();c.startForegroundService(new Intent(c,ExitService.class));}
            finish(result.getString("stream","").startsWith("PASS")?0:1,result);
        }
    }
}
