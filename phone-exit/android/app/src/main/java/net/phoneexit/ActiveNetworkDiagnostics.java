package net.phoneexit;

import android.content.Context;
import android.net.Network;
import android.net.DnsResolver;
import android.net.ConnectivityManager;
import android.os.CancellationSignal;
import java.net.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.*;

/** Explicit probes only; no persistence, arbitrary destinations or process rebinding. */
final class ActiveNetworkDiagnostics {
    private static final AtomicBoolean busy=new AtomicBoolean();
    static JSONObject run(Context context)throws Exception{
        if(!busy.compareAndSet(false,true))throw new Exception("network_probe_busy");
        try{
            if(android.os.Build.VERSION.SDK_INT<29)throw new Exception("network_probe_requires_android_10");
            JSONObject result=new JSONObject().put("version",1).put("topology",NetworkDiagnostics.snapshot(context));
            Network preferred=null;try{preferred=PeerDirectory.exitNetwork(context);}catch(Exception ignored){}
            ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);
            Network processNetwork=cm.getBoundNetworkForProcess();if(processNetwork==null)processNetwork=cm.getActiveNetwork();
            JSONArray modes=new JSONArray();
            modes.put(probe(null,processNetwork,"process_default"));
            if(preferred!=null)modes.put(probe(preferred,preferred,"exit_socket_bound"));
            result.put("modes",modes).put("note","mapping_comparison_not_full_nat_classification");return result;
        }finally{busy.set(false);}
    }
    private static JSONObject probe(Network network,Network dnsNetwork,String mode)throws Exception{
        JSONObject result=new JSONObject().put("mode",mode);JSONArray steps=new JSONArray();
        // Fixed public STUN hosts only. DNS uses the same Network as the socket.
        InetSocketAddress[] targets=new InetSocketAddress[2];
        InetSocketAddress[] mapped=new InetSocketAddress[3];long started=System.nanoTime();
        try(DatagramSocket socket=new DatagramSocket(null)){
            socket.bind(new InetSocketAddress(0));if(network!=null)network.bindSocket(socket);
            for(int i=0;i<2;i++)try{targets[i]=new InetSocketAddress(resolve(dnsNetwork,i==0?"stun.cloudflare.com":"stun.l.google.com"),i==0?3478:19302);}catch(Exception ignored){}
            for(int i=0;i<3;i++){
                JSONObject step=new JSONObject().put("target",i==1?"B":"A");long at=System.nanoTime();
                InetSocketAddress target=targets[i==1?1:0];
                try{if(target==null){step.put("status","dns_unavailable");}else{mapped[i]=StunProbe.exchange(socket,target);step.put("status","response");}}
                catch(SocketTimeoutException e){step.put("status","timeout");}
                catch(SecurityException e){step.put("status","denied");}
                catch(Exception e){step.put("status","socket_error");}
                step.put("elapsedMs",(System.nanoTime()-at)/1_000_000);steps.put(step);
            }
            result.put("sameMappingAcrossTargets",mapped[0]!=null&&mapped[1]!=null?mapped[0].equals(mapped[1]):JSONObject.NULL)
                .put("sameMappingOnRepeat",mapped[0]!=null&&mapped[2]!=null?mapped[0].equals(mapped[2]):JSONObject.NULL);
        }catch(SecurityException e){result.put("error","denied");}catch(Exception e){result.put("error","socket_or_binding_error");}
        return result.put("steps",steps).put("elapsedMs",(System.nanoTime()-started)/1_000_000);
    }
    @android.annotation.TargetApi(29)
    private static InetAddress resolve(Network network,String host)throws Exception{
        CountDownLatch done=new CountDownLatch(1);AtomicReference<InetAddress> address=new AtomicReference<>();CancellationSignal cancel=new CancellationSignal();
        try{
            DnsResolver.getInstance().query(network,host,DnsResolver.TYPE_A,DnsResolver.FLAG_EMPTY,Runnable::run,cancel,new DnsResolver.Callback<List<InetAddress>>(){
                public void onAnswer(List<InetAddress> values,int code){if(code==0)for(InetAddress a:values)if(a instanceof Inet4Address&&PublicAddress.allowed(a)){address.set(a);break;}done.countDown();}
                public void onError(DnsResolver.DnsException error){done.countDown();}
            });
            if(!done.await(2,TimeUnit.SECONDS)||address.get()==null)throw new Exception("dns_unavailable");return address.get();
        }finally{cancel.cancel();}
    }
    static String describe(JSONObject result){
        StringBuilder text=new StringBuilder("Проверка UDP/STUN по запросу. До 20 секунд, несколько КБ. Учитывайте расход мобильного интернета.\nA: Cloudflare; B: Google.\n");
        JSONArray modes=result.optJSONArray("modes");if(modes!=null)for(int i=0;i<modes.length();i++){
            JSONObject mode=modes.optJSONObject(i);if(mode==null)continue;
            text.append("\n").append("exit_socket_bound".equals(mode.optString("mode"))?"Сокет привязан к сети выхода":"Текущая сеть процесса (с учётом его привязки)").append("\n");
            if(mode.has("error"))text.append("Не удалось открыть или привязать сокет: ").append(mode.optString("error")).append("\n");
            JSONArray steps=mode.optJSONArray("steps");if(steps!=null)for(int j=0;j<steps.length();j++){
                JSONObject step=steps.optJSONObject(j);text.append("STUN ").append(step.optString("target")).append(": ");
                String status=step.optString("status");text.append("response".equals(status)?"ответ получен":"timeout".equals(status)?"нет ответа":"dns_unavailable".equals(status)?"DNS не ответил или нет публичного IPv4":"denied".equals(status)?"доступ запрещён":"ошибка сокета").append(" · ").append(step.optLong("elapsedMs")).append(" мс\n");
            }
            text.append("Внешнее соответствие одинаково для A и B: ").append(comparison(mode,"sameMappingAcrossTargets"))
                .append("\nСохранилось при повторе A: ").append(comparison(mode,"sameMappingOnRepeat")).append("\n");
        }
        return text.append("\nЭто не полная классификация NAT и не доказательство доступности WebRTC. Отсутствие ответа не доказывает блокировку всего UDP. IP, порты и ключи в отчёте не сохраняются. Привязка процесса и настройки не изменены.").toString();
    }
    private static String comparison(JSONObject value,String key){return value.isNull(key)?"не измерено":value.optBoolean(key)?"да":"нет";}
}
