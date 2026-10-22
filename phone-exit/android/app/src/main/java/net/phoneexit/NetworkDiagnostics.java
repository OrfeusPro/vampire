package net.phoneexit;

import android.content.Context;
import android.net.*;
import java.net.*;
import java.util.*;
import org.json.*;

/** On-demand topology only: no IPs, SSIDs, MACs, DNS addresses or ICE secrets. */
final class NetworkDiagnostics {
    static String describe(JSONObject snapshot){
        if(!snapshot.optBoolean("available"))return "Android не предоставил сведения о сетях. Повторите проверку.";
        StringBuilder text=new StringBuilder("Снимок сетей по запросу. Номера действуют только в этом снимке.\n");
        text.append("Режим привязки: ").append(snapshot.optString("bindingMode")).append("\n");
        JSONArray rows=snapshot.optJSONArray("networks");
        if(rows==null||rows.length()==0)text.append("Сети не обнаружены.\n");
        if(rows!=null)for(int i=0;i<rows.length();i++){
            JSONObject r=rows.optJSONObject(i);if(r==null)continue;
            text.append("\nСеть №").append(r.optInt("network")).append(" · ")
                .append(r.optBoolean("wifi")?"Wi-Fi":r.optBoolean("cellular")?"Мобильная":r.optBoolean("vpn")?"VPN":"Другая")
                .append(" · ").append(r.optString("interface","—")).append("\n");
            if(r.optBoolean("systemDefault"))text.append("Основная сеть Android\n");
            if(r.optBoolean("preferred"))text.append("Предпочтена Phone Exit при новом выборе\n");
            if(r.optBoolean("managed"))text.append("Выбрана работающим транспортом Phone Exit\n");
            if(r.optBoolean("processBound"))text.append("К ней привязан процесс приложения\n");
            text.append("Доступ к интернету подтверждён: ").append(r.optBoolean("validated")?"да":"нет")
                .append("\nПодходит для выхода: ").append(r.optBoolean("eligible")?"да":"нет")
                .append("\nIPv4 / IPv6 адресов: ").append(r.optInt("ipv4Count")).append(" / ").append(r.optInt("ipv6Count"))
                .append("\nDNS IPv4 / IPv6: ").append(r.optInt("dnsIpv4Count")).append(" / ").append(r.optInt("dnsIpv6Count"))
                .append("\nМаршрут IPv4 по умолчанию: ").append(r.optBoolean("defaultIpv4Route")?"есть":"нет")
                .append("\nMTU: ").append(r.optString("mtu","не предоставлен")).append("\n");
        }
        return text.append("\nСостояние Android не доказывает проходимость NAT или прямого WebRTC. IP-адреса, имена Wi-Fi и ключи здесь не собираются.").toString();
    }
    static JSONObject snapshot(Context context){
        JSONObject result=new JSONObject();
        try{
            ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);
            Network active=cm.getActiveNetwork(),bound=cm.getBoundNetworkForProcess(),managed=WifiBinding.selectedNetwork(),preferred=null;
            try{preferred=PeerDirectory.internetNetwork(context);}catch(java.io.IOException ignored){}
            LinkedHashSet<Network> all=new LinkedHashSet<>(Arrays.asList(cm.getAllNetworks()));
            for(Network n:new Network[]{active,bound,managed,preferred})if(n!=null)all.add(n);
            JSONArray rows=new JSONArray(),wifi=new JSONArray();int index=0;
            for(Network n:all){
                if(index>=32)break;
                NetworkCapabilities caps=cm.getNetworkCapabilities(n);LinkProperties link=cm.getLinkProperties(n);
                String name=link==null?null:link.getInterfaceName();
                JSONObject row=new JSONObject().put("network",++index).put("systemDefault",n.equals(active))
                    .put("processBound",n.equals(bound)).put("managed",n.equals(managed)).put("preferred",n.equals(preferred))
                    .put("interface",name==null?JSONObject.NULL:name).put("available",caps!=null)
                    .put("wifi",caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
                    .put("cellular",caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
                    .put("vpn",caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
                    .put("internet",caps!=null&&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
                    .put("validated",caps!=null&&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
                    .put("notVpn",caps!=null&&caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
                    .put("eligible",PeerDirectory.clientUplink(caps));
                int v4=0,v6=0,dns4=0,dns6=0;boolean route4=false;
                if(link!=null){
                    for(LinkAddress a:link.getLinkAddresses())if(a.getAddress() instanceof Inet4Address)v4++;else if(a.getAddress() instanceof Inet6Address)v6++;
                    for(InetAddress a:link.getDnsServers())if(a instanceof Inet4Address)dns4++;else if(a instanceof Inet6Address)dns6++;
                    for(RouteInfo route:link.getRoutes())if(route.isDefaultRoute()&&route.getDestination().getAddress() instanceof Inet4Address)route4=true;
                }
                row.put("ipv4Count",v4).put("ipv6Count",v6).put("dnsIpv4Count",dns4).put("dnsIpv6Count",dns6)
                    .put("defaultIpv4Route",route4).put("mtu",link==null||android.os.Build.VERSION.SDK_INT<29?JSONObject.NULL:link.getMtu());rows.put(row);
                if(row.getBoolean("wifi"))wifi.put(new JSONObject().put("network",index).put("interface",name==null?JSONObject.NULL:name)
                    .put("nativeInterfacePresent",name!=null&&NetworkInterface.getByName(name)!=null));
            }
            result.put("available",true).put("networks",rows).put("wifi",wifi)
                .put("processBoundToWifi",bound!=null&&cm.getNetworkCapabilities(bound)!=null&&cm.getNetworkCapabilities(bound).hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
                .put("bindingMode",managed==null?"none":WifiBinding.compatible(managed)?"compatible_default":"explicit")
                .put("hasSystemDefault",active!=null).put("hasProcessBinding",bound!=null).put("hasPreferred",preferred!=null);
            JSONArray interfaces=new JSONArray();Enumeration<NetworkInterface> nativeNetworks=NetworkInterface.getNetworkInterfaces();
            while(nativeNetworks!=null&&nativeNetworks.hasMoreElements()&&interfaces.length()<32){
                NetworkInterface n=nativeNetworks.nextElement();int a4=0,a6=0;Enumeration<InetAddress> addresses=n.getInetAddresses();
                while(addresses.hasMoreElements()){InetAddress a=addresses.nextElement();if(a instanceof Inet4Address)a4++;else if(a instanceof Inet6Address)a6++;}
                interfaces.put(new JSONObject().put("name",n.getName()).put("up",n.isUp()).put("loopback",n.isLoopback()).put("virtual",n.isVirtual()).put("ipv4Count",a4).put("ipv6Count",a6));
            }
            result.put("interfaces",interfaces);
        }catch(Exception e){try{result.put("available",false).put("error","network_snapshot_unavailable");}catch(JSONException ignored){}}
        return result;
    }
}
