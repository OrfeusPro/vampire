package net.phoneexit;

import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.json.*;
import org.webrtc.DataChannel;

/** Bounded UDP association. Replies are allowed only from destinations sent to. */
final class UdpAssociation implements AutoCloseable {
    private final ExitEngine engine;
    private final DataChannel dc;
    private final ThreadPoolExecutor sender=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(64),new ThreadPoolExecutor.DiscardPolicy());
    private final Map<String,Long> destinations=new ConcurrentHashMap<>();
    private volatile DatagramSocket socket;
    private volatile boolean closed,ready;
    UdpAssociation(ExitEngine engine,DataChannel dc){this.engine=engine;this.dc=dc;}
    void start(){
        engine.observe(dc,new DataChannel.Observer(){
            public void onBufferedAmountChange(long previous){}
            public void onStateChange(){if(dc.state()==DataChannel.State.CLOSED)close();}
            public void onMessage(DataChannel.Buffer buffer){
                if(closed||buffer.data.remaining()>1400)return;
                byte[] data=new byte[buffer.data.remaining()];buffer.data.get(data);
                if(buffer.binary){if(ready)try{sender.execute(()->send(data));}catch(RejectedExecutionException ignored){}}
                else try{if("open".equals(new JSONObject(new String(data,StandardCharsets.UTF_8)).optString("type"))){
                    if(ready)ExitEngine.sendControl(dc,ExitEngine.json("type","ready"));
                    else sender.execute(UdpAssociation.this::open);
                }}catch(Exception ignored){}
            }
        });
        engine.later(()->{if(!ready)close();},15);
    }
    private synchronized void open(){
        if(closed)return;
        if(!ready)try{
            DatagramSocket candidate=new DatagramSocket(null);
            try{engine.uplink.bind(candidate);candidate.bind(new InetSocketAddress(0));candidate.setSoTimeout(1000);socket=candidate;ready=true;}
            catch(Exception e){candidate.close();throw e;}
            Thread reader=new Thread(this::read,"PhoneExit-UDP");reader.setDaemon(true);reader.start();
        }catch(Exception e){close();return;}
        ExitEngine.sendControl(dc,ExitEngine.json("type","ready"));
    }
    private void send(byte[] data){
        try{
            if(closed||data.length<7||data[0]!=0||data[1]!=0||data[2]!=0)return;
            ByteBuffer b=ByteBuffer.wrap(data);b.position(4);String host;
            if(data[3]==1){byte[] ip=new byte[4];b.get(ip);host=InetAddress.getByAddress(ip).getHostAddress();}
            else if(data[3]==4){byte[] ip=new byte[16];b.get(ip);host=InetAddress.getByAddress(ip).getHostAddress();}
            else if(data[3]==3){int n=b.get()&255;if(n==0||n>253)return;byte[] name=new byte[n];b.get(name);host=new String(name,StandardCharsets.US_ASCII);if(!host.matches("[a-zA-Z0-9._-]+"))return;}
            else return;
            int port=b.getShort()&65535;if(port==0||!b.hasRemaining())return;
            InetAddress[] ips=engine.uplink.resolve(host);if(ips.length==0)return;
            for(InetAddress ip:ips)if(!PublicAddress.allowed(ip))return;
            long now=System.nanoTime();destinations.entrySet().removeIf(e->now-e.getValue()>TimeUnit.SECONDS.toNanos(60));
            String key=ips[0].getHostAddress()+":"+port;
            if(!destinations.containsKey(key)&&destinations.size()>=32)return;
            destinations.put(key,now);
            engine.uplink.check();if(!closed)socket.send(new DatagramPacket(data,b.position(),b.remaining(),ips[0],port));
        }catch(Exception ignored){}
    }
    private void read(){
        byte[] bytes=new byte[1401];
        while(!closed)try{
            DatagramPacket packet=new DatagramPacket(bytes,bytes.length);socket.receive(packet);engine.uplink.check();
            if(packet.getLength()==0||packet.getLength()>1378)continue;
            Long last=destinations.get(packet.getAddress().getHostAddress()+":"+packet.getPort());
            if(last==null||System.nanoTime()-last>TimeUnit.SECONDS.toNanos(60))continue;
            byte[] ip=packet.getAddress().getAddress();ByteBuffer response=ByteBuffer.allocate(6+ip.length+packet.getLength());
            response.put((byte)0).put((byte)0).put((byte)0).put((byte)(ip.length==4?1:4)).put(ip).putShort((short)packet.getPort()).put(bytes,0,packet.getLength()).flip();
            if(dc.state()==DataChannel.State.OPEN&&dc.bufferedAmount()<65536)dc.send(new DataChannel.Buffer(response,true));
        }catch(SocketTimeoutException ignored){}catch(Exception e){if(!closed)close();}
    }
    @Override public synchronized void close(){
        if(closed)return;closed=true;sender.shutdownNow();if(socket!=null)socket.close();destinations.clear();dc.close();engine.forget(this);engine.releaseChannel(dc);
    }
}
