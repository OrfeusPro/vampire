package net.phoneexit;

import android.app.Instrumentation;
import android.content.Context;
import android.net.Network;
import android.os.Bundle;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.*;

/** One-device native offerer/answerer regression; does not enable VPN or alter existing exit access. */
public final class PhoneClientInstrumentation extends Instrumentation {
    private boolean restoreExit,compat;
    @Override public void onCreate(Bundle args){super.onCreate(args);restoreExit=args!=null&&"true".equals(args.getString("restoreExit"));compat=args!=null&&"true".equals(args.getString("compat"));start();}
    @Override public void onStart(){
        Bundle result=new Bundle();int code=0;
        try{testNative();result.putString("stream","PASS Android native client: 3 HTTPS, UDP DNS, native TUN packet, transport loss");}
        catch(Exception e){code=1;result.putString("stream","FAIL Android native client: "+e.getClass().getSimpleName());}
        if(restoreExit)try{
            Context c=getTargetContext();c.getSharedPreferences("runtime",Context.MODE_PRIVATE).edit().putBoolean("enabled",true).commit();
            c.startForegroundService(new android.content.Intent(c,ExitService.class));Thread.sleep(1500);
        }catch(Exception e){code=1;result.putString("stream",result.getString("stream")+"; restore failed "+e.getClass().getSimpleName());}
        finish(code,result);
    }
    private static void require(boolean v)throws IOException{if(!v)throw new IOException("assertion");}
    private void phase(String text){Bundle b=new Bundle();b.putString("stream",text);sendStatus(1,b);}
    private static byte[] read(InputStream in,int n)throws IOException{byte[] b=new byte[n];new DataInputStream(in).readFully(b);return b;}
    private static Socket proxy(int port,int command,String host,int destinationPort)throws Exception{
        Socket socket=new Socket();
        try{
            socket.connect(new InetSocketAddress("127.0.0.1",port),5000);socket.setSoTimeout(20000);
            OutputStream out=socket.getOutputStream();InputStream in=socket.getInputStream();
            out.write(new byte[]{5,1,0});require(Arrays.equals(new byte[]{5,0},read(in,2)));
            byte[] name=host.getBytes(StandardCharsets.US_ASCII);
            ByteArrayOutputStream request=new ByteArrayOutputStream();request.write(new byte[]{5,(byte)command,0,3,(byte)name.length});request.write(name);request.write(destinationPort>>8);request.write(destinationPort);out.write(request.toByteArray());
            // Caller reads the bounded SOCKS response (contains UDP relay port when command=3).
            return socket;
        }catch(Exception e){socket.close();throw e;}
    }
    private void https(int port)throws Exception{
        String host="www.cloudflare.com";
        try(Socket raw=proxy(port,1,host,443)){
            require(read(raw.getInputStream(),10)[1]==0);
            try(SSLSocket tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(raw,host,443,true)){
                SSLParameters params=tls.getSSLParameters();params.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(params);tls.startHandshake();
                tls.getOutputStream().write(("GET /cdn-cgi/trace HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                ByteArrayOutputStream data=new ByteArrayOutputStream();byte[] buffer=new byte[2048];int n;
                while((n=tls.getInputStream().read(buffer))!=-1){require(data.size()+n<=32768);data.write(buffer,0,n);}
                String response=data.toString("UTF-8");require(response.startsWith("HTTP/1.1 200")&&response.contains("ip="));
            }
        }
    }
    private void dns(int port)throws Exception{
        try(Socket control=proxy(port,3,"0.0.0.0",0);DatagramSocket socket=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))){
            byte[] reply=read(control.getInputStream(),10);require(reply[1]==0);int relay=((reply[8]&255)<<8)|(reply[9]&255);
            byte[] dns={0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
            ByteArrayOutputStream query=new ByteArrayOutputStream();query.write(new byte[]{0,0,0,1,1,1,1,1,0,53});query.write(dns);byte[] data=query.toByteArray();
            socket.setSoTimeout(3000);
            for(int attempt=0;attempt<3;attempt++){
                socket.send(new DatagramPacket(data,data.length,InetAddress.getByName("127.0.0.1"),relay));
                try{DatagramPacket packet=new DatagramPacket(new byte[1400],1400);socket.receive(packet);byte[] b=Arrays.copyOf(packet.getData(),packet.getLength());
                    require(SocksDatagram.valid(b)&&b[3]==1&&b.length>=22&&b[10]==0x12&&b[11]==0x34&&(b[12]&0x80)!=0);return;
                }catch(SocketTimeoutException ignored){}
            }
            throw new IOException("dns_timeout");
        }
    }
    private void testNative()throws Exception{
        Context context=getTargetContext();require(!ClientVpnService.active);
        Network wifi=PeerDirectory.wifi(context);
        Object compatOwner=new Object();
        if(compat){
            // Exercise ordinary-default DNS/TCP/UDP and native ICE on a real
            // device without adding a production switch to fake Android denial.
            require(WifiBinding.acquireExitResult(context,wifi,compatOwner)==WifiBinding.Result.ACQUIRED);
            require(context.getSystemService(android.net.ConnectivityManager.class).bindProcessToNetwork(null));
            java.lang.reflect.Field mode=WifiBinding.class.getDeclaredField("defaultRoute");mode.setAccessible(true);mode.setBoolean(null,true);
            require(WifiBinding.usesDefaultRoute(context,wifi));phase("Testing compatible default-network route");
        }
        Pairing pairing=Pairing.parse(ExitEngine.json("version",1,"signal","https://demochko.com/phone-exit/signal.php","token",PeerDirectory.random(32)).toString());
        CountDownLatch connected=new CountDownLatch(1),failed=new CountDownLatch(1);AtomicReference<ClientSocks> bridge=new AtomicReference<>();
        ExitEngine exit=new ExitEngine(context,wifi,pairing,s->{},()->{});
        ClientTransport client=new ClientTransport(context,wifi,pairing,connected::countDown,()->{ClientSocks s=bridge.get();if(s!=null)s.close();failed.countDown();});
        ExecutorService parallel=Executors.newFixedThreadPool(3);
        try{
            phase("Native WebRTC connection");exit.start();client.start();require(connected.await(50,TimeUnit.SECONDS)&&client.ready());
            ClientSocks socks=new ClientSocks(client);bridge.set(socks);socks.start();
            List<Future<?>> jobs=new ArrayList<>();for(int i=0;i<3;i++)jobs.add(parallel.submit(()->{try{https(socks.port());}catch(Exception e){throw new RuntimeException(e);}}));
            for(Future<?> job:jobs)job.get(40,TimeUnit.SECONDS);phase("PASS 3 native HTTPS; checking UDP DNS");dns(socks.port());
            phase("PASS UDP DNS; checking native TUN packet");tunnelDns(socks.port());phase("PASS native TUN packet; checking transport loss");
            try(Socket held=proxy(socks.port(),1,"www.cloudflare.com",443)){
                require(read(held.getInputStream(),10)[1]==0);exit.close();require(failed.await(12,TimeUnit.SECONDS));require(held.getInputStream().read()==-1);
            }
        }finally{
            parallel.shutdownNow();if(bridge.get()!=null)bridge.get().close();client.close();exit.close();WifiBinding.release(context,compatOwner);
        }
    }
    private void tunnelDns(int port)throws Exception{
        // A datagram socket pair supplies IP packets without changing Android routes.
        java.io.FileDescriptor left=new java.io.FileDescriptor(),right=new java.io.FileDescriptor();
        android.system.Os.socketpair(android.system.OsConstants.AF_UNIX,android.system.OsConstants.SOCK_DGRAM,0,left,right);
        android.os.ParcelFileDescriptor tun=android.os.ParcelFileDescriptor.dup(left);
        File config=new File(getTargetContext().getFilesDir(),"client-native-test.yml");boolean started=false;
        try{
            try(FileOutputStream out=new FileOutputStream(config)){out.write(ClientVpnService.tunnelConfig(port).getBytes(StandardCharsets.UTF_8));}
            started=hev.htproxy.TProxyService.TProxyStartService(config.getAbsolutePath(),tun.getFd());require(started);
            byte[] dns={0x12,0x35,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
            byte[] packet=new byte[28+dns.length];java.nio.ByteBuffer b=java.nio.ByteBuffer.wrap(packet);
            b.put((byte)0x45).put((byte)0).putShort((short)packet.length).putShort((short)1).putShort((short)0).put((byte)64).put((byte)17).putShort((short)0);
            b.put(new byte[]{(byte)198,18,0,2,1,1,1,1});b.putShort((short)53000).putShort((short)53).putShort((short)(8+dns.length)).putShort((short)0).put(dns);
            int sum=0;for(int i=0;i<20;i+=2)sum+=((packet[i]&255)<<8)|(packet[i+1]&255);while((sum>>16)!=0)sum=(sum&65535)+(sum>>16);b.putShort(10,(short)~sum);
            android.system.StructPollfd poll=new android.system.StructPollfd();poll.fd=right;poll.events=(short)android.system.OsConstants.POLLIN;
            for(int attempt=0;attempt<3;attempt++){
                android.system.Os.write(right,packet,0,packet.length);
                if(android.system.Os.poll(new android.system.StructPollfd[]{poll},3000)==0)continue;
                byte[] response=new byte[1500];int n=android.system.Os.read(right,response,0,response.length);require(n>=40&&(response[0]&0xf0)==0x40&&response[9]==17);
                int offset=(response[0]&15)*4;require(offset>=20&&n>=offset+20);
                require(response[offset]==0&&response[offset+1]==53&&response[offset+2]==(byte)(53000>>8)&&response[offset+3]==(byte)53000);
                require(response[offset+8]==0x12&&response[offset+9]==0x35&&(response[offset+10]&0x80)!=0);return;
            }
            throw new IOException("tun_dns_timeout");
        }finally{
            if(started)hev.htproxy.TProxyService.TProxyStopService();tun.close();android.system.Os.close(left);android.system.Os.close(right);config.delete();
        }
    }
}
