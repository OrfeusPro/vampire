package net.phoneexit;

import java.net.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.json.*;
import org.webrtc.DataChannel;

/** Loopback-only bridge between the TUN stack and the existing DataChannels. */
final class ClientSocks implements AutoCloseable {
    private final ClientLink transport;
    private final ServerSocket listener;
    private final Set<Socket> sockets=ConcurrentHashMap.newKeySet();
    private final Set<Relay> relays=ConcurrentHashMap.newKeySet();
    private final Semaphore total=new Semaphore(160),tcp=new Semaphore(128),udp=new Semaphore(64);
    private volatile boolean closed;
    ClientSocks(ClientLink transport)throws IOException{
        this.transport=transport;listener=new ServerSocket();listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),0),32);
    }
    int port(){return listener.getLocalPort();}
    void start(){Thread thread=new Thread(()->{
        while(!closed)try{
            Socket socket=listener.accept();
            if(!total.tryAcquire()){socket.close();continue;}
            sockets.add(socket);
            if(closed){done(socket);continue;}
            transport.io().execute(()->handshake(socket));
        }catch(Exception e){if(!closed)close();}
    },"PhoneExit-SOCKS");thread.setDaemon(true);thread.start();}
    private void done(Socket socket){if(sockets.remove(socket)){try{socket.close();}catch(IOException ignored){}total.release();}}
    private static int octet(InputStream in)throws IOException{int n=in.read();if(n<0)throw new EOFException();return n;}
    private static byte[] bytes(InputStream in,int n)throws IOException{byte[] b=new byte[n];new DataInputStream(in).readFully(b);return b;}
    static void reply(Socket socket,int code,int port)throws IOException{
        socket.getOutputStream().write(new byte[]{5,(byte)code,0,1,127,0,0,1,(byte)(port>>8),(byte)port});
    }
    private void handshake(Socket socket){
        boolean handed=false;
        try{
            socket.setSoTimeout(15000);socket.setTcpNoDelay(true);InputStream in=socket.getInputStream();
            if(octet(in)!=5)throw new IOException("version");int count=octet(in);if(count<1)throw new IOException("methods");
            boolean noAuth=false;for(byte method:bytes(in,count))if(method==0)noAuth=true;
            socket.getOutputStream().write(new byte[]{5,(byte)(noAuth?0:255)});if(!noAuth)return;
            if(octet(in)!=5)throw new IOException("version");int command=octet(in);if(octet(in)!=0)throw new IOException("reserved");
            int type=octet(in);String host;
            if(type==1)host=InetAddress.getByAddress(bytes(in,4)).getHostAddress();
            else if(type==4)host=InetAddress.getByAddress(bytes(in,16)).getHostAddress();
            else if(type==3){int n=octet(in);if(n==0)throw new IOException("host");host=new String(bytes(in,n),StandardCharsets.US_ASCII);if(!host.matches("[a-zA-Z0-9._-]+"))throw new IOException("host");}
            else{reply(socket,8,0);return;}
            int port=(octet(in)<<8)|octet(in);
            if(command!=1&&command!=3){reply(socket,7,0);return;}
            if(command==1&&port==0){reply(socket,1,0);return;}
            if(closed||!transport.ready()){reply(socket,1,0);return;}
            Semaphore permit=command==1?tcp:udp;
            if(!permit.tryAcquire()){reply(socket,1,0);return;}
            Relay relay;
            try{relay=command==1?new Tcp(socket,permit,host,port):new Udp(socket,permit,port);}catch(Exception e){permit.release();throw e;}
            relays.add(relay);handed=true;if(closed){relay.close();return;}try{relay.start();}catch(Exception e){relay.close();}
        }catch(Exception e){try{reply(socket,1,0);}catch(IOException ignored){}}
        finally{if(!handed)done(socket);}
    }
    private abstract class Relay implements AutoCloseable,DataChannel.Observer{
        final Socket socket;final Semaphore permit;final DataChannel dc;
        volatile boolean ended,ready;boolean opened;
        Relay(Socket socket,Semaphore permit,boolean datagram){this.socket=socket;this.permit=permit;dc=transport.channel(datagram);}
        void start(){
            transport.observe(dc,this);
            transport.loop().schedule(()->{if(!ready)close();},15,TimeUnit.SECONDS);
            if(this instanceof Udp)retryOpen();
            onStateChange();
        }
        void retryOpen(){
            try{transport.loop().schedule(()->{if(ended||ready)return;if(transport.state(dc)==DataChannel.State.OPEN)control(open());retryOpen();},500,TimeUnit.MILLISECONDS);}catch(RejectedExecutionException ignored){close();}
        }
        public void onStateChange(){
            if(ended)return;
            if(transport.state(dc)==DataChannel.State.CLOSED){close();return;}
            synchronized(this){if(transport.state(dc)==DataChannel.State.OPEN&&!opened){opened=true;if(!control(open()))close();}}
        }
        abstract JSONObject open();
        public void onBufferedAmountChange(long previous){synchronized(this){notifyAll();}}
        boolean control(JSONObject value){return !ended&&transport.control(dc,value);}
        public synchronized void close(){
            if(ended)return;ended=true;notifyAll();
            if(!ready)try{reply(socket,1,0);}catch(IOException ignored){}
            done(socket);relays.remove(this);permit.release();transport.release(dc);
        }
        JSONObject message(DataChannel.Buffer b)throws Exception{
            if(b.data.remaining()>1024)throw new IOException("control");byte[] data=new byte[b.data.remaining()];b.data.get(data);return new JSONObject(new String(data,StandardCharsets.UTF_8));
        }
    }
    private final class Tcp extends Relay {
        final String host;final int port;
        final ArrayBlockingQueue<byte[]> writes=new ArrayBlockingQueue<>(65);
        int credit=262144,outstanding,incoming;boolean localEof,remoteEof,drainStarted;
        Tcp(Socket s,Semaphore permit,String host,int port){super(s,permit,false);this.host=host;this.port=port;}
        JSONObject open(){return ExitEngine.json("type","open","host",host,"port",port);}
        public void onMessage(DataChannel.Buffer b){try{
            if(ended)return;
            if(b.binary){
                int n=b.data.remaining();if(!ready||remoteEof||n<1||n>16384)throw new IOException("frame");
                synchronized(this){if(incoming+n>1048576)throw new IOException("window");incoming+=n;}
                byte[] data=new byte[n];b.data.get(data);if(!writes.offer(data))throw new IOException("queue");
            }else{
                JSONObject msg=message(b);String type=msg.getString("type");
                if(type.equals("ready")&&!ready){
                    reply(socket,0,0);socket.setSoTimeout(0);ready=true;transport.io().execute(this::writer);transport.io().execute(this::reader);
                }else if(type.equals("credit")&&ready){
                    int n=msg.getInt("bytes");synchronized(this){if(n<1||n>outstanding)throw new IOException("credit");outstanding-=n;credit+=n;notifyAll();}finish();
                }else if(type.equals("eof")&&ready&&!remoteEof){remoteEof=true;if(!writes.offer(new byte[0]))throw new IOException("queue");}
                else throw new IOException("protocol");
            }
        }catch(Exception e){close();}}
        void reader(){try{
            byte[] buffer=new byte[16384];InputStream in=socket.getInputStream();
            while(!ended){int n=in.read(buffer);if(n<0){localEof=true;if(!control(ExitEngine.json("type","eof")))close();finish();return;}
                synchronized(this){while(!ended&&(credit<n||transport.buffered(dc)>262144))wait(100);if(ended)return;credit-=n;outstanding+=n;}
                if(!transport.send(dc,new DataChannel.Buffer(ByteBuffer.wrap(Arrays.copyOf(buffer,n)),true)))throw new IOException("send");
            }
        }catch(Exception e){close();}}
        void writer(){try{
            OutputStream out=socket.getOutputStream();while(!ended){byte[] data=writes.take();if(data.length==0){socket.shutdownOutput();finish();return;}
                out.write(data);synchronized(this){incoming-=data.length;}
                if(!control(ExitEngine.json("type","credit","bytes",data.length)))throw new IOException("send");
            }
        }catch(Exception e){close();}}
        synchronized void finish(){
            if(!localEof||!remoteEof||drainStarted)return;drainStarted=true;
            transport.task(()->drain(System.nanoTime()+TimeUnit.SECONDS.toNanos(30)));
        }
        void drain(long deadline){
            if(ended)return;
            synchronized(this){if((outstanding==0&&incoming==0&&transport.buffered(dc)==0)||System.nanoTime()>deadline){close();return;}}
            try{transport.loop().schedule(()->drain(deadline),100,TimeUnit.MILLISECONDS);}catch(RejectedExecutionException ignored){close();}
        }
    }
    private final class Udp extends Relay {
        DatagramSocket datagrams;volatile InetSocketAddress source;final int requestedPort;
        Udp(Socket s,Semaphore permit,int port){super(s,permit,true);requestedPort=port;}
        JSONObject open(){return ExitEngine.json("type","open");}
        public void onMessage(DataChannel.Buffer b){try{
            if(ended)return;
            if(b.binary){
                if(!ready||source==null||b.data.remaining()>1400)return;
                byte[] data=new byte[b.data.remaining()];b.data.get(data);if(SocksDatagram.valid(data))datagrams.send(new DatagramPacket(data,data.length,source));
            }else if(message(b).optString("type").equals("ready")){
                if(ready)return;
                datagrams=new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),0));
                reply(socket,0,datagrams.getLocalPort());socket.setSoTimeout(0);ready=true;
                transport.io().execute(this::readDatagrams);
                transport.io().execute(()->{try{socket.getInputStream().read();}catch(IOException ignored){}finally{close();}});
            }else close();
        }catch(Exception e){close();}}
        void readDatagrams(){
            byte[] buffer=new byte[1401];while(!ended)try{
                DatagramPacket packet=new DatagramPacket(buffer,buffer.length);datagrams.receive(packet);
                byte[] data=Arrays.copyOf(buffer,packet.getLength());
                if(!packet.getAddress().isLoopbackAddress()||!SocksDatagram.valid(data))continue;
                InetSocketAddress sender=new InetSocketAddress(packet.getAddress(),packet.getPort());
                if(source==null){if(requestedPort!=0&&packet.getPort()!=requestedPort)continue;source=sender;}
                if(!source.equals(sender)||transport.buffered(dc)>65536)continue;
                transport.send(dc,new DataChannel.Buffer(ByteBuffer.wrap(data),true));
            }catch(Exception e){close();}
        }
        @Override public synchronized void close(){if(datagrams!=null)datagrams.close();super.close();}
    }
    @Override public synchronized void close(){
        if(closed)return;closed=true;try{listener.close();}catch(IOException ignored){}
        for(Relay relay:new ArrayList<>(relays))relay.close();for(Socket socket:new ArrayList<>(sockets))done(socket);
    }
}
