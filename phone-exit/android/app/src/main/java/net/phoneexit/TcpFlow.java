package net.phoneexit;

import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.*;
import org.json.*;
import org.webrtc.DataChannel;

final class TcpFlow implements AutoCloseable {
    private static final int WINDOW=262144,FRAME=16384;
    private final ExitEngine engine;
    private final DataChannel dc;
    private final ArrayBlockingQueue<byte[]> writes=new ArrayBlockingQueue<>(17);
    private volatile boolean closed,ready,readEof,writeEof;
    private boolean opened;
    private int credit=WINDOW,outstanding,incoming;
    private Socket socket;
    TcpFlow(ExitEngine engine,DataChannel dc) { this.engine=engine; this.dc=dc; }
    void start() {
        engine.observe(dc,new DataChannel.Observer() {
            public void onBufferedAmountChange(long amount) { synchronized(TcpFlow.this) { TcpFlow.this.notifyAll(); } }
            public void onStateChange() { if(!closed&&dc.state()==DataChannel.State.CLOSED) close(); }
            public void onMessage(DataChannel.Buffer buffer) {
                try {
                    if(closed) return;
                    int n=buffer.data.remaining();
                    if(buffer.binary) {
                        if(!ready||writeEof||n==0||n>FRAME) throw new IOException("frame");
                        byte[] bytes=new byte[n]; buffer.data.get(bytes);
                        synchronized(TcpFlow.this) { if(incoming+n>WINDOW) throw new IOException("window"); incoming+=n; }
                        if(!writes.offer(bytes)) throw new IOException("queue");
                    } else {
                        if(n>1024) throw new IOException("control");
                        byte[] bytes=new byte[n]; buffer.data.get(bytes); JSONObject msg=new JSONObject(new String(bytes,StandardCharsets.UTF_8));
                        String type=msg.getString("type");
                        if(type.equals("open")&&!opened) {
                            opened=true; String host=msg.getString("host"); int port=msg.getInt("port");
                            if(host.length()>253||!host.matches("[a-zA-Z0-9._:-]+")||port<1||port>65535) throw new IOException("destination");
                            engine.io.execute(() -> connect(host,port));
                        } else if(type.equals("credit")&&ready) {
                            int count=msg.getInt("bytes"); synchronized(TcpFlow.this) {
                                if(count<=0||count>outstanding) throw new IOException("credit"); outstanding-=count; credit+=count; TcpFlow.this.notifyAll();
                            }
                        } else if(type.equals("eof")&&ready&&!writeEof) {
                            writeEof=true; if(!writes.offer(new byte[0])) throw new IOException("queue");
                        } else throw new IOException("unexpected");
                    }
                } catch(Exception e) { error(1); }
            }
        });
        engine.later(() -> { if(!ready&&!closed) error(4); },15);
    }
    private void connect(String host,int port) {
        try {
            InetAddress[] addresses=engine.wifi.getAllByName(host);
            if(addresses.length==0) throw new IOException("dns");
            for(InetAddress address:addresses) if(!PublicAddress.allowed(address)) { error(2); return; }
            long limit=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            for(InetAddress address:addresses) {
                if(closed) return;
                Socket candidate=engine.wifi.getSocketFactory().createSocket();
                synchronized(this) { if(closed) { candidate.close(); return; } socket=candidate; }
                try { candidate.connect(new InetSocketAddress(address,port),(int)Math.max(1,Math.min(5000,TimeUnit.NANOSECONDS.toMillis(limit-System.nanoTime())))); break; }
                catch(IOException e) { candidate.close(); if(System.nanoTime()>=limit) throw e; }
            }
            if(closed) return;
            if(socket==null||!socket.isConnected()||socket.isClosed()) throw new IOException("connect");
            socket.setTcpNoDelay(true); ready=true;
            if(!ExitEngine.sendControl(dc,ExitEngine.json("type","ready"))) throw new IOException("send");
            engine.io.execute(this::writer); engine.io.execute(this::reader);
        } catch(Exception e) { error(4); }
    }
    private void writer() {
        try {
            OutputStream output=socket.getOutputStream();
            while(!closed) {
                byte[] bytes=writes.take();
                if(bytes.length==0) { socket.shutdownOutput(); finish(); return; }
                output.write(bytes);
                synchronized(this) { incoming-=bytes.length; }
                if(!ExitEngine.sendControl(dc,ExitEngine.json("type","credit","bytes",bytes.length))) throw new IOException("send");
            }
        } catch(Exception e) { if(!closed) error(1); }
    }
    private void reader() {
        try {
            InputStream input=socket.getInputStream(); byte[] bytes=new byte[FRAME];
            while(!closed) {
                int n=input.read(bytes);
                if(n==-1) { readEof=true; ExitEngine.sendControl(dc,ExitEngine.json("type","eof")); finish(); return; }
                synchronized(this) {
                    while(!closed&&(credit<n||dc.bufferedAmount()>WINDOW)) wait(1000);
                    if(closed) return; credit-=n; outstanding+=n;
                }
                if(!dc.send(new DataChannel.Buffer(ByteBuffer.wrap(Arrays.copyOf(bytes,n)),true))) throw new IOException("send");
            }
        } catch(Exception e) { if(!closed) error(1); }
    }
    private void finish() {
        if(readEof&&writeEof) {
            engine.io.execute(() -> {
                try {
                    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(30);
                    synchronized(this) { while(!closed&&(outstanding>0||incoming>0||dc.bufferedAmount()>0)&&System.nanoTime()<deadline) wait(100); }
                } catch(InterruptedException ignored) {} finally { close(); }
            });
        }
    }
    private void error(int code) { if(!closed&&dc.state()==DataChannel.State.OPEN) ExitEngine.sendControl(dc,ExitEngine.json("type","error","code",code)); close(); }
    @Override public synchronized void close() {
        if(closed) return; closed=true; notifyAll();
        if(socket!=null) try { socket.close(); } catch(IOException ignored) {}
        writes.clear(); writes.offer(new byte[0]); dc.close(); engine.forget(this);
        engine.releaseChannel(dc);
    }
}
