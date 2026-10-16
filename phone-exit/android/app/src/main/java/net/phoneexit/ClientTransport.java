package net.phoneexit;

import android.content.Context;
import android.net.Network;
import org.json.*;
import org.webrtc.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Offerer for the same bounded TCP/UDP protocol used by the Windows client. */
final class ClientTransport implements AutoCloseable,ClientLink {
    private final Context context;
    private final Network uplink;
    private final Pairing pairing;
    private final Runnable connected,failed;
    final ScheduledThreadPoolExecutor loop=new ScheduledThreadPoolExecutor(1);
    final ExecutorService io=Executors.newFixedThreadPool(384);
    private final ExecutorService releases=Executors.newSingleThreadExecutor();
    private final ThreadPoolExecutor callbacks=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(2048));
    private final Set<DataChannel> channels=ConcurrentHashMap.newKeySet();
    private final List<IceCandidate> candidates=new ArrayList<>();
    private final AtomicBoolean failure=new AtomicBoolean();
    private PeerConnectionFactory factory;
    private PeerConnection peer;
    private DataChannel control;
    private volatile boolean closed,ready;
    private boolean remoteSet;
    private int cursor,sequence;
    private long ping,pong,lastPong;
    private volatile String phase="startup";
    private void phase(String value){phase=value;android.util.Log.i("PhoneExitClient",value);}
    ClientTransport(Context context,Network uplink,Pairing pairing,Runnable connected,Runnable failed){
        this.context=context;this.uplink=uplink;this.pairing=pairing;this.connected=connected;this.failed=failed;
        loop.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        loop.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
    }
    public boolean ready(){return ready&&!closed&&!failure.get();}
    public ExecutorService io(){return io;}
    public ScheduledExecutorService loop(){return loop;}
    public void task(Runnable r){try{loop.execute(()->{if(!closed)r.run();});}catch(RejectedExecutionException ignored){}}
    void start(){
        task(()->{try{
            phase("uplink binding");
            if(!WifiBinding.acquire(context,uplink,this))throw new Exception("binding");
            WebRtcRuntime.initialize(context);
            // Keep native discovery: disabling it is a known remote-ICE regression
            // (see ControlAgent). Bind to the selected physical client network,
            // which may be cellular. The exit keeps its independent Wi-Fi-only policy.
            PeerConnectionFactory.Options options=new PeerConnectionFactory.Options();options.disableNetworkMonitor=false;
            options.networkIgnoreMask=PeerConnectionFactory.Options.ADAPTER_TYPE_LOOPBACK;
            factory=PeerConnectionFactory.builder().setOptions(options).createPeerConnectionFactory();
            phase("factory ready");
            PeerConnection.RTCConfiguration cfg=new PeerConnection.RTCConfiguration(Arrays.asList(
                PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer(),
                PeerConnection.IceServer.builder("stun:stun.cloudflare.com:3478").createIceServer()));
            cfg.sdpSemantics=PeerConnection.SdpSemantics.UNIFIED_PLAN;
            synchronized(this){
                if(closed)return;
                peer=factory.createPeerConnection(cfg,new PeerConnection.Observer(){
                    public void onSignalingChange(PeerConnection.SignalingState s){}
                    public void onIceConnectionChange(PeerConnection.IceConnectionState s){android.util.Log.i("PhoneExitClient","ICE "+s);if(s==PeerConnection.IceConnectionState.FAILED||s==PeerConnection.IceConnectionState.CLOSED)fail();}
                    public void onIceConnectionReceivingChange(boolean receiving){}
                    public void onIceGatheringChange(PeerConnection.IceGatheringState s){}
                    public void onIceCandidate(IceCandidate c){candidateKind("local",c.sdp);task(()->send(ExitEngine.json("type","candidate","value",ExitEngine.json("candidate",c.sdp,"sdpMid",c.sdpMid,"sdpMLineIndex",c.sdpMLineIndex))));}
                    public void onIceCandidatesRemoved(IceCandidate[] c){}
                    public void onAddStream(MediaStream s){}
                    public void onRemoveStream(MediaStream s){}
                    public void onRenegotiationNeeded(){}
                    public void onDataChannel(DataChannel dc){try{releases.execute(()->{dc.close();dc.dispose();});}catch(RejectedExecutionException ignored){}}
                });
                if(peer==null)throw new Exception("peer");
                control=peer.createDataChannel("phone-exit-control-v1",new DataChannel.Init());
                observe(control,new DataChannel.Observer(){
                    public void onBufferedAmountChange(long previous){}
                    public void onStateChange(){if(!closed&&state(control)==DataChannel.State.CLOSED)fail();}
                    public void onMessage(DataChannel.Buffer b){
                        if(b.binary||b.data.remaining()>2048){fail();return;}
                        byte[] data=new byte[b.data.remaining()];b.data.get(data);
                        task(()->{try{
                            JSONObject msg=new JSONObject(new String(data,java.nio.charset.StandardCharsets.UTF_8));
                            String type=msg.optString("type");
                            if(type.equals("hello")&&!ready){
                                if(msg.getInt("version")!=1||!msg.getJSONArray("features").toString().contains("\"udp-v1\""))throw new Exception("protocol");
                                ready=true;lastPong=System.nanoTime();connected.run();
                                phase("protocol ready");
                            }else if(type.equals("pong")){
                                long id=Long.parseLong(msg.getString("id"));
                                if(id>pong&&id<=ping){pong=id;lastPong=System.nanoTime();}
                            }else if(type.equals("bye"))fail();
                        }catch(Exception e){fail();}});
                    }
                });
                peer.createOffer(new Sdp(){public void onCreateSuccess(SessionDescription sdp){task(()->peer.setLocalDescription(new Sdp(){public void onSetSuccess(){task(()->send(ExitEngine.json("type","offer","value",ExitEngine.json("type","offer","sdp",sdp.description))));}},sdp));}},new MediaConstraints());
            }
        }catch(Exception e){android.util.Log.w("PhoneExitClient","startup "+e.getClass().getSimpleName());fail();}});
        loop.scheduleWithFixedDelay(this::poll,0,1,TimeUnit.SECONDS);
        loop.scheduleWithFixedDelay(()->{
            if(!ready()||state(control)!=DataChannel.State.OPEN)return;
            if(System.nanoTime()-lastPong>TimeUnit.SECONDS.toNanos(8)){fail();return;}
            if(!control(control,ExitEngine.json("type","ping","id",Long.toString(++ping))))fail();
        },2,2,TimeUnit.SECONDS);
        loop.schedule(()->{if(!ready())fail();},45,TimeUnit.SECONDS);
    }
    private JSONObject api(String op,JSONObject message)throws Exception{
        return PeerDirectory.post(uplink,pairing.endpoint,ExitEngine.json("token",pairing.token,"role","pc","op",op,"after",cursor,"message",message==null?JSONObject.NULL:message),262144);
    }
    private void send(JSONObject message){if(!closed)try{api("send",message);if("offer".equals(message.optString("type")))phase("offer sent");}catch(Exception e){android.util.Log.w("PhoneExitClient","send "+e.getClass().getSimpleName());fail();}}
    private void poll(){
        if(closed||ready||peer==null)return;
        try{
            JSONArray messages=api("poll",null).getJSONArray("messages");
            for(int i=0;i<messages.length()&&!closed;i++){
                JSONObject item=messages.getJSONObject(i),msg=item.getJSONObject("message"),value=msg.getJSONObject("value");
                cursor=Math.max(cursor,item.getInt("id"));
                if(msg.getString("type").equals("candidate")){
                    candidateKind("remote",value.getString("candidate"));
                    IceCandidate c=new IceCandidate(value.optString("sdpMid","0"),value.getInt("sdpMLineIndex"),value.getString("candidate"));
                    if(remoteSet)peer.addIceCandidate(c);else{if(candidates.size()>=128)throw new Exception("candidates");candidates.add(c);}
                }else if(msg.getString("type").equals("answer")&&!remoteSet){
                    phase("answer received");
                    peer.setRemoteDescription(new Sdp(){public void onSetSuccess(){task(()->{remoteSet=true;for(IceCandidate c:candidates)peer.addIceCandidate(c);candidates.clear();});}},new SessionDescription(SessionDescription.Type.ANSWER,value.getString("sdp")));
                }
            }
        }catch(Exception e){android.util.Log.w("PhoneExitClient","poll "+e.getClass().getSimpleName());fail();}
    }
    private void candidateKind(String side,String sdp){
        String[] fields=sdp.split(" ");String kind="unknown";for(int i=0;i+1<fields.length;i++)if("typ".equals(fields[i])&&Arrays.asList("host","srflx","prflx","relay").contains(fields[i+1]))kind=fields[i+1];
        android.util.Log.i("PhoneExitClient",side+" candidate "+kind);
    }
    public synchronized DataChannel channel(boolean udp){
        if(!ready())throw new IllegalStateException("closed");
        DataChannel.Init init=new DataChannel.Init();if(udp){init.ordered=false;init.maxRetransmits=0;}
        return peer.createDataChannel((udp?"phone-exit-udp-v1-":"phone-exit-tcp-v1-")+(++sequence),init);
    }
    public synchronized void observe(DataChannel dc,DataChannel.Observer observer){
        if(closed){dc.close();dc.dispose();throw new IllegalStateException("closed");}
        channels.add(dc);
        // JNI calls can synchronously wait for WebRTC's signaling thread. Its observers
        // must return without taking Java locks or making another synchronous JNI call.
        dc.registerObserver(new DataChannel.Observer(){
            public void onBufferedAmountChange(long amount){dispatch(()->observer.onBufferedAmountChange(amount));}
            public void onStateChange(){dispatch(observer::onStateChange);}
            public void onMessage(DataChannel.Buffer buffer){
                if(closed)return;int size=buffer.data.remaining();if(size>16384){fail();return;}
                byte[] data=new byte[size];buffer.data.get(data);boolean binary=buffer.binary;
                dispatch(()->observer.onMessage(new DataChannel.Buffer(java.nio.ByteBuffer.wrap(data),binary)));
            }
        });
    }
    private void dispatch(Runnable runnable){
        try{callbacks.execute(()->{if(!closed)try{runnable.run();}catch(RuntimeException e){fail();}});}catch(RejectedExecutionException e){fail();}
    }
    public synchronized void release(DataChannel dc){
        if(!channels.remove(dc))return;
        releases.execute(()->{dc.unregisterObserver();dc.close();dc.dispose();});
    }
    public synchronized DataChannel.State state(DataChannel dc){return channels.contains(dc)?dc.state():DataChannel.State.CLOSED;}
    public synchronized long buffered(DataChannel dc){return channels.contains(dc)?dc.bufferedAmount():Long.MAX_VALUE;}
    public synchronized boolean send(DataChannel dc,DataChannel.Buffer buffer){return !closed&&channels.contains(dc)&&dc.state()==DataChannel.State.OPEN&&dc.send(buffer);}
    public boolean control(DataChannel dc,JSONObject value){return send(dc,new DataChannel.Buffer(java.nio.ByteBuffer.wrap(value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8)),false));}
    private void fail(){if(!closed&&failure.compareAndSet(false,true)){
        android.util.Log.w("PhoneExitClient","failed at "+phase);
        ready=false;Thread thread=new Thread(failed,"PhoneExit-ClientFailure");thread.setDaemon(true);thread.start();
    }}
    private class Sdp implements SdpObserver{
        public void onCreateSuccess(SessionDescription s){}
        public void onSetSuccess(){}
        public void onCreateFailure(String error){fail();}
        public void onSetFailure(String error){fail();}
    }
    @Override public synchronized void close(){
        if(closed)return;closed=true;ready=false;io.shutdownNow();
        // Queue disposal after any in-flight HTTPS/SDP operation on the signaling thread.
        loop.execute(()->{
            synchronized(ClientTransport.this){
                if(control!=null&&channels.contains(control)&&control.state()==DataChannel.State.OPEN)ExitEngine.sendControl(control,ExitEngine.json("type","bye"));
                for(DataChannel dc:new ArrayList<>(channels))release(dc);
                releases.execute(()->{if(peer!=null){peer.close();peer.dispose();}if(factory!=null)factory.dispose();callbacks.shutdownNow();WifiBinding.release(context,this);});
                releases.shutdown();
            }
        });loop.shutdown();
    }
}
