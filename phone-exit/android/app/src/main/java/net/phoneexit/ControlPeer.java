package net.phoneexit;

import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.json.*;
import org.webrtc.*;

/** Authenticated offer arrives through AES-GCM; subsequent messages use DTLS. */
final class ControlPeer implements AutoCloseable {
    private final ControlAgent agent;
    private final ScheduledExecutorService events=Executors.newSingleThreadScheduledExecutor();
    private final ThreadPoolExecutor actions=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(4));
    private final CompletableFuture<JSONObject> answer=new CompletableFuture<>();
    private final CompletableFuture<Void> disposed=new CompletableFuture<>();
    private final List<IceCandidate> candidates=new ArrayList<>();
    private boolean answerScheduled;
    private PeerConnectionFactory factory;private PeerConnection peer;private DataChannel channel;
    private volatile boolean closed;private volatile long seen=System.nanoTime();
    private volatile String iceState="NEW",gatheringState="NEW",signalingState="STABLE",closeReason="";
    private volatile int callbackCandidates,sdpCandidates,mediaSections,rejectedSections,iceCredentials;
    private final long started=System.nanoTime();
    JSONObject diagnostics(){
        JSONObject value=new JSONObject();try{
            value.put("iceState",iceState).put("gatheringState",gatheringState).put("signalingState",signalingState)
                .put("callbackCandidates",callbackCandidates).put("sdpCandidates",sdpCandidates)
                .put("mediaSections",mediaSections).put("rejectedSections",rejectedSections).put("iceCredentials",iceCredentials)
                .put("closed",closed).put("closeReason",closeReason).put("elapsedMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started));
        }catch(JSONException ignored){}return value;
    }
    private void describe(String sdp){
        int candidates=0,media=0,rejected=0,credentials=0;
        for(String line:sdp.split("\\r?\\n")){
            if(line.startsWith("a=candidate:"))candidates++;
            if(line.startsWith("a=ice-ufrag:"))credentials++;
            if(line.startsWith("m=")){media++;String[] parts=line.trim().split("\\s+");if(parts.length>1&&parts[1].equals("0"))rejected++;}
        }sdpCandidates=candidates;mediaSections=media;rejectedSections=rejected;iceCredentials=credentials;
    }
    ControlPeer(ControlAgent agent){this.agent=agent;}
    private void event(Runnable r){if(!closed)try{events.execute(()->{if(!closed)r.run();});}catch(RejectedExecutionException ignored){}}
    private void publishAnswer(){
        if(closed||answer.isDone()||peer==null)return;
        try{
            SessionDescription d=peer.getLocalDescription();if(d==null)return;
            String sdp=d.description;describe(sdp);
            StringBuilder extra=new StringBuilder();for(IceCandidate candidate:candidates){String line="a="+candidate.sdp;if(!sdp.contains(line+"\r\n")&&!sdp.contains(line+"\n"))extra.append(line).append("\r\n");}
            sdp=sdp.replace("a=end-of-candidates\r\n","").replace("a=end-of-candidates\n","");
            if(!sdp.endsWith("\n"))sdp+="\r\n";sdp+=extra;
            if(sdp.length()>11000)throw new Exception("sdp_limit");
            if(!sdp.contains("a=candidate:"))return;
            answer.complete(new JSONObject().put("sdp",sdp).put("type","answer"));
        }catch(Exception e){answer.completeExceptionally(e);close();}
    }
    JSONObject connect(String offer)throws Exception{
        event(()->{
            try{
                if(!agent.active()||!WifiBinding.acquire(agent.context,agent.wifi,this))throw new Exception("wifi_binding_denied");
                factory=agent.peerFactory();
                PeerConnection.RTCConfiguration cfg=new PeerConnection.RTCConfiguration(Arrays.asList(
                    PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer(),
                    PeerConnection.IceServer.builder("stun:stun.cloudflare.com:3478").createIceServer()));
                cfg.sdpSemantics=PeerConnection.SdpSemantics.UNIFIED_PLAN;
                cfg.continualGatheringPolicy=PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY;
                peer=factory.createPeerConnection(cfg,new PeerConnection.Observer(){
                    public void onSignalingChange(PeerConnection.SignalingState s){signalingState=s.name();}
                    public void onIceConnectionChange(PeerConnection.IceConnectionState s){iceState=s.name();if(s==PeerConnection.IceConnectionState.FAILED)close("direct_ice_failed");else if(s==PeerConnection.IceConnectionState.CLOSED)close("direct_ice_closed");}
                    public void onIceConnectionReceivingChange(boolean b){}
                    public void onIceGatheringChange(PeerConnection.IceGatheringState s){gatheringState=s.name();if(s==PeerConnection.IceGatheringState.COMPLETE)event(()->{SessionDescription d=peer.getLocalDescription();if(d!=null)describe(d.description);});}
                    public void onIceCandidate(IceCandidate c){callbackCandidates=Math.min(32,callbackCandidates+1);event(()->{
                        if(candidates.size()<32)candidates.add(c);
                        // Leave time for STUN after the first host candidate;
                        // continuous gathering can discover Wi-Fi after an early
                        // empty COMPLETE notification and does not promise COMPLETE.
                        if(!answerScheduled){answerScheduled=true;events.schedule(thisPeerPublish(),1500,TimeUnit.MILLISECONDS);}
                    });}
                    public void onIceCandidatesRemoved(IceCandidate[] c){}
                    public void onAddStream(MediaStream s){}
                    public void onRemoveStream(MediaStream s){}
                    public void onRenegotiationNeeded(){}
                    public void onDataChannel(DataChannel dc){event(()->attach(dc));}
                });
                if(peer==null)throw new Exception("peer_unavailable");
                peer.setRemoteDescription(new Sdp(){public void onSetSuccess(){event(()->peer.createAnswer(new Sdp(){
                    public void onCreateSuccess(SessionDescription d){event(()->peer.setLocalDescription(new Sdp(),d));}
                },new MediaConstraints()));}},new SessionDescription(SessionDescription.Type.OFFER,offer));
                events.schedule(()->{publishAnswer();if(!answer.isDone()){answer.completeExceptionally(new Exception("ice_no_candidates"));close("ice_no_candidates");}},12,TimeUnit.SECONDS);
                events.scheduleWithFixedDelay(()->{if(!agent.active())close("direct_wifi_lost");else if(System.nanoTime()-seen>TimeUnit.SECONDS.toNanos(open()?14:60))close("direct_heartbeat_timeout");},2,2,TimeUnit.SECONDS);
            }catch(Exception e){answer.completeExceptionally(e);close();}
        });
        try{return answer.get(16,TimeUnit.SECONDS);}catch(ExecutionException e){close();String reason=e.getCause().getMessage();throw new Exception(reason!=null&&reason.matches("[a-z_]{1,80}")?reason:"direct_connect_failed");}catch(Exception e){close();throw new Exception("direct_connect_failed");}
    }
    private Runnable thisPeerPublish(){return this::publishAnswer;}
    private class Sdp implements SdpObserver{
        public void onCreateSuccess(SessionDescription d){}public void onSetSuccess(){}
        public void onCreateFailure(String s){answer.completeExceptionally(new Exception("sdp_failed"));close();}
        public void onSetFailure(String s){answer.completeExceptionally(new Exception("sdp_failed"));close();}
    }
    private void attach(DataChannel dc){
        if(channel!=null||!dc.label().equals("phone-exit-automation-v1")){dc.close();dc.dispose();return;}
        channel=dc;dc.registerObserver(new DataChannel.Observer(){
            public void onBufferedAmountChange(long n){}
            public void onStateChange(){if(dc.state()==DataChannel.State.CLOSED)close("direct_channel_closed");}
            public void onMessage(DataChannel.Buffer buffer){
                if(closed||buffer.binary||buffer.data.remaining()>12000){close();return;}
                byte[] bytes=new byte[buffer.data.remaining()];buffer.data.get(bytes);
                try{
                    JSONObject v=new JSONObject(new String(bytes,StandardCharsets.UTF_8));
                    if(v.optString("command").equals("connectControl")){close();return;}
                    if(v.optString("type").equals("ping")){
                        String id=v.getString("request");if(!id.matches("[0-9]{1,16}"))throw new Exception();seen=System.nanoTime();
                        event(()->{try{sendText(new JSONObject().put("type","pong").put("request",id).toString());}catch(Exception e){close();}});return;
                    }
                    if(!v.optString("request").matches("[0-9a-f]{32}")||!agent.config.id.equals(v.optString("id"))||v.optString("command").equals("connectControl"))throw new Exception();
                    actions.execute(()->{try{
                        JSONObject result=agent.process(v);byte[] body=result.toString().getBytes(StandardCharsets.UTF_8);
                        if(body.length>2100000)throw new Exception();sendResult(v.getString("request"),body);
                    }catch(Exception e){close();}});
                }catch(Exception e){close();}
            }
        });
    }
    private void sendText(String value){if(!closed&&channel!=null&&channel.state()==DataChannel.State.OPEN)channel.send(new DataChannel.Buffer(ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8)),false));}
    private void sendResult(String id,byte[] bytes)throws Exception{
        byte[] request=new byte[16];for(int i=0;i<16;i++)request[i]=(byte)Integer.parseInt(id.substring(i*2,i*2+2),16);
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(8);
        for(int offset=0;offset<bytes.length;offset+=16384){
            while(!closed&&channel.bufferedAmount()>262144){if(System.nanoTime()>deadline)throw new Exception();Thread.sleep(5);}
            if(closed||!agent.active()||channel.state()!=DataChannel.State.OPEN)throw new Exception();
            int n=Math.min(16384,bytes.length-offset);ByteBuffer frame=ByteBuffer.allocate(24+n).order(ByteOrder.BIG_ENDIAN);
            frame.put(request).putInt(bytes.length).putInt(offset).put(bytes,offset,n).flip();
            if(!channel.send(new DataChannel.Buffer(frame,true)))throw new Exception();
        }
    }
    boolean open(){return !closed&&channel!=null&&channel.state()==DataChannel.State.OPEN;}
    void awaitClosed()throws Exception{try{disposed.get(10,TimeUnit.SECONDS);}catch(Exception e){throw new Exception("direct_cleanup_failed");}}
    @Override public void close(){close("direct_closed");}
    private synchronized void close(String reason){
        if(closed)return;closeReason=reason;closed=true;actions.shutdownNow();answer.completeExceptionally(new Exception(reason));
        // Dispose after the worker has stopped and callbacks have returned.
        events.execute(()->{
            Exception failure=null;
            try{
                if(!actions.awaitTermination(5,TimeUnit.SECONDS))throw new IllegalStateException("direct_cleanup_failed");
                if(channel!=null){channel.unregisterObserver();channel.close();channel.dispose();channel=null;}
                if(peer!=null){peer.close();peer.dispose();peer=null;}factory=null;
            }catch(Exception e){failure=e;}
            finally{
                try{WifiBinding.release(agent.context,this);}catch(Exception e){if(failure==null)failure=e;}
                events.shutdown();if(failure==null)disposed.complete(null);else disposed.completeExceptionally(failure);
            }
        });
    }
}
