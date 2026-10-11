package net.phoneexit;

import java.util.*;
import java.nio.charset.StandardCharsets;
import org.json.*;
import org.webrtc.*;

/** One bounded additional association, negotiated over the primary DTLS channel. */
final class ExtraPeer {
    private final ExitEngine engine;
    private final int lane;
    private final PeerConnection peer;
    private final List<IceCandidate> pending=new ArrayList<>();
    private DataChannel control;
    private boolean remoteSet;
    private volatile boolean closed;
    ExtraPeer(ExitEngine engine,PeerConnectionFactory factory,int lane,JSONObject offer) throws Exception {
        this.engine=engine;this.lane=lane;
        PeerConnection.RTCConfiguration config=new PeerConnection.RTCConfiguration(Arrays.asList(
            PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer(),
            PeerConnection.IceServer.builder("stun:stun.cloudflare.com:3478").createIceServer()));
        config.sdpSemantics=PeerConnection.SdpSemantics.UNIFIED_PLAN;
        peer=factory.createPeerConnection(config,new PeerConnection.Observer(){
            public void onSignalingChange(PeerConnection.SignalingState s){}
            public void onIceConnectionChange(PeerConnection.IceConnectionState s){if(!closed&&(s==PeerConnection.IceConnectionState.FAILED||s==PeerConnection.IceConnectionState.DISCONNECTED))engine.extraFailure();}
            public void onIceConnectionReceivingChange(boolean r){}
            public void onIceGatheringChange(PeerConnection.IceGatheringState s){}
            public void onIceCandidate(IceCandidate c){engine.extraTask(()->engine.sendExtra(ExitEngine.json("type","candidate","lane",lane,"value",ExitEngine.json("candidate",c.sdp,"sdpMid",c.sdpMid,"sdpMLineIndex",c.sdpMLineIndex))));}
            public void onIceCandidatesRemoved(IceCandidate[] c){}
            public void onAddStream(MediaStream s){}
            public void onRemoveStream(MediaStream s){}
            public void onRenegotiationNeeded(){}
            public void onDataChannel(DataChannel dc){engine.extraTask(()->attach(dc));}
        });
        if(peer==null)throw new Exception("extra peer");
        peer.setRemoteDescription(new Sdp(){public void onSetSuccess(){engine.extraTask(()->{
            remoteSet=true;for(IceCandidate c:pending)peer.addIceCandidate(c);pending.clear();
            peer.createAnswer(new Sdp(){public void onCreateSuccess(SessionDescription sdp){engine.extraTask(()->peer.setLocalDescription(new Sdp(){public void onSetSuccess(){engine.extraTask(()->engine.sendExtra(ExitEngine.json("type","answer","lane",lane,"value",ExitEngine.json("type","answer","sdp",sdp.description))));}},sdp));}},new MediaConstraints());
        });}},new SessionDescription(SessionDescription.Type.OFFER,offer.getString("sdp")));
    }
    void candidate(JSONObject value)throws Exception{
        IceCandidate c=new IceCandidate(value.optString("sdpMid","0"),value.getInt("sdpMLineIndex"),value.getString("candidate"));
        if(remoteSet)peer.addIceCandidate(c);else{if(pending.size()>=64)throw new Exception("candidates");pending.add(c);}
    }
    private void attach(DataChannel dc){
        if(closed){dc.close();engine.releaseChannel(dc);return;}
        if(dc.label().equals("phone-exit-lane-v1")&&control==null){
            control=dc;engine.observe(dc,new DataChannel.Observer(){
                public void onBufferedAmountChange(long amount){}
                public void onStateChange(){if(closed)return;if(dc.state()==DataChannel.State.OPEN)ready();if(dc.state()==DataChannel.State.CLOSED)engine.extraFailure();}
                public void onMessage(DataChannel.Buffer buffer){
                    if(closed||buffer.binary||buffer.data.remaining()>1024)return;
                    try{byte[] bytes=new byte[buffer.data.remaining()];buffer.data.get(bytes);JSONObject msg=new JSONObject(new String(bytes,StandardCharsets.UTF_8));String id=msg.optString("id");
                        if("ping".equals(msg.optString("type"))&&id.matches("[0-9]{1,16}"))ExitEngine.sendControl(dc,ExitEngine.json("type","pong","id",id));
                    }catch(Exception ignored){}
                }
            });if(dc.state()==DataChannel.State.OPEN)ready();
        }else if(dc.label().matches("phone-exit-tcp-v1-[0-9]+"))engine.attachExtraFlow(dc);
        else{dc.close();engine.releaseChannel(dc);}
    }
    private void ready(){ExitEngine.sendControl(control,ExitEngine.json("type","lane-ready","lane",lane));}
    private class Sdp implements SdpObserver{
        public void onCreateSuccess(SessionDescription s){}public void onSetSuccess(){}
        public void onCreateFailure(String s){engine.extraFailure();}public void onSetFailure(String s){engine.extraFailure();}
    }
    void closeChannels(){closed=true;if(control!=null){control.close();engine.releaseChannel(control);}}
    void dispose(){peer.close();peer.dispose();}
}
