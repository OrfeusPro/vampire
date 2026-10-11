package net.phoneexit;

import android.content.Context;
import android.net.*;
import org.json.*;
import org.webrtc.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import javax.net.ssl.HttpsURLConnection;

final class ExitEngine implements AutoCloseable {
    final Network wifi;
    private final Context context;
    private final Pairing pairing;
    private final Consumer<String> status;
    private final Runnable stop;
    private final ScheduledExecutorService signals = Executors.newSingleThreadScheduledExecutor();
    // Reader/writer tasks block for each active flow; reserve capacity for
    // connection and final-drain tasks instead of starving them at full load.
    final ExecutorService io = Executors.newFixedThreadPool(384);
    private final ExecutorService releases = Executors.newSingleThreadExecutor();
    private final Set<DataChannel> observed = ConcurrentHashMap.newKeySet();
    private final Set<DataChannel> releasing = ConcurrentHashMap.newKeySet();
    private final Set<TcpFlow> flows = ConcurrentHashMap.newKeySet();
    private final Set<UdpAssociation> datagrams = ConcurrentHashMap.newKeySet();
    private final List<IceCandidate> pending = new ArrayList<>();
    private PeerConnectionFactory factory;
    private PeerConnection peer;
    private DataChannel control;
    private DataChannel extraSignal;
    private final Map<Integer,ExtraPeer> extraPeers=new ConcurrentHashMap<>();
    private volatile boolean closed, linked;
    private volatile long lastPcSeen;
    private boolean remoteSet, offerSeen;
    private int cursor;
    private boolean probeStarted,uploadProbeStarted;
    private volatile WifiDownloadProbe downloadProbe;
    private boolean flowProbeSent;
    final AtomicLong probeBytes=new AtomicLong(),probeFrames=new AtomicLong(),probeCreditWaits=new AtomicLong(),probeBufferWaits=new AtomicLong(),probeWaitNs=new AtomicLong(),probeMaxBuffer=new AtomicLong(),probeSocketBuffer=new AtomicLong();

    ExitEngine(Context context,Network wifi,Pairing pairing,Consumer<String> status,Runnable stop) {
        this.context=context; this.wifi=wifi; this.pairing=pairing; this.status=status; this.stop=stop;
    }
    void start() {
        signals.execute(() -> {
            try {
                // Also confines the native ICE sockets to the selected Wi-Fi.
                ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);
                if (!cm.bindProcessToNetwork(wifi)) {
                    fail("Android запретил доступ к Wi-Fi. Проверьте активный VPN или фильтр трафика (например, AdGuard).");
                    return;
                }
                PeerConnectionFactory.initialize(PeerConnectionFactory.InitializationOptions.builder(context).createInitializationOptions());
                factory=PeerConnectionFactory.builder().createPeerConnectionFactory();
                PeerConnection.RTCConfiguration config = new PeerConnection.RTCConfiguration(Arrays.asList(
                    PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer(),
                    PeerConnection.IceServer.builder("stun:stun.cloudflare.com:3478").createIceServer()));
                config.sdpSemantics=PeerConnection.SdpSemantics.UNIFIED_PLAN;
                peer=factory.createPeerConnection(config,new PeerConnection.Observer() {
                    public void onSignalingChange(PeerConnection.SignalingState s) {}
                    public void onIceConnectionChange(PeerConnection.IceConnectionState s) {
                        if (s==PeerConnection.IceConnectionState.FAILED) fail("Прямая связь не установлена");
                        if (s==PeerConnection.IceConnectionState.DISCONNECTED) later(() -> {
                            if (!closed && peer.iceConnectionState()==PeerConnection.IceConnectionState.DISCONNECTED) fail("Связь с ПК потеряна");
                        },10);
                    }
                    public void onIceConnectionReceivingChange(boolean receiving) {}
                    public void onIceGatheringChange(PeerConnection.IceGatheringState s) {}
                    public void onIceCandidate(IceCandidate c) { enqueue(() -> send(json("type","candidate","value",json("candidate",c.sdp,"sdpMid",c.sdpMid,"sdpMLineIndex",c.sdpMLineIndex)))); }
                    public void onIceCandidatesRemoved(IceCandidate[] c) {}
                    public void onAddStream(MediaStream stream) {}
                    public void onRemoveStream(MediaStream stream) {}
                    public void onRenegotiationNeeded() {}
                    public void onDataChannel(DataChannel dc) { attach(dc); }
                });
                if (peer==null) throw new Exception("WebRTC недоступен");
                status.accept("Ожидаю ПК через Wi-Fi");
                signals.scheduleWithFixedDelay(this::poll,0,1,TimeUnit.SECONDS);
                signals.schedule(() -> { if (!linked) fail("Истекло время сопряжения"); },600,TimeUnit.SECONDS);
                signals.scheduleWithFixedDelay(() -> {
                    if(linked&&!closed&&System.nanoTime()-lastPcSeen>TimeUnit.SECONDS.toNanos(12)) fail("ПК не отвечает, выход остановлен");
                },2,2,TimeUnit.SECONDS);
            } catch(Exception e) { android.util.Log.e("PhoneExit","Startup failed",e); fail("Не удалось запустить соединение (" + e.getClass().getSimpleName() + ")"); }
        });
    }
    private void enqueue(Runnable task) { if (!closed) { try { signals.execute(() -> { if(!closed) task.run(); }); } catch(RejectedExecutionException ignored) {} } }
    void later(Runnable task,long seconds) { if(!closed) { try { signals.schedule(() -> { if(!closed) task.run(); },seconds,TimeUnit.SECONDS); } catch(RejectedExecutionException ignored) {} } }
    private JSONObject api(String op,JSONObject message) throws Exception {
        HttpsURLConnection connection=(HttpsURLConnection)wifi.openConnection(pairing.endpoint);
        connection.setInstanceFollowRedirects(false); connection.setRequestMethod("POST");
        connection.setConnectTimeout(10000); connection.setReadTimeout(10000); connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type","application/json");
        byte[] body=json("token",pairing.token,"role","phone","op",op,"after",cursor,"message",message==null?JSONObject.NULL:message).toString().getBytes(StandardCharsets.UTF_8);
        connection.setFixedLengthStreamingMode(body.length);
        try {
            try(OutputStream output=connection.getOutputStream()) { output.write(body); }
            if(connection.getResponseCode()!=200) throw new IOException("HTTP "+connection.getResponseCode());
            ByteArrayOutputStream result=new ByteArrayOutputStream();
            try(InputStream input=connection.getInputStream()) {
                byte[] buf=new byte[4096]; int n;
                while((n=input.read(buf))!=-1) { if(result.size()+n>262144) throw new IOException("response size"); result.write(buf,0,n); }
            }
            return new JSONObject(result.toString("UTF-8"));
        } finally { connection.disconnect(); }
    }
    private void send(JSONObject message) { if(closed||linked) return; try { api("send",message); } catch(Exception e) { fail("Ошибка сигнализации"); } }
    private void poll() {
        if(closed||linked) return;
        try {
            JSONArray messages=api("poll",null).getJSONArray("messages");
            for(int i=0;i<messages.length();i++) {
                JSONObject item=messages.getJSONObject(i), message=item.getJSONObject("message"), value=message.getJSONObject("value");
                String type=message.getString("type");
                if(type.equals("candidate")) {
                    IceCandidate c=new IceCandidate(value.optString("sdpMid","0"),value.getInt("sdpMLineIndex"),value.getString("candidate"));
                    if(remoteSet) peer.addIceCandidate(c); else pending.add(c);
                } else if(type.equals("offer")&&!offerSeen) {
                    offerSeen=true;
                    peer.setRemoteDescription(new Sdp() {
                        public void onSetSuccess() { enqueue(() -> {
                            remoteSet=true; for(IceCandidate c:pending) peer.addIceCandidate(c); pending.clear();
                            peer.createAnswer(new Sdp() {
                                public void onCreateSuccess(SessionDescription sdp) {
                                    enqueue(() -> peer.setLocalDescription(new Sdp() { public void onSetSuccess() {
                                        enqueue(() -> send(json("type","answer","value",json("type","answer","sdp",sdp.description))));
                                    } },sdp));
                                }
                            },new MediaConstraints());
                        }); }
                    },new SessionDescription(SessionDescription.Type.OFFER,value.getString("sdp")));
                }
                cursor=Math.max(cursor,item.getInt("id"));
            }
        } catch(Exception e) { fail("Ошибка обмена параметрами соединения"); }
    }
    private void attach(DataChannel dc) {
        if(closed) { dc.close(); return; }
        if(dc.label().equals("phone-exit-control-v1")&&control==null) {
            control=dc;
            observe(dc,new DataChannel.Observer() {
                public void onBufferedAmountChange(long amount) {}
                public void onMessage(DataChannel.Buffer buffer) {
                    if(closed||buffer.binary||buffer.data.remaining()>1024) return;
                    try {
                        byte[] bytes=new byte[buffer.data.remaining()]; buffer.data.get(bytes);
                        JSONObject message=new JSONObject(new String(bytes,StandardCharsets.UTF_8));
                        if("bye".equals(message.optString("type"))) { fail("ПК отключился"); return; }
                        String id=message.optString("id","");
                        if("ping".equals(message.optString("type"))&&id.matches("[0-9]{1,16}")) {
                            lastPcSeen=System.nanoTime(); sendControl(dc,json("type","pong","id",id));
                        }
                        if("download-probe".equals(message.optString("type"))&&id.matches("[0-9a-f]{16}")) enqueue(()->startDownloadProbe(id,false));
                        if("upload-probe".equals(message.optString("type"))&&id.matches("[0-9a-f]{16}")) enqueue(()->startDownloadProbe(id,true));
                        if("flow-probe".equals(message.optString("type"))&&id.matches("[0-9a-f]{16}")) enqueue(()->{
                            if(closed||flowProbeSent)return;flowProbeSent=true;
                            sendControl(dc,json("type","flow-probe","id",id,"bytes",probeBytes.get(),"frames",probeFrames.get(),"creditWaits",probeCreditWaits.get(),"bufferWaits",probeBufferWaits.get(),"waitMs",TimeUnit.NANOSECONDS.toMillis(probeWaitNs.get()),"maxBuffer",probeMaxBuffer.get(),"socketBuffer",probeSocketBuffer.get()));
                        });
                    } catch(JSONException ignored) {}
                }
                public void onStateChange() {
                    if(closed) return;
                    if(dc.state()==DataChannel.State.OPEN) { lastPcSeen=System.nanoTime(); linked=true; sendHello(dc); status.accept("ПК подключён · TCP и UDP через Wi-Fi"); }
                    if(dc.state()==DataChannel.State.CLOSED&&!closed) fail("ПК отключился");
                }
            });
            if(dc.state()==DataChannel.State.OPEN) { lastPcSeen=System.nanoTime(); linked=true; sendHello(dc); status.accept("ПК подключён · TCP и UDP через Wi-Fi"); }
        } else if(linked&&dc.label().equals("phone-exit-links-v1")&&extraSignal==null){
            extraSignal=dc;
            observe(dc,new DataChannel.Observer(){
                public void onBufferedAmountChange(long amount){}
                public void onStateChange(){if(!closed&&dc.state()==DataChannel.State.CLOSED)extraFailure();}
                public void onMessage(DataChannel.Buffer buffer){
                    if(closed)return;
                    if(buffer.binary||buffer.data.remaining()>32768){extraFailure();return;}
                    byte[] bytes=new byte[buffer.data.remaining()];buffer.data.get(bytes);
                    enqueue(()->{try{handleExtra(new JSONObject(new String(bytes,StandardCharsets.UTF_8)));}catch(Exception invalid){extraFailure();}});
                }
            });
        } else if(linked&&dc.label().matches("phone-exit-udp-v1-[0-9]+")&&datagrams.size()<64) {
            UdpAssociation association=new UdpAssociation(this,dc);datagrams.add(association);association.start();
        } else if(linked&&dc.label().matches("phone-exit-tcp-v1-[0-9]+")&&flows.size()<128) {
            TcpFlow flow=new TcpFlow(this,dc); flows.add(flow); flow.start();
        } else dc.close();
    }
    void forget(TcpFlow flow) { flows.remove(flow); }
    private void sendHello(DataChannel dc){sendControl(dc,json("type","hello","version",1,"features",new JSONArray().put("udp-v1").put("download-probe-v1").put("upload-probe-v1").put("flow-probe-v1").put("multi-peer-v1"),"limits",json("tcp",128,"udp",64,"mtu",1400,"tcpWindow",1048576,"maxTcpWindow",4194304,"maxPeers",4)));}
    private synchronized void handleExtra(JSONObject msg)throws Exception{
        if(closed||!linked)return;
        int lane=msg.getInt("lane");if(lane<1||lane>3)throw new Exception("lane");
        String type=msg.getString("type");JSONObject value=msg.getJSONObject("value");
        if(type.equals("offer")&&!extraPeers.containsKey(lane)&&"offer".equals(value.optString("type"))){
            if(value.getString("sdp").isEmpty()||value.getString("sdp").length()>32768)throw new Exception("sdp");
            extraPeers.put(lane,new ExtraPeer(this,factory,lane,value));
        }else if(type.equals("candidate")&&extraPeers.containsKey(lane))extraPeers.get(lane).candidate(value);
        else throw new Exception("extra signal");
    }
    void extraTask(Runnable task){enqueue(task);}
    void extraFailure(){if(!closed)enqueue(()->fail("Дополнительное соединение потеряно"));}
    void sendExtra(JSONObject message){if(!closed&&(extraSignal==null||extraSignal.state()!=DataChannel.State.OPEN||!sendControl(extraSignal,message)))extraFailure();}
    void attachExtraFlow(DataChannel dc){attach(dc);}
    private void startDownloadProbe(String id,boolean upload){
        if(closed||!linked||(downloadProbe!=null&&!downloadProbe.finished)||(upload?uploadProbeStarted:probeStarted))return;
        if(upload)uploadProbeStarted=true;else probeStarted=true;
        WifiDownloadProbe probe=new WifiDownloadProbe();downloadProbe=probe;
        ScheduledFuture<?> timeout=signals.schedule(probe::close,60,TimeUnit.SECONDS);
        io.execute(()->{
            WifiDownloadProbe.Result result=probe.run(wifi,upload);timeout.cancel(false);
            enqueue(()->{if(!closed&&control.state()==DataChannel.State.OPEN)sendControl(control,json("type",upload?"upload-probe":"download-probe","id",id,"bytes",result.bytes,"elapsedMs",result.elapsedMs,"success",result.success));});
        });
    }
    void forget(UdpAssociation association) { datagrams.remove(association); }
    void observe(DataChannel channel,DataChannel.Observer observer) {
        synchronized(channel) { channel.registerObserver(observer); observed.add(channel); }
    }
    void releaseChannel(DataChannel channel) {
        if(!releasing.add(channel)) return;
        // Serialize native disposal and finish it before disposing the peer/factory.
        // A delayed main-thread callback can otherwise unregister a stale observer.
        try { releases.execute(() -> { synchronized(channel) {
            if(observed.remove(channel)) channel.unregisterObserver();
            channel.dispose();
        } }); } catch(RejectedExecutionException ignored) {}
    }
    static JSONObject json(Object... pairs) {
        JSONObject out=new JSONObject();
        try { for(int i=0;i<pairs.length;i+=2) out.put((String)pairs[i],pairs[i+1]); } catch(JSONException e) { throw new IllegalArgumentException(e); }
        return out;
    }
    static boolean sendControl(DataChannel dc,JSONObject value) { return dc.send(new DataChannel.Buffer(ByteBuffer.wrap(value.toString().getBytes(StandardCharsets.UTF_8)),false)); }
    private void fail(String text) { if(!closed) { status.accept("Ошибка: "+text); stop.run(); } }
    private class Sdp implements SdpObserver {
        public void onCreateSuccess(SessionDescription sdp) {}
        public void onSetSuccess() {}
        public void onCreateFailure(String error) { fail("Ошибка WebRTC SDP"); }
        public void onSetFailure(String error) { fail("Ошибка WebRTC SDP"); }
    }
    @Override public synchronized void close() {
        if(closed) return; closed=true; signals.shutdownNow();
        if(downloadProbe!=null)downloadProbe.close();
        for(TcpFlow flow:flows) flow.close(); flows.clear(); io.shutdownNow();
        for(UdpAssociation association:datagrams) association.close();datagrams.clear();
        for(ExtraPeer extra:extraPeers.values())extra.closeChannels();
        if(extraSignal!=null){extraSignal.close();releaseChannel(extraSignal);}
        if(control!=null) { if(linked&&control.state()==DataChannel.State.OPEN) sendControl(control,json("type","bye")); control.close(); releaseChannel(control); }
        releases.execute(() -> {
            for(ExtraPeer extra:extraPeers.values())extra.dispose();extraPeers.clear();
            if(peer!=null) { peer.close(); peer.dispose(); } if(factory!=null) factory.dispose();
            context.getSystemService(ConnectivityManager.class).bindProcessToNetwork(null);
        });
        releases.shutdown();
    }
}
