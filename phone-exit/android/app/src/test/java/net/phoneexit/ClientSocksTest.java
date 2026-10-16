package net.phoneexit;

import org.junit.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import org.json.*;
import org.webrtc.DataChannel;
import java.net.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/** Real sockets and production bridge; native channels replaced by an explicit remote script. */
public class ClientSocksTest {
    private FakeLink link;private ClientSocks socks;
    @Before public void setup()throws Exception{link=new FakeLink();socks=new ClientSocks(link);socks.start();}
    @After public void cleanup(){socks.close();link.shutdown();}
    private Socket client()throws Exception{Socket s=new Socket("127.0.0.1",socks.port());s.setSoTimeout(3000);s.getOutputStream().write(new byte[]{5,1,0});assertArrayEquals(new byte[]{5,0},s.getInputStream().readNBytes(2));return s;}
    private void request(Socket s,int command)throws Exception{s.getOutputStream().write(new byte[]{5,(byte)command,0,1,1,1,1,1,0,53});}
    private FakeChannel remote()throws Exception{FakeChannel c=link.created.poll(3,TimeUnit.SECONDS);assertNotNull(c);assertNotNull(c.controls.poll(3,TimeUnit.SECONDS));return c;}
    private void ready(FakeChannel c)throws Exception{c.message(new JSONObject().put("type","ready"));}
    @Test public void bindAndUnsupportedAuthenticationRejected()throws Exception{
        try(Socket s=client()){request(s,2);assertEquals(7,s.getInputStream().readNBytes(10)[1]);assertEquals(-1,s.getInputStream().read());}
        try(Socket s=new Socket("127.0.0.1",socks.port())){s.setSoTimeout(3000);s.getOutputStream().write(new byte[]{5,1,2});assertArrayEquals(new byte[]{5,(byte)255},s.getInputStream().readNBytes(2));assertEquals(-1,s.getInputStream().read());}
    }
    @Test public void binaryTrafficCreditAndHalfClose()throws Exception{
        try(Socket s=client()){
            request(s,1);FakeChannel c=remote();ready(c);assertEquals(0,s.getInputStream().readNBytes(10)[1]);
            byte[] bytes=new byte[40000];new Random(17).nextBytes(bytes);s.getOutputStream().write(bytes);s.shutdownOutput();
            ByteArrayOutputStream received=new ByteArrayOutputStream();while(received.size()<bytes.length){byte[] chunk=c.binary.poll(3,TimeUnit.SECONDS);assertNotNull(chunk);assertTrue(chunk.length<=16384);received.write(chunk);c.message(new JSONObject().put("type","credit").put("bytes",chunk.length));}
            assertArrayEquals(bytes,received.toByteArray());assertEquals("eof",c.controls.poll(3,TimeUnit.SECONDS).getString("type"));
            c.binary(bytes,0,16384);c.binary(bytes,16384,16384);c.binary(bytes,32768,7232);c.message(new JSONObject().put("type","eof"));
            assertArrayEquals(bytes,s.getInputStream().readNBytes(bytes.length));assertEquals(-1,s.getInputStream().read());
        }
    }
    @Test public void threeParallelFlowsAndCloseAll()throws Exception{
        List<Socket> sockets=new ArrayList<>();
        try{
            for(int i=0;i<3;i++){Socket s=client();sockets.add(s);request(s,1);FakeChannel c=remote();ready(c);assertEquals(0,s.getInputStream().readNBytes(10)[1]);c.binary(new byte[]{(byte)i},0,1);assertEquals(i,s.getInputStream().read());}
            socks.close();for(Socket s:sockets)assertEquals(-1,s.getInputStream().read());
        }finally{for(Socket s:sockets)s.close();}
    }
    @Test public void exhaustedCreditStopsReadingUntilGranted()throws Exception{
        try(Socket s=client()){
            request(s,1);FakeChannel c=remote();ready(c);s.getInputStream().readNBytes(10);
            byte[] data=new byte[262144+32768];s.getOutputStream().write(data);
            int n=0;while(true){byte[] b=c.binary.poll(400,TimeUnit.MILLISECONDS);if(b==null)break;n+=b.length;}
            // Socket reads can split frames, leaving less than one frame of credit.
            assertTrue(n>262144-16384&&n<=262144);assertNull(c.binary.poll(250,TimeUnit.MILLISECONDS));
            c.message(new JSONObject().put("type","credit").put("bytes",16384));assertNotNull(c.binary.poll(3,TimeUnit.SECONDS));
        }
    }
    @Test public void invalidCreditAndOversizeRemoteFrameCloseSocket()throws Exception{
        for(boolean credit:new boolean[]{true,false})try(Socket s=client()){
            request(s,1);FakeChannel c=remote();ready(c);s.getInputStream().readNBytes(10);
            if(credit)c.message(new JSONObject().put("type","credit").put("bytes",1));else c.binary(new byte[16385],0,16385);
            assertEquals(-1,s.getInputStream().read());
        }
    }
    @Test public void failedTransportDoesNotOpenNewFlows()throws Exception{
        link.available=false;try(Socket s=client()){request(s,1);assertEquals(1,s.getInputStream().readNBytes(10)[1]);assertEquals(-1,s.getInputStream().read());}assertNull(link.created.poll());
    }
    @Test public void udpBoundariesRepliesAndControlClose()throws Exception{
        try(Socket s=client();DatagramSocket udp=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))){
            // UDP ASSOCIATE with unknown local endpoint, as used by the native TUN stack.
            s.getOutputStream().write(new byte[]{5,3,0,1,0,0,0,0,0,0});FakeChannel c=remote();ready(c);byte[] reply=s.getInputStream().readNBytes(10);assertEquals(0,reply[1]);int port=((reply[8]&255)<<8)|(reply[9]&255);
            ready(c); // duplicate unreliable ready must not close the association
            byte[] one={0,0,0,1,1,1,1,1,0,53,9,8};
            udp.send(new DatagramPacket(one,one.length,InetAddress.getByName("127.0.0.1"),port));assertArrayEquals(one,c.binary.poll(3,TimeUnit.SECONDS));
            byte[] two=one.clone();two[10]=7;udp.send(new DatagramPacket(two,two.length,InetAddress.getByName("127.0.0.1"),port));assertArrayEquals(two,c.binary.poll(3,TimeUnit.SECONDS));
            c.binary(one,0,one.length);udp.setSoTimeout(3000);DatagramPacket packet=new DatagramPacket(new byte[1400],1400);udp.receive(packet);assertArrayEquals(one,Arrays.copyOf(packet.getData(),packet.getLength()));
            s.close();assertTrue(c.released.await(3,TimeUnit.SECONDS));
        }
    }
    private static final class FakeChannel {
        final DataChannel dc=mock(DataChannel.class);DataChannel.Observer observer;
        final BlockingQueue<JSONObject> controls=new LinkedBlockingQueue<>();final BlockingQueue<byte[]> binary=new LinkedBlockingQueue<>();final CountDownLatch released=new CountDownLatch(1);
        void message(JSONObject value){byte[] data=value.toString().getBytes(StandardCharsets.UTF_8);observer.onMessage(new DataChannel.Buffer(ByteBuffer.wrap(data),false));}
        void binary(byte[] data,int start,int count){observer.onMessage(new DataChannel.Buffer(ByteBuffer.wrap(Arrays.copyOfRange(data,start,start+count)),true));}
    }
    private static final class FakeLink implements ClientLink {
        final ExecutorService io=Executors.newCachedThreadPool();final ScheduledExecutorService loop=Executors.newSingleThreadScheduledExecutor();
        final BlockingQueue<FakeChannel> created=new LinkedBlockingQueue<>();final Map<DataChannel,FakeChannel> map=new ConcurrentHashMap<>();volatile boolean available=true;
        public boolean ready(){return available;}
        public DataChannel channel(boolean udp){FakeChannel c=new FakeChannel();map.put(c.dc,c);return c.dc;}
        public void observe(DataChannel dc,DataChannel.Observer observer){FakeChannel c=map.get(dc);c.observer=observer;created.offer(c);}
        public void release(DataChannel dc){FakeChannel c=map.remove(dc);if(c!=null)c.released.countDown();}
        public DataChannel.State state(DataChannel dc){return map.containsKey(dc)?DataChannel.State.OPEN:DataChannel.State.CLOSED;}
        public long buffered(DataChannel dc){return 0;}
        public boolean send(DataChannel dc,DataChannel.Buffer b){FakeChannel c=map.get(dc);if(c==null)return false;byte[] bytes=new byte[b.data.remaining()];b.data.get(bytes);if(b.binary)c.binary.offer(bytes);else try{c.controls.offer(new JSONObject(new String(bytes,StandardCharsets.UTF_8)));}catch(Exception e){throw new AssertionError(e);}return true;}
        public boolean control(DataChannel dc,JSONObject value){FakeChannel c=map.get(dc);if(c==null)return false;c.controls.offer(value);return true;}
        public ExecutorService io(){return io;}public ScheduledExecutorService loop(){return loop;}public void task(Runnable r){loop.execute(r);}
        void shutdown(){io.shutdownNow();loop.shutdownNow();}
    }
}
