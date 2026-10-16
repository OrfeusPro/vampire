package net.phoneexit;

import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import org.webrtc.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

public class ClientCallbacksTest {
    @Test public void closeDisposesFactoryAfterBusySignalingLoop()throws Exception{
        ClientTransport link=new ClientTransport(null,null,null,()->{},()->{});
        PeerConnectionFactory factory=mock(PeerConnectionFactory.class);
        java.lang.reflect.Field f=ClientTransport.class.getDeclaredField("factory");f.setAccessible(true);f.set(link,factory);
        CountDownLatch entered=new CountDownLatch(1),resume=new CountDownLatch(1),disposed=new CountDownLatch(1);
        doAnswer(call->{disposed.countDown();return null;}).when(factory).dispose();
        link.loop.execute(()->{entered.countDown();try{resume.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}});
        assertTrue(entered.await(2,TimeUnit.SECONDS));
        try{link.close();}finally{resume.countDown();}
        assertTrue("Queued cleanup must run even when close races an active HTTPS/SDP task",disposed.await(3,TimeUnit.SECONDS));
        assertTrue(link.loop.awaitTermination(2,TimeUnit.SECONDS));
        verify(factory,times(1)).dispose();
    }
    @Test public void nativeCallbackReturnsWhileChannelCreationHoldsTransportLock()throws Exception{
        ClientTransport link=new ClientTransport(null,null,null,()->{},()->{});
        PeerConnection peer=mock(PeerConnection.class);DataChannel one=mock(DataChannel.class),two=mock(DataChannel.class);
        AtomicReference<DataChannel.Observer> nativeObserver=new AtomicReference<>();CountDownLatch processed=new CountDownLatch(1);
        java.lang.reflect.Field p=ClientTransport.class.getDeclaredField("peer");p.setAccessible(true);p.set(link,peer);
        java.lang.reflect.Field r=ClientTransport.class.getDeclaredField("ready");r.setAccessible(true);r.set(link,true);
        when(one.state()).thenReturn(DataChannel.State.OPEN);
        doAnswer(call->{nativeObserver.set(call.getArgument(0));return null;}).when(one).registerObserver(any());
        try{
            link.observe(one,new DataChannel.Observer(){
                public void onBufferedAmountChange(long n){}
                public void onMessage(DataChannel.Buffer b){}
                public void onStateChange(){link.state(one);processed.countDown();}
            });
            when(peer.createDataChannel(anyString(),any())).thenAnswer(call->{
                CountDownLatch returned=new CountDownLatch(1);
                Thread signaling=new Thread(()->{nativeObserver.get().onStateChange();returned.countDown();});signaling.setDaemon(true);signaling.start();
                assertTrue("Native observer must never wait for the transport monitor",returned.await(2,TimeUnit.SECONDS));return two;
            });
            assertSame(two,link.channel(true));assertTrue(processed.await(2,TimeUnit.SECONDS));
        }finally{link.close();}
    }
}
