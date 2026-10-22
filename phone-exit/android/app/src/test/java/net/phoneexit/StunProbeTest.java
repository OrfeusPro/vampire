package net.phoneexit;

import java.net.*;
import java.nio.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class StunProbeTest {
    private final byte[] transaction=new byte[12];
    private byte[] response(){return ByteBuffer.allocate(32).putShort((short)0x101).putShort((short)12).putInt(StunProbe.COOKIE).put(transaction)
        .putShort((short)0x20).putShort((short)8).put((byte)0).put((byte)1).putShort((short)(54321^(StunProbe.COOKIE>>>16))).putInt(0x08080808^StunProbe.COOKIE).array();}
    @Test public void xorMappedAddressIsDecodedWithoutPublishingEndpoint()throws Exception{
        byte[] frame=response();InetSocketAddress mapped=StunProbe.response(frame,frame.length,transaction);
        assertEquals(54321,mapped.getPort());assertArrayEquals(new byte[]{8,8,8,8},mapped.getAddress().getAddress());
        assertEquals(20,StunProbe.request(transaction).length);
    }
    @Test public void forgedTransactionTruncationAndAttributeOverflowAreRejected(){
        byte[] wrong=response();wrong[8]=1;assertThrows(Exception.class,()->StunProbe.response(wrong,wrong.length,transaction));
        byte[] frame=response();assertThrows(Exception.class,()->StunProbe.response(frame,31,transaction));
        byte[] overflow=response();overflow[23]=100;assertThrows(Exception.class,()->StunProbe.response(overflow,overflow.length,transaction));
        byte[] cookie=response();cookie[4]=0;assertThrows(Exception.class,()->StunProbe.response(cookie,cookie.length,transaction));
    }
    @Test public void localUdpExchangeValidatesTransactionAndClosesSockets()throws Exception{
        try(DatagramSocket server=new DatagramSocket(0,InetAddress.getLoopbackAddress());DatagramSocket client=new DatagramSocket()){
            server.setSoTimeout(2000);
            Thread responder=new Thread(()->{try{byte[] input=new byte[64];DatagramPacket packet=new DatagramPacket(input,input.length);server.receive(packet);
                byte[] out=response();System.arraycopy(input,8,out,8,12);server.send(new DatagramPacket(out,out.length,packet.getSocketAddress()));
            }catch(Exception e){throw new RuntimeException(e);}});responder.start();
            assertEquals(54321,StunProbe.exchange(client,new InetSocketAddress(InetAddress.getLoopbackAddress(),server.getLocalPort())).getPort());responder.join(2500);assertFalse(responder.isAlive());
        }
    }
}
