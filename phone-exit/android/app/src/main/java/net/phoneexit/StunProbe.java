package net.phoneexit;

import java.net.*;
import java.nio.*;
import java.security.SecureRandom;
import java.util.Arrays;

/** Bounded STUN Binding codec. Mapped endpoints exist only in memory. */
final class StunProbe {
    static final int COOKIE=0x2112a442;
    static byte[] request(byte[] transaction){
        if(transaction.length!=12)throw new IllegalArgumentException();
        return ByteBuffer.allocate(20).putShort((short)1).putShort((short)0).putInt(COOKIE).put(transaction).array();
    }
    static InetSocketAddress response(byte[] data,int length,byte[] transaction)throws Exception{
        if(length<20||length>data.length)throw new Exception("stun_invalid");
        ByteBuffer b=ByteBuffer.wrap(data,0,length).order(ByteOrder.BIG_ENDIAN);
        int type=Short.toUnsignedInt(b.getShort()),size=Short.toUnsignedInt(b.getShort());
        if(type!=0x101||b.getInt()!=COOKIE||size%4!=0||size!=length-20)throw new Exception("stun_invalid");
        byte[] actual=new byte[12];b.get(actual);if(!Arrays.equals(actual,transaction))throw new Exception("stun_transaction");
        InetSocketAddress mapped=null;
        while(b.remaining()>=4){
            int attribute=Short.toUnsignedInt(b.getShort()),n=Short.toUnsignedInt(b.getShort()),padding=(4-n%4)%4;
            if(n+padding>b.remaining())throw new Exception("stun_invalid");
            int start=b.position();
            if((attribute==0x20||attribute==1)&&n==8&&data[start+1]==1){
                int port=Short.toUnsignedInt(b.getShort(start+2));byte[] address=Arrays.copyOfRange(data,start+4,start+8);
                if(attribute==0x20){port^=COOKIE>>>16;byte[] mask=ByteBuffer.allocate(4).putInt(COOKIE).array();for(int i=0;i<4;i++)address[i]^=mask[i];}
                if(port==0)throw new Exception("stun_invalid");
                if(attribute==0x20||mapped==null)mapped=new InetSocketAddress(InetAddress.getByAddress(address),port);
            }
            b.position(start+n+padding);
        }
        if(b.remaining()!=0||mapped==null)throw new Exception("stun_no_ipv4_mapping");return mapped;
    }
    static InetSocketAddress exchange(DatagramSocket socket,InetSocketAddress target)throws Exception{
        byte[] transaction=new byte[12];new SecureRandom().nextBytes(transaction);byte[] request=request(transaction);
        socket.send(new DatagramPacket(request,request.length,target));long end=System.nanoTime()+1_500_000_000L;
        for(int count=0;count<8;count++){
            long left=(end-System.nanoTime())/1_000_000;if(left<=0)throw new SocketTimeoutException();socket.setSoTimeout((int)left);
            byte[] bytes=new byte[1024];DatagramPacket packet=new DatagramPacket(bytes,bytes.length);socket.receive(packet);
            if(!target.equals(packet.getSocketAddress()))continue;
            try{return response(bytes,packet.getLength(),transaction);}catch(Exception ignored){}
        }
        throw new SocketTimeoutException();
    }
}
