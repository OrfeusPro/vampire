package net.phoneexit;
import java.net.*;

final class PublicAddress {
    static boolean allowed(InetAddress address) {
        if(address.isAnyLocalAddress()||address.isLoopbackAddress()||address.isLinkLocalAddress()||address.isSiteLocalAddress()||address.isMulticastAddress()) return false;
        byte[] b=address.getAddress();
        if(b.length==4) {
            int a=b[0]&255,c=b[1]&255,d=b[2]&255;
            return a!=0 && a!=10 && a!=127 && a<224 && !(a==100&&c>=64&&c<=127)
                && !(a==169&&c==254) && !(a==172&&c>=16&&c<=31) && !(a==192&&c==168)
                && !(a==192&&c==0) && !(a==192&&c==2) && !(a==198&&(c==18||c==19))
                && !(a==198&&c==51&&d==100) && !(a==203&&c==0&&d==113);
        }
        // Only global unicast 2000::/3, excluding documentation and transition ranges.
        return b.length==16 && (b[0]&0xe0)==0x20 && !((b[0]&255)==0x20&&(b[1]&255)==0x02)
            && !((b[0]&255)==0x20&&(b[1]&255)==0x01&&(b[2]&255)==0&&(b[3]&255)==0)
            && !((b[0]&255)==0x20&&(b[1]&255)==0x01&&(b[2]&255)==0x0d&&(b[3]&255)==0xb8);
    }
}
