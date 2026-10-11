package net.phoneexit;
import java.net.InetAddress;

public class PublicAddressTest {
    public static void main(String[] args) throws Exception {
        for(String address:new String[]{"0.0.0.0","127.0.0.1","10.1.2.3","172.16.0.1","192.168.0.1","100.64.0.1","169.254.169.254","224.0.0.1","255.255.255.255","198.18.0.1","::1","fc00::1","fe80::1","ff02::1","::ffff:127.0.0.1","2001:db8::1","2002:0a00:0001::1"}) {
            if(PublicAddress.allowed(InetAddress.getByName(address))) throw new AssertionError("Allowed reserved address: "+address);
        }
        for(String address:new String[]{"1.1.1.1","8.8.8.8","2606:4700:4700::1111"}) {
            if(!PublicAddress.allowed(InetAddress.getByName(address))) throw new AssertionError("Blocked public address: "+address);
        }
        System.out.println("PASS: public IPv4/IPv6 and private/mapped/transition exclusions");
    }
}
