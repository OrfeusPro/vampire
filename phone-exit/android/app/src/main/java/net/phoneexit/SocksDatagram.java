package net.phoneexit;

/** Datagram boundaries are preserved; SOCKS fragmentation is deliberately unsupported. */
final class SocksDatagram {
    static boolean valid(byte[] b){
        if(b.length<7||b.length>1400||b[0]!=0||b[1]!=0||b[2]!=0)return false;
        int offset;
        if(b[3]==1)offset=8;
        else if(b[3]==4)offset=20;
        else if(b[3]==3){
            int n=b[4]&255;if(n<1||n>253||b.length<5+n+3)return false;
            for(int i=5;i<5+n;i++){int c=b[i]&255;if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-'))return false;}
            offset=5+n;
        }else return false;
        return b.length>offset+2&&((b[offset]&255)!=0||(b[offset+1]&255)!=0);
    }
}
