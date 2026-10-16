package net.phoneexit;

import android.net.Network;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/** Explicit, single-use, fixed-size benchmark; never stores downloaded content. */
final class WifiDownloadProbe implements AutoCloseable {
    private volatile HttpsURLConnection connection;
    private volatile boolean closed;
    volatile boolean finished;
    private static final int SIZE=5000000;
    static final class Result {
        long bytes,elapsedMs;
        boolean success;
    }
    Result run(ExitNetwork wifi,boolean upload) {
        Result result=new Result();long start=System.nanoTime();
        try {
            URL url=new URL(upload?"https://speed.cloudflare.com/__up":"https://speed.cloudflare.com/__down?bytes=5000000");
            InetAddress[] addresses=wifi.resolve(url.getHost());
            if(addresses.length==0)throw new Exception("dns");
            for(InetAddress address:addresses)if(!PublicAddress.allowed(address))throw new Exception("destination");
            HttpsURLConnection candidate=(HttpsURLConnection)wifi.connection(url);
            synchronized(this){if(closed){candidate.disconnect();return result;}connection=candidate;}
            candidate.setInstanceFollowRedirects(false);candidate.setConnectTimeout(10000);candidate.setReadTimeout(10000);
            candidate.setRequestProperty("Accept-Encoding","identity");candidate.setRequestProperty("Cache-Control","no-store");
            if(upload){
                candidate.setRequestMethod("POST");candidate.setDoOutput(true);candidate.setFixedLengthStreamingMode(SIZE);
                candidate.setRequestProperty("Content-Type","application/octet-stream");
                byte[] buffer=new byte[16384];new java.security.SecureRandom().nextBytes(buffer);
                try(OutputStream output=candidate.getOutputStream()){
                    while(!closed&&result.bytes<SIZE&&System.nanoTime()-start<60000000000L){
                        int n=(int)Math.min(buffer.length,SIZE-result.bytes);output.write(buffer,0,n);result.bytes+=n;
                    }
                }
            }
            if(candidate.getResponseCode()!=200)throw new Exception("http");
            if(!upload)try(InputStream input=candidate.getInputStream()){
                byte[] buffer=new byte[16384];
                while(!closed&&result.bytes<SIZE&&System.nanoTime()-start<60000000000L){
                    int n=input.read(buffer,0,(int)Math.min(buffer.length,SIZE-result.bytes));
                    if(n<0)break;result.bytes+=n;
                }
            }
            result.success=!closed&&result.bytes==SIZE;
        }catch(Exception ignored){}finally{
            result.elapsedMs=Math.min(65000,Math.max(1,(System.nanoTime()-start)/1000000));close();finished=true;
        }
        return result;
    }
    @Override public synchronized void close(){closed=true;if(connection!=null)connection.disconnect();}
}
