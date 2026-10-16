package net.phoneexit;

import org.json.JSONObject;
import org.webrtc.DataChannel;
import java.util.concurrent.*;

/** Transport boundary also used to exercise real loopback SOCKS without an Android device. */
interface ClientLink {
    boolean ready();
    DataChannel channel(boolean udp);
    void observe(DataChannel dc,DataChannel.Observer observer);
    void release(DataChannel dc);
    DataChannel.State state(DataChannel dc);
    long buffered(DataChannel dc);
    boolean send(DataChannel dc,DataChannel.Buffer buffer);
    boolean control(DataChannel dc,JSONObject value);
    ExecutorService io();
    ScheduledExecutorService loop();
    void task(Runnable r);
}
