package net.phoneexit;

import android.content.Context;
import org.webrtc.PeerConnectionFactory;

/** Native globals must not be reinitialized while another factory is alive. */
final class WebRtcRuntime {
    private static boolean initialized;
    static synchronized void initialize(Context context){
        if(initialized)return;
        PeerConnectionFactory.initialize(PeerConnectionFactory.InitializationOptions.builder(context.getApplicationContext()).createInitializationOptions());
        initialized=true;
    }
}
