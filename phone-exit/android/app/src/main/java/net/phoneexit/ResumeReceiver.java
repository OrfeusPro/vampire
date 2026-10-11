package net.phoneexit;
import android.content.*;
public final class ResumeReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context,Intent intent) {
        String action=intent.getAction();
        if(!Intent.ACTION_BOOT_COMPLETED.equals(action)&&!Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) return;
        if(!ExitService.enabled(context)) return;
        try { context.startForegroundService(new Intent(context,ExitService.class)); }
        catch(RuntimeException e) { ExitService.update("Откройте Phone Exit для возобновления доступа"); }
    }
}
