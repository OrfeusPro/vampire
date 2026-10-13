package net.phoneexit;

import android.accessibilityservice.*;
import android.content.*;
import android.graphics.*;
import android.os.*;
import android.view.*;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.util.Base64;
import org.json.*;
import java.io.*;
import java.util.concurrent.*;

public final class ControlAccessibility extends AccessibilityService {
    static volatile ControlAccessibility current;
    static volatile String foreground="";
    private long lastScreenshot=-1000,lastAction=-1000;
    @Override protected void onServiceConnected(){current=this;}
    @Override public void onAccessibilityEvent(AccessibilityEvent e){if(e.getPackageName()!=null)foreground=e.getPackageName().toString();}
    @Override public void onInterrupt(){}
    @Override public void onDestroy(){if(current==this)current=null;foreground="";super.onDestroy();}
    static boolean allowed(Context c){return ExitService.enabled(c)&&c.getSharedPreferences("control",MODE_PRIVATE).getBoolean("enabled",true);}
    private boolean validAccess(){return current==this&&allowed(this)&&!getSystemService(android.app.KeyguardManager.class).isKeyguardLocked();}
    private boolean protectedUi(){return foreground.equals(getPackageName())||foreground.contains("packageinstaller")||foreground.contains("permissioncontroller")||foreground.equals("com.android.settings")||foreground.equals("com.android.systemui");}
    private String activePackage(){AccessibilityNodeInfo root=getRootInActiveWindow();if(root==null)return "";try{return root.getPackageName()==null?"":root.getPackageName().toString();}finally{root.recycle();}}
    private JSONObject inputText(JSONObject args,boolean delete,boolean enter)throws Exception{
        if(protectedUi()||foreground.isEmpty())throw new Exception("protected_system_ui");
        AccessibilityNodeInfo root=getRootInActiveWindow();if(root==null)throw new Exception("input_field_not_accessible");
        AccessibilityNodeInfo field=null;
        try{
            field=root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT);
            if(field==null||!field.isEditable()||field.isPassword())throw new Exception("input_field_not_accessible");
            boolean done;
            if(enter){if(Build.VERSION.SDK_INT<30)throw new Exception("key_not_supported");done=field.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.getId());}
            else{
                String text=args.optString("text","");
                if(delete){String old=field.getText()==null?"":field.getText().toString();int cursor=field.getTextSelectionStart();if(cursor<0)cursor=old.length();int end=field.getTextSelectionEnd();if(end<cursor)end=cursor;
                    int from=cursor==end&&cursor>0?old.offsetByCodePoints(cursor,-1):cursor;text=old.substring(0,from)+old.substring(end);}
                if(text.length()>4096)throw new Exception("text_too_large");Bundle data=new Bundle();data.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,text);done=field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,data);
            }
            if(!done)throw new Exception("input_field_action_rejected");return new JSONObject().put("performed",true);
        }finally{if(field!=null)field.recycle();root.recycle();}
    }
    // Local bot capture keeps pixels in memory: no PNG/Base64 encode/decode round trip.
    Bitmap captureLocal(java.util.function.BooleanSupplier connected)throws Exception{
        CompletableFuture<Bitmap> future=new CompletableFuture<>();Handler main=new Handler(Looper.getMainLooper());long deadline=SystemClock.elapsedRealtime()+7500;
        Runnable[] task=new Runnable[1];task[0]=()->{try{
            if(future.isDone())return;if(!validAccess()||!connected.getAsBoolean())throw new Exception("control_disabled_or_screen_locked");
            long now=SystemClock.elapsedRealtime();if(now>=deadline)throw new Exception("action_timeout");long wait=lastScreenshot+1000-now;
            if(wait>0){main.postDelayed(task[0],wait);return;}lastScreenshot=now;
            if(Build.VERSION.SDK_INT<30)throw new Exception("screenshot_requires_android_11");
            takeScreenshot(Display.DEFAULT_DISPLAY,getMainExecutor(),new TakeScreenshotCallback(){
                public void onFailure(int code){future.completeExceptionally(new Exception("screenshot_denied_"+code));}
                public void onSuccess(ScreenshotResult shot){Bitmap hardware=null,bitmap=null,scaled=null;try{
                    if(future.isDone())return;if(!validAccess()||!connected.getAsBoolean())throw new Exception("control_disabled_or_screen_locked");
                    hardware=Bitmap.wrapHardwareBuffer(shot.getHardwareBuffer(),shot.getColorSpace());if(hardware==null)throw new Exception("screenshot_failed");
                    bitmap=hardware.copy(Bitmap.Config.ARGB_8888,false);float scale=Math.min(1f,1280f/Math.max(bitmap.getWidth(),bitmap.getHeight()));
                    scaled=Bitmap.createScaledBitmap(bitmap,Math.round(bitmap.getWidth()*scale),Math.round(bitmap.getHeight()*scale),true);
                    if(future.complete(scaled)){if(scaled==bitmap)bitmap=null;scaled=null;}
                }catch(Exception e){future.completeExceptionally(e);}finally{if(scaled!=null&&scaled!=bitmap)scaled.recycle();if(bitmap!=null)bitmap.recycle();if(hardware!=null)hardware.recycle();shot.getHardwareBuffer().close();}}
            });
        }catch(Exception e){future.completeExceptionally(e);}};main.post(task[0]);
        try{return future.get(8,TimeUnit.SECONDS);}catch(TimeoutException e){future.cancel(false);throw new Exception("action_timeout");}catch(InterruptedException e){future.cancel(false);Thread.currentThread().interrupt();throw e;}catch(ExecutionException e){throw new Exception(e.getCause().getMessage());}
    }
    JSONObject execute(String command,JSONObject args,java.util.function.BooleanSupplier connected) throws Exception {
        CompletableFuture<JSONObject> future=new CompletableFuture<>();
        Handler main=new Handler(Looper.getMainLooper());long deadline=SystemClock.elapsedRealtime()+7500;
        Runnable[] task=new Runnable[1];task[0]=()->{
            try{
                if(!validAccess()||!connected.getAsBoolean())throw new Exception("control_disabled_or_screen_locked");
                if(future.isDone())return;
                long now=SystemClock.elapsedRealtime();if(now>=deadline)throw new Exception("action_timeout");
                boolean shot=command.equals("screenshot"),rateAction=java.util.Arrays.asList("tap","swipe","longPress","gesture","back","home","launch","keyevent","inputText").contains(command);
                long wait=shot?lastScreenshot+1000-now:rateAction?lastAction+1000-now:0;
                if(wait>0){main.postDelayed(task[0],wait);return;}
                if(shot)lastScreenshot=now;if(rateAction)lastAction=now;
                String observed=activePackage();foreground=observed;
                if(command.equals("foreground")){if(observed.isEmpty())throw new Exception("foreground_unavailable");future.complete(new JSONObject().put("package",observed).put("activity",JSONObject.NULL));return;}
                if(command.equals("inputText")){future.complete(inputText(args,false,false));return;}
                if(command.equals("keyevent")){
                    int key=args.getInt("key");
                    if(key==66||key==67){future.complete(inputText(args,key==67,key==66));return;}
                    if(key==24||key==25){if(protectedUi())throw new Exception("protected_system_ui");getSystemService(android.media.AudioManager.class).adjustStreamVolume(android.media.AudioManager.STREAM_MUSIC,key==24?1:-1,0);future.complete(new JSONObject().put("performed",true));return;}
                    int action=key==3?GLOBAL_ACTION_HOME:key==4?GLOBAL_ACTION_BACK:key==187?GLOBAL_ACTION_RECENTS:0;
                    if(action==0)throw new Exception("key_not_supported");if(key!=3&&protectedUi())throw new Exception("protected_system_ui");
                    if(!performGlobalAction(action))throw new Exception("action_failed");future.complete(new JSONObject().put("performed",true));return;
                }
                if(command.equals("back")||command.equals("home")){
                    if(protectedUi()&&command.equals("back"))throw new Exception("protected_system_ui");
                    if(!performGlobalAction(command.equals("back")?GLOBAL_ACTION_BACK:GLOBAL_ACTION_HOME))throw new Exception("action_failed");
                    future.complete(new JSONObject().put("performed",true));return;
                }
                if(command.equals("launch")){
                    String pkg=args.getString("package");if(!pkg.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+")||pkg.length()>200||pkg.equals(getPackageName())||pkg.contains("packageinstaller")||pkg.contains("permissioncontroller")||pkg.equals("com.android.settings"))throw new Exception("invalid_package");
                    Intent launch=getPackageManager().getLaunchIntentForPackage(pkg);if(launch==null)throw new Exception("package_not_launchable");
                    String activity=args.optString("activity","");if(!activity.isEmpty()){if(activity.startsWith("."))activity=pkg+activity;if(launch.getComponent()==null||!launch.getComponent().getClassName().equals(activity))throw new Exception("activity_not_launcher");}
                    launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);startActivity(launch);future.complete(new JSONObject().put("launched",true));return;
                }
                if(command.equals("screenshot")){
                    if(Build.VERSION.SDK_INT<30)throw new Exception("screenshot_requires_android_11");
                    String format=args.optString("format","jpg");int quality=args.optInt("quality",80),targetW=args.optInt("width",0),targetH=args.optInt("height",0);
                    if(!format.equals("jpg")&&!format.equals("png")||quality<0||quality>100||targetW<0||targetH<0||targetW>1280||targetH>1280||(targetW==0)!=(targetH==0))throw new Exception("invalid_screenshot_options");
                    takeScreenshot(Display.DEFAULT_DISPLAY,getMainExecutor(),new TakeScreenshotCallback(){
                        public void onFailure(int code){future.completeExceptionally(new Exception("screenshot_denied_"+code));}
                        public void onSuccess(ScreenshotResult shot){
                            try{
                                if(future.isDone())return;
                                if(!validAccess()||!connected.getAsBoolean())throw new Exception("control_disabled");
                                Bitmap hardware=Bitmap.wrapHardwareBuffer(shot.getHardwareBuffer(),shot.getColorSpace());
                                if(hardware==null)throw new Exception("screenshot_failed");
                                Bitmap bitmap=hardware.copy(Bitmap.Config.ARGB_8888,false);hardware.recycle();
                                int w=bitmap.getWidth(),h=bitmap.getHeight();float scale=Math.min(1f,1280f/Math.max(w,h));
                                Bitmap scaled=Bitmap.createScaledBitmap(bitmap,targetW>0?targetW:Math.round(w*scale),targetH>0?targetH:Math.round(h*scale),true);
                                ByteArrayOutputStream out=new ByteArrayOutputStream();scaled.compress(format.equals("png")?Bitmap.CompressFormat.PNG:Bitmap.CompressFormat.JPEG,quality,out);
                                if(out.size()>1400000)throw new Exception("screenshot_too_large");
                                JSONObject result=new JSONObject().put("width",scaled.getWidth()).put("height",scaled.getHeight()).put("nativeWidth",w).put("nativeHeight",h).put("captureStartedElapsedMs",now).put("format",format.equals("png")?"png":"jpeg").put("image",Base64.encodeToString(out.toByteArray(),Base64.NO_WRAP));
                                if(scaled!=bitmap)scaled.recycle();bitmap.recycle();future.complete(result);
                            }catch(Exception e){future.completeExceptionally(e);}finally{shot.getHardwareBuffer().close();}
                        }
                    });return;
                }
                if(!command.equals("tap")&&!command.equals("swipe")&&!command.equals("longPress")&&!command.equals("gesture"))throw new Exception("unsupported_command");
                if(foreground.isEmpty()||protectedUi())throw new Exception("protected_system_ui");
                WindowManager wm=getSystemService(WindowManager.class);Point screen=new Point();wm.getDefaultDisplay().getRealSize(screen);
                float scale=Math.min(1f,1280f/Math.max(screen.x,screen.y));int w=Math.round(screen.x*scale),h=Math.round(screen.y*scale);
                if(args.getInt("width")!=w||args.getInt("height")!=h)throw new Exception("screen_geometry_changed");
                GestureDescription.Builder gestures=new GestureDescription.Builder();
                if(command.equals("gesture")){
                    JSONArray strokes=args.getJSONArray("strokes");if(strokes.length()<1||strokes.length()>10)throw new Exception("invalid_gesture");
                    for(int i=0;i<strokes.length();i++){JSONObject stroke=strokes.getJSONObject(i);int start=stroke.optInt("startMs",0),duration=stroke.getInt("durationMs");JSONArray points=stroke.getJSONArray("points");
                        if(start<0||duration<1||start+duration>5000||points.length()<1||points.length()>64)throw new Exception("invalid_gesture");Path path=new Path();
                        for(int j=0;j<points.length();j++){JSONObject point=points.getJSONObject(j);float x=coordinate(point,"x",w)/scale,y=coordinate(point,"y",h)/scale;if(j==0)path.moveTo(x,y);else path.lineTo(x,y);}
                        gestures.addStroke(new GestureDescription.StrokeDescription(path,start,duration));
                    }
                }else{
                boolean single=command.equals("tap")||command.equals("longPress");
                Path path=new Path();int x=coordinate(args,single?"x":"x1",w),y=coordinate(args,single?"y":"y1",h);path.moveTo(x/scale,y/scale);
                int duration=80;
                if(command.equals("longPress")){duration=args.getInt("durationMs");if(duration<100||duration>5000)throw new Exception("invalid_duration");}
                if(command.equals("swipe")){duration=args.getInt("durationMs");if(duration<100||duration>3000)throw new Exception("invalid_duration");path.lineTo(coordinate(args,"x2",w)/scale,coordinate(args,"y2",h)/scale);}
                gestures.addStroke(new GestureDescription.StrokeDescription(path,0,duration));}
                if(!dispatchGesture(gestures.build(),new GestureResultCallback(){
                    public void onCompleted(GestureDescription g){try{future.complete(new JSONObject().put("performed",true));}catch(Exception e){future.completeExceptionally(e);}}
                    public void onCancelled(GestureDescription g){future.completeExceptionally(new Exception("gesture_cancelled"));}
                },null))throw new Exception("gesture_rejected");
            }catch(Exception e){future.completeExceptionally(e);}
        };main.post(task[0]);
        try{return future.get(8,TimeUnit.SECONDS);}catch(TimeoutException e){future.cancel(false);throw new Exception("action_timeout");}catch(InterruptedException e){future.cancel(false);Thread.currentThread().interrupt();throw new Exception("action_cancelled");}catch(ExecutionException e){throw new Exception(e.getCause().getMessage());}
    }
    private static int coordinate(JSONObject args,String field,int limit)throws Exception{Object value=args.get(field);if(!(value instanceof Number)||((Number)value).doubleValue()!=((Number)value).intValue())throw new Exception("invalid_coordinate");int n=((Number)value).intValue();if(n<0||n>=limit)throw new Exception("invalid_coordinate");return n;}
}
