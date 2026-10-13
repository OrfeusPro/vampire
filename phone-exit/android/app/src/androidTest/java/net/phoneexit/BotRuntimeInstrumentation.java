package net.phoneexit;
import android.app.Instrumentation;
import android.content.*;
import android.os.*;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/** USB-only fixture: real separate Python process, Binder, screen capture and gestures. */
public final class BotRuntimeInstrumentation extends Instrumentation {
    private Bundle args;
    @Override public void onCreate(Bundle b){args=b;super.onCreate(b);start();}
    private void write(File f,String s)throws Exception{try(OutputStream out=new FileOutputStream(f)){out.write(s.getBytes(StandardCharsets.UTF_8));}}
    @Override public void onStart(){Bundle result=new Bundle();Context c=getTargetContext();JSONObject old=null;File dir=new File(BotStore.root(c),"runtime-test");
        if(args.containsKey("retryPolicy")){retryPolicy(c,result);return;}
        if(args.containsKey("retryRuntime")){retryRuntime(c,result);return;}
        if(args.containsKey("diagnostics")){diagnostics(c,result);return;}
        if(args.containsKey("visionZip")){visionBenchmark(c,result);return;}
        try{
            old=BotStore.read(c,"state");if(old.optString("botId").equals("runtime-test"))old=new JSONObject();dir.mkdirs();
            write(new File(dir,"manifest.json"),"{\"packages\":[\"net.phoneexit.fixture\"]}");
            write(new File(dir,"bot.py"),"def tick(host,settings,state,directory):\n f=host.call('capture')\n m=host.call('match',name='fixture_color',spec={'detector':{'type':'hsv_ratio','low':[60,10,100],'high':[100,255,255],'minRatio':.01}})\n if not m['found']: raise RuntimeError('fixture_color_not_found')\n host.call('tap',x=int(f['width']*settings['x']),y=int(f['height']*settings['y']),width=f['width'],height=f['height'])\n state['count']=state.get('count',0)+1\n return {'status':'running','step':'fixture_'+str(state['count'])}\n");
            JSONObject value=new JSONObject().put("settingsVersion",1).put("x",Double.parseDouble(args.getString("x","0.5"))).put("y",Double.parseDouble(args.getString("y","0.12"))).put("farm_map_spots",new JSONArray());
            BotStore.write(c,"runtime-test-installed",new JSONObject().put("directory",dir.getAbsolutePath()).put("version","test").put("settingsVersion",1));
            BotStore.write(c,"runtime-test-settings",new JSONObject().put("revision",1).put("value",value));
            BotStore.write(c,"state",new JSONObject().put("botId","runtime-test").put("desired","paused").put("generation","test-run").put("status","starting"));
            c.startActivity(new Intent(c,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));Thread.sleep(1000);
            c.startActivity(c.getPackageManager().getLaunchIntentForPackage("net.phoneexit.fixture").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            Thread.sleep(1500);long ready=SystemClock.elapsedRealtime()+30000;
            while(ControlAccessibility.current==null&&SystemClock.elapsedRealtime()<ready)Thread.sleep(300);
            if(ControlAccessibility.current==null)throw new Exception("accessibility_permission_required");
            BotStore.write(c,"state",new JSONObject().put("botId","runtime-test").put("desired","running").put("generation","test-run").put("status","starting"));
            c.startForegroundService(new Intent(c,BotService.class));
            int target=Integer.parseInt(args.getString("ticks","30"));if(target<30||target>3600)throw new Exception("invalid_test_ticks");
            long end=SystemClock.elapsedRealtime()+target*1500L+50000;int count=0;boolean revision=false;
            while(SystemClock.elapsedRealtime()<end){JSONObject s=BotStore.read(c,"state");String step=s.optString("step");if(s.optString("status").equals("error"))throw new Exception(s.optString("error","bot_error"));
                if(step.startsWith("fixture_"))count=Integer.parseInt(step.substring(8));
                if(count>=10&&!revision){BotStore.write(c,"runtime-test-settings",new JSONObject().put("revision",2).put("value",value));revision=true;}
                if(count>=target&&s.optInt("appliedRevision")==2)break;Thread.sleep(300);
            }
            if(count<target||!revision)throw new Exception("bot_runtime_timeout");
            BotManager.manualPause(c);String step=BotStore.read(c,"state").optString("step");Thread.sleep(2500);if(!step.equals(BotStore.read(c,"state").optString("step")))throw new Exception("bot_pause_failed");
            result.putString("stream","PASS "+target+" local Python/OpenCV/Binder screenshots/actions, settings revision 2, manual pause");finish(0,result);
        }catch(Exception e){result.putString("stream","FAIL "+BotManager.safe(e));finish(1,result);}
        finally{c.stopService(new Intent(c,BotService.class));try{if(old!=null)BotStore.write(c,"state",old);}catch(Exception ignored){}}
    }
    private void retryPolicy(Context c,Bundle result){JSONObject old=null;int code=0;
        try{
            old=BotStore.read(c,"state");long now=100000;
            JSONObject state=new JSONObject().put("botId","retry-test").put("desired","running").put("generation","first");
            JSONObject failure=new JSONObject().put("status","error").put("error","farm_floor_not_verified").put("step","farm_transition").put("pause",true);
            for(int i=1;i<=5;i++){
                String generation=state.getString("generation");BotRetry.apply(state,failure,now+i*10000,false);
                if(state.getInt("retryCount")!=i||!state.getString("desired").equals("running")||state.getString("generation").equals(generation)||state.getLong("retryAt")!=now+i*10000+5000||!state.isNull("error"))throw new Exception("retry_schedule_failed");
                JSONObject success=new JSONObject().put("status","running");BotRetry.apply(state,success,now+i*10000+6000,false);
                if(state.getInt("retryCount")!=i||state.has("retryAt"))throw new Exception("success_reset_budget");
            }
            state.put("error","farm_floor_not_verified");BotRetry.apply(state,failure,now+70000,false);
            if(!state.getBoolean("retryExhausted")||!state.getString("desired").equals("paused")||!state.getString("error").equals("farm_floor_not_verified")||state.getJSONArray("retryHistory").length()!=6)throw new Exception("retry_limit_failed");
            long first=state.getLong("retryWindowStarted");BotRetry.expire(state,first+BotRetry.WINDOW_MS-1);
            if(state.getInt("retryCount")!=5)throw new Exception("retry_expired_early");
            BotRetry.expire(state,first+BotRetry.WINDOW_MS);
            if(state.getInt("retryCount")!=0||!state.getString("desired").equals("paused"))throw new Exception("retry_expiry_resumed_bot");
            for(boolean editor:new boolean[]{true,false}){
                JSONObject paused=new JSONObject().put("desired","paused");
                JSONObject report=editor?failure:new JSONObject().put("status","paused").put("pause",true);
                BotRetry.apply(paused,report,now,editor);
                if(paused.has("retryCount")||!paused.getString("desired").equals("paused"))throw new Exception("non_error_pause_retried");
            }
            BotRetry.reset(state);state.put("desired","running").put("generation","live");BotStore.write(c,"state",state);
            BotManager.report(c,"live",failure);JSONObject scheduled=BotStore.read(c,"state");
            if(scheduled.getInt("retryCount")!=1||!scheduled.has("retryAt"))throw new Exception("manager_did_not_retry");
            BotManager.report(c,"live",failure);if(BotStore.read(c,"state").getInt("retryCount")!=1)throw new Exception("stale_report_retried");
            BotManager.manualPause(c);JSONObject manual=BotStore.read(c,"state");
            if(manual.has("retryAt")||!manual.getString("desired").equals("paused"))throw new Exception("manual_pause_did_not_cancel");
            result.putString("stream","PASS 5 retries, terminal cause/history, persisted 6h window, success retains budget, editor/manual pauses, stale generation");
        }catch(Exception e){result.putString("stream","FAIL "+e.getMessage());code=1;}
        finally{if(old!=null)try{BotStore.write(c,"state",old);}catch(Exception ignored){}}
        finish(code,result);
    }
    private void retryRuntime(Context c,Bundle result){JSONObject old=null;int code=0;File dir=new File(BotStore.root(c),"retry-runtime");
        try{
            old=BotStore.read(c,"state");dir.mkdirs();
            write(new File(dir,"manifest.json"),"{\"packages\":[\"net.phoneexit\"]}");
            write(new File(dir,"bot.py"),"def tick(host,settings,state,directory):\n host.call('capture')\n state['count']=state.get('count',0)+1\n return {'status':'error','step':'fixture_failure_'+str(state['count']),'error':'fixture_transient_error','pause':True}\n");
            BotStore.write(c,"retry-runtime-installed",new JSONObject().put("directory",dir.getAbsolutePath()).put("version","test"));
            BotStore.write(c,"retry-runtime-settings",new JSONObject().put("revision",1).put("value",new JSONObject()));
            BotStore.write(c,"state",new JSONObject().put("botId","retry-runtime").put("desired","running").put("status","starting").put("generation","fixture-"+System.nanoTime()));
            c.startActivity(new Intent(c,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            c.startForegroundService(new Intent(c,BotService.class));
            long end=SystemClock.elapsedRealtime()+60000;JSONObject state=null;
            while(SystemClock.elapsedRealtime()<end){Thread.sleep(250);state=BotStore.read(c,"state");
                if(state.optBoolean("retryExhausted"))break;
                if(!state.optString("desired").equals("running"))throw new Exception("fixture_stopped_before_retry_limit");
            }
            if(state==null||!state.optBoolean("retryExhausted")||state.optInt("retryCount")!=5||!state.optString("desired").equals("paused")||!state.optString("error").equals("fixture_transient_error")||!state.optString("lastRetryStep").equals("fixture_failure_1")||state.getJSONArray("retryHistory").length()!=6)throw new Exception("retry_runtime_failed");
            String generation=state.getString("generation");Thread.sleep(1500);
            if(!BotStore.read(c,"state").getString("generation").equals(generation))throw new Exception("sixth_restart_dispatched");
            result.putString("stream","PASS real Python/Binder/capture: 5 automatic restarts, state reset on each, sixth error stays paused with cause");
        }catch(Exception e){result.putString("stream","FAIL "+e.getMessage());code=1;}
        finally{c.stopService(new Intent(c,BotService.class));if(old!=null)try{BotStore.write(c,"state",old);BotManager.resumeWanted(c);}catch(Exception ignored){}}
        finish(code,result);
    }
    private void diagnostics(Context c,Bundle result){
        File testRoot=new File(c.getCacheDir(),"diagnostics-fixture");
        Context isolated=new ContextWrapper(c){@Override public File getFilesDir(){testRoot.mkdirs();return testRoot;}};
        try(BotVision vision=new BotVision()){
            android.graphics.Bitmap bitmap=android.graphics.Bitmap.createBitmap(64,32,android.graphics.Bitmap.Config.ARGB_8888);bitmap.eraseColor(android.graphics.Color.BLUE);vision.capture(bitmap);
            JSONObject state=new JSONObject().put("generation","fixture-"+System.nanoTime()).put("botId","fixture").put("version","test");JSONObject report=new JSONObject().put("error","fixture_error").put("step","fixture_step");
            String id=BotDiagnostics.save(isolated,state,report,vision.diagnosticJpeg(),vision.frameCapturedAt);JSONObject saved=BotDiagnostics.get(isolated,id);
            if(!saved.getBoolean("hasScreenshot")||saved.getLong("frameCapturedAt")<=0||!saved.getString("error").equals("fixture_error"))throw new Exception("diagnostic_fixture_failed");
            byte[] data=android.util.Base64.decode(saved.getString("image"),android.util.Base64.NO_WRAP);android.graphics.Bitmap decoded=android.graphics.BitmapFactory.decodeByteArray(data,0,data.length);if(decoded==null||decoded.getWidth()!=64||android.graphics.Color.blue(decoded.getPixel(10,10))<240)throw new Exception("diagnostic_frame_mismatch");decoded.recycle();
            if(BotDiagnostics.save(isolated,state,report,null,0)!=null)throw new Exception("diagnostic_duplicate");
            boolean rejected=false;try{BotDiagnostics.get(isolated,"../state");}catch(Exception expected){rejected=true;}if(!rejected)throw new Exception("diagnostic_path_escape");
            File expired=new File(BotDiagnostics.root(isolated),(System.currentTimeMillis()-BotDiagnostics.TTL-1000)+"-"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");expired.mkdirs();BotDiagnostics.prune(isolated,true);if(expired.exists())throw new Exception("diagnostic_ttl_failed");
            result.putString("stream","PASS exact cached JPEG frame, report, duplicate suppression, TTL and invalid id");finish(0,result);
        }catch(Exception e){result.putString("stream","FAIL "+BotManager.safe(e));finish(1,result);}finally{removeFixture(testRoot);}
    }
    private void removeFixture(File f){File[] children=f.listFiles();if(children!=null)for(File child:children)removeFixture(child);f.delete();}
    private void visionBenchmark(Context c,Bundle result){
        try{
            File root=new File(c.getCacheDir(),"vision-benchmark");root.mkdirs();
            try(java.util.zip.ZipInputStream zip=new java.util.zip.ZipInputStream(new FileInputStream(args.getString("visionZip")))){
                java.util.zip.ZipEntry entry;byte[] bytes=new byte[65536];long total=0;int count=0;
                while((entry=zip.getNextEntry())!=null){File out=new File(root,entry.getName());if(++count>4096||!out.getCanonicalPath().startsWith(root.getCanonicalPath()+File.separator))throw new Exception("invalid_test_archive");if(entry.isDirectory()){out.mkdirs();continue;}out.getParentFile().mkdirs();try(OutputStream dest=new FileOutputStream(out)){int n;while((n=zip.read(bytes))!=-1){total+=n;if(total>120000000)throw new Exception("large_test_archive");dest.write(bytes,0,n);}}}
            }
            JSONObject config=new JSONObject(BotManager.read(new File(root,"imported.json"),1048576)).getJSONObject("vision").getJSONObject("templates");
            if(!org.opencv.android.OpenCVLoader.initLocal())throw new Exception("opencv_unavailable");
            if(args.containsKey("arrivalFrame")){
                JSONObject v=new JSONObject(BotManager.read(new File(root,"imported.json"),1048576)).getJSONObject("vision");
                double tx=Double.parseDouble(args.getString("arrivalX")),ty=Double.parseDouble(args.getString("arrivalY"));
                java.util.Set<Double> angles=new java.util.TreeSet<>();JSONArray coarse=v.getJSONArray("farm_tyriosa_marker_angles"),sources=v.getJSONArray("map_navigation_marker_templates");
                for(int i=0;i<coarse.length();i++){double a=coarse.getDouble(i);angles.add(a);for(int offset:new int[]{-30,-15,15,30})angles.add((a+offset+360)%360);}
                long started=SystemClock.elapsedRealtime();JSONObject best=new JSONObject().put("found",false).put("confidence",0);
                try(BotVision vision=new BotVision()){
                    vision.capture(android.graphics.BitmapFactory.decodeFile(args.getString("arrivalFrame")));
                    for(int i=0;i<sources.length();i++)for(double angle:angles){
                        JSONObject spec=new JSONObject().put("file",new File(sources.getString(i)).getName()).put("blackMask",true).put("goldNeighborhood",true).put("angle",angle).put("threshold",v.optDouble("map_navigation_marker_threshold",.55)).put("region",new JSONArray().put((tx-48)/1280).put((ty-48)/720).put((tx+48)/1280).put((ty+48)/720));
                        JSONObject found=vision.match(root,"arrival_"+i+"_"+angle,spec);if(found.getBoolean("found")&&found.getDouble("confidence")>best.getDouble("confidence"))best=found;
                    }
                    if(!best.getBoolean("found")||Math.hypot(best.getJSONArray("point").getDouble(0)-tx,best.getJSONArray("point").getDouble(1)-ty)>20)throw new Exception("local_arrival_not_recognized:"+best);
                    result.putString("stream","PASS local arrival same sources/angles/filter ms="+(SystemClock.elapsedRealtime()-started)+" "+best);finish(0,result);return;
                }
            }
            if(args.containsKey("hudFrame")){
                try(BotVision vision=new BotVision()){
                    vision.capture(android.graphics.BitmapFactory.decodeFile(args.getString("hudFrame")));
                    JSONObject pin=vision.match(root,"hud_pin",new JSONObject().put("file","dungeon_minimap_toggle_icon.png").put("detector",new JSONObject().put("type","minimap_pin")));
                    JSONObject on=vision.match(root,"hud_on",config.getJSONObject("auto_battle_on")),off=vision.match(root,"hud_off",config.getJSONObject("auto_battle_off"));
                    boolean hud=pin.optBoolean("panelVisible")&&(on.getBoolean("found")||off.getBoolean("found")),expected="true".equals(args.getString("hudExpected"));
                    if(hud!=expected)throw new Exception("hud_replay_failed:"+pin+":"+on+":"+off);
                    result.putString("stream","PASS minimap+AUTO expected="+expected+" "+pin+" on="+on+" off="+off);finish(0,result);return;
                }
            }
            if(args.containsKey("powerFrame")){
                try(BotVision vision=new BotVision()){
                    vision.capture(android.graphics.BitmapFactory.decodeFile(args.getString("powerFrame")));
                    JSONObject colors=vision.match(root,"power_colors",new JSONObject().put("detector",new JSONObject().put("type","power_saving_colors").put("detector_only",true)));
                    JSONObject emblem=vision.match(root,"power_emblem",config.getJSONObject("power_saving_emblem"));
                    boolean power=colors.getBoolean("found")&&emblem.getBoolean("found"),expected="true".equals(args.getString("powerExpected"));
                    if(power!=expected)throw new Exception("power_saving_replay_failed:"+colors+":"+emblem);
                    result.putString("stream","PASS original power saving colors+emblem expected="+expected+" "+colors);finish(0,result);return;
                }
            }
            if(args.containsKey("markerFrame")){
                try(BotVision vision=new BotVision()){
                    vision.capture(android.graphics.BitmapFactory.decodeFile(args.getString("markerFrame")));
                    JSONObject spec=new JSONObject().put("file","map_navigation_player_arrow_vmos_http.png").put("blackMask",true).put("goldNeighborhood",true).put("angle",180).put("threshold",.55).put("region",new JSONArray("[0.22,0.16,0.78,0.84]"));
                    JSONObject marker=vision.match(root,"saved_marker",spec);
                    result.putString("stream",marker.toString());
                    if(!marker.getBoolean("found")||Math.abs(marker.getJSONArray("point").getInt(0)-769)>4||Math.abs(marker.getJSONArray("point").getInt(1)-413)>4)throw new Exception("saved_marker_not_recognized");
                    result.putString("stream","PASS saved SG arrow position "+marker.toString());finish(0,result);return;
                }
            }
            StringBuilder report=new StringBuilder();int original=org.opencv.core.Core.getNumThreads();
            try(BotVision vision=new BotVision()){
                vision.capture(android.graphics.BitmapFactory.decodeFile(args.getString("visionFrame")));
                JSONObject pin=vision.match(root,"hud_pin",new JSONObject().put("file","dungeon_minimap_toggle_icon.png").put("detector",new JSONObject().put("type","minimap_pin")));
                if(!pin.getBoolean("found")||!pin.optBoolean("panelVisible"))throw new Exception("minimap_pin_not_confirmed");
                JSONObject metrics=vision.match(root,"hud_metrics",new JSONObject().put("region",new JSONArray("[0.065,0.145,0.225,0.335]")).put("detector",new JSONObject().put("type","region_features")));
                if(!metrics.has("pathRatio")||!metrics.has("edgeRatio")||metrics.getDouble("edgeRatio")<0)throw new Exception("region_features_failed");
                report.append("PASS original minimap pin mask, selected gold strokes and region features\n");
            }
            if(args.containsKey("popupFrame")){try(BotVision vision=new BotVision()){
                vision.capture(android.graphics.BitmapFactory.decodeFile(args.getString("popupFrame")));
                JSONObject detector=new JSONObject().put("type","colored_button").put("regions",new JSONArray("[[0.46,0.49,0.70,0.64],[0.45,0.58,0.72,0.74]]")).put("hueRanges",new JSONArray("[[78,112]]")).put("minArea",850);
                JSONObject ok=vision.match(root,"entry_ok",new JSONObject().put("detector",detector));
                if(!ok.getBoolean("found")||Math.abs(ok.getJSONArray("point").getInt(0)-746)>10||Math.abs(ok.getJSONArray("point").getInt(1)-410)>10)throw new Exception("entry_ok_position_failed");
                detector.put("regions",new JSONArray("[[0.30,0.49,0.52,0.64],[0.30,0.58,0.53,0.74]]")).put("hueRanges",new JSONArray("[[0,10],[165,179]]")).put("minArea",700);
                JSONObject cancel=vision.match(root,"entry_cancel",new JSONObject().put("detector",detector));
                if(!cancel.getBoolean("found")||Math.abs(cancel.getJSONArray("point").getInt(0)-531)>10)throw new Exception("entry_cancel_position_failed");
                report.append("PASS original farm HSV OK/Cancel contours on real remote popup\n");
            }}
            for(int threads:new int[]{1,2,4}){
                try(BotVision vision=new BotVision()){
                    org.opencv.core.Core.setNumThreads(threads);long total=0;
                    for(int pass=0;pass<2;pass++){
                        android.graphics.Bitmap frame=android.graphics.BitmapFactory.decodeFile(args.getString("visionFrame"));vision.capture(frame);
                        for(String name:new String[]{"game_update_notice_title","death_popup","died_text","power_saving_died_text","revive_button","power_saving","game_inventory_icon","town_supplies_icon"}){
                            if(!config.has(name))continue;long started=SystemClock.elapsedRealtime();JSONObject match=vision.match(root,name,config.getJSONObject(name));long ms=SystemClock.elapsedRealtime()-started;
                            total+=ms;report.append("threads=").append(threads).append(" pass=").append(pass).append(' ').append(name).append(" ms=").append(ms).append(" found=").append(match.getBoolean("found")).append(" confidence=").append(match.getDouble("confidence")).append('\n');
                        }
                    }report.append("threads=").append(threads).append(" total_ms=").append(total).append('\n');
                }
            }
            try(BotVision vision=new BotVision()){
                org.opencv.core.Mat raw=org.opencv.imgcodecs.Imgcodecs.imread(new File(root,"templates/map_navigation_player_arrow_vmos_http.png").getAbsolutePath(),org.opencv.imgcodecs.Imgcodecs.IMREAD_COLOR);
                org.opencv.core.Mat scene=org.opencv.core.Mat.zeros(720,1280,org.opencv.core.CvType.CV_8UC3);
                org.opencv.core.Mat target=scene.submat(new org.opencv.core.Rect(700,400,raw.cols(),raw.rows()));raw.copyTo(target);target.release();
                org.opencv.core.Mat rgba=new org.opencv.core.Mat();org.opencv.imgproc.Imgproc.cvtColor(scene,rgba,org.opencv.imgproc.Imgproc.COLOR_BGR2RGBA);
                android.graphics.Bitmap frame=android.graphics.Bitmap.createBitmap(1280,720,android.graphics.Bitmap.Config.ARGB_8888);org.opencv.android.Utils.matToBitmap(rgba,frame);rgba.release();vision.capture(frame);
                JSONObject spec=new JSONObject().put("file","map_navigation_player_arrow_vmos_http.png").put("blackMask",true).put("goldNeighborhood",true).put("threshold",.99).put("region",new JSONArray("[0.4,0.3,0.8,0.8]"));
                for(int i=0;i<2;i++){JSONObject marker=vision.match(root,"synthetic_marker",spec);if(!marker.getBoolean("found")||Math.abs(marker.getJSONArray("point").getInt(0)-(700+raw.cols()/2))>1||Math.abs(marker.getJSONArray("point").getInt(1)-(400+raw.rows()/2))>1)throw new Exception("gold_marker_not_recognized");}
                for(int i=0;i<2;i++){
                    if(i==0)scene.put(10,10,new byte[]{(byte)255,(byte)255,(byte)255});else scene.setTo(new org.opencv.core.Scalar(0,0,0));
                    org.opencv.core.Mat changed=new org.opencv.core.Mat();org.opencv.imgproc.Imgproc.cvtColor(scene,changed,org.opencv.imgproc.Imgproc.COLOR_BGR2RGBA);
                    android.graphics.Bitmap next=android.graphics.Bitmap.createBitmap(1280,720,android.graphics.Bitmap.Config.ARGB_8888);org.opencv.android.Utils.matToBitmap(changed,next);changed.release();vision.capture(next);
                    long hits=vision.unchangedHits;JSONObject marker=vision.match(root,"synthetic_marker",spec);
                    if(i==0&&(!marker.getBoolean("found")||vision.unchangedHits!=hits+1))throw new Exception("unchanged_roi_not_reused");
                    if(i==1&&(marker.getBoolean("found")||vision.unchangedHits!=hits))throw new Exception("changed_roi_stale_match");
                }
                report.append("PASS exact ROI reuse across fresh frames; inside change invalidates recognition\n");
                raw.release();scene.release();report.append("PASS gold marker position and prepared-template reuse\n");
            }
            org.opencv.core.Core.setNumThreads(original);result.putString("stream",report.toString());finish(0,result);
        }catch(Exception e){result.putString("stream","FAIL "+BotManager.safe(e));finish(1,result);}
    }
}
