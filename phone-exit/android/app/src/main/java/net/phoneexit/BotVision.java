package net.phoneexit;

import android.graphics.*;
import android.util.Base64;
import org.json.*;
import org.opencv.android.*;
import org.opencv.core.*;
import org.opencv.imgcodecs.Imgcodecs;
import org.opencv.imgproc.Imgproc;
import java.io.File;
import java.util.*;
import java.security.MessageDigest;

// Frames and template Mats are local to the bridge, never sent through WebRTC.
final class BotVision implements AutoCloseable {
    private BotAtlasVision atlasVision;
    private Mat frame;private final Map<String,Mat> templates=new LinkedHashMap<>();private final Map<String,JSONObject> cache=new HashMap<>();
    long frameCapturedAt;
    byte[] diagnosticJpeg(){if(frame==null)return null;Mat resized=new Mat();MatOfByte bytes=new MatOfByte();MatOfInt options=new MatOfInt(Imgcodecs.IMWRITE_JPEG_QUALITY,80);try{double scale=Math.min(1,1280.0/Math.max(frame.cols(),frame.rows()));Imgproc.resize(frame,resized,new Size(Math.round(frame.cols()*scale),Math.round(frame.rows()*scale)));if(!Imgcodecs.imencode(".jpg",resized,bytes,options))return null;return bytes.toArray();}finally{resized.release();bytes.release();options.release();}}
    private final Map<String,Mat> scaledTemplates=new LinkedHashMap<>();private final Map<String,Mat> scaledMasks=new HashMap<>();
    private final Map<String,JSONObject> unchangedMatches=new LinkedHashMap<>();private final Map<String,String> regionHashes=new HashMap<>();long unchangedHits;
    BotVision(){if(!OpenCVLoader.initLocal())throw new IllegalStateException("opencv_unavailable");}
    JSONObject capture(JSONObject shot)throws Exception{
        byte[] data=Base64.decode(shot.getString("image"),Base64.NO_WRAP);Bitmap bitmap=BitmapFactory.decodeByteArray(data,0,data.length);if(bitmap==null)throw new Exception("bot_frame_decode");
        return capture(bitmap);
    }
    JSONObject capture(Bitmap bitmap)throws Exception{
        if(frame!=null)frame.release();Mat rgba=new Mat();Utils.bitmapToMat(bitmap,rgba);bitmap.recycle();frame=new Mat();Imgproc.cvtColor(rgba,frame,Imgproc.COLOR_RGBA2BGR);rgba.release();cache.clear();
        frameCapturedAt=System.currentTimeMillis();regionHashes.clear();return new JSONObject().put("width",frame.cols()).put("height",frame.rows());
    }
    JSONObject match(File directory,String name,JSONObject spec)throws Exception{
        if(frame==null)throw new Exception("bot_capture_required");String key=directory.getAbsolutePath()+name+spec.toString();if(cache.containsKey(key))return cache.get(key);
        JSONArray region=spec.optJSONArray("region");int w=frame.cols(),h=frame.rows();int x=region==null?0:(int)Math.round(region.getDouble(0)*w),y=region==null?0:(int)Math.round(region.getDouble(1)*h);
        int right=region==null?w:(int)Math.round(region.getDouble(2)*w),bottom=region==null?h:(int)Math.round(region.getDouble(3)*h);
        x=Math.max(0,x);y=Math.max(0,y);right=Math.min(w,right);bottom=Math.min(h,bottom);if(right<=x||bottom<=y)throw new Exception("bot_invalid_region");
        Mat roi=frame.submat(new org.opencv.core.Rect(x,y,right-x,bottom-y));JSONObject detector=spec.optJSONObject("detector");String type=detector==null?"":detector.optString("type");
        JSONObject result=new JSONObject().put("found",false).put("confidence",0).put("point",new JSONArray().put((x+right)/2).put((y+bottom)/2));
        try{
            if(type.equals("atlas_point")){if(atlasVision==null)atlasVision=new BotAtlasVision();result=atlasVision.locate(directory,frame,spec);cache.put(key,result);return result;}
            if(type.equals("power_saving_colors")){result=powerSavingColors();cache.put(key,result);return result;}
            if(type.equals("region_features")){result=regionFeatures(roi);cache.put(key,result);return result;}
            if(type.equals("colored_button")){result=coloredButton(detector);cache.put(key,result);return result;}
            if(type.equals("hsv_ratio")){
                Mat hsv=new Mat(),mask=new Mat();try{JSONArray low=detector.getJSONArray("low"),high=detector.getJSONArray("high");Imgproc.cvtColor(roi,hsv,Imgproc.COLOR_BGR2HSV);Core.inRange(hsv,new Scalar(low.getDouble(0),low.getDouble(1),low.getDouble(2)),new Scalar(high.getDouble(0),high.getDouble(1),high.getDouble(2)),mask);double ratio=Core.countNonZero(mask)/(double)mask.total();return new JSONObject().put("found",ratio>=detector.getDouble("minRatio")).put("confidence",ratio).put("point",new JSONArray().put((x+right)/2).put((y+bottom)/2));}finally{hsv.release();mask.release();}
            }
            if(type.equals("red_text")||type.equals("bright_text")){
                result=components(roi,x,y,detector,type.equals("red_text"));
                if(result.getBoolean("found")||detector.optBoolean("detector_only")){cache.put(key,result);return result;}
            }
            if(detector!=null&&detector.optBoolean("detector_only")){cache.put(key,result);return result;}
            String file=spec.optString("file","");if(file.isEmpty())return result;File source=new File(directory,"templates/"+file);
            if(!source.getCanonicalPath().startsWith(new File(directory,"templates").getCanonicalPath()+File.separator))throw new Exception("bot_invalid_template");
            Mat raw=templates.get(source.getAbsolutePath());if(raw==null){raw=Imgcodecs.imread(source.getAbsolutePath(),Imgcodecs.IMREAD_UNCHANGED);if(raw.empty()){raw.release();return result;}
                if(templates.size()>=128){String first=templates.keySet().iterator().next();templates.remove(first).release();}templates.put(source.getAbsolutePath(),raw);}
            if(type.equals("minimap_pin")){result=minimapPin(raw);cache.put(key,result);return result;}
            String regionKey=x+":"+y+":"+right+":"+bottom;
            String digest=regionHashes.get(regionKey);if(digest==null){byte[] pixels=new byte[(int)(roi.total()*roi.channels())];roi.get(0,0,pixels);byte[] hash=MessageDigest.getInstance("SHA-256").digest(pixels);digest=Base64.encodeToString(hash,Base64.NO_WRAP);regionHashes.put(regionKey,digest);}
            String unchangedKey=key+":"+w+":"+h+":"+digest;
            JSONObject previous=unchangedMatches.get(unchangedKey);if(previous!=null){unchangedHits++;cache.put(key,previous);return previous;}
            Mat tpl=new Mat(),mask=new Mat(),hay=roi;List<Mat> channels=new ArrayList<>();boolean alpha=raw.channels()==4;
            try{
                if(alpha){Imgproc.cvtColor(raw,tpl,Imgproc.COLOR_BGRA2BGR);Core.split(raw,channels);channels.get(3).copyTo(mask);Imgproc.threshold(mask,mask,1,255,Imgproc.THRESH_BINARY);}else raw.copyTo(tpl);
                if(!alpha&&spec.optBoolean("blackMask")){Mat gray=new Mat();try{Imgproc.cvtColor(tpl,gray,Imgproc.COLOR_BGR2GRAY);Imgproc.threshold(gray,mask,8,255,Imgproc.THRESH_BINARY);alpha=true;}finally{gray.release();}}
                double angle=spec.optDouble("angle",0);if(angle!=0){
                    Mat rotation=Imgproc.getRotationMatrix2D(new org.opencv.core.Point(tpl.cols()/2.,tpl.rows()/2.),angle,1),rotated=new Mat(),rotatedMask=new Mat();
                    try{double cos=Math.abs(rotation.get(0,0)[0]),sin=Math.abs(rotation.get(0,1)[0]);int rw=(int)(tpl.rows()*sin+tpl.cols()*cos),rh=(int)(tpl.rows()*cos+tpl.cols()*sin);rotation.put(0,2,rotation.get(0,2)[0]+rw/2.-tpl.cols()/2.);rotation.put(1,2,rotation.get(1,2)[0]+rh/2.-tpl.rows()/2.);Imgproc.warpAffine(tpl,rotated,rotation,new Size(rw,rh));rotated.copyTo(tpl);if(alpha){Imgproc.warpAffine(mask,rotatedMask,rotation,new Size(rw,rh),Imgproc.INTER_NEAREST);rotatedMask.copyTo(mask);}}finally{rotation.release();rotated.release();rotatedMask.release();}
                }
                if(type.equals("edge_template")){
                    hay=new Mat();Imgproc.cvtColor(roi,hay,Imgproc.COLOR_BGR2GRAY);Imgproc.Canny(hay,hay,detector.optInt("canny_low",45),detector.optInt("canny_high",140));
                    Imgproc.cvtColor(tpl,tpl,Imgproc.COLOR_BGR2GRAY);Imgproc.Canny(tpl,tpl,detector.optInt("canny_low",45),detector.optInt("canny_high",140));alpha=false;
                }
                JSONArray scales=spec.optJSONArray("scales");if(scales==null)scales=new JSONArray().put(1.0);double best=0;int bestX=0,bestY=0,bestW=0,bestH=0;org.opencv.core.Point point=new org.opencv.core.Point((right-x)/2.,(bottom-y)/2.);
                for(int i=0;i<scales.length();i++){
                    double scale=scales.getDouble(i);if(scale<=0||scale>4)continue;int tw=(int)Math.round(tpl.cols()*scale),th=(int)Math.round(tpl.rows()*scale);if(tw<1||th<1||tw>hay.cols()||th>hay.rows())continue;
                    String preparedKey=source.getAbsolutePath()+":"+type+":"+spec.optBoolean("blackMask")+":"+angle+":"+(detector==null?"":detector.optInt("canny_low",45)+":"+detector.optInt("canny_high",140))+":"+tw+":"+th;Mat scaled=scaledTemplates.get(preparedKey),scaledMask=scaledMasks.get(preparedKey),scores=new Mat();
                    if(scaled==null){scaled=new Mat();Imgproc.resize(tpl,scaled,new Size(tw,th));if(alpha){scaledMask=new Mat();Imgproc.resize(mask,scaledMask,new Size(tw,th),0,0,Imgproc.INTER_NEAREST);}if(scaledTemplates.size()>=256){String first=scaledTemplates.keySet().iterator().next();scaledTemplates.remove(first).release();Mat oldMask=scaledMasks.remove(first);if(oldMask!=null)oldMask.release();}scaledTemplates.put(preparedKey,scaled);if(scaledMask!=null)scaledMasks.put(preparedKey,scaledMask);}
                    try{
                        boolean sqdiff=alpha||spec.optString("method").equals("sqdiff");if(alpha){Imgproc.matchTemplate(hay,scaled,scores,Imgproc.TM_SQDIFF_NORMED,scaledMask);}else Imgproc.matchTemplate(hay,scaled,scores,sqdiff?Imgproc.TM_SQDIFF_NORMED:Imgproc.TM_CCOEFF_NORMED);
                        if(spec.optBoolean("goldNeighborhood"))restrictGold(scores,hay,scaled,sqdiff);
                        Core.patchNaNs(scores,sqdiff?1:0);Core.MinMaxLocResult m=Core.minMaxLoc(scores);double confidence=sqdiff?1-m.minVal:m.maxVal;org.opencv.core.Point loc=sqdiff?m.minLoc:m.maxLoc;
                        if(Double.isFinite(confidence)&&confidence>best){best=Math.min(1,Math.max(0,confidence));bestX=x+(int)loc.x;bestY=y+(int)loc.y;bestW=tw;bestH=th;point=new org.opencv.core.Point(bestX+tw/2,bestY+th/2);}
                    }finally{scores.release();}
                }
                result=new JSONObject().put("found",best>=spec.optDouble("threshold",0.82)).put("confidence",best).put("point",new JSONArray().put((int)point.x).put((int)point.y)).put("rect",new JSONArray().put(bestX).put(bestY).put(bestX+bestW).put(bestY+bestH));
            }finally{tpl.release();mask.release();for(Mat ch:channels)ch.release();if(hay!=roi)hay.release();}
            if(unchangedMatches.size()>=1024)unchangedMatches.remove(unchangedMatches.keySet().iterator().next());unchangedMatches.put(unchangedKey,result);
            cache.put(key,result);return result;
        }finally{roi.release();}
    }
    // MultiBot farm.find_farm_colored_button, with unchanged HSV/morphology,
    // contour area, dimensions and score. Coordinates refer to this frame.
    private JSONObject minimapPin(Mat raw)throws Exception{
        Mat resized=new Mat(),gray=new Mat(),template=new Mat(),mask=new Mat(),kernel=Mat.ones(3,3,CvType.CV_8U);Mat hay=null;double best=-1;org.opencv.core.Rect box=null;
        try{
            Imgproc.resize(frame,resized,new Size(1280,720));Imgproc.cvtColor(resized,gray,Imgproc.COLOR_BGR2GRAY);hay=gray.submat(new org.opencv.core.Rect(0,72,128,148));
            Imgproc.cvtColor(raw,template,raw.channels()==4?Imgproc.COLOR_BGRA2GRAY:Imgproc.COLOR_BGR2GRAY);Core.compare(template,new Scalar(60),mask,Core.CMP_GE);Imgproc.dilate(mask,mask,kernel);
            for(double scale:new double[]{.8,.9,1.,1.1,1.2}){Mat sample=new Mat(),alpha=new Mat(),scores=new Mat(),valid=new Mat();try{
                Size size=new Size(Math.round(template.cols()*scale),Math.round(template.rows()*scale));Imgproc.resize(template,sample,size);Imgproc.resize(mask,alpha,size,0,0,Imgproc.INTER_NEAREST);if(sample.cols()>hay.cols()||sample.rows()>hay.rows())continue;
                Imgproc.matchTemplate(hay,sample,scores,Imgproc.TM_CCOEFF_NORMED,alpha);Core.patchNaNs(scores,-1);Core.inRange(scores,new Scalar(-1),new Scalar(1),valid);Core.bitwise_not(valid,valid);scores.setTo(new Scalar(-1),valid);Core.MinMaxLocResult match=Core.minMaxLoc(scores);
                if(match.maxVal>best){best=match.maxVal;box=new org.opencv.core.Rect((int)match.maxLoc.x,(int)match.maxLoc.y+72,sample.cols(),sample.rows());}
            }finally{for(Mat mat:new Mat[]{sample,alpha,scores,valid})mat.release();}}
            JSONObject result=new JSONObject().put("found",best>=.72).put("confidence",Math.max(0,best));if(box==null||best<.72)return result;
            Mat crop=resized.submat(box),hsv=new Mat(),stroke=new Mat(),gold=new Mat(),selected=new Mat();try{
                Core.compare(template,new Scalar(100),stroke,Core.CMP_GE);Imgproc.resize(stroke,stroke,new Size(box.width,box.height),0,0,Imgproc.INTER_NEAREST);Imgproc.cvtColor(crop,hsv,Imgproc.COLOR_BGR2HSV);Core.inRange(hsv,new Scalar(15,30,90),new Scalar(40,255,255),gold);Core.bitwise_and(gold,stroke,selected);int count=Core.countNonZero(stroke);double ratio=count>0?Core.countNonZero(selected)/(double)count:.5;
                result.put("goldStrokeRatio",ratio).put("point",new JSONArray().put((int)Math.round((box.x+box.width/2.)*frame.cols()/1280.)).put((int)Math.round((box.y+box.height/2.)*frame.rows()/720.)));
                if(ratio>=.60)result.put("panelVisible",true);else if(ratio<=.25)result.put("panelVisible",false);return result;
            }finally{for(Mat mat:new Mat[]{crop,hsv,stroke,gold,selected})mat.release();}
        }finally{if(hay!=null)hay.release();for(Mat mat:new Mat[]{resized,gray,template,mask,kernel})mat.release();}
    }
    private JSONObject powerSavingColors()throws Exception{
        // Exact BGR/gray predicates from MultiBot, including strict >/< edges.
        Mat gray=new Mat();
        try{
            Imgproc.cvtColor(frame,gray,Imgproc.COLOR_BGR2GRAY);
            byte[] values=new byte[(int)gray.total()];gray.get(0,0,values);int dark=0;
            for(byte value:values)if((value&255)<85)dark++;
            int w=frame.cols(),h=frame.rows();
            Mat top=gray.submat(new org.opencv.core.Rect((int)(w*.34),(int)(h*.08),(int)(w*.66)-(int)(w*.34),(int)(h*.24)-(int)(h*.08)));
            Mat center=frame.submat(new org.opencv.core.Rect((int)(w*.33),(int)(h*.25),(int)(w*.67)-(int)(w*.33),(int)(h*.68)-(int)(h*.25)));
            try{
                byte[] pixels=new byte[(int)(center.total()*3)],brightPixels=new byte[(int)top.total()];center.get(0,0,pixels);top.get(0,0,brightPixels);
                int bright=0,blue=0,gold=0;for(byte value:brightPixels)if((value&255)>150)bright++;
                for(int i=0;i<pixels.length;i+=3){int b=pixels[i]&255,g=pixels[i+1]&255,r=pixels[i+2]&255;if(b>55&&b>r+8&&b>g+4)blue++;if(r>105&&g>85&&b<90)gold++;}
                double d=dark/(double)gray.total(),t=bright/(double)top.total(),b=blue/(double)center.total(),g=gold/(double)center.total();
                return new JSONObject().put("found",d>=.45&&t>=.007&&b>=.20&&g>=.010).put("confidence",0).put("darkRatio",d).put("topBrightRatio",t).put("blueRatio",b).put("goldRatio",g);
            }finally{top.release();center.release();}
        }finally{gray.release();}
    }
    private JSONObject regionFeatures(Mat crop)throws Exception{
        Mat gray=new Mat(),hsv=new Mat(),mask=new Mat(),edges=new Mat();List<Mat> channels=new ArrayList<>();
        try{Imgproc.cvtColor(crop,gray,Imgproc.COLOR_BGR2GRAY);Imgproc.cvtColor(crop,hsv,Imgproc.COLOR_BGR2HSV);Core.split(hsv,channels);double total=crop.total();JSONObject result=new JSONObject().put("found",false).put("confidence",0);
            for(int threshold:new int[]{55,60,70,80}){Core.compare(gray,new Scalar(threshold),mask,Core.CMP_LT);result.put("dark"+threshold+"Ratio",Core.countNonZero(mask)/total);}
            Imgproc.Canny(gray,edges,50,120);result.put("edgeRatio",Core.countNonZero(edges)/total).put("meanSaturation",Core.mean(channels.get(1)).val[0]);
            Core.inRange(hsv,new Scalar(0,0,0),new Scalar(179,184,89),mask);result.put("darkMapRatio",Core.countNonZero(mask)/total);
            Core.inRange(hsv,new Scalar(0,0,86),new Scalar(179,119,255),mask);result.put("brightTownRatio",Core.countNonZero(mask)/total);
            Core.inRange(hsv,new Scalar(0,0,66),new Scalar(179,94,214),mask);result.put("pathRatio",Core.countNonZero(mask)/total);return result;
        }finally{for(Mat mat:new Mat[]{gray,hsv,mask,edges})mat.release();for(Mat mat:channels)mat.release();}
    }
    private JSONObject coloredButton(JSONObject spec)throws Exception{
        JSONArray regions=spec.getJSONArray("regions"),ranges=spec.getJSONArray("hueRanges");
        double best=-1;int px=0,py=0;Mat kernel=Mat.ones(5,9,CvType.CV_8U);
        try{for(int r=0;r<regions.length();r++){
            JSONArray bounds=regions.getJSONArray(r);int x1=Math.max(0,(int)Math.round(bounds.getDouble(0)*frame.cols())),y1=Math.max(0,(int)Math.round(bounds.getDouble(1)*frame.rows()));
            int x2=Math.min(frame.cols(),(int)Math.round(bounds.getDouble(2)*frame.cols())),y2=Math.min(frame.rows(),(int)Math.round(bounds.getDouble(3)*frame.rows()));if(x2<=x1||y2<=y1)continue;
            Mat crop=frame.submat(new org.opencv.core.Rect(x1,y1,x2-x1,y2-y1)),hsv=new Mat(),mask=Mat.zeros(crop.rows(),crop.cols(),CvType.CV_8U),part=new Mat(),hierarchy=new Mat();List<MatOfPoint> contours=new ArrayList<>();
            try{
                Imgproc.cvtColor(crop,hsv,Imgproc.COLOR_BGR2HSV);
                for(int h=0;h<ranges.length();h++){JSONArray range=ranges.getJSONArray(h);Core.inRange(hsv,new Scalar(range.getInt(0),45,45),new Scalar(range.getInt(1),255,255),part);Core.bitwise_or(mask,part,mask);}
                Imgproc.morphologyEx(mask,mask,Imgproc.MORPH_CLOSE,kernel);Imgproc.findContours(mask,contours,hierarchy,Imgproc.RETR_EXTERNAL,Imgproc.CHAIN_APPROX_SIMPLE);
                for(MatOfPoint contour:contours){org.opencv.core.Rect box=Imgproc.boundingRect(contour);double area=Imgproc.contourArea(contour);
                    if(area<spec.getDouble("minArea")||box.width<90||box.height<25||box.width/(double)Math.max(1,box.height)<2)continue;
                    double score=area*box.width/Math.max(1.,box.height);if(score>best){best=score;px=x1+box.x+box.width/2;py=y1+box.y+box.height/2;}
                }
            }finally{for(MatOfPoint contour:contours)contour.release();for(Mat mat:new Mat[]{crop,hsv,mask,part,hierarchy})mat.release();}
        }}finally{kernel.release();}
        return new JSONObject().put("found",best>=0).put("confidence",best>=0?1:0).put("point",new JSONArray().put(px).put(py));
    }
    private JSONObject components(Mat roi,int x,int y,JSONObject spec,boolean red)throws Exception{
        Mat mask=new Mat(),hsv=new Mat(),other=new Mat(),kernel=Mat.ones(2,2,CvType.CV_8U),labels=new Mat(),stats=new Mat(),centroids=new Mat();
        try{
            if(red){Imgproc.cvtColor(roi,hsv,Imgproc.COLOR_BGR2HSV);int sat=spec.optInt("min_saturation",70),val=spec.optInt("min_value",80);
                Core.inRange(hsv,new Scalar(0,sat,val),new Scalar(spec.optInt("hue_high1",12),255,255),mask);Core.inRange(hsv,new Scalar(spec.optInt("hue_low2",165),sat,val),new Scalar(179,255,255),other);Core.bitwise_or(mask,other,mask);
            }else{Imgproc.cvtColor(roi,hsv,Imgproc.COLOR_BGR2GRAY);Imgproc.threshold(hsv,mask,spec.optInt("min_value",180),255,Imgproc.THRESH_BINARY);}
            if(spec.optBoolean("morph_open",true))Imgproc.morphologyEx(mask,mask,Imgproc.MORPH_OPEN,kernel);Imgproc.dilate(mask,mask,kernel);
            int count=Imgproc.connectedComponentsWithStats(mask,labels,stats,centroids,8),valid=0;double cx=0,cy=0;
            for(int i=1;i<count;i++){double area=stats.get(i,Imgproc.CC_STAT_AREA)[0];if(area>=spec.optInt("min_component_area",red?12:6)&&area<=spec.optInt("max_component_area",red?1500:2000)&&stats.get(i,Imgproc.CC_STAT_WIDTH)[0]>=spec.optInt("min_width",red?4:2)&&stats.get(i,Imgproc.CC_STAT_HEIGHT)[0]>=spec.optInt("min_height",red?4:3)){valid++;cx+=centroids.get(i,0)[0];cy+=centroids.get(i,1)[0];}}
            double ratio=Core.countNonZero(mask)/(double)mask.total(),minRatio=spec.optDouble(red?"min_red_ratio":"min_bright_ratio",red?0.00025:0.012);int min=spec.optInt("min_components",red?1:3);
            return new JSONObject().put("found",ratio>=minRatio&&valid>=min&&valid<=spec.optInt("max_components",100000)).put("confidence",Math.min(1,ratio/Math.max(minRatio,0.00001)*0.55+Math.min(valid/(double)Math.max(min,1),1)*0.45)).put("point",new JSONArray().put(x+(valid>0?(int)(cx/valid):roi.cols()/2)).put(y+(valid>0?(int)(cy/valid):roi.rows()/2)));
        }finally{for(Mat m:new Mat[]{mask,hsv,other,kernel,labels,stats,centroids})m.release();}
    }
    private void restrictGold(Mat scores,Mat hay,Mat template,boolean lower)throws Exception{
        Mat hsv=new Mat(),mask=new Mat(),gold=new Mat(),density=new Mat(),allowed=new Mat();Mat centers=null;
        try{
            Imgproc.cvtColor(template,hsv,Imgproc.COLOR_BGR2HSV);Core.inRange(hsv,new Scalar(16,95,110),new Scalar(45,255,255),mask);
            if(Core.countNonZero(mask)<6)return;
            Imgproc.cvtColor(hay,hsv,Imgproc.COLOR_BGR2HSV);Core.inRange(hsv,new Scalar(16,95,110),new Scalar(45,255,255),mask);mask.convertTo(gold,CvType.CV_32F,1./255);
            Imgproc.boxFilter(gold,density,CvType.CV_32F,new Size(17,17),new org.opencv.core.Point(-1,-1),false,Core.BORDER_DEFAULT);
            centers=density.submat(new org.opencv.core.Rect(template.cols()/2,template.rows()/2,scores.cols(),scores.rows()));Core.compare(centers,new Scalar(6),allowed,Core.CMP_LT);scores.setTo(new Scalar(lower?1:-1),allowed);
        }finally{if(centers!=null)centers.release();for(Mat m:new Mat[]{hsv,mask,gold,density,allowed})m.release();}
    }
    public void close(){if(atlasVision!=null){atlasVision.close();atlasVision=null;}if(frame!=null)frame.release();for(Mat m:templates.values())m.release();for(Mat m:scaledTemplates.values())m.release();for(Mat m:scaledMasks.values())m.release();scaledTemplates.clear();scaledMasks.clear();templates.clear();cache.clear();unchangedMatches.clear();regionHashes.clear();}
}
