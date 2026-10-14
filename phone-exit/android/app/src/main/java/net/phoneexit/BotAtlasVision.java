package net.phoneexit;

import org.json.*;
import org.opencv.core.*;
import org.opencv.features2d.*;
import org.opencv.calib3d.Calib3d;
import org.opencv.imgcodecs.Imgcodecs;
import org.opencv.imgproc.Imgproc;
import java.io.File;
import java.util.*;

/** Local terrain registration. Never infer a traversable area from the atlas. */
final class BotAtlasVision implements AutoCloseable {
    private String loaded="";private Mat atlasDescriptors;private KeyPoint[] atlasKeys;private int aw,ah;
    private final SIFT sift=SIFT.create(18000);
    JSONObject locate(File directory,Mat frame,JSONObject spec)throws Exception {
        JSONObject detector=spec.getJSONObject("detector");String file=spec.getString("file");
        File base=new File(directory,"templates"),asset=new File(base,file);
        if(!asset.getCanonicalPath().startsWith(base.getCanonicalPath()+File.separator))throw new Exception("bot_invalid_template");
        if(!loaded.equals(asset.getCanonicalPath())){
            Mat image=Imgcodecs.imread(asset.getAbsolutePath(),Imgcodecs.IMREAD_GRAYSCALE),mask=new Mat();MatOfKeyPoint keys=new MatOfKeyPoint();
            try {if(image.empty()||image.cols()>4096||image.rows()>4096)throw new Exception("bot_invalid_atlas");if(atlasDescriptors!=null)atlasDescriptors.release();atlasDescriptors=new Mat();sift.detectAndCompute(image,mask,keys,atlasDescriptors);atlasKeys=keys.toArray();aw=image.cols();ah=image.rows();loaded=asset.getCanonicalPath();}
            finally{image.release();mask.release();keys.release();}
        }
        JSONObject out=new JSONObject().put("found",false).put("registered",false).put("confidence",0);
        JSONArray region=spec.getJSONArray("region");int x=(int)(region.getDouble(0)*frame.cols()),y=(int)(region.getDouble(1)*frame.rows());int w=(int)(region.getDouble(2)*frame.cols())-x,h=(int)(region.getDouble(3)*frame.rows())-y;
        if(x<0||y<0||w<32||h<32||x+w>frame.cols()||y+h>frame.rows())throw new Exception("bot_invalid_region");
        Mat roi=frame.submat(new Rect(x,y,w,h)),gray=new Mat(),desc=new Mat(),empty=new Mat(),inliers=new Mat();MatOfKeyPoint keys=new MatOfKeyPoint();List<MatOfDMatch> pairs=new ArrayList<>();MatOfPoint2f src=new MatOfPoint2f(),dst=new MatOfPoint2f();Mat matrix=null;BFMatcher matcher=BFMatcher.create(Core.NORM_L2,false);
        try {
            Imgproc.cvtColor(roi,gray,Imgproc.COLOR_BGR2GRAY);sift.detectAndCompute(gray,empty,keys,desc);if(desc.empty()||atlasDescriptors.empty())return out;
            matcher.knnMatch(desc,atlasDescriptors,pairs,2);KeyPoint[] current=keys.toArray();List<Point> from=new ArrayList<>(),to=new ArrayList<>();
            for(MatOfDMatch pair:pairs){DMatch[] p=pair.toArray();if(p.length==2&&p[0].distance<.68*p[1].distance){from.add(current[p[0].queryIdx].pt);to.add(atlasKeys[p[0].trainIdx].pt);}}
            if(from.size()<20)return out;src.fromList(from);dst.fromList(to);matrix=Calib3d.estimateAffinePartial2D(src,dst,inliers,Calib3d.RANSAC,3,2000,.99,10);
            if(matrix.empty())return out;int count=Core.countNonZero(inliers);if(count<20||count<from.size()*.4)return out;
            double a=matrix.get(0,0)[0],b=matrix.get(0,1)[0],c=matrix.get(0,2)[0],d=matrix.get(1,0)[0],e=matrix.get(1,1)[0],f=matrix.get(1,2)[0],det=a*e-b*d;
            if(det<=0||Math.abs(Math.atan2(d,a))>.06)return out;
            double minX=w,maxX=0,minY=h,maxY=0;List<Double> errors=new ArrayList<>();
            for(int i=0;i<from.size();i++)if(inliers.get(i,0)[0]!=0){Point p=from.get(i),q=to.get(i);minX=Math.min(minX,p.x);maxX=Math.max(maxX,p.x);minY=Math.min(minY,p.y);maxY=Math.max(maxY,p.y);errors.add(Math.hypot(a*p.x+b*p.y+c-q.x,d*p.x+e*p.y+f-q.y));}
            Collections.sort(errors);double error=errors.get(errors.size()/2);if(error>2.5||maxX-minX<80||maxY-minY<80)return out;
            JSONArray target=detector.getJSONArray("target");double tx=target.getDouble(0),ty=target.getDouble(1);if(tx<0||tx>=1||ty<0||ty>=1)throw new Exception("bot_invalid_map_target");
            double px=(e*(tx*aw-c)-b*(ty*ah-f))/det+x,py=(-d*(tx*aw-c)+a*(ty*ah-f))/det+y;
            boolean visible=px>=x+18&&px<x+w-18&&py>=y+18&&py<y+h-18;
            JSONArray transform=new JSONArray().put(new JSONArray().put(a/aw).put(b/aw).put((c-a*x-b*y)/aw)).put(new JSONArray().put(d/ah).put(e/ah).put((f-d*x-e*y)/ah));
            return out.put("registered",true).put("found",visible).put("confidence",count/(double)from.size()).put("inliers",count).put("residual",error).put("point",new JSONArray().put(px).put(py)).put("matrix",transform);
        } finally {if(matrix!=null)matrix.release();for(MatOfDMatch p:pairs)p.release();for(Mat m:new Mat[]{roi,gray,desc,empty,inliers,keys,src,dst})m.release();matcher.clear();}
    }
    public void close(){if(atlasDescriptors!=null){atlasDescriptors.release();atlasDescriptors=null;}sift.clear();loaded="";}
}
