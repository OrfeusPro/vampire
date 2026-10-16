package net.phoneexit;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.text.TextUtils;
import android.util.LruCache;
import android.view.*;
import android.widget.*;
import org.json.JSONObject;
import java.io.*;
import java.util.*;

/** Offline country artwork shared with the Windows client, including its attribution. */
final class PhoneChoiceAdapter extends BaseAdapter {
    private static final int TEXT=Color.rgb(239,244,250),MUTED=Color.rgb(157,170,188);
    private final Context context;
    private final List<JSONObject> phones;
    private final LruCache<String,Bitmap> flags=new LruCache<>(32);
    private JSONObject countries=new JSONObject();
    PhoneChoiceAdapter(Context context,List<JSONObject> phones){
        this.context=context;this.phones=new ArrayList<>(phones);
        try(InputStream in=context.getAssets().open("flags/countries-ru.json")){
            ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[2048];int n;
            while((n=in.read(b))!=-1){if(out.size()+n>32768)throw new IOException("countries size");out.write(b,0,n);}
            countries=new JSONObject(out.toString("UTF-8"));
        }catch(Exception ignored){}
    }
    private int dp(int n){return Math.round(n*context.getResources().getDisplayMetrics().density);}
    public int getCount(){return phones.size();}
    public JSONObject getItem(int position){return phones.get(position);}
    public long getItemId(int position){return position;}
    private Bitmap flag(String country){
        Bitmap bitmap=flags.get(country);if(bitmap!=null)return bitmap;
        try(InputStream in=context.getAssets().open("flags/"+country+".png")){
            bitmap=BitmapFactory.decodeStream(in);if(bitmap!=null)flags.put(country,bitmap);
        }catch(IOException ignored){}
        if(bitmap==null&&!country.equals("unknown"))return flag("unknown");return bitmap;
    }
    @Override public View getView(int position,View recycled,ViewGroup parent){
        Row row;
        if(recycled instanceof LinearLayout&&recycled.getTag() instanceof Row){row=(Row)recycled.getTag();}
        else{
            row=new Row();LinearLayout root=new LinearLayout(context);root.setGravity(Gravity.CENTER_VERTICAL);root.setPadding(dp(20),dp(12),dp(20),dp(12));root.setMinimumHeight(dp(68));
            row.root=root;row.icon=new ImageView(context);row.icon.setScaleType(ImageView.ScaleType.FIT_CENTER);row.icon.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            LinearLayout.LayoutParams icon=new LinearLayout.LayoutParams(dp(32),dp(32));icon.setMarginEnd(dp(14));root.addView(row.icon,icon);
            LinearLayout labels=new LinearLayout(context);labels.setOrientation(LinearLayout.VERTICAL);root.addView(labels,new LinearLayout.LayoutParams(0,-2,1));
            row.name=new TextView(context);row.name.setTextSize(16);row.name.setMaxLines(2);row.name.setEllipsize(TextUtils.TruncateAt.END);labels.addView(row.name);
            row.country=new TextView(context);row.country.setTextSize(13);row.country.setTextColor(MUTED);LinearLayout.LayoutParams subtitle=new LinearLayout.LayoutParams(-1,-2);subtitle.topMargin=dp(3);labels.addView(row.country,subtitle);
            root.setTag(row);
        }
        JSONObject phone=getItem(position);String code=phone.optString("country").toUpperCase(Locale.ROOT);if(!code.matches("[A-Z]{2}"))code="";
        String country=code.isEmpty()?"Страна неизвестна":countries.optString(code,code);
        boolean busy=phone.optBoolean("busy");row.name.setText(phone.optString("name"));row.name.setTextColor(busy?MUTED:TEXT);
        row.country.setText(country+(busy?" · занят":""));row.icon.setImageBitmap(flag(code.isEmpty()?"unknown":code));
        return row.root;
    }
    private static final class Row{LinearLayout root;ImageView icon;TextView name,country;}
}
