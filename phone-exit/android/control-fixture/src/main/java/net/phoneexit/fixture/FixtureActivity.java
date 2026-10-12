package net.phoneexit.fixture;
import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.*;
import android.view.inputmethod.EditorInfo;
import android.widget.*;
import org.json.JSONObject;
import java.io.FileOutputStream;

/** Temporary permission-free USB fixture. Never installed by the product. */
public final class FixtureActivity extends Activity {
    final org.json.JSONArray tapTimes=new org.json.JSONArray();
    int taps,longPresses,swipes,enters;float downY;String text="";TextView metrics;EditText input;
    @Override public void onCreate(Bundle state){super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(32,32,32,32);root.setBackgroundColor(Color.rgb(240,244,248));setContentView(root);
        TextView title=new TextView(this);title.setText("Проверка управления Phone Exit");title.setTextSize(22);root.addView(title);
        Button button=new Button(this);button.setText("Тест нажатия / удержания");root.addView(button,new LinearLayout.LayoutParams(-1,160));
        button.setOnClickListener(v->{taps++;tapTimes.put(android.os.SystemClock.elapsedRealtime());save();});button.setOnLongClickListener(v->{longPresses++;save();return true;});
        input=new EditText(this);input.setHint("Поле для тестового текста");input.setSingleLine(true);input.setImeOptions(EditorInfo.IME_ACTION_DONE);root.addView(input,new LinearLayout.LayoutParams(-1,160));
        input.addTextChangedListener(new android.text.TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int c,int after){}public void onTextChanged(CharSequence s,int start,int before,int count){text=s.toString();save();}public void afterTextChanged(android.text.Editable e){}});
        input.setOnEditorActionListener((v,id,event)->{enters++;save();return true;});
        TextView pad=new TextView(this);pad.setText("Область для свайпа");pad.setGravity(Gravity.CENTER);pad.setBackgroundColor(Color.rgb(160,200,190));root.addView(pad,new LinearLayout.LayoutParams(-1,400));
        pad.setOnTouchListener((v,e)->{if(e.getAction()==MotionEvent.ACTION_DOWN)downY=e.getY();if(e.getAction()==MotionEvent.ACTION_UP&&Math.abs(e.getY()-downY)>30){swipes++;save();}return true;});
        metrics=new TextView(this);root.addView(metrics);save();
    }
    void save(){try{JSONObject v=new JSONObject().put("tapTimes",tapTimes).put("taps",taps).put("longPresses",longPresses).put("swipes",swipes).put("enters",enters).put("text",text);if(metrics!=null)metrics.setText(v.toString());try(FileOutputStream out=openFileOutput("metrics.json",MODE_PRIVATE)){out.write(v.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));}}catch(Exception e){throw new IllegalStateException(e);}}
}
