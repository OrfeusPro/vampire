package net.phoneexit;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.GradientDrawable;
import android.content.res.ColorStateList;
import android.view.Gravity;
import android.view.View;
import android.widget.*;

public final class MainActivity extends Activity {
    private final Handler handler = new Handler();
    private TextView status;
    private TextView accessState;
    private Button available, stop;
    private PowerMark power;
    private static final int BACKGROUND=Color.rgb(16,21,31), CARD=Color.rgb(25,35,50),
        TEXT=Color.rgb(239,244,250), MUTED=Color.rgb(157,170,188), ACCENT=Color.rgb(98,231,188);
    private final Runnable refresh = new Runnable() {
        public void run() {
            status.setText(ExitService.status);
            boolean enabled=ExitService.enabled(MainActivity.this);
            accessState.setText(enabled?"Автоматический доступ включён":"Доступ выключен");
            accessState.setTextColor(enabled?ACCENT:MUTED);
            available.setEnabled(!enabled); stop.setEnabled(enabled);
            available.setAlpha(enabled?0.5f:1f); stop.setAlpha(enabled?1f:0.5f);
            power.active=enabled; power.invalidate();
            handler.postDelayed(this,1000);
        }
    };
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        boolean personal=false;
        try { personal=PersonalAccount.asset(this)!=null; } catch(Exception ignored) {}
        ScrollView scroll=new ScrollView(this); scroll.setFillViewport(true);
        scroll.setBackgroundColor(BACKGROUND); scroll.setFitsSystemWindows(true);
        LinearLayout layout = column(24); scroll.addView(layout);
        LinearLayout brand=new LinearLayout(this); brand.setGravity(Gravity.CENTER_VERTICAL);
        ImageView brandIcon=new ImageView(this); brandIcon.setImageResource(R.drawable.phone_exit_brand);
        brandIcon.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        LinearLayout.LayoutParams iconParams=new LinearLayout.LayoutParams(dp(48),dp(48));iconParams.setMarginEnd(dp(12));
        brand.addView(brandIcon,iconParams);
        TextView title = label("Phone Exit",30,TEXT); title.setTypeface(Typeface.DEFAULT,Typeface.BOLD);brand.addView(title);
        layout.addView(brand);
        TextView version=label(getString(R.string.app_version,BuildConfig.VERSION_NAME),13,MUTED);
        add(layout,version,6);
        add(layout,label("Личный интернет. Через твои телефоны.",14,MUTED),10);

        LinearLayout connection=column(24); connection.setBackground(surface(CARD,20)); add(layout,connection,26);
        power=new PowerMark(); LinearLayout.LayoutParams markParams=new LinearLayout.LayoutParams(dp(100),dp(100));
        markParams.gravity=Gravity.CENTER_HORIZONTAL; connection.addView(power,markParams);
        accessState=label("Доступ выключен",18,MUTED); accessState.setGravity(Gravity.CENTER);
        add(connection,accessState,18);
        status=label(ExitService.status,15,TEXT); status.setGravity(Gravity.CENTER); status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        add(connection,status,10);

        EditText code = new EditText(this); code.setHint(R.string.pairing_hint); code.setMinLines(3); code.setMaxLines(6);
        code.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
            | android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        code.setTextColor(TEXT); code.setHintTextColor(MUTED); code.setBackgroundTintList(ColorStateList.valueOf(ACCENT));
        code.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS); add(connection,code,18);
        Button connect = action(getString(R.string.connect),true); add(connection,connect,12);
        available = action("Включить доступ для своего ПК",true); add(connection,available,22);
        stop = action("Остановить доступ",false); add(connection,stop,10);
        if(personal) {
            code.setVisibility(android.view.View.GONE); connect.setVisibility(android.view.View.GONE);
            available.setText("Включить автоматический доступ");
        }
        LinearLayout details=column(22); details.setBackground(surface(CARD,20)); add(layout,details,16);
        TextView heading=label("Как это работает",18,TEXT); heading.setTypeface(Typeface.DEFAULT,Typeface.BOLD); details.addView(heading);
        TextView info = label(getString(R.string.intro),14,MUTED); add(details,info,12);
        if(personal) info.setText("Этот телефон появляется в вашем списке на ПК автоматически. При потере Wi-Fi приложение ждёт сеть и подключается заново.");
        add(details,label("Работает в фоне с уведомлением. Можно свернуть приложение, пока доступ включён.",14,MUTED),14);
        Button forget=action("Удалить привязку к ПК",false); add(layout,forget,20);
        add(layout,label("Wi-Fi телефона  ·  Шифрование WebRTC\nПрямое подключение к твоему ПК",12,MUTED),22);
        connect.setOnClickListener(v -> {
            try {
                String raw=code.getText().toString();
                if(new org.json.JSONObject(raw).optInt("version")==2) DirectoryConfig.parse(raw).save(this);
                else Pairing.parse(raw);
            }
            catch (Exception e) { status.setText(getString(R.string.invalid_pairing,e.getMessage())); return; }
            Intent intent = new Intent(this,ExitService.class).putExtra("pairing",code.getText().toString());
            startForegroundService(intent);
            code.setText("");
        });
        stop.setOnClickListener(v -> ExitService.stopEnabled(this));
        available.setOnClickListener(v -> {
            try {
                DirectoryConfig config=PersonalAccount.prepare(this,true);
                if(config==null) { status.setText("Сначала добавьте телефон в приложении ПК и вставьте код привязки"); return; }
                startForegroundService(new Intent(this,ExitService.class).putExtra("pairing",config.raw));
            } catch(Exception e) { status.setText("Не удалось прочитать привязку. Добавьте телефон заново."); }
        });
        forget.setOnClickListener(v -> new android.app.AlertDialog.Builder(this).setTitle("Удалить привязку?")
            .setMessage("Этот телефон перестанет принимать подключения своего ПК. Удалите его также из списка на ПК.")
            .setPositiveButton("Удалить",(dialog,which) -> {
                ExitService.stopEnabled(this); DirectoryConfig.forget(this);
                getSharedPreferences("runtime",MODE_PRIVATE).edit().putBoolean("ignorePersonal",true).apply();
                status.setText("Привязка удалена");
            })
            .setNegativeButton("Отмена",null).show());
        setContentView(scroll);
        if(personal) {
            try {
                boolean first=!getSharedPreferences("runtime",MODE_PRIVATE).contains("enabled");
                DirectoryConfig config=PersonalAccount.prepare(this,false);
                if(config!=null&&(first||ExitService.enabled(this))) startForegroundService(new Intent(this,ExitService.class).putExtra("pairing",config.raw));
            } catch(Exception e) { status.setText("Не удалось включить автоматический доступ"); }
        } else if(ExitService.enabled(this)) {
            startForegroundService(new Intent(this,ExitService.class));
        }
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},1);
    }
    private int dp(int value) { return Math.round(value*getResources().getDisplayMetrics().density); }
    private LinearLayout column(int padding) {
        LinearLayout box=new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(padding),dp(padding),dp(padding),dp(padding)); return box;
    }
    private TextView label(String text,int size,int color) {
        TextView view=new TextView(this); view.setText(text); view.setTextSize(size); view.setTextColor(color);
        view.setLineSpacing(dp(3),1f); return view;
    }
    private GradientDrawable surface(int color,int radius) {
        GradientDrawable shape=new GradientDrawable(); shape.setColor(color); shape.setCornerRadius(dp(radius)); return shape;
    }
    private void add(LinearLayout parent,View child,int margin) {
        LinearLayout.LayoutParams params=new LinearLayout.LayoutParams(-1,-2); params.topMargin=dp(margin); parent.addView(child,params);
    }
    private Button action(String text,boolean primary) {
        Button button=new Button(this); button.setText(text); button.setTextSize(14); button.setAllCaps(false);
        button.setTypeface(Typeface.DEFAULT,Typeface.BOLD); button.setTextColor(primary?BACKGROUND:TEXT);
        button.setBackgroundTintList(null); button.setBackground(surface(primary?ACCENT:Color.rgb(38,49,68),12));
        button.setMinHeight(dp(52)); button.setPadding(dp(12),dp(12),dp(12),dp(12));
        button.setStateListAnimator(null); return button;
    }
    private final class PowerMark extends View {
        boolean active;
        final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        PowerMark() { super(MainActivity.this); setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO); }
        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float cx=getWidth()/2f,cy=getHeight()/2f,r=Math.min(getWidth(),getHeight())/2f-dp(3);
            paint.setStyle(Paint.Style.STROKE); paint.setStrokeWidth(dp(2)); paint.setColor(Color.rgb(48,65,86));
            canvas.drawCircle(cx,cy,r,paint);
            paint.setColor(active?ACCENT:MUTED); paint.setStrokeWidth(dp(3)); paint.setStrokeCap(Paint.Cap.ROUND);
            float inner=r*0.57f; canvas.drawArc(cx-inner,cy-inner,cx+inner,cy+inner,-48,276,false,paint);
            canvas.drawLine(cx,cy-inner-dp(5),cx,cy-dp(7),paint);
        }
    }
    @Override public void onResume() { super.onResume(); handler.post(refresh); }
    @Override public void onPause() { handler.removeCallbacks(refresh); super.onPause(); }
}
