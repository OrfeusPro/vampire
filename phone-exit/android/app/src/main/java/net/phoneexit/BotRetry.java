package net.phoneexit;

import org.json.*;
import java.util.UUID;

/** Bounded retries for error stops only; a new generation recognises afresh. */
final class BotRetry {
    static final int LIMIT=5;
    static final long DELAY_MS=5000;
    static final long WINDOW_MS=6*60*60*1000L;
    static void reset(JSONObject state){
        for(String key:new String[]{"retryCount","retryLimit","retryAt","retryExhausted","retryWindowStarted","lastRetryError","lastRetryStep","retryHistory"})state.remove(key);
    }
    static void expire(JSONObject state,long now)throws Exception{
        long started=state.optLong("retryWindowStarted",0);
        if(started>0&&now-started>=WINDOW_MS){
            state.put("retryCount",0);state.remove("retryWindowStarted");state.remove("retryHistory");
            // Expiring a budget must not resume a manually/error-paused bot.
        }
    }
    static void apply(JSONObject state,JSONObject report,long now,boolean editor)throws Exception{
        expire(state,now);
        state.remove("retryAt");
        String error=report.optString("error","");
        if(!report.optBoolean("pause")||!report.optBoolean("retryable",true)||error.isEmpty()||error.equals("null")
                ||report.optString("reason").equals("phone_stop")||editor
                ||error.equals("settings_changed_during_action"))return;
        int count=state.optInt("retryCount",0);
        if(!state.has("retryWindowStarted"))state.put("retryWindowStarted",now);
        JSONArray history=state.optJSONArray("retryHistory");if(history==null)history=new JSONArray();
        if(history.length()<LIMIT+1)history.put(new JSONObject().put("at",now).put("error",error).put("step",report.optString("step")));
        state.put("retryHistory",history).put("retryLimit",LIMIT).put("lastRetryError",error).put("lastRetryStep",report.optString("step"));
        if(count>=LIMIT){state.put("retryExhausted",true).put("status","error").put("reason","retry_limit_reached").put("desired","paused");return;}
        state.put("retryCount",count+1).put("retryExhausted",false).put("retryAt",now+DELAY_MS)
             .put("desired","running").put("status","waiting").put("step","auto_restart_pending")
             .put("reason","auto_retry_"+(count+1)+"_of_"+LIMIT).put("error",JSONObject.NULL)
             .put("generation",UUID.randomUUID().toString());
    }
}
