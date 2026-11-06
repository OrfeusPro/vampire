/* Received prompts and explicit per-bot preferences. No guessed game commands. */
(function(root) {
  'use strict';
  const SOURCE='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960';
  const CURRENT_SOURCE='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f';
  const fields={quest_follow:['quest_id'],dialogue_select:['dialogue_id','choice_id'],dialogue_skip:['dialogue_id'],tutorial_equip:['item_instance_id']};
  const id=s=>typeof s==='string'&&/^[a-zA-Z0-9_-]{1,64}$/.test(s);
  const hash=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
  const text=(s,max)=>typeof s==='string'&&s.length<=max;
  const decimal=s=>typeof s==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(s)&&BigInt(s)<=18446744073709551615n;
  const policy=value=>value&&Object.keys(value).sort().join()==='auto_quests,skip_dialogues'
    &&typeof value.skip_dialogues==='boolean'&&typeof value.auto_quests==='boolean'?{...value}:null;
  const stopReasons=new Set(['death','user_stop','unknown_result','stale_context','not_admitted','waiting_data','connection_lost']);
  function automation(value){
    if(!value||!['idle','running','waiting_npc','paused','unknown','blocked','waiting_data','dead'].includes(value.state)
      ||!text(value.npc_label??'',128)||value.selected_quest_id!=null&&!decimal(value.selected_quest_id)
      ||value.stop_reason!=null&&!stopReasons.has(value.stop_reason)
      ||value.enabled!==undefined&&typeof value.enabled!=='boolean'
      ||value.cancel_pending!==undefined&&typeof value.cancel_pending!=='boolean'
      ||value.pending_request_id!=null&&!/^[a-f0-9]{32}$/.test(value.pending_request_id))return null;
    return {state:value.state,npc_label:value.npc_label||'',supported:value.supported===true,
      selected_quest_id:value.selected_quest_id??null,stop_reason:value.stop_reason??null,
      ...(value.enabled!==undefined?{enabled:value.enabled}:{}),...(value.cancel_pending!==undefined?{cancel_pending:value.cancel_pending}:{}),
      pending_request_id:value.pending_request_id??null};
  }
  function preferences(bot,storage) {
    if(!id(bot))throw Error('Неверный аккаунт');
    if(storage===undefined)try{storage=root.localStorage;}catch{storage=null;}
    const key='vampir.live.interaction.v1.'+bot;
    let value={skip_dialogues:true,auto_quests:false};
    function refresh(){try {const raw=storage?.getItem(key);if(raw&&raw.length<=256){const saved=JSON.parse(raw);
      if(typeof saved.skip_dialogues==='boolean')value.skip_dialogues=saved.skip_dialogues;
      if(typeof saved.auto_quests==='boolean')value.auto_quests=saved.auto_quests;}}catch{}}
    refresh();return {get value(){refresh();return {...value};},set(name,enabled){
      if(!Object.hasOwn(value,name)||typeof enabled!=='boolean')throw Error('Неверная настройка');
      refresh();
      value={...value,[name]:enabled};try{storage?.setItem(key,JSON.stringify(value));}catch{}
      return {...value};}};
  }
  function project(snapshot,bot,session) {
    const unknown={known:false,messagesKnown:false,ready:false,messages:[],actions:[],questActions:[],results:[],automation:null,policy:null};
    const data=snapshot?.interaction,person=snapshot?.character;
    if(snapshot?.state!=='connected'||snapshot.bot_id!==bot||snapshot.session_id!==session||!person
      ||!data||!['observed_prompts','owner_action_offers'].includes(data.semantics)||![SOURCE,CURRENT_SOURCE].includes(data.source_sha256)
      ||data.source_sha256===CURRENT_SOURCE&&data.semantics!=='owner_action_offers'
      ||data.character_key!==person.key||data.world_id!==person.world_id||!hash(data.revision)
      ||!Array.isArray(data.messages)||data.messages.length>16||!Array.isArray(data.actions)||data.actions.length>48)return unknown;
    if(data.semantics==='owner_action_offers'&&(data.messages_known!==false||data.messages.length!==0))return unknown;
    const actions=[];const seen=new Set();
    for(const a of data.actions) {
      if(!a||!id(a.id)||seen.has(a.id)||!Object.hasOwn(fields,a.kind)||!hash(a.context)
        ||!a.arguments||typeof a.arguments!=='object'||Object.keys(a.arguments).sort().join()!==fields[a.kind].slice().sort().join()
        ||!Object.values(a.arguments).every(decimal)||typeof a.enabled!=='boolean'||!text(a.reason??'',256)
        ||data.source_sha256===CURRENT_SOURCE&&a.kind!=='quest_follow')return unknown;
      seen.add(a.id);actions.push({id:a.id,kind:a.kind,context:a.context,arguments:{...a.arguments},enabled:data.actions_ready===true&&a.enabled,reason:a.reason||null});
    }
    const messages=[];const messageIds=new Set();
    for(const m of data.messages) {
      if(!m||!id(m.id)||messageIds.has(m.id)||!['dialogue','cutscene','tutorial','notice'].includes(m.kind)
        ||!text(m.text,4096)||!text(m.speaker??'',128)||typeof m.active!=='boolean'
        ||!Array.isArray(m.choices)||m.choices.length>12)return unknown;
      const choices=[];
      for(const c of m.choices){if(!c||!text(c.text,512)||!id(c.action_id)||!seen.has(c.action_id))return unknown;
        choices.push({text:c.text,action_id:c.action_id});}
      if(m.skip_action_id!=null&&(!seen.has(m.skip_action_id)||actions.find(a=>a.id===m.skip_action_id)?.kind!=='dialogue_skip'))return unknown;
      messageIds.add(m.id);messages.push({id:m.id,kind:m.kind,text:m.text,speaker:m.speaker||'',active:m.active,
        choices,skip_action_id:m.skip_action_id??null,auto_skip:m.auto_skip===true});
    }
    const questActions=[];
    if(Array.isArray(data.quest_actions)&&data.quest_actions.length<=128)for(const q of data.quest_actions){
      const a=actions.find(a=>a.id===q?.action_id);
      if(decimal(q?.quest_id)&&a?.kind==='quest_follow'&&a.arguments.quest_id===q.quest_id)questActions.push({quest_id:q.quest_id,action_id:q.action_id});}
    const results=Array.isArray(data.action_results)?data.action_results.slice(0,64).filter(r=>r&&/^[a-f0-9]{32}$/.test(r.request_id)
      &&['queued','executing','sent','confirmed','failed','unknown'].includes(r.status)).map(r=>({request_id:r.request_id,status:r.status})):[];
    return {known:true,messagesKnown:data.semantics==='observed_prompts',ready:data.actions_ready===true,messages,actions,questActions,results,
      automation:automation(data.automation),policy:policy(snapshot.action_policy)};
  }
  function create({botId,sessionId,dispatch,configurePolicy,configureQuest,onChange=()=>{},storage,cryptoImpl=root.crypto,now=Date.now}) {
    const prefs=preferences(botId,storage);let view=project(null,botId,sessionId),disposed=false,status='',busy=null;
    const attempts=new Map();let autoBlocked=false,policyBusy=false,policyError=false,wasConnected=false,generation=0,currentSource=false;
    function notify(){if(!disposed)onChange();}
    function currentPolicy(){return view.policy??(currentSource?{skip_dialogues:prefs.value.skip_dialogues,auto_quests:false}:prefs.value);}
    function available(actionId){const a=view.actions.find(a=>a.id===actionId);return !disposed&&!!a?.enabled&&!busy&&!policyBusy&&!policyError
      &&view.automation?.state!=='dead'&&view.automation?.stop_reason!=='death'&&!attempts.has(a.id+':'+a.context);}
    async function perform(actionId,origin='manual') {
      const a=view.actions.find(a=>a.id===actionId);
      if(disposed||!available(actionId)||typeof dispatch!=='function'||(origin==='auto_skip'&&autoBlocked))return false;
      if(attempts.size>=4096){status='Достигнут лимит действий сессии';autoBlocked=true;notify();return false;}
      const key=a.id+':'+a.context,version=generation;attempts.set(key,'preparing');busy={key,started:now(),request_id:null,origin};status='Отправка…';notify();
      try {
        const material=[botId,sessionId,a.id,a.context].join('|');
        const digest=await cryptoImpl.subtle.digest('SHA-256',new TextEncoder().encode(material));
        const requestId=Array.from(new Uint8Array(digest).slice(0,16),b=>b.toString(16).padStart(2,'0')).join('');
        if(disposed||version!==generation||!view.actions.some(next=>next.id===a.id&&next.context===a.context&&next.enabled)){
          attempts.set(key,'cancelled');busy=null;status='Состояние изменилось';notify();return false;}
        busy.request_id=requestId;
        const result=await dispatch({action_id:a.id,request_id:requestId,policy:currentPolicy(),origin});
        if(disposed)return false;
        if(!busy||busy.key!==key){if(['confirmed','failed'].includes(attempts.get(key)))return true;
          attempts.set(key,'unknown');autoBlocked=true;return false;}
        if(!result||!['queued','executing','sent','confirmed','failed','unknown'].includes(result.status))throw Error('Неизвестный ответ');
        attempts.set(key,result.status);
        if(['confirmed','failed','unknown'].includes(result.status))busy=null;
        if(result.status==='unknown')autoBlocked=true;
        if(result.status==='confirmed'&&origin==='manual')autoBlocked=false;
        status=result.status==='confirmed'?'Действие подтверждено':result.status==='failed'?'Действие отклонено':result.status==='unknown'?'Результат неизвестен':'Ожидание подтверждения';
      }catch{attempts.set(key,'unknown');busy=null;autoBlocked=true;status='Результат неизвестен — повтор не отправлен';}
      notify();return true;
    }
    function canToggleQuest(questId){return !disposed&&!policyBusy&&view.known&&decimal(questId)
      &&view.automation?.supported===true&&typeof configureQuest==='function'
      &&view.automation.state!=='dead'&&view.automation.stop_reason!=='death'
      &&(!view.automation.cancel_pending||currentPolicy().auto_quests&&view.automation.selected_quest_id===questId);}
    async function configureQuestState(questId,enabled){
      if(disposed||policyBusy||!view.known||typeof configureQuest!=='function')return false;
      const version=generation;policyBusy=true;status=enabled?'Выбор задания…':'Остановка автовыполнения…';notify();
      try{
        const result=await configureQuest({quest_id:questId,enabled});
        if(disposed||version!==generation||!view.known)return false;
        const nextPolicy=policy(result?.policy),nextAutomation=automation(result?.automation);
        if(result?.bot_id!==botId||result?.session_id!==sessionId||result?.status!=='quest_automation_updated'
          ||!nextPolicy||nextPolicy.auto_quests!==enabled||!nextAutomation||nextAutomation.supported!==true
          ||nextAutomation.selected_quest_id!==(enabled?questId:null))throw Error('Настройка не подтверждена');
        view={...view,policy:nextPolicy,automation:nextAutomation};policyError=false;
        prefs.set('auto_quests',enabled);
        status=enabled?(nextAutomation.state==='running'?'Автовыполнение включено':'Задание выбрано · ожидание подключения шага'):'Автовыполнение остановлено';
        return true;
      }catch{
        if(!disposed){policyError=true;autoBlocked=true;status='Изменение автовыполнения не подтверждено';}return false;
      }finally{policyBusy=false;notify();}
    }
    async function toggleQuest(questId){
      if(!canToggleQuest(questId))return false;
      const stopping=currentPolicy().auto_quests&&view.automation?.selected_quest_id===questId;
      if(!stopping&&(policyError||autoBlocked))return false;
      if(!await configureQuestState(stopping?null:questId,!stopping))return false;
      if(stopping)return true;
      const actionId=view.questActions.find(q=>q.quest_id===questId)?.action_id;
      if(actionId&&available(actionId))await perform(actionId);
      return true;
    }
    return {get view(){return view;},get policy(){return currentPolicy();},get policyBusy(){return policyBusy;},get status(){return status;},available,perform,canToggleQuest,toggleQuest,
      questAction(questId){return view.automation?.state==='waiting_npc'?null:view.questActions.find(q=>q.quest_id===questId)?.action_id??null;},
      async setPolicy(name,value){if(disposed||policyBusy)return false;
        if(name==='auto_quests'&&view.automation?.supported===true&&typeof configureQuest==='function'){
          if(!value)return configureQuestState(null,false);
          if(view.automation.selected_quest_id)return configureQuestState(view.automation.selected_quest_id,true);
          status='Нажмите на задание, чтобы выбрать его';notify();return false;
        }
        prefs.set(name,value);
        if(!view.ready&&view.automation?.supported!==true||typeof configurePolicy!=='function'){notify();return !currentSource;}
        policyBusy=true;status='Применение настройки…';notify();
        const version=generation;
        try{const result=await configurePolicy({...currentPolicy(),[name]:value});
          if(disposed||version!==generation||!view.known)return false;
          if(currentSource){const next=policy(result?.policy);if(result?.bot_id!==botId||result?.session_id!==sessionId
            ||result?.status!=='policy_updated'||!next||next[name]!==value)throw Error('Настройка не подтверждена');view={...view,policy:next};}
          policyError=false;status='Настройки применены';}
        catch{policyError=true;autoBlocked=true;status='Изменение настройки не подтверждено';}
        finally{policyBusy=false;notify();}return !policyError;},
      observe(snapshot){
        if(disposed)return;
        const connected=snapshot?.state==='connected'&&snapshot.bot_id===botId&&snapshot.session_id===sessionId;
        if(!connected)generation++;
        else currentSource=snapshot.interaction?.source_sha256===CURRENT_SOURCE;
        if(connected&&!wasConnected&&!autoBlocked)status='';wasConnected=connected;
        view=project(snapshot,botId,sessionId);
        if(busy?.request_id){const result=view.results.find(r=>r.request_id===busy.request_id);
          if(result&&['confirmed','failed','unknown'].includes(result.status)){attempts.set(busy.key,result.status);
            if(result.status==='confirmed'&&busy.origin==='manual')autoBlocked=false;busy=null;
            if(result.status==='unknown')autoBlocked=true;
            status=result.status==='confirmed'?'Действие подтверждено':result.status==='failed'?'Действие отклонено':'Результат неизвестен';}
          else if(now()-busy.started>=10000){attempts.set(busy.key,'unknown');busy=null;autoBlocked=true;status='Результат неизвестен — повтор не отправлен';}}
        if(!connected){if(busy){attempts.set(busy.key,'unknown');autoBlocked=true;}
          busy=null;status=autoBlocked?'Связь прервана — результат действия неизвестен':'Нет текущих данных сессии';}
        if(view.automation?.state==='dead'||view.automation?.stop_reason==='death')status='Автовыполнение остановлено: персонаж погиб';
        else if(view.automation?.state==='paused')status='Автовыполнение приостановлено';
        if(!busy&&!autoBlocked&&currentPolicy().skip_dialogues&&view.ready){
          const m=view.messages.find(m=>m.active&&m.auto_skip&&['dialogue','cutscene'].includes(m.kind)&&m.skip_action_id&&available(m.skip_action_id));
          if(m)void perform(m.skip_action_id,'auto_skip');
        }
        notify();
      },dispose(){disposed=true;generation++;busy=null;attempts.clear();}};
  }
  const api={SOURCE,CURRENT_SOURCE,preferences,project,create};root.VampirLiveInteraction=api;
  if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
