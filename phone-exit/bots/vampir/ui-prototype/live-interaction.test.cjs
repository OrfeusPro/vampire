const assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
const ui=require('./live-interaction.js');
const adapterApi=require('./live-state.js');
const storage=()=>{const map=new Map();return {writes:0,getItem:k=>map.get(k)??null,setItem(k,v){this.writes++;map.set(k,v);}};};
function snapshot(bot='fixture',session='1'.repeat(32)) {
  return {schema:2,bot_id:bot,session_id:session,state:'connected',character:{key:'42',world_id:10012,name:'Тест',hp:1,max_hp:1,mp:1,max_mp:1,level:1},entities:[],
    interaction:{semantics:'observed_prompts',source_sha256:ui.SOURCE,character_key:'42',world_id:10012,revision:'a'.repeat(64),actions_ready:true,
      actions:[{id:'skip',kind:'dialogue_skip',context:'b'.repeat(64),arguments:{dialogue_id:'1'},enabled:true},
        {id:'answer',kind:'dialogue_select',context:'b'.repeat(64),arguments:{dialogue_id:'1',choice_id:'2'},enabled:true},
        {id:'quest',kind:'quest_follow',context:'c'.repeat(64),arguments:{quest_id:'110120'},enabled:true}],
      messages:[{id:'message1',kind:'dialogue',speaker:'Наставник',text:'Поговорим?',active:true,auto_skip:true,skip_action_id:'skip',choices:[{text:'Да',action_id:'answer'}]}],
      quest_actions:[{quest_id:'110120',action_id:'quest'}],action_results:[],automation:{state:'idle'}}};
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function settle(){for(let i=0;i<20;i++)await tick();}
(async()=>{
  const saved=storage(),a=ui.preferences('a',saved),b=ui.preferences('b',saved);
  assert.deepEqual(a.value,{skip_dialogues:true,auto_quests:false});assert.equal(saved.writes,0);
  a.set('skip_dialogues',false);assert.equal(ui.preferences('a',saved).value.skip_dialogues,false);assert.equal(b.value.skip_dialogues,true);
  assert.equal(saved.writes,1);
  const sameAccount=ui.preferences('a',saved);sameAccount.set('auto_quests',true);assert.equal(a.value.auto_quests,true);
  for(let i=0;i<50;i++){
    const bot='f'+i,session=i.toString(16).padStart(32,'0'),s=snapshot(bot,session);
    assert.equal(ui.project(s,bot,session).known,true);assert.equal(ui.project(s,bot,'other').known,false);
    assert.equal(ui.project({...s,state:'disconnected'},bot,session).known,false);
  }
  const s=snapshot(),calls=[],prefs=storage();
  const ctl=ui.create({botId:s.bot_id,sessionId:s.session_id,storage:prefs,cryptoImpl:webcrypto,dispatch:async p=>{calls.push(p);return {status:'confirmed'};}});
  ctl.observe(s);await settle();assert.equal(calls.length,1);assert.equal(calls[0].action_id,'skip');assert.equal(calls[0].origin,'auto_skip');
  for(let i=0;i<20;i++)ctl.observe(s);await settle();assert.equal(calls.length,1);assert.equal(prefs.writes,0);
  const other=[];const second=ui.create({botId:s.bot_id,sessionId:s.session_id,storage:storage(),cryptoImpl:webcrypto,dispatch:async p=>{other.push(p);return {status:'confirmed'};}});
  second.observe(s);await settle();assert.equal(other[0].request_id,calls[0].request_id);second.dispose();
  const manualStore=storage();ui.preferences(s.bot_id,manualStore).set('skip_dialogues',false);
  const manualCalls=[],manual=ui.create({botId:s.bot_id,sessionId:s.session_id,storage:manualStore,cryptoImpl:webcrypto,dispatch:async p=>{manualCalls.push(p);return {status:'confirmed'};}});
  manual.observe(s);await settle();assert.equal(manualCalls.length,0);
  await manual.perform('answer');assert.equal(manualCalls[0].action_id,'answer');assert.equal(manualCalls[0].origin,'manual');
  await manual.setPolicy('auto_quests',true);assert.equal(manualCalls.length,1);
  assert.equal(manual.questAction('110120'),'quest');await manual.perform('quest');assert.equal(manualCalls[1].policy.auto_quests,true);
  const waiting=structuredClone(s);waiting.interaction.messages=[];waiting.interaction.automation={state:'waiting_npc',npc_label:'Наставник'};
  manual.observe(waiting);await settle();assert.equal(manualCalls.length,2);assert.equal(manual.view.automation.npc_label,'Наставник');
  assert.equal(manual.questAction('110120'),null);
  const failed=[];const uncertain=ui.create({botId:s.bot_id,sessionId:s.session_id,storage:storage(),cryptoImpl:webcrypto,dispatch:async p=>{failed.push(p);throw Error('Lost response');}});
  uncertain.observe(s);await settle();const newer=structuredClone(s);newer.interaction.actions[0].context='d'.repeat(64);
  newer.interaction.messages[0].id='message2';uncertain.observe(newer);await settle();assert.equal(failed.length,1);assert.match(uncertain.status,/неизвестен/);
  for(const mutate of [v=>v.interaction.character_key='99',v=>v.interaction.source_sha256='0'.repeat(64),
    v=>v.interaction.messages[0].choices[0].action_id='missing',v=>v.interaction.actions[0].arguments.dialogue_id='18446744073709551616']) {
    const bad=structuredClone(s);mutate(bad);assert.equal(ui.project(bad,s.bot_id,s.session_id).known,false);
  }
  const noCapability=structuredClone(s);noCapability.interaction.actions_ready=false;
  assert.equal(ui.project(noCapability,s.bot_id,s.session_id).actions.every(a=>!a.enabled),true);
  const tutorial=structuredClone(s);tutorial.interaction.actions.push({id:'equip',kind:'tutorial_equip',context:'d'.repeat(64),arguments:{item_instance_id:'50'},enabled:true});
  tutorial.interaction.messages=[{id:'training1',kind:'tutorial',text:'Наденьте предмет',active:true,auto_skip:true,skip_action_id:'skip',choices:[{text:'Надеть',action_id:'equip'}]}];
  const trainingCalls=[],training=ui.create({botId:s.bot_id,sessionId:s.session_id,storage:storage(),cryptoImpl:webcrypto,
    dispatch:async payload=>{trainingCalls.push(payload);return {status:'confirmed'};}});
  training.observe(tutorial);await settle();assert.equal(trainingCalls.length,0);await training.perform('equip');
  assert.equal(trainingCalls[0].action_id,'equip');training.dispose();
  let resolveLate;const late=ui.create({botId:s.bot_id,sessionId:s.session_id,storage:manualStore,cryptoImpl:webcrypto,
    dispatch:()=>new Promise(resolve=>resolveLate=resolve)});
  late.observe(null);late.observe(s);assert.equal(late.status,'');const sending=late.perform('answer');await settle();
  late.observe(null);resolveLate({status:'queued'});await sending;late.observe(s);assert.match(late.status,/неизвестен/);late.dispose();
  let ack,posted;const racing=ui.create({botId:s.bot_id,sessionId:s.session_id,storage:manualStore,cryptoImpl:webcrypto,
    dispatch:payload=>{posted=payload;return new Promise(resolve=>ack=resolve);}});
  racing.observe(s);const pending=racing.perform('answer');await settle();const acknowledged=structuredClone(s);
  acknowledged.interaction.action_results=[{request_id:posted.request_id,status:'confirmed'}];racing.observe(acknowledged);
  ack({status:'queued'});await pending;assert.equal(racing.status,'Действие подтверждено');racing.dispose();
  ctl.dispose();manual.dispose();uncertain.dispose();
  let first;const ready=new Promise(resolve=>first=resolve),posts=[];
  const fetchImpl=async(url,options={})=>{
    let body;
    if(url.endsWith('/state'))body=s;
    else if(url.endsWith('/control'))body={bot_id:s.bot_id,session_id:s.session_id,token:'e'.repeat(64)};
    else {assert.equal(options.method,'POST');assert.equal(options.headers['X-Session-Token'],'e'.repeat(64));
      const sent=JSON.parse(options.body);posts.push([url,sent]);
      body=url.endsWith('/policy')?{...sent,status:'policy_updated'}:{...sent,status:'queued'};}
    return {ok:true,text:async()=>JSON.stringify(body)};
  };
  const live=adapterApi.create({botId:s.bot_id,sessionId:s.session_id,fetchImpl,documentImpl:{hidden:false,addEventListener(){},removeEventListener(){}},onChange:next=>{if(next)first();}});
  await ready;const policy={auto_quests:true,skip_dialogues:false};
  const result=await live.action({action_id:'answer',request_id:'f'.repeat(32),policy,origin:'manual'});
  assert.equal(result.status,'queued');assert.equal(posts[0][1].arguments.choice_id,'2');assert.equal(posts[0][1].session_id,s.session_id);
  await live.policy(policy);assert.equal(posts[1][1].policy.skip_dialogues,false);
  await assert.rejects(()=>live.action({action_id:'missing',request_id:'f'.repeat(32),policy,origin:'manual'}));
  assert.equal(posts.length,2);live.dispose();
  console.log('Live prompts: default skip, isolated preferences, manual choice/quest, NPC wait, deduplication, unknown and API identity passed');
})().catch(error=>{console.error(error);process.exitCode=1;});

// Owner offers do not assert that a dialogue decoder observed an empty list.
{
  const owner=snapshot();owner.interaction.semantics='owner_action_offers';owner.interaction.messages_known=false;
  owner.interaction.messages=[];owner.interaction.actions=owner.interaction.actions.filter(a=>a.kind==='quest_follow');
  const view=ui.project(owner,owner.bot_id,owner.session_id);
  assert.equal(view.known,true);assert.equal(view.messagesKnown,false);assert.equal(view.actions[0].enabled,true);
  owner.interaction.messages_known=true;assert.equal(ui.project(owner,owner.bot_id,owner.session_id).known,false);
  owner.interaction.messages_known=false;owner.interaction.messages=[{id:'invented'}];
  assert.equal(ui.project(owner,owner.bot_id,owner.session_id).known,false);
}

// Current quest automation is owner state; stored wishes cannot start it.
(async()=>{
 function current(){
  const value=snapshot();value.interaction.source_sha256=ui.CURRENT_SOURCE;
  value.interaction.semantics='owner_action_offers';value.interaction.messages_known=false;value.interaction.messages=[];
  value.interaction.actions=value.interaction.actions.filter(a=>a.kind==='quest_follow');
  value.interaction.automation={supported:true,state:'idle',selected_quest_id:null,stop_reason:null};
  value.action_policy={skip_dialogues:false,auto_quests:false};return value;
 }
 const state=current(),saved=storage();ui.preferences(state.bot_id,saved).set('auto_quests',true);
 const updates=[],actions=[];
 const response=(payload,other={})=>({bot_id:state.bot_id,session_id:state.session_id,status:'quest_automation_updated',
  policy:{skip_dialogues:false,auto_quests:payload.enabled},automation:{supported:true,
   state:payload.enabled?'waiting_data':'paused',selected_quest_id:payload.enabled?payload.quest_id:null,
   stop_reason:payload.enabled?null:'user_stop'},...other});
 const controller=ui.create({botId:state.bot_id,sessionId:state.session_id,storage:saved,cryptoImpl:webcrypto,
  configureQuest:async payload=>{updates.push(payload);return response(payload);},
  dispatch:async payload=>{actions.push(payload);return {status:'queued'};}});
 controller.observe(state);await settle();assert.equal(controller.policy.auto_quests,false);assert.equal(actions.length,0);
 assert.equal(controller.canToggleQuest('110120'),true);
 assert.equal(await controller.toggleQuest('110120'),true);
 assert.deepEqual(updates,[{quest_id:'110120',enabled:true}]);assert.equal(actions.length,1);
 assert.equal(actions[0].policy.auto_quests,true);assert.equal(controller.policy.auto_quests,true);
 assert.equal(controller.view.automation.selected_quest_id,'110120');assert.match(controller.status,/Ожидание подтверждения/);
 assert.equal(await controller.toggleQuest('110120'),true);
 assert.deepEqual(updates[1],{quest_id:null,enabled:false});assert.equal(actions.length,1);
 assert.equal(controller.policy.auto_quests,false);assert.equal(controller.view.automation.selected_quest_id,null);
 assert.match(controller.status,/остановлено/);controller.dispose();

 // Switching the owner selection never emits a concurrent second step while the old one is pending.
 const switchingState=current();switchingState.interaction.actions.push({id:'other-quest',kind:'quest_follow',context:'d'.repeat(64),arguments:{quest_id:'110121'},enabled:true});
 switchingState.interaction.quest_actions.push({quest_id:'110121',action_id:'other-quest'});
 const selectionCalls=[],switchActions=[],switching=ui.create({botId:state.bot_id,sessionId:state.session_id,storage:storage(),cryptoImpl:webcrypto,
  configureQuest:async payload=>{selectionCalls.push(payload);return response(payload);},
  dispatch:async payload=>{switchActions.push(payload);return {status:'queued'};}});
 switching.observe(switchingState);await switching.toggleQuest('110120');await switching.toggleQuest('110121');
 assert.deepEqual(selectionCalls.map(payload=>payload.quest_id),['110120','110121']);
 assert.equal(switching.view.automation.selected_quest_id,'110121');assert.equal(switchActions.length,1);
 assert.equal(switchActions[0].action_id,'quest');switching.dispose();

 // Selecting a current quest may wait for admission without inventing a game command.
 const waiting=current();waiting.interaction.actions_ready=false;waiting.interaction.actions=[];waiting.interaction.quest_actions=[];
 const waitingCalls=[],waitingController=ui.create({botId:state.bot_id,sessionId:state.session_id,storage:storage(),cryptoImpl:webcrypto,
  configureQuest:async payload=>{waitingCalls.push(payload);return response(payload);},dispatch:async()=>{throw Error('Unadmitted game command');}});
 waitingController.observe(waiting);assert.equal(waitingController.view.ready,false);
 assert.equal(await waitingController.toggleQuest('110120'),true);assert.equal(waitingCalls.length,1);
 assert.match(waitingController.status,/ожидание подключения шага/);
 waitingController.observe({...waiting,action_policy:{skip_dialogues:false,auto_quests:false},
  interaction:{...waiting.interaction,automation:{supported:true,state:'dead',selected_quest_id:null,stop_reason:'death'}}});
 assert.equal(waitingController.policy.auto_quests,false);assert.equal(waitingController.canToggleQuest('110120'),false);
 assert.match(waitingController.status,/погиб/);waitingController.dispose();

 // Policy failure and mismatched owners fail closed before the offered game action.
 for(const makeResponse of [()=>{throw Error('Lost response');},payload=>response(payload,{session_id:'other'})]){
  const dispatched=[];const failed=ui.create({botId:state.bot_id,sessionId:state.session_id,storage:storage(),cryptoImpl:webcrypto,
   configureQuest:async payload=>makeResponse(payload),dispatch:async payload=>{dispatched.push(payload);return {status:'confirmed'};}});
  failed.observe(state);assert.equal(await failed.toggleQuest('110120'),false);assert.equal(dispatched.length,0);
  assert.equal(failed.policy.auto_quests,false);assert.match(failed.status,/не подтверждено/);
  assert.equal(await failed.toggleQuest('110120'),false);assert.equal(dispatched.length,0);failed.dispose();
 }
 let complete;
 const staleActions=[],stale=ui.create({botId:state.bot_id,sessionId:state.session_id,storage:storage(),cryptoImpl:webcrypto,
  configureQuest:()=>new Promise(resolve=>complete=resolve),dispatch:async value=>{staleActions.push(value);return {status:'confirmed'};}});
 stale.observe(state);const changing=stale.toggleQuest('110120');await tick();
 stale.observe({...state,session_id:'replacement'});complete(response({quest_id:'110120',enabled:true}));
 assert.equal(await changing,false);assert.equal(staleActions.length,0);assert.equal(stale.view.known,false);stale.dispose();
 assert.equal(await stale.setPolicy('auto_quests',false),false);assert.equal(await stale.toggleQuest('110120'),false);

 // Disposing during an acknowledgement never sends the first game action afterwards.
 let release;let sends=0;
 const disposed=ui.create({botId:state.bot_id,sessionId:state.session_id,storage:storage(),cryptoImpl:webcrypto,
  configureQuest:()=>new Promise(resolve=>release=resolve),dispatch:async()=>{sends++;return {status:'confirmed'};}});
 disposed.observe(state);const inFlight=disposed.toggleQuest('110120');await tick();disposed.dispose();
 release(response({quest_id:'110120',enabled:true}));assert.equal(await inFlight,false);assert.equal(sends,0);
 const unsupported=current();unsupported.interaction.automation.supported=false;
 assert.equal(ui.project(unsupported,unsupported.bot_id,unsupported.session_id).ready,true);
 const falsePrompt=current();falsePrompt.interaction.semantics='observed_prompts';
 assert.equal(ui.project(falsePrompt,falsePrompt.bot_id,falsePrompt.session_id).known,false);
 const wrongKind=current();wrongKind.interaction.actions[0].kind='dialogue_skip';wrongKind.interaction.actions[0].arguments={dialogue_id:'1'};
 assert.equal(ui.project(wrongKind,wrongKind.bot_id,wrongKind.session_id).known,false);
 const metadata=current();metadata.interaction.automation={supported:true,state:'paused',selected_quest_id:null,stop_reason:'user_stop',enabled:false,cancel_pending:true,pending_request_id:'e'.repeat(32)};
 assert.deepEqual(ui.project(metadata,metadata.bot_id,metadata.session_id).automation,
  {...metadata.interaction.automation,npc_label:''});
 metadata.interaction.automation.stop_reason='server says click here';
 assert.equal(ui.project(metadata,metadata.bot_id,metadata.session_id).automation,null);
 console.log('Current quest toggle: owner policy, first dispatch, second-click stop, waiting admission, death, stale identity and fail-closed updates passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
