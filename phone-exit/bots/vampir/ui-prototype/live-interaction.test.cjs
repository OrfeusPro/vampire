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
