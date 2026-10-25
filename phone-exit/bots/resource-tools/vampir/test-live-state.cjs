const assert=require('node:assert/strict');
const live=require('../../vampir/ui-prototype/live-state.js');
const state={schema:2,bot_id:'a',session_id:'session-a',state:'connected',entities:[],
  character:{key:'42',name:'Персонаж',hp:null,max_hp:null,mp:null,max_mp:null,level:null}};
assert.equal(live.playerStatus(live.validate(state,'a','session-a')).vitals[0].known,false);
assert.equal(live.playerStatus(null).vitals[0].value,null);
assert.throws(()=>live.validate(state,'b','session-a'));
assert.throws(()=>live.validate(state,'a','old-session'));
const known={...state,character:{...state.character,hp:0,max_hp:100,mp:30,max_mp:50}};
assert.equal(live.playerStatus(known).vitals[0].known,true);
assert.equal(live.playerStatus(known).vitals[0].value,0);
assert.equal(live.playerStatus({...known,state:'disconnected'}).vitals[1].value,null);
assert.throws(()=>live.validate({...state,character:{...state.character,hp:-1}},'a','session-a'));
assert.throws(()=>live.validate({...state,entities:Array(2049).fill({})},'a','session-a'));
(async()=>{
  const callbacks=new Map(),changes=[];
  let requests=0,signal;
  const documentImpl={hidden:false,addEventListener:(key,fn)=>callbacks.set(key,fn),removeEventListener:key=>callbacks.delete(key)};
  const adapter=live.create({botId:'a',sessionId:'session-a',onChange:value=>changes.push(value),documentImpl,
    fetchImpl:async(url,options)=>{requests++;signal=options.signal;assert.equal(url,'http://127.0.0.1:17947/bots/a/state');
      return {ok:true,text:async()=>JSON.stringify(state)};}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(adapter.state.character.key,'42');
  documentImpl.hidden=true;callbacks.get('visibilitychange')();
  assert.equal(adapter.state,null);
  await new Promise(resolve=>setTimeout(resolve,1050));
  assert.equal(requests,1);
  documentImpl.hidden=false;callbacks.get('visibilitychange')();
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(requests,2);
  adapter.dispose();adapter.dispose();
  assert.equal(callbacks.size,0);assert.equal(adapter.state,null);
  console.log('Live state: identity, nullable vitals, visibility and disposal passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
