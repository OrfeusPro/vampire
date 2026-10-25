/* Explicit live adapter for one bot/window. No demo storage or game commands. */
(function(root){
  'use strict';
  const id=value=>typeof value==='string'&&/^[a-zA-Z0-9_-]{1,48}$/.test(value);
  const number=value=>Number.isSafeInteger(value)&&value>=0;
  function validate(value,botId,sessionId){
    if(!value||value.schema!==2||value.bot_id!==botId||value.session_id!==sessionId
      ||!['connecting','connected','disconnected'].includes(value.state))throw Error('Данные другой сессии или неверный формат.');
    const copy=JSON.parse(JSON.stringify(value));
    if(copy.character){
      const p=copy.character;
      if(typeof p.key!=='string'||!/^\d{1,20}$/.test(p.key)
        ||(p.name!==null&&(typeof p.name!=='string'||p.name.length>256)))throw Error('Неверные данные персонажа.');
      for(const key of ['hp','max_hp','mp','max_mp','level'])if(p[key]!==null&&!number(p[key]))throw Error('Неверный параметр персонажа.');
    }
    if(!Array.isArray(copy.entities)||copy.entities.length>2048)throw Error('Превышен лимит объектов.');
    return copy;
  }
  function playerStatus(snapshot){
    const p=snapshot?.state==='connected'?snapshot.character:null;
    const vital=(key,max)=>({id:key,value:p?.[key]??null,max:p?.[max]??null,
      known:number(p?.[key])&&number(p?.[max])&&p[max]>0&&p[key]<=p[max]});
    return {source:'live',name:p?.name??null,level:p?.level??null,
      vitals:[vital('hp','max_hp'),vital('mp','max_mp')],connected:!!p};
  }
  function create({botId,sessionId,onChange,fetchImpl=root.fetch,documentImpl=root.document}){
    if(!id(botId)||!id(sessionId)||typeof onChange!=='function'||typeof fetchImpl!=='function')throw Error('Нужны ID бота и сессии.');
    const base='http://127.0.0.1:17947/bots/'+encodeURIComponent(botId);
    let closed=false,timer=null,request=null,snapshot=null,epoch=0,entityPage=0;
    function clear(){snapshot=null;onChange(null);}
    async function poll(version){
      if(closed||version!==epoch||documentImpl?.hidden)return;
      request=new AbortController();const current=request;
      const timeout=setTimeout(()=>current.abort(),2000);
      try{
        const response=await fetchImpl(base+'/state'+(entityPage?'?entity_page='+entityPage:''),{cache:'no-store',signal:current.signal});
        if(!response.ok)throw Error('Нет сессии.');
        const text=await response.text();if(text.length>262144)throw Error('Превышен лимит состояния.');
        const next=validate(JSON.parse(text),botId,sessionId);
        if(!closed&&version===epoch){snapshot=next;if([0,1].includes(next.environment?.entity_page))entityPage=next.environment.entity_page;onChange(next);}
      }catch(error){if(!closed&&version===epoch)clear();}
      finally{
        clearTimeout(timeout);if(request===current)request=null;
        if(!closed&&version===epoch&&!documentImpl?.hidden)timer=setTimeout(()=>poll(version),1000);
      }
    }
    function visibility(){epoch++;clearTimeout(timer);request?.abort();
      if(documentImpl?.hidden)clear();else poll(epoch);}
    documentImpl?.addEventListener('visibilitychange',visibility);
    poll(epoch);
    return {get state(){return snapshot&&JSON.parse(JSON.stringify(snapshot));},
      setEntityPage(page){if(![0,1].includes(page)||closed)throw Error('Неверная страница окружения.');
        if(page===entityPage)return;entityPage=page;visibility();},
      dispose(){if(closed)return;closed=true;epoch++;clearTimeout(timer);request?.abort();
        documentImpl?.removeEventListener('visibilitychange',visibility);clear();}};
  }
  const api={validate,playerStatus,create};root.VampirLiveState=api;
  if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
