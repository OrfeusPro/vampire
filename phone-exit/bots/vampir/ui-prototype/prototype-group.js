/* One group subscription feeds the existing character UI and the shared map. */
(function(root){
 'use strict';
 function mount(args){
  const {app,el,append,button}=args;
  const host=el('div',undefined,'live-group'),viewport=el('section',undefined,'group-viewport');
  const panel=el('aside',undefined,'group-panel'),status=el('p','Загрузка персонажей…');
  const filter=el('select'),list=el('div',undefined,'group-roster');filter.setAttribute('aria-label','Сервер группы');
  const selectedIds=new Set();
  const selection=el('span','Выбрано 0'),message=el('p',undefined,'group-message');message.setAttribute('role','status');
  const token=document.querySelector('meta[name="console-token"]')?.content;
  let sessions={},controller,consumer,live,timer,request,disposed=false,revision='',selected=args.profile;
  const server=row=>[row.region,row.server??row.server_id].filter(Boolean).join(' · ');
  const api=async(body)=>{
   const response=await fetch('/api/world',{method:body?'POST':'GET',headers:{'X-Console-Token':token,
    ...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{}),cache:'no-store',signal:request?.signal});
   if(!response.ok)throw Error('Действие не выполнено. Проверьте состояние аккаунта.');
   return response.json();
  };
  const visible=()=>Object.entries(sessions).filter(([,row])=>row.state==='connected'&&(!filter.value||server(row)===filter.value))
   .sort((a,b)=>server(a[1]).localeCompare(server(b[1]),'ru')||a[1].character.name.localeCompare(b[1].character.name,'ru'));
  function choose(id){
   const row=sessions[id];if(row?.state!=='connected')return;
   selected=id;
   if(!live)live=root.VampirPrototypeLive.mount({...args,app:viewport,profile:id,
    group:{sessionId:row.session_id,select:choose,sessions:()=>sessions,adapter}});
   else live.select(id,row.session_id);
   render();
  }
  function adapter(id,sessionId,onChange){
   consumer={id,sessionId,onChange};
   const state=sessions[id];
   onChange(state?.session_id===sessionId?state:null);
   return {dispose(){if(consumer?.onChange===onChange)consumer=null;},
    action:async()=>{throw Error('Действие ещё недоступно в этой сессии');},
    policy:async()=>{throw Error('Автоматизация ещё недоступна в этой сессии');},setEntityPage(){}};
  }
  function render(){
   const servers=[...new Set(Object.values(sessions).filter(row=>row.state==='connected').map(server))].sort();
   const chosen=filter.value||'';
   if(JSON.stringify(servers)!==filter.dataset.values){
    filter.dataset.values=JSON.stringify(servers);filter.replaceChildren(new Option('Все серверы',''),...servers.map(s=>new Option(s,s)));filter.value=servers.includes(chosen)?chosen:'';
   }
   const values=visible(),key=JSON.stringify(values.map(([id,row])=>[id,row.session_id,row.character?.name,row.character?.level,selectedIds.has(id),id===selected]));
   if(key!==revision){
    revision=key;list.replaceChildren();let lastServer;
    for(const [id,row] of values){
     const title=server(row);if(title!==lastServer){list.append(el('h3',title));lastServer=title;}
     const line=el('div',undefined,'group-member'),check=el('input');check.type='checkbox';check.checked=selectedIds.has(id);
     check.setAttribute('aria-label','Выбрать '+row.character.name);
     check.onchange=()=>{check.checked?selectedIds.add(id):selectedIds.delete(id);render();};
     const item=button('',()=>choose(id),'group-member-select');item.setAttribute('aria-pressed',String(id===selected));
     append(item,el('strong',row.character.name),el('small',server(row)+' · ур. '+(row.character.level??'—')));
     append(line,check,item);list.append(line);
    }
   }
   const online=Object.values(sessions).filter(row=>row.state==='connected').length;
   status.textContent=online+' онлайн · '+values.length+' в группе';
   selection.textContent='Выбрано '+selectedIds.size;
  }
  const all=button('Выбрать группу',()=>{for(const [id] of visible())selectedIds.add(id);render();},'group-control');
  const clear=button('Снять',()=>{selectedIds.clear();render();},'group-control');
  const stop=button('Выйти выбранными',async()=>{
   stop.disabled=true;let done=0;
   try{
    for(const id of [...selectedIds]){
     const row=sessions[id];if(!row?.session_id||!['connected','connecting'].includes(row.state))continue;
     await api({id,action:'stop',session_id:row.session_id});done++;
    }
    message.textContent='Запрошен выход для '+done+' персонажей.';selectedIds.clear();
   }catch(error){message.textContent=error.message;}
   finally{stop.disabled=false;render();}
  },'group-control');
  filter.onchange=render;
  append(panel,el('h2','Группа ботов'),status,filter,append(el('div',undefined,'group-controls'),all,clear),list,
   selection,stop,message);
  append(host,viewport,panel);app.replaceChildren(host);
  viewport.append(el('p','Ожидание персонажа в мире. Вход доступен в панели аккаунтов.','group-empty'));
  async function poll(){
   if(disposed||request||document.hidden)return;
   request=new AbortController();const timeout=setTimeout(()=>request?.abort(),8000);
   try{
    sessions=(await api()).sessions;
    for(const id of selectedIds)if(sessions[id]?.state!=='connected')selectedIds.delete(id);
    const current=sessions[selected];
    if(!live&&current?.state!=='connected')selected=visible()[0]?.[0];
    if(sessions[selected]?.state==='connected')choose(selected);
    if(consumer){const row=sessions[consumer.id];consumer.onChange(row?.session_id===consumer.sessionId?row:null);}
    live?.refreshGroup();render();
   }catch{sessions={};consumer?.onChange(null);live?.refreshGroup();render();status.textContent='Потеряна связь с панелью';}
   finally{clearTimeout(timeout);request=null;if(!disposed&&!document.hidden)timer=setTimeout(poll,2000);}
  }
  function visibility(){clearTimeout(timer);if(document.hidden)request?.abort();else poll();}
  document.addEventListener('visibilitychange',visibility);poll();
  return {dispose(){disposed=true;clearTimeout(timer);request?.abort();live?.dispose();document.removeEventListener('visibilitychange',visibility);},
   resume(){disposed=false;live?.resume();document.addEventListener('visibilitychange',visibility);poll();}};
 }
 root.VampirPrototypeGroup={mount};
})(window);
