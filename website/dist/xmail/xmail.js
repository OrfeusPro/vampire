'use strict';
const csrf=document.querySelector('meta[name="csrf-token"]').content;
const errors={invalid_login:'Неверный логин или пароль.',login_limit:'Слишком много попыток входа. Попробуйте через 15 минут.',auth_required:'Сессия завершена. Войдите снова.',csrf:'Обновите страницу и повторите действие.',imap_connect:'Не удалось подключиться к IMAP. Попробуйте позже.',imap_command:'Не удалось прочитать ящик. Проверьте пароль или доступ к папке.',imap_timeout:'Почтовый сервер не ответил вовремя.',message_too_large:'Письмо больше 12 МБ. Откройте его в обычном почтовом клиенте.',message_missing:'Письмо уже удалено или перемещено.',folder_changed:'Папка изменилась. Обновите список писем.',mime_limits:'Слишком сложная структура письма. Откройте его в обычном почтовом клиенте.'};
async function api(data,download=false){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),45000);
 try{
  const response=await fetch('/xmail/api',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(data),signal:controller.signal});
  if(!response.ok){let error={};try{error=await response.json();}catch{}if(error.error==='auth_required'){location.replace('/xmail/');throw new Error(errors.auth_required);}throw new Error(errors[error.error]||'Не удалось выполнить запрос. Повторите позже.');}
  return download?response.blob():response.json();
 }finally{clearTimeout(timer);}
}
const login=document.querySelector('#login-form');
if(login){login.addEventListener('submit',async event=>{event.preventDefault();const button=login.querySelector('button'),error=document.querySelector('#login-error');button.disabled=true;button.textContent='Входим…';error.textContent='';try{await api({action:'login',username:login.elements.username.value,password:login.elements.password.value});location.replace('/xmail/');}catch(e){error.textContent=e.message;}finally{button.disabled=false;button.textContent='Войти';}});}
else{
 const state={accounts:[],folders:new Map(),lists:new Map(),issues:new Map(),selected:'',folder:'',query:'',unread:false,current:'',syncing:false,updated:null};
 const elements={accounts:document.querySelector('#accounts'),messages:document.querySelector('#messages'),reader:document.querySelector('#reader'),workspace:document.querySelector('.workspace'),status:document.querySelector('#sync-status'),info:document.querySelector('#list-info'),more:document.querySelector('#load-more'),folder:document.querySelector('#folder-filter')};
 const node=(tag,text,cls)=>{const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(cls)el.className=cls;return el;};
 const accountName=id=>state.accounts.find(a=>a.id===id)?.email||id;
 const listKey=(a,f)=>a+'|'+f;
 const messageKey=m=>[m.account,m.folder,m.validity,m.uid].join('|');
 function renderFolders(){
  const previous=state.folder;elements.folder.replaceChildren(node('option','Все папки'));elements.folder.firstChild.value='';
  const folders=new Map();for(const [account,items]of state.folders)if(!state.selected||account===state.selected)for(const f of items)folders.set(f.name,f.name);
  for(const name of folders.keys()){const option=node('option',name);option.value=name;elements.folder.append(option);}elements.folder.value=previous;if(elements.folder.value!==previous)state.folder='';
 }
 function render(){
  const all=[];let total=0,more=false;
  for(const [key,list]of state.lists){if(state.selected&&list.account!==state.selected)continue;if(state.folder&&list.folderName!==state.folder)continue;total+=list.total;more ||=list.more;for(const m of list.messages){if(state.unread&&!m.unread)continue;const searchable=[m.subject,m.from,accountName(m.account),m.folderName].join(' ').toLocaleLowerCase();if(state.query&&!searchable.includes(state.query))continue;all.push(m);}}
  all.sort((a,b)=>b.timestamp-a.timestamp||b.uid-a.uid);
  elements.messages.replaceChildren();
  for(const m of all){const button=node('button',undefined,'message'+(m.unread?' unread':'')+(messageKey(m)===state.current?' selected':''));const line=node('span',undefined,'message-from');line.append(node('span',m.from||'Отправитель не указан'),node('time',m.timestamp?new Date(m.timestamp*1000).toLocaleString('ru',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}):''));const tags=node('span',undefined,'message-tags');tags.append(node('span',accountName(m.account)),node('span',m.folderName));button.append(line,node('strong',m.subject||'(Без темы)'),tags);button.addEventListener('click',()=>openMessage(m));elements.messages.append(button);}
  document.querySelector('#message-count').textContent=all.length+' / '+total;
  document.querySelector('#mailbox-title').textContent=state.selected?accountName(state.selected):'Вся почта';
  const issueLines=[...state.issues].filter(([id])=>!state.selected||id===state.selected).map(([id,text])=>accountName(id)+': '+text);
  elements.info.textContent=(all.length?'Показано '+all.length+' из '+total+'. Последние письма из каждой папки; ранние — по кнопке ниже.':state.syncing?'Проверяем папки…':'Писем по выбранным условиям нет.')+(issueLines.length?'\n'+issueLines.join('\n'):'');
  elements.more.hidden=!more;elements.more.disabled=state.syncing;
  for(const button of elements.accounts.querySelectorAll('button')){const id=button.dataset.account;button.classList.toggle('active',state.selected===id);button.classList.toggle('has-error',state.issues.has(id));button.lastChild.textContent=state.issues.has(id)?'Ошибка':state.folders.has(id)?'Подключён':'…';}
  document.querySelector('#all-accounts').classList.toggle('active',!state.selected);
 }
 async function folderList(account,folder,page=0){
  const response=await api({action:'messages',account,folder:folder.id,page});const key=listKey(account,folder.id);const previous=state.lists.get(key);
  const messages=response.messages.map(m=>({...m,account,folder:folder.id,folderName:folder.name}));
  const merged=page&&previous&&previous.validity===response.validity?[...previous.messages,...messages]:page===0&&previous?.validity===response.validity?[...messages,...previous.messages.filter(m=>m.uid<(messages.at(-1)?.uid||0))]:messages;
  const unique=new Map(merged.map(m=>[m.uid,m]));
  state.lists.set(key,{account,folder:folder.id,folderName:folder.name,validity:response.validity,total:response.total,messages:[...unique.values()],page:page||((previous?.validity===response.validity)?previous.page:0)||0,more:page?response.more:previous?.page&&previous.validity===response.validity?previous.more:response.more});
 }
 async function pool(items,work){let next=0;await Promise.all(Array.from({length:Math.min(3,items.length)},async()=>{while(next<items.length){const item=items[next++];await work(item);}}));}
 async function sync(older=false){
  if(state.syncing||document.hidden)return;state.syncing=true;document.querySelector('#refresh').disabled=true;elements.status.textContent=older?'Загружаем ранние письма…':'Обновляем ящики…';render();
  try{
   if(older){const targets=[...state.lists.values()].filter(x=>x.more&&(!state.selected||x.account===state.selected)&&(!state.folder||x.folderName===state.folder));await pool(targets,async list=>{try{await folderList(list.account,{id:list.folder,name:list.folderName},list.page+1);state.issues.delete(list.account);}catch(e){state.issues.set(list.account,e.message);}render();});}
   else{await pool(state.accounts,async account=>{if(document.hidden)return;try{const response=await api({action:'folders',account:account.id});state.folders.set(account.id,response.folders);renderFolders();for(const folder of response.folders){if(document.hidden)break;await folderList(account.id,folder,0);}state.issues.delete(account.id);}catch(e){state.issues.set(account.id,e.message);}render();});}
   state.updated=new Date();elements.status.textContent=(state.issues.size?'Есть ошибки · ':'Обновлено · ')+state.updated.toLocaleTimeString('ru');
  }catch(e){elements.status.textContent=e.message;}finally{state.syncing=false;document.querySelector('#refresh').disabled=false;render();}
 }
 let readerRequest=0;
 async function openMessage(message){
  const ticket=++readerRequest;state.current=messageKey(message);elements.workspace.classList.add('reading');elements.reader.replaceChildren(node('p','Загружаем письмо…','muted'));render();
  try{const response=await api({action:'message',account:message.account,folder:message.folder,uid:message.uid,validity:message.validity});if(ticket!==readerRequest)return;
   const back=node('button','← К списку','reader-back');back.addEventListener('click',()=>elements.workspace.classList.remove('reading'));
   const head=node('div',undefined,'reader-header');head.append(node('p',accountName(message.account)+' / '+message.folderName,'eyebrow'),node('h2',response.subject));const meta=node('dl',undefined,'reader-meta');for(const [label,value]of [['От',response.from],['Кому',response.to],['Дата',response.date]])meta.append(node('dt',label),node('dd',value));head.append(meta);
   const attachments=node('div',undefined,'attachment-list');response.attachments.forEach((file,index)=>{const button=node('button','↓ '+file.name+' · '+Math.ceil(file.size/1024)+' КБ');button.addEventListener('click',async()=>{button.disabled=true;try{const blob=await api({action:'attachment',account:message.account,folder:message.folder,uid:message.uid,validity:message.validity,attachment:index},true),url=URL.createObjectURL(blob),a=node('a');a.href=url;a.download=file.name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);}catch(e){const error=node('p',e.message,'error-box');attachments.append(error);}finally{button.disabled=false;}});attachments.append(button);});
   elements.reader.replaceChildren(back,head,node('pre',response.text||'В письме нет текстового содержимого.','message-body'),attachments);
   if(innerWidth<=1050)elements.reader.scrollIntoView({block:'start'});
  }catch(e){if(ticket===readerRequest){const back=node('button','← К списку');back.addEventListener('click',()=>elements.workspace.classList.remove('reading'));elements.reader.replaceChildren(back,node('p',e.message,'error-box'));}}
 }
 document.querySelector('#all-accounts').addEventListener('click',()=>{state.selected='';state.folder='';renderFolders();render();});
 document.querySelector('#search').addEventListener('input',e=>{state.query=e.target.value.toLocaleLowerCase();render();});elements.folder.addEventListener('change',e=>{state.folder=e.target.value;render();});document.querySelector('#read-filter').addEventListener('change',e=>{state.unread=e.target.value==='unread';render();});
 document.querySelector('#refresh').addEventListener('click',()=>sync());elements.more.addEventListener('click',()=>sync(true));
 document.querySelector('#logout').addEventListener('click',async()=>{try{await api({action:'logout'});location.replace('/xmail/');}catch(e){elements.status.textContent=e.message;}});
 async function start(){try{const response=await api({action:'accounts'});state.accounts=response.accounts;document.querySelector('#account-count').textContent=state.accounts.length;for(const account of state.accounts){const button=node('button',undefined,'account');button.dataset.account=account.id;button.append(node('span',account.email),node('span','…'));button.addEventListener('click',()=>{state.selected=account.id;state.folder='';renderFolders();render();});elements.accounts.append(button);}await sync();}catch(e){elements.status.textContent=e.message;}}
 document.addEventListener('visibilitychange',()=>{if(!document.hidden)sync();});setInterval(()=>{if(!document.hidden)sync();},30000);start();
}
