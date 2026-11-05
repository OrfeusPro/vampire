'use strict';
const token=document.querySelector('meta[name="console-token"]').content;
const el=id=>document.getElementById(id);
let snapshot={accounts:[],jobs:{},catalogs:{}}, selected=null, initial=true, currentPc=null, accountDevice={device_profile:'current-pc',device_settings:{}};
const labels={active:'В мире',connecting:'Подключение',stopped:'Остановлен',error:'Ошибка',needs_character:'Нужен персонаж',disabled:'Отключён'};
const stages={sdk_fetch_player:'Проверка игрового профиля',sdk_basic_terms:'Чтение основных условий',sdk_individual_terms:'Чтение индивидуальных условий',sdk_first_profile:'Первое создание профиля SDK',registration_form:'Регистрация · отдельное окно Netmarble',registration_code:'Ожидание нового письма с кодом',configuration:'Загрузка конфигурации',source_validation:'Проверка версии',lobby_preparation:'Подготовка лобби',nid_browser:'Вход Netmarble · отдельное окно',sdk_sign_in:'Авторизация SDK',sdk_launcher_token:'Получение SDK token',sdk_launcher_sign_in:'Вход SDK',lobby_connect:'Подключение к лобби',lobby_exchange:'Обмен с лобби',game_target_selection:'Проверка сервера',selected_lobby_login:'Вход в выбранное лобби',game_system_inputs:'Подготовка клиента',game_connect:'Подключение к игре',game_login_preparation:'Подготовка входа',game_login_exchange:'Вход и получение персонажей',character_creation:'Создание персонажа'};
async function api(path,body){const response=await fetch(path,{method:body?'POST':'GET',headers:{'X-Console-Token':token,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});const data=await response.json();if(!response.ok)throw Error(data.error||'Операция не выполнена');return data;}
function notice(text){el('notice').textContent=text;el('toast').textContent=text;}
function option(value,text){const node=document.createElement('option');node.value=value;node.textContent=text;return node;}
function current(){return snapshot.accounts.find(a=>a.id===selected);}
function isGoogle(account){return account?.login_provider==='google';}
function runnableAccounts(){return snapshot.accounts.filter(a=>a.enabled!==false&&!isGoogle(a)&&!['Не задействован','Не использовать'].includes(deviceType(a)));}
function renderProvider(){
 const google=el('login-provider').value==='google',running=!!snapshot.jobs[selected]?.running;
 el('login-provider').disabled=running||!!selected;
 el('password').required=!selected&&!google;el('password').disabled=running||google;el('mail-password').disabled=running||google;
 el('provider-hint').textContent=google?'Верификация: выберите аккаунт в таблице. Войдите через Google во внешнем браузере; код из Gmail введите сами в окне Netmarble. Пароли не сохраняются. Прямой выход ПК.':'Почтовый вход Netmarble. Ручной ввод доступен в отдельном окне.';
 if(google)for(const id of ['start','servers','characters','create','register','prepare-sdk','manual-sign-in','auth-flow'])el(id).disabled=true;
}
el('login-provider').onchange=()=>{el('password').value='';el('mail-password').value='';render();};
function deviceType(account){return account.device_type||(account.reported_device==='UgPhone'?'UgPhone':'Бот');}
const typeClass={'Телефон':'phone','ПК':'pc','UgPhone':'ugphone','LdCloud':'ldcloud','Бот':'bot','Не задействован':'reserve','Не использовать':'excluded'};
function accountNumber(account){return snapshot.accounts.findIndex(a=>a.id===account.id)+1;}
function onDevice(account){return ['Телефон','ПК','UgPhone','LdCloud'].includes(deviceType(account));}
function characterLabel(account){
 const list=snapshot.character_lists?.[account.id+'|'+account.region+'|'+account.server_id]?.characters||[];
 const character=account.character_key?list.find(c=>c.key===account.character_key):(list.length===1?list[0]:null);
 return character?.name||account.reported_character_name||(account.create_nickname?account.create_nickname+' · план':'—');
}
function renderAvailability(){
 const excluded=el('account-device-type').value==='Не использовать';
 if(excluded)el('enabled').checked=false;
 el('enabled').disabled=excluded||!!snapshot.jobs[selected]?.running;
 el('device-use-hint').textContent=excluded?'Не запускается и не верифицируется. Чтобы вернуть аккаунт в работу, выберите другой тип и включите его.':'Не задействован'===el('account-device-type').value?'Резерв: исключён из общего запуска. Ручной запуск и верификация доступны.':'Тип не меняет Windows-параметры шаблона и сетевой маршрут.';
}
el('account-device-type').onchange=renderAvailability;
function rosterAccounts(){
 return [
  ...snapshot.accounts.filter(account=>!onDevice(account)),
  ...snapshot.accounts.filter(account=>onDevice(account)),
 ];
}
function servers(value){const catalog=snapshot.catalogs[el('region').value];el('server').replaceChildren(option('','Выберите сервер'));for(const server of catalog?.servers||[]){const node=option(server.id,server.name+(server.excluded?' · вход ограничен':''));node.disabled=server.excluded;el('server').append(node);}if(value&&!Array.from(el('server').options).some(o=>o.value===String(value)))el('server').append(option(value,'Сервер '+value+(catalog?' · отсутствует в каталоге':' · обновите каталог')));el('server').value=value??'';el('catalog-age').textContent=catalog?'Каталог: '+new Date(catalog.observed_utc).toLocaleString('ru-RU'): 'Каталог ещё не загружен';}
function characters(value){const cached=snapshot.character_lists?.[selected+'|'+el('region').value+'|'+el('server').value];const job=snapshot.jobs[selected];const sameTarget=job?.region===el('region').value&&String(job?.server_id)===el('server').value;const rows=cached?.characters||(sameTarget?(job?.characters||[]):[]);el('characters-age').textContent=cached?'Подтверждённый список: '+new Date(cached.observed_utc).toLocaleString('ru-RU'):'Подтверждённый список пока не сохранён';el('character').replaceChildren(option('','Не назначен'));for(const row of rows){const node=option(row.index,row.name||'Персонаж '+(row.index+1));node.dataset.key=row.key;el('character').append(node);}if(value!==null&&value!==undefined&&!rows.some(r=>r.index===value)){const node=option(value,'Слот '+(value+1)+' · прочитайте персонажей');node.dataset.key=current()?.character_key||'';el('character').append(node);}el('character').value=value??'';}
function edit(account){selected=account?.id||null;el('heading').textContent=account?.email||'Новый аккаунт';el('email').value=account?.email||'';el('email').readOnly=!!account;el('password').value='';el('mail-password').value='';el('password-details').open=!account;el('terms').checked=false;el('manual-mail-code').checked=false;el('manual-sign-in').checked=false;el('registration-code').value='';el('sdk-country').value='';el('sdk-locale').value='';el('sdk-terms-mode').value='';el('login-provider').value=account?.login_provider||'email';el('enabled').checked=account?.enabled!==false;el('label').value=account?.label||'';editConnection(account);el('auth-flow').value=account?.auth_flow||'launcher';el('region').value=account?.region||'EU';el('nickname').value=account?.create_nickname||'';el('random-nickname').checked=account?.create_random_nickname!==false;el('create-class').replaceChildren(...(snapshot.creation_classes||[]).map(c=>option(c.key,c.label)));el('create-class').value=account?.create_class||'Gunner';servers(account?.server_id);characters(account?.character_index);render();renderTemplateSelection(account?.device_template_id||'');}

const shownPasswords=new Map();
const verificationSelection=new Set();
labels.verified='Верификация подтверждена';
stages['verify_device-registration']='Регистрация устройства Netmarble';
stages.verify_workplace='Подтверждение защиты аккаунта';
stages.verification_mail='Ожидание свежего письма';
stages.manual_nid_browser='Введите логин и пароль в отдельном окне Netmarble';
stages.manual_google_browser='Нажмите Google и войдите в аккаунт во внешнем браузере';
stages.manual_verification_code='Введите код из Gmail в окне Netmarble · до 10 минут';

function renderVerification(){
 const queue=snapshot.verification;
 const active=queue?.state==='running'||queue?.state==='cancelling';
 const canResume=queue?.state==='stopped'&&queue.manual_retry===true;
 el('verify-selected').disabled=active||canResume||verificationSelection.size===0;
 el('resume-verification').hidden=!canResume;
 el('resume-verification').disabled=!canResume;
 el('stop-verification').disabled=queue?.state!=='running'&&!canResume;
 const account=snapshot.accounts.find(row=>row.id===(queue?.active||queue?.failed));
 const job=snapshot.jobs[account?.id];
 const stage=stages[job?.stage]||'Подготовка';
 let summary='Выбрано аккаунтов: '+verificationSelection.size;
 if(queue?.state==='running') summary=`${account?.email||''} · ${stage} · подтверждено ${queue.completed.length} · в очереди ${queue.pending.length}`;
 if(queue?.state==='cancelling') summary='Остановка очереди…';
 if(queue?.state==='completed') summary=`Подтверждено аккаунтов: ${queue.completed.length}`;
 if(queue?.state==='cancelled') summary=`Очередь остановлена. Подтверждено аккаунтов: ${queue.completed.length}`;
 if(queue?.state==='stopped') summary=`${account?.email||''} · ${queue.message||job?.message||'Не удалось запустить верификацию.'} Подтверждено аккаунтов: ${queue.completed.length}`;
 el('verification-status').textContent=summary;
}

el('verify-selected').onclick=async()=>{
 const accounts=snapshot.accounts.filter(row=>verificationSelection.has(row.id)).map(row=>row.id);
 el('verify-selected').disabled=true;
 try{
  await api('/api/verification-queue',{accounts});
  verificationSelection.clear();
  await refresh();
 }catch(error){notice(error.message);renderVerification();}
};
el('stop-verification').onclick=async()=>{
 try{await api('/api/verification-queue',{action:'stop'});await refresh();}
 catch(error){notice(error.message);}
};
el('resume-verification').onclick=async()=>{
 el('resume-verification').disabled=true;
 try{await api('/api/verification-queue',{action:'resume-manual'});await refresh();}
 catch(error){notice(error.message);renderVerification();}
};
const registrationLabels={unknown:'Netmarble не проверен',in_progress:'Регистрация идёт',unconfirmed:'Регистрация не подтверждена',registered:'Netmarble зарегистрирован',email_in_use:'Почта занята в Netmarble',nid_verified:'Вход Netmarble подтверждён',sdk_created:'Профиль SDK подтверждён'};
function passwordCell(account,kind){
 const cell=document.createElement('div'),wrap=document.createElement('div'),text=document.createElement('span'),button=document.createElement('button');cell.className='password-card';const label=document.createElement('label');label.textContent=kind==='mail'?'Пароль почты':'Пароль Netmarble';cell.append(label);
 const key=account.id+':'+kind,visible=shownPasswords.has(key),saved=kind==='mail'?account.mail_password_saved:account.password_saved;
 wrap.className='password-cell';text.textContent=visible?shownPasswords.get(key):(saved?'••••••••':'—');
 button.type='button';button.textContent=visible?'◉':'👁';button.disabled=!saved;
 button.setAttribute('aria-label',(visible?'Скрыть':'Показать')+' пароль '+(kind==='mail'?'почты':'Netmarble')+' '+account.email);
 button.onclick=async()=>{if(shownPasswords.has(key)){shownPasswords.delete(key);renderRoster();return;}button.disabled=true;try{const result=await api('/api/reveal',{id:account.id,kind});if(document.hasFocus()){shownPasswords.set(key,result.password);renderRoster();}}catch(error){notice(error.message);}finally{button.disabled=!saved;}};
 wrap.append(text,button);cell.append(wrap);return cell;
}
function canVerify(account){
 const queue=snapshot.verification;
 return queue?.state!=='running'&&queue?.state!=='cancelling'&&account.enabled!==false&&deviceType(account)!=='Не использовать'&&!snapshot.jobs[account.id]?.running&&
  (isGoogle(account)?account.socks_port==null:(account.email.endsWith('@vampir.top')&&account.mail_password_saved));
}
function accountStatus(account){
 const job=snapshot.jobs[account.id],queue=snapshot.verification;
 const same=!account.device_template_id||(job?.device_template_id===account.device_template_id&&job?.device_template_revision===account.device_template_revision);
 if(job?.running)return {text:stages[job.stage]||labels[job.status]||job.status,kind:'connecting'};
 if(deviceType(account)==='Не использовать')return {text:'Не использовать',kind:'excluded'};
 if(account.enabled===false)return {text:'Отключён',kind:'disabled'};
 if(deviceType(account)==='Не задействован')return {text:'Резерв · ручной запуск',kind:'reserve'};
 if(queue?.state==='running'&&queue.pending.includes(account.id))return {text:'В очереди',kind:'connecting'};
 if(account.device_verified||(!account.device_template_id&&queue?.completed.includes(account.id)))return {text:'Верифицирован',kind:'verified'};
 if(same&&job?.status==='error')return {text:job.message||'Ошибка входа',kind:'error'};
 if(account.device_template_id)return {text:'Новое устройство · вход не проверен',kind:'stopped'};
 if(account.mail_status==='planned')return {text:'Заготовка',kind:'stopped'};
 return {text:isGoogle(account)?'Google · ручной вход':(registrationLabels[account.registration_status]||'Не проверен'),kind:'stopped'};
}
function cellLink(text,handler,title=''){
 const node=document.createElement('button');node.type='button';node.className='cell-link';node.textContent=text;node.onclick=handler;node.title=title;return node;
}
let rosterSort={key:null,direction:1};
const collator=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
function sortValue(account,key){
 return ({number:accountNumber(account),account:account.email,character:characterLabel(account),class:snapshot.creation_classes?.find(c=>c.key===account.create_class)?.label||account.create_class,server:account.region+' · '+(snapshot.catalogs[account.region]?.servers.find(s=>s.id===account.server_id)?.name||account.server_id||''),device:deviceType(account),template:account.device_template_name||'',
  'device-name':account.device_name||'',status:accountStatus(account).text})[key]||'';
}
for(const key of ['number','account','character','class','server','device','template','device-name','status'])el('sort-'+key).onclick=()=>{rosterSort={key,direction:rosterSort.key===key?-rosterSort.direction:1};renderRoster();};
const columnKeys=['number','account','character','class','server','device','template','device-name','status'];
const selectColumnKeys=['class','server','device','template','status'];
function columnValue(account,key){return String(sortValue(account,key)||'—');}
function renderColumnFilters(){
 for(const key of selectColumnKeys){
  const select=el('filter-'+key),chosen=select.value;
  const values=[...new Set(snapshot.accounts.map(a=>columnValue(a,key)))].sort(collator.compare);
  const signature=JSON.stringify([values,chosen&&!values.includes(chosen)?chosen:null]);
  if(select.dataset.optionsSignature===signature)continue;
  select.replaceChildren(option('','Все'),...values.map(value=>option(value,value)));
  if(chosen&&!values.includes(chosen))select.append(option(chosen,chosen+' · нет в снимке'));
  select.value=chosen;select.dataset.optionsSignature=signature;
 }
}
for(const key of columnKeys)el('filter-'+key)[selectColumnKeys.includes(key)?'onchange':'oninput']=()=>renderRoster();
el('reset-column-filters').onclick=()=>{for(const key of columnKeys)el('filter-'+key).value='';renderRoster();};
function visibleAccounts(){
 const query=el('search').value.trim().toLowerCase(),filter=el('roster-filter').value||'all';
 const rows=rosterAccounts().filter(a=>{
  if(filter==='active'&&!onDevice(a)||filter==='planned'&&deviceType(a)!=='Бот'||filter==='reserve'&&deviceType(a)!=='Не задействован'||filter==='excluded'&&deviceType(a)!=='Не использовать'||filter==='unassigned'&&a.device_template_id)return false;
  if(!columnKeys.every(key=>{const value=el('filter-'+key).value;if(!value)return true;const actual=columnValue(a,key);return selectColumnKeys.includes(key)?actual===value:actual.toLocaleLowerCase('ru').includes(value.toLocaleLowerCase('ru'));}))return false;
  const server=snapshot.catalogs[a.region]?.servers.find(s=>s.id===a.server_id)?.name||'';
  return !query||[accountNumber(a),deviceType(a),a.email,a.label,characterLabel(a),a.device_template_name,a.device_name,server].join(' ').toLowerCase().includes(query);
 });
 if(rosterSort.key)rows.sort((a,b)=>collator.compare(sortValue(a,rosterSort.key),sortValue(b,rosterSort.key))*rosterSort.direction);
 return rows;
}
function renderRoster(){
 renderColumnFilters();
 for(const identifier of verificationSelection){const account=snapshot.accounts.find(a=>a.id===identifier);if(!account||!canVerify(account))verificationSelection.delete(identifier);}
 const body=el('roster-body');body.replaceChildren();
 for(const key of ['number','account','character','class','server','device','template','device-name','status']){
  const button=el('sort-'+key),active=rosterSort.key===key;
  button.parentElement.setAttribute('aria-sort',active?(rosterSort.direction===1?'ascending':'descending'):'none');
  button.querySelector('span').textContent=active?(rosterSort.direction===1?'↑':'↓'):'↕';
 }
 for(const account of visibleAccounts()){
  const row=document.createElement('tr');row.className=(onDevice(account)?'active-game-account ':'')+'device-type-'+typeClass[deviceType(account)];
  const number=document.createElement('td');number.className='row-number';number.textContent=accountNumber(account);row.append(number);
  const email=document.createElement('td'),wrap=document.createElement('div'),checkbox=document.createElement('input');wrap.className='account-cell';
  checkbox.type='checkbox';checkbox.className='verify-checkbox';checkbox.checked=verificationSelection.has(account.id);checkbox.disabled=!canVerify(account);
  checkbox.setAttribute('aria-label','Выбрать для верификации '+account.email);
  checkbox.onchange=()=>{if(checkbox.checked)verificationSelection.add(account.id);else verificationSelection.delete(account.id);renderVerification();};
  const identity=document.createElement('div'),link=cellLink(account.email,()=>openAccount(account));link.className='email-link';
  const provider=document.createElement('small');provider.textContent=isGoogle(account)?'Google':'Netmarble';identity.append(link,provider);wrap.append(checkbox,identity);email.append(wrap);row.append(email);
  const server=snapshot.catalogs[account.region]?.servers.find(s=>s.id===account.server_id);
  for(const value of [characterLabel(account),snapshot.creation_classes?.find(c=>c.key===account.create_class)?.label||account.create_class,account.region+' · '+(server?.name||account.server_id||'Не выбран')]){
   const cell=document.createElement('td');cell.append(cellLink(value,()=>openAccount(account,'character')));row.append(cell);
  }
  const reported=document.createElement('td');reported.append(cellLink(deviceType(account),()=>openAccount(account,'device')));row.append(reported);
  const templateCell=document.createElement('td'),template=(snapshot.device_templates||[]).find(t=>t.id===account.device_template_id);
  if(template){const box=document.createElement('div');box.className='template-cell';const badge=document.createElement('span');badge.className='slot-badge';badge.textContent=template.members.length+'/2';box.append(cellLink(template.name,()=>openTemplate(template.id)),badge);templateCell.append(box);}
  else templateCell.append(cellLink('Назначить',()=>openAccount(account,'device')));
  row.append(templateCell);
  const name=document.createElement('td');name.append(cellLink(account.device_name||'Не задано',()=>template?openTemplate(template.id):openAccount(account,'device'),'Имя для следующей регистрации устройства'));row.append(name);
  const state=document.createElement('td'),status=accountStatus(account),pill=cellLink(status.text,()=>openAccount(account,'session'));pill.className='status-pill '+status.kind;state.append(pill);row.append(state);
  const actions=document.createElement('td'),settings=cellLink('···',()=>openAccount(account),'Настройки аккаунта');settings.className='row-settings';actions.append(settings);row.append(actions);body.append(row);
 }
 el('account-count').textContent=snapshot.accounts.length;
 el('device-count').textContent=(snapshot.device_templates||[]).length;
 el('online-count').textContent=Object.values(snapshot.jobs).filter(j=>j.running).length;
 renderVerification();renderAccountSecrets();renderDeviceList();
}
function renderAccountSecrets(){
 const box=el('account-secrets');box.replaceChildren();const account=current();if(!account)return;
 box.append(passwordCell(account,'mail'),passwordCell(account,'netmarble'));
}
window.addEventListener('blur',()=>{shownPasswords.clear();renderAccountSecrets();el('template-show-keys').checked=false;maskTemplateKeys();});

el('copy-roster').onclick=async()=>{
 const button=el('copy-roster'),status=el('copy-roster-status');button.disabled=true;status.textContent='Подготовка экспорта…';
 try{
  const rows=[['№','Почта','Пароль почты','Пароль Netmarble','Ник персонажа','Класс','Сервер','Устройство','Шаблон устройства','Имя при регистрации','Статус']];
  for(const account of rosterAccounts()){
   const passwords=[];
   for(const [kind,saved] of [['mail',account.mail_password_saved],['netmarble',account.password_saved]])passwords.push(saved?(await api('/api/reveal',{id:account.id,kind})).password:'—');
   const server=snapshot.catalogs[account.region]?.servers.find(s=>s.id===account.server_id)?.name||account.server_id||'Не выбран';
   rows.push([accountNumber(account),account.email,...passwords,characterLabel(account),snapshot.creation_classes?.find(c=>c.key===account.create_class)?.label||account.create_class,account.region+' · '+server,deviceType(account),account.device_template_name||'—',account.device_name||'—',accountStatus(account).text]);
  }
  await navigator.clipboard.writeText(rows.map(row=>row.map(value=>{value=String(value);return /[\t\r\n"]/.test(value)?'"'+value.replace(/"/g,'""')+'"':value;}).join('\t')).join('\r\n'));
  status.textContent='Вся таблица с сохранёнными паролями скопирована.';
 }catch(error){status.textContent='Не удалось скопировать таблицу. Частичный экспорт не выполнен.';}
 finally{button.disabled=false;}
};

function renderReadiness(){
 const box=el('readiness'),plan=snapshot.readiness?.[selected];box.replaceChildren();
 if(isGoogle(current())){box.textContent='Google: для верификации выберите флажок в таблице. Вход и код из Gmail вводятся вручную; дальнейшие этапы продолжаются автоматически.';return;}
 if(!plan){box.textContent='Сохраните аккаунт, чтобы увидеть этапы подготовки.';return;}
 const title=document.createElement('strong');title.textContent='Подготовка по сохранённым данным';box.append(title);
 const list=document.createElement('ul');
 for(const step of plan.steps){const row=document.createElement('li');row.textContent=(step.observed?'✓ ':'○ ')+step.text;list.append(row);}
 const route=document.createElement('p');route.textContent=plan.route_text;
 const next=document.createElement('p');next.textContent=plan.next_step;
 const limits=document.createElement('small');limits.textContent='Показаны сохранённые наблюдения. Доступность серверов и совместимость текущей сборки проверяются отдельно. Изменения формы учитываются после сохранения.';
 box.append(list,route,next,limits);
}
function render(){renderReadiness();renderRoster();const job=snapshot.jobs[selected],status=job?.status||'stopped';el('badge').className='badge '+status;el('badge').textContent=labels[status]||status;el('message').textContent=job?.message||'Сохраните настройки и выберите действие';el('stage').textContent=job?.running?(job.manual_sign_in&&job.stage==='nid_browser'?'Введите логин и пароль в отдельном окне Netmarble':(stages[job.stage]||job.stage)):'';el('stop').disabled=!job?.running;el('start-all').disabled=runnableAccounts().length<2||Object.values(snapshot.jobs).some(j=>j.running);for(const node of el('settings').elements)node.disabled=!!job?.running;el('password').disabled=!!job?.running;for(const id of ['start','servers','characters'])el(id).disabled=!selected||current()?.enabled===false||!!job?.running;el('prepare-sdk').disabled=!selected||current()?.enabled===false||!!snapshot.jobs[selected]?.running||current()?.registration_status==='sdk_created'||current()?.character_index!==null||current()?.character_key!==null;el('create').disabled=!selected||current()?.enabled===false||!!snapshot.jobs[selected]?.running||current()?.create_class!=='Gunner'||!current()?.server_id||current()?.character_index!==null;const registration=current()?.registration_status||'unknown';el('registration-state').textContent=({unknown:'Регистрация не проверялась',in_progress:'Регистрация выполняется',unconfirmed:'Предыдущая попытка не подтверждена. Проверьте окно или попробуйте обычный вход; автоматического повтора нет.',registered:'Регистрация Netmarble подтверждена',sdk_created:'Игровой профиль SDK создан. Можно перейти к выбору сервера и персонажа.',nid_verified:'Ранее вход Netmarble был подтверждён. Результат текущей попытки показан ниже, в состоянии сессии.',email_in_use:'Netmarble: почта уже используется. Повторная регистрация не нужна; вход ещё не проверен.'})[registration];el('register').disabled=!selected||current()?.enabled===false||!!job?.running||(!current()?.mail_password_saved&&!el('manual-mail-code').checked)||!el('terms').checked||registration==='registered'||registration==='in_progress'||registration==='email_in_use'||registration==='nid_verified'||registration==='sdk_created';el('code-entry').hidden=!(job?.running&&job.manual_mail_code&&job.stage==='registration_code'&&!job.code_sent);renderAvailability();renderProvider();renderTemplateSelection();renderAccountSecrets();}
async function refresh(){const wasRunning=snapshot.jobs[selected]?.running;const catalogStamp=snapshot.catalogs[el('region').value]?.observed_utc;snapshot=await api('/api/state');if(initial){initial=false;edit(snapshot.accounts[0]);}else{if(catalogStamp!==snapshot.catalogs[el('region').value]?.observed_utc)servers(el('server').value);if(wasRunning&&!snapshot.jobs[selected]?.running){el('nickname').value=current()?.create_nickname||'';servers(el('server').value);characters(el('character').value===''?null:Number(el('character').value));}render();}}
el('generate-nickname').onclick=async()=>{try{const data=await api('/api/nickname',{});el('nickname').value=data.nickname;notice('Новый ник в форме. Нажмите «Сохранить настройки», чтобы использовать его.');}catch(error){notice(error.message);}};
el('terms').onchange=()=>render();
el('manual-mail-code').onchange=()=>render();
el('send-code').onclick=async()=>{try{const value=el('registration-code').value;el('registration-code').value='';await api('/api/registration-code',{id:selected,code:value});notice('Код передан в форму регистрации.');await refresh();}catch(error){notice(error.message);}};
el('new').onclick=()=>openAccount(null);
el('region').onchange=()=>{servers(null);characters(null);restoreCharacterConnection();};
el('server').onchange=()=>{characters(null);restoreCharacterConnection();};
el('character').onchange=()=>restoreCharacterConnection();
el('settings').onsubmit=async event=>{event.preventDefault();try{const assignment={enabled:el('enabled').checked,label:el('label').value,device_profile:accountDevice.device_profile,device_settings:accountDevice.device_settings,socks_port:el('socks-port').value?Number(el('socks-port').value):null,region:el('region').value,server_id:el('server').value?Number(el('server').value):null,character_index:el('character').value===''?null:Number(el('character').value),character_key:el('character').selectedOptions[0]?.dataset.key||null,create_nickname:el('nickname').value,create_class:el('create-class').value,create_random_nickname:el('random-nickname').checked,auth_flow:el('auth-flow').value,login_provider:el('login-provider').value,device_template_id:el('account-template').value||null,device_name:accountDevice.device_name||'',device_type:el('account-device-type').value};const result=await api('/api/save',{email:el('email').value,password:el('password').value,mail_password:el('mail-password').value,assignment});await refresh();edit(snapshot.accounts.find(a=>a.id===result.id));notice('Настройки сохранены. Пароль скрыт.');}catch(error){notice(error.message);}};
async function job(operation){try{if(!selected)return;activateTab('session');await api('/api/job',{id:selected,operation,...(operation==='register'?{accept_required_terms:el('terms').checked,manual_mail_code:el('manual-mail-code').checked}:operation==='stop'?{}:{manual_sign_in:el('manual-sign-in').checked,...(operation==='prepare-sdk'?{terms_country:el('sdk-country').value,terms_locale:el('sdk-locale').value,basic_terms_mode:el('sdk-terms-mode').value}:{})})});if(operation==='register')el('terms').checked=false;else if(operation!=='stop')el('manual-sign-in').checked=false;await refresh();notice(operation==='stop'?'Бот остановлен.':'Операция запущена. Для входа может открыться отдельное окно Netmarble.');}catch(error){notice(error.message);}}
for(const operation of ['start','stop','servers','characters','register','create','prepare-sdk'])el(operation).onclick=()=>job(operation);
el('start-all').onclick=async()=>{try{for(const account of runnableAccounts().slice(0,2))await api('/api/job',{id:account.id,operation:'start'});await refresh();notice('Два независимых запуска начаты.');}catch(error){notice(error.message);}};

const deviceFields=[
 ['device_key','SDK deviceKey','identity'],['nm_device_key','SDK nmDeviceKey','identity'],['nid_device_key','NID deviceKey','identity'],
 ['vendor','CPU vendor · до 12 ASCII','cpu'],['brand','CPU brand · до 48 ASCII','cpu'],
 ['major','Windows major','windows'],['minor','Windows minor','windows'],['build','Windows build','windows'],['product_type','Windows product type','windows'],['suite_mask','Windows suite mask','windows'],
 ['I_DeviceModel','Модель устройства','metadata'],['I_DeviceOSVersion','Версия ОС · metadata, автоматически из Windows при заполнении','metadata'],['I_NMCPU','CPU · metadata, автоматически из CPU при заполнении','metadata'],['I_NMRAM','Оперативная память · metadata','metadata'],['I_NMVGA','Видеокарта · metadata','metadata'],['I_TimeZone','Часовой пояс · metadata','metadata'],['I_LanguageCD','Язык · metadata','metadata']];
function editConnection(account){
 accountDevice={device_profile:account?.device_profile||'current-pc',device_settings:account?.device_settings||{},device_name:account?.device_name||''};
 el('account-device-type').value=account?deviceType(account):'Бот';
 el('socks-port').value=account?.socks_port??'';
 el('account-template').value=account?.device_template_id||'';
}
function restoreCharacterConnection(){
 if(current()?.device_template_id)return;
 const key=el('character').selectedOptions[0]?.dataset.key;
 const target=[selected,el('region').value,el('server').value,key].join('|');
 const saved=key?snapshot.character_connections?.[target]:null;
 if(saved){accountDevice={...accountDevice,...saved};el('socks-port').value=saved.socks_port??'';}
}
function activateTab(name){
 for(const key of ['account','character','device','session']){el('panel-'+key).hidden=key!==name;el('tab-'+key).className=key===name?'selected':'';}
}
function openDialog(id){if(!el(id).open)el(id).showModal();}
function closeDialog(id){el(id).close();shownPasswords.clear();renderAccountSecrets();maskTemplateKeys();}
function openAccount(account,tab='account'){
 edit(account);activateTab(tab);el('notice').textContent='';openDialog('account-dialog');
}
for(const key of ['account','character','device','session'])el('tab-'+key).onclick=()=>activateTab(key);
for(const button of document.querySelectorAll('[data-close]'))button.onclick=()=>closeDialog(button.dataset.close);
el('account-dialog').addEventListener('close',()=>{shownPasswords.clear();renderAccountSecrets();el('password').value='';el('mail-password').value='';});
el('template-dialog').addEventListener('close',()=>{templateRequest++;el('template-show-keys').checked=false;maskTemplateKeys();});
el('search').oninput=()=>renderRoster();el('roster-filter').onchange=()=>renderRoster();
function renderTemplateSelection(value){
 const select=el('account-template'),chosen=value??select.value;
 select.replaceChildren(option('','Не назначен · прежняя привязка'));
 for(const template of snapshot.device_templates||[]){
  const item=option(template.id,template.name+' · '+template.members.length+'/2');
  item.disabled=template.members.length>=2&&!template.members.some(a=>a.id===selected);select.append(item);
 }
 select.value=chosen||'';
 const template=(snapshot.device_templates||[]).find(t=>t.id===select.value);
 const info=el('assigned-template-info');info.replaceChildren();
 if(template){
  const title=document.createElement('strong');title.textContent=template.name;
  const details=document.createElement('div');details.textContent='Имя регистрации: '+template.device_name+' · занято '+template.members.length+' из 2 мест';
  const hardware=document.createElement('div');hardware.textContent=[template.settings.cpu?.brand?.trim(),template.settings.metadata?.I_NMRAM,template.settings.metadata?.I_NMVGA].filter(Boolean).join(' · ');
  info.append(title,details,hardware);
 }else info.textContent='Сохраните назначение шаблона. Прежние индивидуальные настройки остаются до назначения.';
 el('inspect-assigned-template').disabled=!template;
}
el('account-template').onchange=()=>renderTemplateSelection();
el('inspect-assigned-template').onclick=()=>openTemplate(el('account-template').value);
el('new-account-template').onclick=()=>newTemplate();
let templateId=null,templateEditing=false,templateRevision=null,templateRequest=0;
const templateDisplayOrder=['I_DeviceModel','vendor','brand','I_NMRAM','I_NMVGA','I_DeviceOSVersion','I_NMCPU','I_TimeZone','I_LanguageCD','major','minor','build','product_type','suite_mask','device_key','nm_device_key','nid_device_key'];
for(const [key,label,group] of [...deviceFields].sort((a,b)=>templateDisplayOrder.indexOf(a[0])-templateDisplayOrder.indexOf(b[0]))){
 const wrap=document.createElement('label'),input=document.createElement('input');wrap.textContent=label;input.id='template-'+key;
 input.maxLength=group==='identity'?128:group==='cpu'?(key==='vendor'?12:48):256;
 if(group==='identity')input.type='password';
 if(group==='windows'){input.type='number';input.min='0';}
 if(group==='identity'||key==='brand'||key==='I_DeviceModel'||key==='I_NMVGA')wrap.className='wide';
 wrap.append(input);el('template-fields').append(wrap);
}
function maskTemplateKeys(){for(const [key,,group] of deviceFields)if(group==='identity')el('template-'+key).type=el('template-show-keys').checked?'text':'password';}
el('template-show-keys').onchange=maskTemplateKeys;
function templateBusy(){
 const template=(snapshot.device_templates||[]).find(t=>t.id===templateId);
 return !!template?.members.some(a=>snapshot.jobs[a.id]?.running);
}
function templateMode(editing){
 templateEditing=editing;
 el('template-name').readOnly=!editing;el('template-device-name').readOnly=!editing;
 for(const [key] of deviceFields)el('template-'+key).readOnly=!editing;
 el('template-edit').hidden=editing;el('template-edit').disabled=templateBusy();
 el('template-save').hidden=!editing;el('template-save').disabled=templateBusy();el('template-regenerate').hidden=!editing;
}
function fillTemplate(settings,display={}){
 for(const [key,,group] of deviceFields){el('template-'+key).value=settings[group]?.[key]??'';el('template-'+key).placeholder=display[key]||'';}
 el('template-show-keys').checked=false;maskTemplateKeys();
}
function openTemplate(identifier){
 const template=(snapshot.device_templates||[]).find(t=>t.id===identifier);if(!template)return;
 templateRequest++;templateId=identifier;templateRevision=template.revision;
 el('template-heading').textContent=template.name;el('template-name').value=template.name;el('template-device-name').value=template.device_name;
 el('template-source').textContent=template.source+' Общие параметры для двух мест; изменение имени действует при следующей регистрации.';el('template-error').textContent='';fillTemplate(template.settings,template.display_metadata);
 const members=el('template-members');members.replaceChildren();
 for(const member of template.members){const text=document.createElement('span');text.textContent=member.email+(member.character_name?' · '+member.character_name:'');members.append(text);}
 if(!template.members.length)members.textContent='Свободно · 0 из 2';
 templateMode(false);openDialog('template-dialog');
}
async function loadPc(){
 const value=await api('/api/current-pc',{});if(!value.device_settings||!Array.isArray(value.unknown))throw Error('Нет данных этого ПК.');
 currentPc=value;renderPcValues();return value;
}
async function newTemplate(){
 const request=++templateRequest;templateId=null;templateRevision=null;
 el('template-heading').textContent='Новый шаблон';el('template-name').value='';el('template-device-name').value='';
 el('template-error').textContent='Чтение основы и создание ключей…';el('template-members').replaceChildren();templateMode(true);openDialog('template-dialog');
 try{
  if(!currentPc)await loadPc();
  const generated=await api('/api/device-identity',{});if(request!==templateRequest||!el('template-dialog').open)return;
  const settings=structuredClone(currentPc.device_settings);settings.identity=generated.identity;
  settings.metadata??={};settings.metadata.I_DeviceModel||='Desktop PC';
  let number=1;while((snapshot.device_templates||[]).some(t=>t.name==='VAMPIR-PC-'+String(number).padStart(2,'0')))number++;
  const name='VAMPIR-PC-'+String(number).padStart(2,'0');el('template-name').value=name;el('template-device-name').value=generated.device_name;
  fillTemplate(settings);el('template-source').textContent='На основе характеристик этого ПК. Desktop PC — общее описание; модель производителя может быть неизвестна.';el('template-error').textContent='';
 }catch(error){el('template-error').textContent=error.message;}
}
function readTemplate(){
 const settings={};for(const [key,,group] of deviceFields){const value=el('template-'+key).value;if(value!==''){settings[group]??={};settings[group][key]=group==='windows'?Number(value):value;}}
 return settings;
}
el('template-edit').onclick=()=>templateMode(true);
el('template-regenerate').onclick=async()=>{
 try{const result=await api('/api/device-identity',{});for(const [key,value] of Object.entries(result.identity))el('template-'+key).value=value;}
 catch(error){el('template-error').textContent=error.message;}
};
el('template-form').onsubmit=async event=>{
 event.preventDefault();if(!templateEditing)return;
 el('template-save').disabled=true;
 try{
  const result=await api('/api/device-template',{id:templateId,name:el('template-name').value,device_name:el('template-device-name').value,settings:readTemplate(),revision:templateRevision});
  await refresh();if(!templateId&&el('account-dialog').open)renderTemplateSelection(result.id);openTemplate(result.id);
  notice('Шаблон сохранён. Его параметры общие для назначенных аккаунтов. Изменение ключей потребует новой верификации.');
 }catch(error){el('template-error').textContent=error.message;}
 finally{el('template-save').disabled=templateBusy();}
};
function renderDeviceList(){
 const box=el('device-list');box.replaceChildren();
 for(const template of snapshot.device_templates||[]){
  const card=document.createElement('div');card.className='device-card';const content=document.createElement('div'),name=document.createElement('strong');name.textContent=template.name;
  const detail=document.createElement('p');detail.textContent=template.device_name+' · '+template.members.length+'/2 · '+(template.settings.cpu?.brand?.trim()||'CPU не задан');
  const members=document.createElement('p');members.textContent=template.members.map(a=>a.character_name||a.email).join(' · ')||'Нет назначений';
  content.append(name,detail,members);const button=document.createElement('button');button.textContent='Просмотр';button.onclick=()=>openTemplate(template.id);card.append(content,button);box.append(card);
 }
 if(!box.children.length)box.textContent='Шаблоны пока не созданы.';
}
el('show-devices').onclick=()=>{renderDeviceList();openDialog('devices-dialog');};
el('new-template').onclick=newTemplate;el('new-template-from-pc').onclick=newTemplate;
el('generate-unassigned').onclick=async()=>{
 const button=el('generate-unassigned');button.disabled=true;
 try{const result=await api('/api/generate-devices',{});await refresh();notice('Создано шаблонов: '+result.created+'. Назначено аккаунтов: '+result.assigned+'.');}
 catch(error){notice(error.message);}
 finally{button.disabled=false;}
};
function renderPcValues(){
 if(!currentPc)return;
 el('current-pc-info').textContent=[currentPc.os_display,currentPc.source,currentPc.limits,...currentPc.unknown].filter(Boolean).join(' ');
 const box=el('pc-values');box.replaceChildren();
 for(const [label,value] of [['CPU',currentPc.device_settings.cpu?.brand?.trim()],['Модель устройства',currentPc.display_metadata.I_DeviceModel||'Не заполнена в прошивке'],['Оперативная память',currentPc.display_metadata.I_NMRAM],['Видеокарта',currentPc.display_metadata.I_NMVGA],['Версия для SDK',currentPc.display_metadata.I_DeviceOSVersion],['Часовой пояс',currentPc.display_metadata.I_TimeZone]]){
  const node=document.createElement('div');node.className='pc-value';const title=document.createElement('small'),text=document.createElement('span');title.textContent=label;text.textContent=value||'Не удалось прочитать';node.append(title,text);box.append(node);
 }
}
el('show-current-pc').onclick=async()=>{openDialog('pc-dialog');if(!currentPc)await el('refresh-current-pc').onclick();};
el('refresh-current-pc').onclick=async()=>{
 const button=el('refresh-current-pc');button.disabled=true;
 try{await loadPc();}catch(error){el('current-pc-info').textContent=error.message;}finally{button.disabled=false;}
};

setInterval(()=>refresh().catch(()=>notice('Панель потеряла связь с локальным процессом.')),2000);
refresh().then(()=>el('refresh-current-pc').onclick()).catch(error=>notice(error.message));
