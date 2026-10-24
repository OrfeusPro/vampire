/* Game resource based HUD; game commands are intentionally not simulated. */
(()=>{
  const byId=id=>document.getElementById(id),node=(tag,text)=>{const n=document.createElement(tag);if(text)n.textContent=text;return n;};
  const tools=byId('workspaceTools');const close=node('button','×');close.className='workspace-close';close.setAttribute('aria-label','Закрыть инструменты карты');tools.prepend(close);
  const toggleTools=()=>{tools.hidden=!tools.hidden;};close.onclick=toggleTools;
  const settings=node('div');settings.className='group';settings.append(node('h2','Отображение карты'));
  for(const row of [...document.querySelectorAll('main>section>.toggles')])settings.append(row);
  tools.append(settings);
  const notice=node('div');notice.className='hud-notice';notice.hidden=true;notice.setAttribute('role','status');document.body.append(notice);let timer;
  function message(text){clearTimeout(timer);notice.textContent=text;notice.hidden=false;timer=setTimeout(()=>notice.hidden=true,5000);}
  const top=node('div');top.className='hud-top';top.setAttribute('aria-label','Панель игры');
  const side=node('div');side.className='hud-side';side.setAttribute('aria-label','Панель карты');
  const bottom=node('div');bottom.className='hud-bottom';bottom.setAttribute('aria-label','Быстрый доступ');
  const menu=node('section');menu.className='hud-menu';menu.hidden=true;menu.setAttribute('aria-label','Главное меню игры');
  const menuClose=node('button','×');menuClose.className='hud-close';menuClose.setAttribute('aria-label','Закрыть меню');menuClose.onclick=()=>menu.hidden=true;
  menu.append(menuClose,node('h2','Меню'));const grid=node('div');grid.className='hud-menu-grid';menu.append(grid);
  const dialog=node('section');dialog.className='hud-dialog';dialog.hidden=true;dialog.setAttribute('role','dialog');dialog.setAttribute('aria-modal','true');
  const title=node('h2'),frame=node('iframe');const dialogClose=node('button','Закрыть ×');dialogClose.onclick=()=>{dialog.hidden=true;frame.removeAttribute('src');lastFocus?.focus();};dialog.append(dialogClose,title,frame);let lastFocus;
  function open(titleText,target){lastFocus=document.activeElement;title.textContent=titleText;frame.title=titleText;frame.src=target;dialog.hidden=false;menu.hidden=true;dialogClose.focus();}
  function button(label,action,image){const b=node('button');b.type='button';b.className='hud-button';b.setAttribute('aria-label',label);b.title=label;if(image){const img=node('img');img.src='../../'+image;img.alt='';b.append(img);}b.append(node('span',label));b.onclick=action;return b;}
  top.append(button('Инструменты',toggleTools),button('Меню',()=>{menu.hidden=!menu.hidden;}));
  side.append(button('Поиск',()=>{tools.hidden=false;byId('search').focus();}),button('Слои',()=>{tools.hidden=false;byId('layers').scrollIntoView({block:'center'});}),button('Персонаж',()=>{tools.hidden=false;settings.scrollIntoView({block:'center'});if(!byId('sessionLayer').checked)message('Включите показ сессии в панели. Подключение к игре выполняется отдельно.');else byId('sessionFocus').click();}));
  bottom.append(button('Вся карта',()=>byId('whole').click()),button('Навыки',()=>open('Навыки','skills.html')),button('Предметы',()=>open('Предметы','../loot/items.html')),button('Коллекции',()=>open('Коллекции','../collections/index.html')));
  const caption=node('div','Ресурсы интерфейса игры · локальная карта');caption.className='hud-caption';
  document.body.append(top,side,bottom,menu,dialog,caption);
  document.addEventListener('keydown',e=>{if(e.key==='Escape'){if(!dialog.hidden)dialogClose.click();else{menu.hidden=true;tools.hidden=true;}}});
  byId('canvas').addEventListener('pointerdown',()=>{menu.hidden=true;});
  fetch('game-ui-manifest.json',{cache:'no-cache'}).then(r=>{if(!r.ok)throw Error('Нет источников HUD');return r.json();}).then(async spec=>{
    const response=await fetch(spec.file,{cache:'no-cache'});if(!response.ok)throw Error('Не загружены ресурсы HUD');const bytes=await response.arrayBuffer();
    const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(v=>v.toString(16).padStart(2,'0')).join('');if(digest!==spec.sha256)throw Error('Изменились источники HUD');
    const proof=JSON.parse(new TextDecoder().decode(bytes));
    for(const item of proof.menu_buttons){const b=button(item.label,()=>{if(item.target)open(item.label,item.target);else if(item.control==='ButtonOptionSetting'){menu.hidden=true;tools.hidden=false;settings.scrollIntoView({block:'center'});}else message(item.label+': ресурс кнопки найден, данные сессии и игровая команда ещё не подключены.');},item.image.file);b.dataset.gameControl=item.control;grid.append(b);}
    for(const b of bottom.querySelectorAll('button')){const item=proof.menu_buttons.find(x=>x.label===b.textContent);if(item){const img=node('img');img.src='../../'+item.image.file;img.alt='';b.prepend(img);}}
    const info=node('button','Источники интерфейса');info.onclick=()=>open('Исходные компоненты и ограничения','game-ui-resources.json');info.style.marginTop='14px';menu.append(info);
  }).catch(error=>message(error.message));
})();
