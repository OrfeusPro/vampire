'use strict';
(() => {
  const $=id=>document.getElementById(id),{json,node}=CatalogData,params=new URLSearchParams(location.search),books=location.pathname.endsWith('/books.html'),page=books?'books.html':'items.html';
  const alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'}),typeNames={Equipment:'Снаряжение',Etc:'Прочее',ItemBox:'Коробки',SkillBook:'Книги навыков',SkillCard:'Карты навыков',SkillAcquirePotion:'Зелья изучения навыков',CostumeArmor:'Облики',Vehicle:'Транспорт',Pet:'Питомцы',Sephira:'Sephira',Collection:'Коллекционные предметы',CombatPotion:'Боевые зелья',HpPotion:'Зелья HP',TombCard:'Карты Tomb'};
  let classData,items,index,originsByItem={},npcById=new Map(),entries=[],limit=Math.max(60,Math.min(6000,Number(params.get('limit'))||60));
  const name=item=>[...new Set((item.names_en||[]).map(n=>n.Name).filter(Boolean))].join(' / ')||'Предмет '+item.data.Id;
  function icon(parent,item,href){for(const image of item.icon?.images||[]){const a=node('a'),slot=node('span',undefined,'item-icon'),img=node('img');a.href=href;img.src='../../'+image.file;img.alt=name(item);img.loading='lazy';const bg=item.rarity?.background?.images||[];if(bg.length===1)slot.style.backgroundImage='url("../../'+bg[0].file+'")';slot.append(img);a.append(slot);parent.append(a);}}
  function showSources(parent,id,compact=false){
    const origins=originsByItem[id]||[],ids=ItemsCatalogModel.sourceNpcIds(origins),section=node('div',undefined,'book-sources');
    const heading=node('div',undefined,'source-heading');heading.append(node(compact?'h4':'h3','В наградах монстров'),node('span',String(ids.length),'source-count'));section.append(heading);
    if(!ids.length)section.append(node('p','Личные записи наград NPC не найдены. Другие источники могут быть указаны ниже.','muted'));
    const list=node('div',undefined,'source-npc-grid');section.append(list);
    function append(npcId,target){const n=npcById.get(npcId),link=node('a',undefined,'source-npc');link.href='../atlas/monsters.html?npc='+encodeURIComponent(npcId);link.append(node('span','Ур. '+(n?.level||'—'),'source-level'),node('span',n?.name||'NPC '+npcId));link.title='NPC '+npcId+(n?.world_ids?.length?' · миры '+n.world_ids.join(', '):' · размещения не найдены');target.append(link);}
    for(const npcId of ids)append(npcId,list);
    if(ids.length){const map=node('a','На карте ↗','source-map');map.href=ItemsCatalogModel.sourceMapUrl(id);heading.append(map);}
    if(!compact){const raw=node('details',undefined,'source-data');raw.append(node('summary','Данные и условия · '+origins.length+' цепочек'),node('p','Записи NpcReward клиента; условия серверной выдачи и шанс в процентах не подтверждены.','muted'),node('pre',JSON.stringify(origins,null,2)));section.append(raw);}
    parent.append(section);return section;
  }
  const query=()=>{const p=new URLSearchParams();if($('search').value.trim())p.set('q',$('search').value.trim());if(!books&&$('type').value!=='all')p.set('type',$('type').value);if($('rarity').value!=='all')p.set('rarity',$('rarity').value);if((books||$('type').value==='31')&&$('classFilter').value!=='all')p.set('class',$('classFilter').value);for(const key of ['effect','passive','limits'])if($(key).value!=='all')p.set(key,$(key).value);if(limit>60)p.set('limit',String(limit));return p;};
  function render(append=false){const q=$('search').value.trim().toLowerCase(),type=$('type').value,rarity=$('rarity').value;
    $('classLabel').hidden=!(books||type==='31');
    const rows=entries.filter(item=>ItemsCatalogModel.matches(item,{effect:$('effect').value,passive:$('passive').value,limits:$('limits').value})&&CatalogClasses.matches(classData.books[item.data.Id],books||type==='31'?$('classFilter').value:'all')&&(books?item.type_name==='EItemType::SkillBook':type==='all'||item.data.Type===type)&&(rarity==='all'||item.data.Rarity===rarity)&&(item.data.Id+' '+name(item)+' '+(item.icon?.key||'')).toLowerCase().includes(q));
    const p=query();history.replaceState(null,'',page+(p.size?'?'+p:''));const start=append?$('grid').children.length:0;if(!append)$('grid').replaceChildren();$('count').textContent=rows.length+' предметов · показано '+Math.min(limit,rows.length);$('more').hidden=limit>=rows.length;
    if(!rows.length)$('grid').append(node('p','Ничего не найдено. Измените поиск или фильтры.','empty'));
    for(const item of rows.slice(start,limit)){
      const card=node('article',undefined,'catalog-card'+(books?' book-list-card':'')),target=new URLSearchParams(p);target.set('item',item.data.Id);
      const href=page+'?'+target,visual=books?node('div',undefined,'book-list-visual'):card,body=books?node('div',undefined,'book-list-body'):card;
      icon(visual,item,href);
      const h=node('h3'),link=node('a',name(item));link.href=href;h.append(link);
      body.append(h);
      if(books){
        const meta=node('div',undefined,'book-list-meta');meta.append(node('span',item.rarity?.label||'Редкость не указана','item-rarity'),node('span','ID '+item.data.Id,'book-list-id'));body.append(meta);
        body.append(node('p','Класс: '+CatalogClasses.label(classData.books[item.data.Id],classData.classes),'book-list-class'));
        const effect=ItemsCatalogModel.effectLabel(item.data.EffectType,index.item_effect_types);if(effect!=='Тип не указан')body.append(node('p',effect,'book-list-effect muted'));
      }else{
        body.append(node('p',item.rarity?.label||'Редкость не указана','item-rarity'),node('p','ID '+item.data.Id,'muted'));
        if(item.type_name==='EItemType::SkillBook')body.append(node('p','Класс: '+CatalogClasses.label(classData.books[item.data.Id],classData.classes),'muted'));
        body.append(node('p',ItemsCatalogModel.effectLabel(item.data.EffectType,index.item_effect_types),'muted'));
        const flags=ItemsCatalogModel.flags(item);if(flags.passive)body.append(node('p','Группа пассива: '+item.data.PassiveSkillGroupId,'muted'));if(flags.limits)body.append(node('p','Указаны ограничения предмета','muted'));
      }
      if(books)card.append(visual,body);$('grid').append(card);
    }
    for(const card of [...$('grid').children].slice(start)){const href=card.querySelector('h3 a')?.href;if(!href)continue;const id=new URL(href).searchParams.get('item');if(items[id]?.type_name==='EItemType::SkillBook')showSources(card,id,true);}
    CatalogData.syncListLinks($('grid'),limit);
  }
  $('search').oninput=$('type').onchange=$('rarity').onchange=$('classFilter').onchange=$('effect').onchange=$('passive').onchange=$('limits').onchange=()=>{limit=60;render();};$('more').onclick=()=>{limit+=60;render(true);};
  (async()=>{
    if(books){$('pageTitle').textContent='Книги навыков';$('subtitle').textContent='Книги изучения: целевые навыки, свойства и источники';$('back').textContent='Все книги';$('typeLabel').hidden=true;document.title='Vampir · книги навыков';}
    classData=await CatalogData.classData();CatalogData.classOptions($('classFilter'),classData);if([...$('classFilter').options].some(o=>o.value===params.get('class')))$('classFilter').value=params.get('class');
    index=await json('index.json');items=await json(index.files.items.file,index.files.items.sha256);entries=Object.values(items).sort((a,b)=>ItemRarity.compare(a,b)||alphabet.compare(name(a),name(b))||alphabet.compare(a.data.Id,b.data.Id));
    npcById=new Map(index.npcs.map(n=>[String(n.id),n]));
    if(index.files['item-origins']){const spec=index.files['item-origins'];originsByItem=await json(spec.file,spec.sha256);}
    const types=new Map(),rarities=new Map();for(const item of entries){types.set(item.data.Type,typeNames[item.type_name?.split('::').pop()]||item.type_name?.split('::').pop()||'Тип '+item.data.Type);if(!books||item.type_name==='EItemType::SkillBook')rarities.set(item.data.Rarity,item.rarity?.label||'Редкость '+item.data.Rarity);}
    for(const [id,label]of [...types].sort((a,b)=>alphabet.compare(a[1],b[1]))){const o=node('option',label);o.value=id;$('type').append(o);}
    for(const [id,label]of rarities){const o=node('option',label);o.value=id;$('rarity').append(o);}
    const effects=[...new Set(entries.filter(item=>!books||item.type_name==='EItemType::SkillBook').map(item=>item.data.EffectType))];for(const value of effects.sort((a,b)=>alphabet.compare(ItemsCatalogModel.effectLabel(a,index.item_effect_types),ItemsCatalogModel.effectLabel(b,index.item_effect_types)))){const o=node('option',ItemsCatalogModel.effectLabel(value,index.item_effect_types));o.value=value;$('effect').append(o);}
    $('search').value=params.get('q')||'';for(const key of ['type','rarity','effect','passive','limits'])if([...$(key).options].some(o=>o.value===params.get(key)))$(key).value=params.get(key);
    const id=params.get('item');if(id){
      if(!items[id])throw Error('Предмет '+id+' не найден в данных клиента');
      $('listing').hidden=true;$('detail').hidden=false;const item=items[id],back=new URLSearchParams(params);back.delete('item');$('back').href=page+(back.size?'?'+back:'');$('crumb').textContent=name(item);document.title=name(item)+' · Vampir';
      const card=$('product');icon(card,item,'../../'+(item.icon?.images?.[0]?.file||''));card.append(node('h3',name(item)),node('p',item.rarity?.label||'Редкость не указана','item-rarity'),node('p','ID '+id));
      if(!ItemsCatalogModel.sourceNpcIds(originsByItem[id]).length){const sources=node('a','Показать записи областей на карте','button');sources.href='../atlas/index.html?item='+encodeURIComponent(id)+'&rewardScope=area';if(item.in_area_candidate)card.append(sources);}
      if(item.type_name==='EItemType::SkillBook')card.append(node('p','Класс: '+CatalogClasses.label(classData.books[id],classData.classes),'muted'));
      await ItemDetails.render(card,id,item,index.files['item-details'],items);
      const sourceBlock=showSources(card,id),panels=card.querySelector('.product-panels');
      if(panels)panels.after(sourceBlock);
      const craftBlock=card.querySelector('.craft-origins');if(craftBlock)sourceBlock.after(craftBlock);
    }else {render();CatalogData.restoreList($('grid'));}
    for(const id of ['search','type','rarity','classFilter','effect','passive','limits'])$(id).disabled=false;
    CatalogData.autoMore($('more'),()=>{limit+=60;render(true);});
  })().catch(error=>{$('error').textContent='Не удалось загрузить каталог: '+error.message;});
})();
