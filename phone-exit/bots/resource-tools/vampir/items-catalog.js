'use strict';
(() => {
  const $=id=>document.getElementById(id),{json,node}=CatalogData,params=new URLSearchParams(location.search),books=location.pathname.endsWith('/books.html'),page=books?'books.html':'items.html';
  const alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'}),typeNames={Equipment:'Снаряжение',Etc:'Прочее',ItemBox:'Коробки',SkillBook:'Книги навыков',SkillCard:'Карты навыков',SkillAcquirePotion:'Зелья изучения навыков',CostumeArmor:'Облики',Vehicle:'Транспорт',Pet:'Питомцы',Sephira:'Sephira',Collection:'Коллекционные предметы',CombatPotion:'Боевые зелья',HpPotion:'Зелья HP',TombCard:'Карты Tomb'};
  let classData,items,index,entries=[],limit=Math.max(60,Math.min(6000,Number(params.get('limit'))||60));
  const name=item=>[...new Set((item.names_en||[]).map(n=>n.Name).filter(Boolean))].join(' / ')||'Предмет '+item.data.Id;
  function icon(parent,item,href){for(const image of item.icon?.images||[]){const a=node('a'),slot=node('span',undefined,'item-icon'),img=node('img');a.href=href;img.src='../../'+image.file;img.alt=name(item);img.loading='lazy';const bg=item.rarity?.background?.images||[];if(bg.length===1)slot.style.backgroundImage='url("../../'+bg[0].file+'")';slot.append(img);a.append(slot);parent.append(a);}}
  const query=()=>{const p=new URLSearchParams();if($('search').value.trim())p.set('q',$('search').value.trim());if(!books&&$('type').value!=='all')p.set('type',$('type').value);if($('rarity').value!=='all')p.set('rarity',$('rarity').value);if((books||$('type').value==='31')&&$('classFilter').value!=='all')p.set('class',$('classFilter').value);if(limit>60)p.set('limit',String(limit));return p;};
  function render(append=false){const q=$('search').value.trim().toLowerCase(),type=$('type').value,rarity=$('rarity').value;
    $('classLabel').hidden=!(books||type==='31');
    const rows=entries.filter(item=>CatalogClasses.matches(classData.books[item.data.Id],books||type==='31'?$('classFilter').value:'all')&&(books?item.type_name==='EItemType::SkillBook':type==='all'||item.data.Type===type)&&(rarity==='all'||item.data.Rarity===rarity)&&(item.data.Id+' '+name(item)+' '+(item.icon?.key||'')).toLowerCase().includes(q));
    const p=query();history.replaceState(null,'',page+(p.size?'?'+p:''));const start=append?$('grid').children.length:0;if(!append)$('grid').replaceChildren();$('count').textContent=rows.length+' предметов · показано '+Math.min(limit,rows.length);$('more').hidden=limit>=rows.length;
    if(!rows.length)$('grid').append(node('p','Ничего не найдено. Измените поиск или фильтры.','empty'));
    for(const item of rows.slice(start,limit)){const card=node('article',undefined,'catalog-card'),link=node('a',name(item)),h=node('h3'),target=new URLSearchParams(p);target.set('item',item.data.Id);link.href=page+'?'+target;icon(card,item,link.href);h.append(link);card.append(h,node('p',item.rarity?.label||'Редкость не указана','item-rarity'),node('p','ID '+item.data.Id,'muted'));if(item.type_name==='EItemType::SkillBook')card.append(node('p','Класс: '+CatalogClasses.label(classData.books[item.data.Id],classData.classes),'muted'));$('grid').append(card);}
    CatalogData.syncListLinks($('grid'),limit);
  }
  $('search').oninput=$('type').onchange=$('rarity').onchange=$('classFilter').onchange=()=>{limit=60;render();};$('more').onclick=()=>{limit+=60;render(true);};
  (async()=>{
    if(books){$('pageTitle').textContent='Книги навыков';$('subtitle').textContent='Книги изучения: целевые навыки, свойства и источники';$('back').textContent='Все книги';$('typeLabel').hidden=true;document.title='Vampir · книги навыков';}
    classData=await CatalogData.classData();CatalogData.classOptions($('classFilter'),classData);if([...$('classFilter').options].some(o=>o.value===params.get('class')))$('classFilter').value=params.get('class');
    index=await json('index.json');items=await json(index.files.items.file,index.files.items.sha256);entries=Object.values(items).sort((a,b)=>ItemRarity.compare(a,b)||alphabet.compare(name(a),name(b))||alphabet.compare(a.data.Id,b.data.Id));
    const types=new Map(),rarities=new Map();for(const item of entries){types.set(item.data.Type,typeNames[item.type_name?.split('::').pop()]||item.type_name?.split('::').pop()||'Тип '+item.data.Type);if(!books||item.type_name==='EItemType::SkillBook')rarities.set(item.data.Rarity,item.rarity?.label||'Редкость '+item.data.Rarity);}
    for(const [id,label]of [...types].sort((a,b)=>alphabet.compare(a[1],b[1]))){const o=node('option',label);o.value=id;$('type').append(o);}
    for(const [id,label]of rarities){const o=node('option',label);o.value=id;$('rarity').append(o);}
    $('search').value=params.get('q')||'';for(const key of ['type','rarity'])if([...$(key).options].some(o=>o.value===params.get(key)))$(key).value=params.get(key);
    const id=params.get('item');if(id){
      if(!items[id])throw Error('Предмет '+id+' не найден в данных клиента');
      $('listing').hidden=true;$('detail').hidden=false;const item=items[id],back=new URLSearchParams(params);back.delete('item');$('back').href=page+(back.size?'?'+back:'');$('crumb').textContent=name(item);document.title=name(item)+' · Vampir';
      const card=$('product');icon(card,item,'../../'+(item.icon?.images?.[0]?.file||''));card.append(node('h3',name(item)),node('p',item.rarity?.label||'Редкость не указана','item-rarity'),node('p','ID '+id));
      const sources=node('a','Показать источники на карте','button');sources.href='../atlas/index.html?item='+encodeURIComponent(id);card.append(sources);
      if(item.type_name==='EItemType::SkillBook')card.append(node('p','Класс: '+CatalogClasses.label(classData.books[id],classData.classes),'muted'));
      await ItemDetails.render(card,id,item,index.files['item-details'],items);
      if(index.files['item-origins']){
        const spec=index.files['item-origins'],origins=(await json(spec.file,spec.sha256))[id]||[],ids=[...new Set(origins.map(row=>row.npc_id))],panel=node('details');
        panel.append(node('summary','Личные записи наград NPC · '+ids.length+' NPC · '+origins.length+' цепочек'));
        if(!ids.length)panel.append(node('p','Личные записи NPC для предмета не найдены. Это не доказывает отсутствие дропа в игре.','muted'));
        const npcs=new Map(index.npcs.map(n=>[n.id,n]));
        for(const npcId of ids){const n=npcs.get(npcId),line=node('p'),a=node('a',(n?.name||'NPC')+' · '+npcId);a.href='../atlas/monsters.html?npc='+encodeURIComponent(npcId);line.append(a);panel.append(line);}
        const raw=node('details');raw.append(node('summary','Исходные цепочки'),node('pre',JSON.stringify(origins,null,2)));panel.append(raw);card.append(panel);
      }
    }else {render();CatalogData.restoreList($('grid'));}
    for(const id of ['search','type','rarity','classFilter'])$(id).disabled=false;
    CatalogData.autoMore($('more'),()=>{limit+=60;render(true);});
  })().catch(error=>{$('error').textContent='Не удалось загрузить каталог: '+error.message;});
})();
