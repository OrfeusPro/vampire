'use strict';
(()=>{
  const $=id=>document.getElementById(id),{json,node}=CatalogData,model=CollectionsModel,params=new URLSearchParams(location.search);
  let data,rows=[],shown=0,limit=Math.max(60,Math.min(4200,Number(params.get('limit'))||60));
  const query=()=>{const p=new URLSearchParams();if($('search').value.trim())p.set('q',$('search').value.trim());for(const k of ['tab','rarity','bonus'])if($(k).value!=='all')p.set(k,$(k).value);if($('sort').value!=='quality')p.set('sort',$('sort').value);if(limit>60)p.set('limit',String(limit));return p;};
  const tabs=()=>new Map(data.tabs.map(t=>[t.id,t.name]));
  function itemLine(member,compact=false){
    const item=data.items[member.item_id],line=node(item?'a':'div',undefined,'collection-item'+(compact?' collection-tile':'')),slot=node('span',undefined,'item-icon');
    if(item)line.href='../loot/items.html?item='+encodeURIComponent(item.id);
    const image=item?.icon?.images?.length===1?item.icon.images[0]:null,bg=item?.rarity?.background?.images;
    if(bg?.length===1)slot.style.backgroundImage='url("../../'+bg[0].file+'")';
    if(image){const img=node('img');img.src='../../'+image.file;img.alt='';img.loading='lazy';slot.append(img);}else slot.textContent='?';
    const label=item?.name||'Предмет '+member.row.CollectParam;
    const requirement='×'+member.row.Count+' · Заточка +'+member.row.EnchantLevel+(item?.rarity?.label?' · '+item.rarity.label:'');
    const text=node('span',undefined,compact?'collection-item-tip':'collection-item-text');text.append(node('strong',label),node('small',requirement));
    if(compact){line.setAttribute('aria-label',label+' · '+requirement);text.setAttribute('role','tooltip');
      if(Number(member.row.EnchantLevel)>0)slot.append(node('span','+'+member.row.EnchantLevel,'collection-enchant'));
      if(Number(member.row.Count)>1)slot.append(node('span','×'+member.row.Count,'collection-quantity'));
    }
    line.append(slot,text);return line;
  }
  function bonuses(entry){
    const box=node('section',undefined,'collection-bonuses');box.append(node('h3','Бонус коллекции'));
    if(!entry.bonuses.length)box.append(node('p','Связанные параметры не найдены.','muted'));
    for(const b of entry.bonuses){const line=node('div',undefined,'collection-stat'),tip=node('span',undefined,'collection-tip'),button=node('button',model.bonusName(b)),description=node('span',undefined,'tip');button.type='button';
      description.id='tip-'+entry.id+'-'+b.row.Id;button.setAttribute('aria-describedby',description.id);description.setAttribute('role','tooltip');
      description.textContent=(b.name?.Desc||'Описание в локализации не найдено.').replaceAll('\\r\\n','\n').replaceAll('\\n','\n');
      if(b.display?.IsPercentage==='1')description.textContent+='\n\nПроцентный параметр: показаны единицы клиента, пересчёт в проценты не установлен.';
      tip.append(button,description);line.append(tip,node('strong',model.bonusValue(b)));box.append(line);
    }return box;
  }
  function content(host,entry,full=false){
    host.classList.add(full?'collection-detail':'collection-row');
    const info=node('div',undefined,'collection-info');
    const heading=node(full?'h2':'h3'),link=node('a',entry.name),p=query();p.set('collection',entry.id);link.href='index.html?'+p;
    if(full)heading.textContent=entry.name;else heading.append(link);info.append(heading,bonuses(entry));
    const meta=node('div',undefined,'collection-meta');meta.append(node('span',tabs().get(entry.row.CollectionTabId)||'Категория '+entry.row.CollectionTabId,'badge'),node('span',entry.rarity?.label||'Редкость '+entry.row.Rarity,'badge'),node('span','ID '+entry.id,'muted'));info.append(meta);
    if(entry.row.DateTimeSetting||entry.row.FixedTermId)info.append(node('p','Указан срок или расписание · доступность требует проверки в игре','collection-condition'));
    if(entry.row.ServerServiceGroupId)info.append(node('p','Есть условие группы сервера · '+entry.row.ServerServiceGroupId,'collection-condition'));
    const list=node('div',undefined,'collection-items');list.setAttribute('aria-label','Предметы коллекции');for(const member of entry.requirements)list.append(itemLine(member,!full));host.append(info,list);
    if(full){const raw=node('details',undefined,'collection-raw');raw.append(node('summary','Исходные записи и условия'),node('pre',JSON.stringify(entry,null,2)));host.append(raw);}
  }
  function render(append=false){
    if(!append){rows=model.select(data.entries,data.items,Object.fromEntries(query()));$('grid').replaceChildren();shown=0;}
    const end=Math.min(rows.length,limit);for(const entry of rows.slice(shown,end)){const card=node('article',undefined,'catalog-card');content(card,entry);$('grid').append(card);}shown=end;
    if(!rows.length)$('grid').append(node('p','Коллекции не найдены. Измените поиск или фильтры.','empty'));
    $('count').textContent=rows.length+' коллекций · показано '+shown+' · поиск также по предметам и бонусам';$('more').hidden=shown>=rows.length;
    const p=query();history.replaceState(null,'','index.html'+(p.size?'?'+p:''));
    for(const a of $('grid').querySelectorAll('a[href*="collection="]')){const target=new URL(a.href);if(limit>60)target.searchParams.set('limit',String(limit));a.href=target;}
  }
  (async()=>{
    const manifest=await json('manifest.json');data=await json(manifest.file,manifest.sha256);
    for(const t of data.tabs){const o=node('option',t.name+' · '+manifest.statistics.tabs[t.id]);o.value=t.id;$('tab').append(o);}
    const rarities=new Map(data.entries.map(e=>[e.row.Rarity,e.rarity?.label||'Редкость '+e.row.Rarity]));
    for(const [id,label]of rarities){const o=node('option',label);o.value=id;$('rarity').append(o);}
    const bonuses=new Map(data.entries.flatMap(e=>e.bonuses.map(b=>[b.row.Type,model.bonusName(b)])));
    for(const [id,label]of [...bonuses].sort((a,b)=>a[1].localeCompare(b[1],'ru'))){const o=node('option',label);o.value=id;$('bonus').append(o);}
    $('search').value=params.get('q')||'';for(const k of ['tab','rarity','bonus','sort'])if([...$(k).options].some(o=>o.value===params.get(k)))$(k).value=params.get(k);
    if(params.has('collection')){const entry=data.entries.find(e=>e.id===params.get('collection'));if(!entry)throw Error('Коллекция не найдена: '+params.get('collection'));$('listing').hidden=true;$('detail').hidden=false;const p=new URLSearchParams(params);p.delete('collection');$('back').href='index.html'+(p.size?'?'+p:'');$('crumb').textContent=entry.name;document.title=entry.name+' · Vampir';content($('collection'),entry,true);}
    else{render();CatalogData.restoreList($('grid'));}
    for(const k of ['search','tab','rarity','bonus','sort']){$(k).disabled=false;$(k)[k==='search'?'oninput':'onchange']=()=>{limit=60;render();};}
    const more=()=>{limit+=60;render(true);};$('more').onclick=more;CatalogData.autoMore($('more'),more);
  })().catch(error=>{$('error').textContent='Не удалось загрузить коллекции: '+error.message;});
})();
