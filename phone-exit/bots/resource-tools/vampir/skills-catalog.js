'use strict';
(() => {
  const $=id=>document.getElementById(id),{json,node}=CatalogData,params=new URLSearchParams(location.search),alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
  let classData,skillMeta={},entries=[],rankBackgrounds=new Map(),limit=Math.max(60,Math.min(10000,Number(params.get('limit'))||60));
  const name=entry=>entry.display_names?.map(n=>n.text).join(' / ')||'Навык '+entry.id;
  const npcIds=entry=>entry.all_npc_ids||entry.npc_ids||[];
  $('relation').options[0].textContent='Обычные навыки';
  const serviceOption=node('option','Служебные записи · Registered');serviceOption.value='service';$('relation').append(serviceOption);
  const sortLabel=node('label','Сортировка'),sortSelect=node('select');sortSelect.id='sort';sortSelect.disabled=true;
  for(const [value,text] of [['rank','Ранг: сначала выше'],['rank-asc','Ранг: сначала ниже'],['name','По названию']]){const option=node('option',text);option.value=value;sortSelect.append(option);}sortLabel.append(sortSelect);$('relation').closest('.filters').append(sortLabel);
  const query=()=>{const p=new URLSearchParams();if($('search').value.trim())p.set('q',$('search').value.trim());if($('relation').value!=='all')p.set('relation',$('relation').value);if($('classFilter').value!=='all')p.set('class',$('classFilter').value);if($('sort').value!=='rank')p.set('sort',$('sort').value);if(limit>60)p.set('limit',String(limit));return p;};
  function render(append=false){
    const q=$('search').value.trim().toLowerCase(),relation=$('relation').value;
    const rows=entries.filter(e=>CatalogClasses.matches(classData.skills[e.id],$('classFilter').value)&&(e.id+' '+name(e)).toLowerCase().includes(q)&&SkillsCatalogModel.matchesRelation(e,relation)).sort((a,b)=>SkillsCatalogModel.compare(a,b,skillMeta,$('sort').value));
    const p=query();history.replaceState(null,'','skills.html'+(p.size?'?'+p:''));const start=append?$('grid').children.length:0;if(!append)$('grid').replaceChildren();$('count').textContent=rows.length+' навыков · показано '+Math.min(limit,rows.length);$('more').hidden=limit>=rows.length;
    if(!rows.length)$('grid').append(node('p','Ничего не найдено. Измените поиск или фильтр.','empty'));
    for(const entry of rows.slice(start,limit)){
      const meta=skillMeta[entry.id],kind=meta?.kind||'unknown',card=node('article',undefined,'catalog-card skill-list-card'),url=new URLSearchParams(p);url.set('skill',entry.id);
      const target='skills.html?'+url,portrait=node('a',undefined,'skill-list-icon');portrait.href=target;portrait.setAttribute('aria-label',name(entry));
      const image=entry.images?.Img?.images?.[0],background=entry.images?.ImgBg?.images;
      const rank=String(meta?.rarity_raw??''),rankBackground=rankBackgrounds.get(rank);
      const selectedBackground=background?.length===1?background[0]:rankBackground;
      if(selectedBackground)portrait.style.backgroundImage='url("../../'+selectedBackground.file+'")';
      if(rankBackground&&background?.length!==1){portrait.dataset.backgroundSource='same-rank';portrait.title='Подложка подобрана по текстуре навыков с таким же значением Skill.Rarity.';}
      if(image){const img=node('img');img.src='../../'+image.file;img.alt='';img.loading='lazy';portrait.append(img);}else portrait.append(node('span','?'));
      portrait.dataset.rarity=meta?.rarity_raw||'';
      if((entry.images?.Img?.images?.length||0)>1)portrait.title=(portrait.title?portrait.title+' ':'')+'Есть несколько ресурсов иконки; показан первый вариант.';
      const body=node('div',undefined,'skill-list-body'),h=node('h3'),a=node('a',name(entry));a.href=target;h.append(a);
      const classLine=node('p','Класс: '+CatalogClasses.label(classData.skills[entry.id],classData.classes),'skill-list-class');
      classLine.title='По явным полям класса в данных клиента; фактическая доступность не проверена.';
      const tags=node('div',undefined,'skill-list-tags'),type=node('span',({active:'Активный',passive:'Пассивный',unknown:'Тип не указан'})[kind],'skill-kind '+kind);
      type.title=kind==='unknown'?'Нет однозначной отметки типа в описании связанной книги.':'Тип прямо указан в описании связанной книги.';tags.append(type,node('span','ID '+entry.id,'skill-list-id'));
      const links=node('p',undefined,'skill-list-counts');
      for(const [label,count] of [['Книги',entry.book_count],['Предметы',entry.passive_item_count],['NPC',npcIds(entry).length]])if(count)links.append(node('span',label+' '+count));
      body.append(h,classLine,tags,links);card.append(portrait,body);$('grid').append(card);
    }
    CatalogData.syncListLinks($('grid'),limit);
  }
  $('search').oninput=$('relation').onchange=$('classFilter').onchange=$('sort').onchange=()=>{limit=60;render();};$('more').onclick=()=>{limit+=60;render(true);};
  (async()=>{
    const manifest=await json('monster-manifest.json'),index=await json(manifest.skill_index.file,manifest.skill_index.sha256);
    classData=await CatalogData.classData();CatalogData.classOptions($('classFilter'),classData);if([...$('classFilter').options].some(o=>o.value===params.get('class')))$('classFilter').value=params.get('class');
    const metaSpec=await json('../skill-catalog-meta-manifest.json');skillMeta=(await json('../'+metaSpec.file,metaSpec.sha256)).skills;
    if([...$('sort').options].some(option=>option.value===params.get('sort')))$('sort').value=params.get('sort');
    entries=Object.values(index.skills).sort((a,b)=>alphabet.compare(name(a),name(b))||alphabet.compare(a.id,b.id));
    const backgroundCounts=new Map();
    for(const entry of entries){const rank=skillMeta[entry.id]?.rarity_raw,images=entry.images?.ImgBg?.images;if(rank===undefined||images?.length!==1)continue;const key=String(rank),file=images[0].file,counts=backgroundCounts.get(key)||new Map();counts.set(file,(counts.get(file)||0)+1);backgroundCounts.set(key,counts);}
    for(const [rank,counts] of backgroundCounts){const [file]=[...counts].sort((a,b)=>b[1]-a[1]||alphabet.compare(a[0],b[0]))[0];rankBackgrounds.set(rank,{file});}
    $('search').value=params.get('q')||'';if([...$('relation').options].some(o=>o.value===params.get('relation')))$('relation').value=params.get('relation');
    const id=params.get('skill');
    if(id){
      $('listing').hidden=true;$('detail').hidden=false;const back=new URLSearchParams(params);back.delete('skill');$('back').href='skills.html'+(back.size?'?'+back:'');
      const entry=index.skills[id];$('crumb').textContent=entry?name(entry):'Навык '+id;document.title=($('crumb').textContent)+' · Vampir';
      const skill=entry?.detail?await json(entry.detail.file,entry.detail.sha256):{id};
      if(entry?.npc_ids.length){const a=node('a','NPC на Nocturne · '+entry.npc_ids.length,'button');a.href='index.html?skill='+encodeURIComponent(id)+'&skillNpc=1';$('actions').append(a);}
      else $('actions').append(node('p','Связанные NPC на Nocturne не найдены.','muted'));
      $('actions').append(node('p','Класс: '+CatalogClasses.label(classData.skills[id],classData.classes),'muted'));SkillCard.render($('selectedSkill'),skill,id,true);
      if(entry&&npcIds(entry).length){
        const catalog=await json(manifest.npc_catalog.file,manifest.npc_catalog.sha256);
        const section=node('section'),grid=node('div',undefined,'catalog-grid'),more=node('button','Показать ещё');more.type='button';
        const rows=npcIds(entry).map(nid=>{const npc=catalog.npcs[nid];if(!npc)throw Error('Отсутствует NPC '+nid);return npc;})
          .sort((a,b)=>alphabet.compare(a.name,b.name)||alphabet.compare(a.id,b.id));
        section.append(node('h2','NPC с этим навыком · '+rows.length),node('p','Все миры клиента. Сохранены все варианты Battle; фактическое применение навыка и доступность NPC не проверены.','muted'),grid,more);$('selectedSkill').append(section);
        let shown=0;
        function load(){for(const npc of rows.slice(shown,shown+60)){const card=node('article',undefined,'catalog-card'),h=node('h3'),a=node('a',npc.name||'NPC '+npc.id);a.href='monsters.html?npc='+encodeURIComponent(npc.id);h.append(a);card.append(h,node('p','Уровень '+(npc.level||'не указан')+' · NPC '+npc.id,'muted'),node('p',npc.world_ids.length?'Миры: '+npc.world_ids.join(', '):'Размещений в клиенте не найдено','muted'));grid.append(card);}shown=Math.min(shown+60,rows.length);more.hidden=shown>=rows.length;}
        more.onclick=load;load();CatalogData.autoMore(more,load);
      }
    }else {render();CatalogData.restoreList($('grid'));}
    $('search').disabled=$('relation').disabled=$('classFilter').disabled=$('sort').disabled=false;
    CatalogData.autoMore($('more'),()=>{limit+=60;render(true);});
  })().catch(error=>{$('error').textContent='Не удалось загрузить каталог: '+error.message;});
})();
