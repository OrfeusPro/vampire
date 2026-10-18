'use strict';
(() => {
  const $=id=>document.getElementById(id),{json,node}=CatalogData,params=new URLSearchParams(location.search),alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
  let classData,entries=[],limit=Math.max(60,Math.min(10000,Number(params.get('limit'))||60));
  const name=entry=>entry.display_names?.map(n=>n.text).join(' / ')||'Навык '+entry.id;
  const query=()=>{const p=new URLSearchParams();if($('search').value.trim())p.set('q',$('search').value.trim());if($('relation').value!=='all')p.set('relation',$('relation').value);if($('classFilter').value!=='all')p.set('class',$('classFilter').value);if(limit>60)p.set('limit',String(limit));return p;};
  function render(append=false){
    const q=$('search').value.trim().toLowerCase(),relation=$('relation').value;
    const rows=entries.filter(e=>CatalogClasses.matches(classData.skills[e.id],$('classFilter').value)&&(e.id+' '+name(e)).toLowerCase().includes(q)&&(relation==='all'||relation==='books'&&e.book_count>0||relation==='items'&&e.passive_item_count>0||relation==='npcs'&&e.npc_ids.length>0));
    const p=query();history.replaceState(null,'','skills.html'+(p.size?'?'+p:''));const start=append?$('grid').children.length:0;if(!append)$('grid').replaceChildren();$('count').textContent=rows.length+' навыков · показано '+Math.min(limit,rows.length);$('more').hidden=limit>=rows.length;
    if(!rows.length)$('grid').append(node('p','Ничего не найдено. Измените поиск или фильтр.','empty'));
    for(const entry of rows.slice(start,limit)){const card=node('article',undefined,'catalog-card'),a=node('a',name(entry)),h=node('h3'),url=new URLSearchParams(p);url.set('skill',entry.id);a.href='skills.html?'+url;SkillCard.images(card,entry);h.append(a);card.append(h,node('p','ID '+entry.id,'muted'),node('p','Класс: '+CatalogClasses.label(classData.skills[entry.id],classData.classes),'muted'),node('p','Книги: '+(entry.book_count||0)+' · Предметы: '+(entry.passive_item_count||0)+' · NPC: '+entry.npc_ids.length,'muted'));$('grid').append(card);}
    CatalogData.syncListLinks($('grid'),limit);
  }
  $('search').oninput=$('relation').onchange=$('classFilter').onchange=()=>{limit=60;render();};$('more').onclick=()=>{limit+=60;render(true);};
  (async()=>{
    const manifest=await json('monster-manifest.json'),index=await json(manifest.skill_index.file,manifest.skill_index.sha256);
    classData=await CatalogData.classData();CatalogData.classOptions($('classFilter'),classData);if([...$('classFilter').options].some(o=>o.value===params.get('class')))$('classFilter').value=params.get('class');
    entries=Object.values(index.skills).sort((a,b)=>alphabet.compare(name(a),name(b))||alphabet.compare(a.id,b.id));
    $('search').value=params.get('q')||'';if([...$('relation').options].some(o=>o.value===params.get('relation')))$('relation').value=params.get('relation');
    const id=params.get('skill');
    if(id){
      $('listing').hidden=true;$('detail').hidden=false;const back=new URLSearchParams(params);back.delete('skill');$('back').href='skills.html'+(back.size?'?'+back:'');
      const entry=index.skills[id];$('crumb').textContent=entry?name(entry):'Навык '+id;document.title=($('crumb').textContent)+' · Vampir';
      const skill=entry?.detail?await json(entry.detail.file,entry.detail.sha256):{id};
      if(entry?.npc_ids.length){const a=node('a','Показать NPC на карте · '+entry.npc_ids.length,'button');a.href='index.html?skill='+encodeURIComponent(id)+'&skillNpc=1';$('actions').append(a);}
      else $('actions').append(node('p','Связанные NPC на Nocturne не найдены.','muted'));
      $('actions').append(node('p','Класс: '+CatalogClasses.label(classData.skills[id],classData.classes),'muted'));SkillCard.render($('selectedSkill'),skill,id,true);
    }else {render();CatalogData.restoreList($('grid'));}
    $('search').disabled=$('relation').disabled=$('classFilter').disabled=false;
    CatalogData.autoMore($('more'),()=>{limit+=60;render(true);});
  })().catch(error=>{$('error').textContent='Не удалось загрузить каталог: '+error.message;});
})();
