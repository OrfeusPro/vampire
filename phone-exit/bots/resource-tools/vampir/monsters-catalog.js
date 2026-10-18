'use strict';
(() => {
  const $=id=>document.getElementById(id),{json,node}=CatalogData,params=new URLSearchParams(location.search),alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
  let entries=[],limit=Math.max(60,Math.min(10000,Number(params.get('limit'))||60)),catalog,manifest,items;
  const a=(text,href,cls)=>{const link=node('a',text,cls);link.href=href;return link;};
  const query=()=>{const p=new URLSearchParams();for(const [field,key,empty]of [['search','q',''],['minLevel','min',''],['maxLevel','max',''],['sort','sort','level'],['world','world','all'],['drops','drops','all'],['portraits','images','all']])if($(field).value!==empty)p.set(key,$(field).value);if(limit>60)p.set('limit',String(limit));return p;};
  function render(append=false){
    const rows=MonstersCatalogModel.select(entries,{query:$('search').value,min:$('minLevel').value,max:$('maxLevel').value,sort:$('sort').value,world:$('world').value,dropsOnly:$('drops').value==='direct',images:$('portraits').value}),p=query(),start=append?$('grid').children.length:0;
    history.replaceState(null,'','monsters.html'+(p.size?'?'+p:''));if(!append)$('grid').replaceChildren();$('count').textContent=rows.length+' NPC · показано '+Math.min(limit,rows.length);$('more').hidden=limit>=rows.length;
    if(!rows.length)$('grid').append(node('p','Ничего не найдено. Измените поиск, уровни или фильтры.','empty'));
    for(const row of rows.slice(start,limit)){
      const card=node('article',undefined,'catalog-card'),target=new URLSearchParams(p),h=node('h3');target.set('npc',row.id);
      MonsterCard.renderPortraits(card,row.portraits,row.id,row.name,true);h.append(a(row.name,'monsters.html?'+target));card.append(node('span','Ур. '+(row.level||'—'),'badge'),h,node('p','NPC '+row.id,'muted'),node('p','Личные предметы: '+row.drop_item_count,'muted'),node('p',row.placement_count+' размещений · '+row.world_ids.length+' миров','muted'));$('grid').append(card);
    }
    CatalogData.syncListLinks($('grid'),limit);
  }
  for(const id of ['search','minLevel','maxLevel'])$(id).oninput=()=>{limit=60;render();};
  for(const id of ['sort','world','drops','portraits'])$(id).onchange=()=>{limit=60;render();};
  $('more').onclick=()=>{limit+=60;render(true);};
  const itemName=(id)=>[...new Set((items[id]?.names_en||[]).map(n=>n.Name).filter(Boolean))].join(' / ')||'Предмет '+id;
  function raw(parent,title,value){const d=node('details');d.append(node('summary',title),node('pre',JSON.stringify(value,null,2)));parent.append(d);}
  function drops(parent,source,area=false){
    const rows=Object.entries(source).sort(([id,a],[other,b])=>ItemRarity.compare(items[id],items[other])||alphabet.compare(itemName(id),itemName(other))||alphabet.compare(id,other));
    const section=node('section',undefined,'npc-section');parent.append(section);section.append(node('h3',(area?'Предметы в записях области':'Личные предметные награды')+' · '+rows.length));
    if(!rows.length){section.append(node('p',area?'Предметные строки области не найдены.':'Личные предметные награды NPC в данных не найдены. Это не доказывает отсутствие дропа в игре.','muted'));return;}
    section.append(node('p',area?'Записи AreaReward показаны отдельно. Они не добавлены к личному дропу NPC.':'Записи NpcReward. Условия серверной выдачи и шансы в процентах не подтверждены.','muted'));
    const grid=node('div',undefined,'catalog-grid'),more=node('button','Показать ещё предметы');section.append(grid,more);let shown=0;
    function append(){for(const [id,chains]of rows.slice(shown,shown+60)){
      const item=items[id],card=node('article',undefined,'catalog-card'),title=node('h4'),url='../loot/items.html?item='+encodeURIComponent(id);
      for(const image of item?.icon?.images||[]){const link=a('',url),slot=node('span',undefined,'item-icon'),img=node('img');img.src='../../'+image.file;img.alt=itemName(id);img.loading='lazy';const backgrounds=item?.rarity?.background?.images||[];if(backgrounds.length===1)slot.style.backgroundImage='url("../../'+backgrounds[0].file+'")';slot.append(img);link.append(slot);card.append(link);}
      title.append(a(itemName(id),url));card.append(title,node('p',item?.rarity?.label||'Редкость не указана','muted'),node('p','Количество по строкам: '+WorldMapModel.dropAmounts(chains).join(' / '),'muted'),node('p','Шанс: не установлен','muted'));
      raw(card,'Условия и исходные цепочки · '+chains.length,chains);grid.append(card);
    }shown=Math.min(rows.length,shown+60);more.hidden=shown>=rows.length;}
    more.onclick=append;append();CatalogData.autoMore(more,append);
  }
  async function detail(row){
    $('listing').hidden=true;$('detail').hidden=false;const back=new URLSearchParams(params);back.delete('npc');$('back').href='monsters.html'+(back.size?'?'+back:'');$('crumb').textContent=row.name;document.title=row.name+' · Vampir';
    const data=await json(row.detail.file,row.detail.sha256),card=$('npc');card.append(node('h2',row.name),node('p','Уровень '+(row.level||'—')+' · NPC '+row.id,'muted'));
    MonsterCard.renderPortraits(card,data.portraits,row.id,row.name);
    const actions=node('div',undefined,'detail-actions');card.append(actions);
    if(row.on_nocturne)actions.append(a('Показать на Nocturne','index.html?npc='+encodeURIComponent(row.id),'button'));
    else if(row.world_ids.length)actions.append(a('Показать в мире '+row.world_ids[0],'world.html?world='+encodeURIComponent(row.world_ids[0])+'&npc='+encodeURIComponent(row.id),'button'));
    actions.append(a('Исходные данные NPC',row.detail.file,'button'));
    const lootIndex=await json('../loot/index.json');items=await json('../loot/'+lootIndex.files.items.file,lootIndex.files.items.sha256);
    MonsterCard.renderFacts(card,data);
    if(!data.battle.length)card.append(node('p','Боевые параметры по указанной группе не найдены.','muted'));
    const skills=Object.values(data.skills||{});if(skills.length){const section=node('section',undefined,'npc-section');section.append(node('h3','Навыки · '+skills.length));for(const skill of skills){const name=skill.display_names?.map(n=>n.text).join(' / ')||'Навык '+skill.id;const line=node('p');line.append(a(name,'skills.html?skill='+encodeURIComponent(skill.id)),document.createTextNode(' · ID '+skill.id));section.append(line);}card.append(section);}
    drops(card,data.drops||{});
    const areas=Object.values(data.area_candidates||{});if(areas.length){const section=node('details',undefined,'npc-section');section.append(node('summary','Отдельно: награды областей размещения · '+areas.length));let loaded=false;section.ontoggle=()=>{if(!section.open||loaded)return;loaded=true;section.append(node('p','Выбор списка в клиенте зависит от конкретного размещения NPC. Область не доказывает личный дроп или выдачу за каждое убийство.','muted'));for(const area of areas){const group=node('details');group.append(node('summary','Область '+area.area_id+' · '+Object.keys(area.drops||{}).length+' предметов'));let shown=false;group.ontoggle=()=>{if(!group.open||shown)return;shown=true;MonsterCard.renderFacts(group,{rewards:area.rewards},true);drops(group,area.drops||{},true);raw(group,'Строки AreaReward',area.rewards);};section.append(group);}};card.append(section);}
    const placements=data.placements||[],section=node('section',undefined,'npc-section');section.append(node('h3','Места появления · '+placements.length),node('p','Исходные размещения клиента. Текущая видимость, расписание и серверные условия не вычисляются.','muted'));card.append(section);
    if(!placements.length)section.append(node('p','Записи размещения не найдены.','muted'));
    const list=node('div'),more=node('button','Показать ещё размещения');section.append(list,more);let shown=0;
    function append(){for(const spawn of placements.slice(shown,shown+60)){const p=node('p');p.append(a('Мир '+spawn.WorldInfoId+' · размещение '+spawn.Id,'index.html?world='+encodeURIComponent(spawn.WorldInfoId)+'&npc='+encodeURIComponent(row.id)+'&spawn='+encodeURIComponent(spawn.Id)));p.append(node('small',' · область '+(spawn.AreaInfoId||'—')+' · XYZ '+spawn.PosX+', '+spawn.PosY+', '+spawn.PosZ));list.append(p);}shown=Math.min(placements.length,shown+60);more.hidden=shown>=placements.length;}
    more.onclick=append;append();CatalogData.autoMore(more,append);
    raw(card,'Определение NPC и исходные награды',{npc:data.npc,rewards:data.rewards,battle_relation:data.battle_relation});
  }
  (async()=>{
    manifest=await json('monster-manifest.json');catalog=await json(manifest.npc_catalog.file,manifest.npc_catalog.sha256);entries=Object.values(catalog.npcs);
    for(const id of [...new Set(entries.flatMap(n=>n.world_ids))].sort(alphabet.compare)){const option=node('option','Мир '+id);option.value=id;$('world').append(option);}
    for(const [field,key]of [['search','q'],['minLevel','min'],['maxLevel','max'],['sort','sort'],['world','world'],['drops','drops'],['portraits','images']]){const value=params.get(key);if(value!==null&&($(field).tagName!=='SELECT'||[...$(field).options].some(o=>o.value===value)))$(field).value=value;}
    const id=params.get('npc');if(id){const row=catalog.npcs[id];if(!row)throw Error('NPC '+id+' не найден');await detail(row);}else{render();CatalogData.restoreList($('grid'));CatalogData.autoMore($('more'),()=>{limit+=60;render(true);});}
    for(const input of document.querySelectorAll('.filters input,.filters select'))input.disabled=false;
  })().catch(error=>{$('error').textContent='Не удалось загрузить NPC: '+error.message;});
})();
