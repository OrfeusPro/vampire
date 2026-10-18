/* Shared Battle and reward facts; no runtime modifiers inferred. */
window.MonsterCard=(()=>{
function el(tag,text,className){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;}
function number(value) { return value !== '' && value != null && Number.isFinite(Number(value)) ? Number(value).toLocaleString('ru') : '—'; }
const facts=SkillCard.facts,renderSkillDetail=SkillCard.render;
function renderBattleDetails(card, variants, detail) {
  const panel = el('details'); panel.append(el('summary', 'Боевые параметры и навыки'));
  for(const [index,battle]of variants.entries()) {
    if(variants.length>1)panel.append(el('h3','Вариант '+(index+1)));
    const attack=detail.battle_enums?.EAttackApplyType?.[battle.AttackApplyType];
    const attackNames={None:'Не задан',Melee:'Ближний бой',Range:'Дальний бой',Magic:'Магический'};
    const attackKey=attack?.name.split('::').pop();
    const attribute=detail.battle_enums?.EAttributeType?.[battle.Attribute]?.name.split('::').pop();
    facts(panel,[['HP',number(battle.HP)],['Атака',number(battle.AttackPower)],['Защита',number(battle.DefensePower)],
      ['Флаг агрессии',battle.Aggressive==='0'?'Нет · 0':battle.Aggressive==='1'?'Да · 1':battle.Aggressive],
      ['Тип атаки',(attackNames[attackKey]||attackKey||'Не расшифрован')+' · '+battle.AttackApplyType],
      ['Дальность обнаружения',number(battle.SightRange)],['Предел преследования',number(battle.MaxChaseDistance)],
      ['Радиус запроса помощи',number(battle.RequestHelpRange)],['Атрибут',(attribute==='Max'?'Служебное значение Max':attribute||'Не расшифрован')+' · '+battle.Attribute]]);
    panel.append(el('p','Расстояния указаны в единицах клиента. Флаг агрессии не доказывает текущее поведение монстра.', 'muted'));
    const ids=battle.SkillIdList.split(',').map(id=>id.trim()).filter(Boolean);
    panel.append(el('h3','Навыки · '+ids.length));
    for(const id of ids){
      renderSkillDetail(panel,detail.skills?.[id],id);
    }
  }
  const source=el('details');source.append(el('summary','Исходные боевые записи'),el('pre',JSON.stringify(variants,null,2)));panel.append(source);card.append(panel);
}
function renderMonsterFacts(card, detail, rewardsOnly = false, showNotice = true, showRewards = true) {
  const stats = el('div', undefined, 'monsterStats');
  const variants = rewardsOnly ? [] : detail?.battle || [];
  if (variants.length === 1) {
    for (const [field, label] of [['HP', 'HP'], ['AttackPower', 'Атака'], ['DefensePower', 'Защита']]) {
      const cell = el('div'); cell.append(el('small', label), el('strong', number(variants[0][field]))); stats.append(cell);
    }
    card.append(stats);
    renderBattleDetails(card, variants, detail);
  } else if (variants.length > 1) {
    card.append(el('p', 'В клиенте найдено ' + variants.length + ' вариантов боевых параметров; действующий вариант не определён.', 'muted'));
    renderBattleDetails(card, variants, detail);
  }
  const rewards = (detail?.rewards || []).filter(r => r.type_name !== 'ERewardType::Item' && r.type_name !== 'ERewardType::RewardGroup');
  if (showRewards && rewards.length) {
    const summary = el('div', undefined, 'rewardSummary');
    for (const r of rewards) {
      const label = r.type_name === 'ERewardType::Exp' ? 'Опыт' : ({Gold:'Золото',Diamond:'Алмазы',EventDiamond:'Ивент-алмазы'}[r.RewardParam] || r.RewardParam) || r.type_name.replace('ERewardType::', '');
      const amount = r.MinRewardValue === r.MaxRewardValue ? number(r.MinRewardValue) : number(r.MinRewardValue) + '–' + number(r.MaxRewardValue);
      const badge=el('span', label + ': ' + amount, 'badge');
      badge.title=(r.RewardParam || r.type_name)+' · RewardRate: '+(r.RewardRate || 'не указан')+' (исходные единицы, не проценты). Серверная выдача не проверена.';
      summary.append(badge);
    }
    card.append(summary);
  }
  if(showNotice)card.append(el('p', 'Данные клиента: серверные изменения, условия и гарантированность наград не проверены.', 'muted'));
}
function renderPortraits(parent,portraits,id,label,compact=false){
  if(!portraits?.images?.length)return;
  const group=el('div',undefined,'npcPortraits'+(compact?' compact':''));
  for(const image of portraits.images){
    const figure=el('figure'),a=el('a'),img=el('img');a.href='../../'+image.file;a.target='_blank';a.rel='noopener';
    img.src='../../'+image.file;img.alt='Изображение NPC '+(label||id);img.loading='lazy';
    const sources=(image.field_sources||[]).map(i=>portraits.sources[i]).filter(Boolean);
    a.title=image.asset_path+' · '+sources.map(s=>s.table+'.'+s.field+(s.group_id?' · группа '+s.group_id:'')).join(' / ');
    a.append(img);figure.append(a,el('figcaption',sources.some(s=>s.table==='NpcProfile')?'Из профиля NPC':'Изображение NPC из клиента'));group.append(figure);
  }
  parent.append(group);
}
let rewardTip;
function renderRewardIcon(parent,item,id,label,chains,area=false){
  const a=el('a',undefined,'npc-reward-icon');a.href='../loot/items.html?item='+encodeURIComponent(id);
  const image=item?.icon?.images?.[0],backgrounds=item?.rarity?.background?.images||[];
  if(backgrounds.length===1)a.style.backgroundImage='url("../../'+backgrounds[0].file+'")';
  if(image){const img=el('img');img.src='../../'+image.file;img.alt=label;img.loading='lazy';a.append(img);}else a.append(el('span','?'));
  const text=[label,item?.rarity?.label||'Редкость не указана','ID '+id,area?'Награды области':'Награды NPC',
    'Количество: '+WorldMapModel.dropAmounts(chains).join(' / '),'Шанс в процентах не установлен.',
    item?.icon?.status==='ambiguous_paths'?'Ресурс иконки неоднозначен':null,
    image?.color_verified===false?'Цвет иконки ещё не сверен с Android':null].filter(Boolean).join('\n');
  a.setAttribute('aria-label',text);let timer,owned;
  function hide(){clearTimeout(timer);owned?.remove();if(rewardTip===owned)rewardTip=null;owned=null;a.removeAttribute('aria-describedby');}
  function later(){timer=setTimeout(hide,150);}
  function show(){
    clearTimeout(timer);rewardTip?.remove();const tip=el('div',undefined,'reward-tooltip');tip.id='npc-reward-tooltip';tip.setAttribute('role','dialog');tip.setAttribute('aria-label',label);
    tip.append(el('strong',label),el('p',text.split('\n').slice(1).join('\n')));
    const source=el('details');source.append(el('summary','Исходные данные · JSON'),el('pre',JSON.stringify(chains,null,2)));tip.append(source);
    document.body.append(tip);owned=tip;rewardTip=tip;a.setAttribute('aria-describedby',tip.id);
    const box=a.getBoundingClientRect(),width=tip.getBoundingClientRect().width,below=innerHeight-box.bottom-12,above=box.top-12;
    tip.style.left=Math.max(8,Math.min(box.left,innerWidth-width-8))+'px';tip.style.maxHeight=Math.max(80,Math.min(360,Math.max(above,below)))+'px';
    if(below>=Math.min(240,above))tip.style.top=(box.bottom+6)+'px';else tip.style.bottom=(innerHeight-box.top+6)+'px';
    tip.onmouseenter=()=>clearTimeout(timer);tip.onmouseleave=later;tip.onfocusin=()=>clearTimeout(timer);
    tip.onfocusout=event=>{if(!tip.contains(event.relatedTarget)&&event.relatedTarget!==a)later();};
    tip.onkeydown=event=>{if(event.key==='Escape'){hide();a.focus();hide();}};
  }
  a.onmouseenter=show;a.onmouseleave=later;a.onfocus=show;a.onblur=event=>{if(!owned?.contains(event.relatedTarget))later();};a.onclick=hide;a.onkeydown=event=>{if(event.key==='Escape')hide();};
  parent.append(a);
}
return {renderFacts:renderMonsterFacts,renderPortraits,renderRewardIcon};
})();
