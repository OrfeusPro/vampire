/* Item details use source values; no inferred percent or cumulative enchant stats. */
window.ItemDetails = (() => {
  let manifest;
  const cache = new Map();
  const labels = {Id:'ID',GroupId:'Группа',Type:'Тип предмета',InventoryCategory:'Категория инвентаря',EquipmentType:'Снаряжение',Rarity:'Редкость',ClassInfoId:'Класс',Tier:'Тир',Weight:'Вес (единицы клиента)',MaxStackableCount:'Максимум в стопке',MaxOwnedCount:'Максимум во владении',MinUseLevel:'Минимальный уровень',MaxUseLevel:'Максимальный уровень',Usable:'Использование',UsesCountType:'Режим расходования',AutoUse:'Автоиспользование',QuickSlot:'Быстрая ячейка',CoolTime:'Перезарядка (единицы клиента)',UseLimitType:'Тип ограничения',UseLimitValue:'Значение ограничения',Unshared:'Unshared — исходный флаг',SellingPriceType:'Тип цены продажи',SellingPrice:'Цена продажи',ProvidingExp:'Предоставляемый опыт',RequiredGold:'Требуемое золото',EffectType:'Тип эффекта',EffectParams:'Параметры эффекта',EffectGrade:'Уровень эффекта',ItemEnchantOperationGroupId:'Группа параметров заточки',BlessingOperationGroupId:'Группа благословения',PassiveSkillGroupId:'Группа пассивных навыков',ItemUseLimitId:'ID ограничения использования',LimitGroupId:'Группа ограничений',UseCostType:'Тип стоимости использования',UseCostParam:'Параметр стоимости',UseCostValue:'Стоимость использования',Img:'Ресурс иконки',Resource:'Ресурс предмета',AuctionTabType:'Раздел аукциона',IsWaste:'IsWaste — исходный флаг',InventorySlotNotCount:'Не учитывать ячейку — исходный флаг',RewardViewOrder:'Порядок награды',ReplaceString1:'Подстановка 1',ReplaceString2:'Подстановка 2'};
  const statRu = {HitValue:'Точность',HitValueSkill:'Точность навыков',SkillAttackSpeedMultiplier:'Скорость применения навыков',AttackPowerReduction:'Защита',DamageReductionCritical:'Сопротивление критическому урону',AttackPower:'Атака',AttackPowerMelee:'Атака ближнего боя',AttackPowerRange:'Атака дальнего боя',AttackPowerMagic:'Магическая атака',WeaponAttackPower:'Дополнительная атака оружия',WeaponAttackPowerMin:'Минимальная атака оружия',WeaponAttackPowerMax:'Максимальная атака оружия',HitValueMelee:'Точность ближнего боя',HitValueRange:'Точность дальнего боя',HitValueMagic:'Магическая точность',DamageValueCritical:'Критический урон',DefensePower:'Защита',MaxHp:'Максимум HP',MaxMp:'Максимум MP'};
  function node(tag,text){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;}
  async function json(file,hash){const response=await fetch(file);if(!response.ok)throw Error(file+': HTTP '+response.status);const bytes=await response.arrayBuffer();if(hash){const actual=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(v=>v.toString(16).padStart(2,'0')).join('');if(actual!==hash)throw Error('Изменились данные характеристик: '+file);}return window.AtlasLocale ? await AtlasLocale.localize(JSON.parse(new TextDecoder().decode(bytes))) : JSON.parse(new TextDecoder().decode(bytes));}
  function load(spec){if(!cache.has(spec.file))cache.set(spec.file,json(spec.file,spec.sha256));return cache.get(spec.file);}
  function raw(parent,value){const d=node('details'),s=node('summary','Источники и исходные значения'),pre=node('pre',JSON.stringify(value,null,2));d.append(s,pre);parent.append(d);}
  function table(parent,rows){const t=node('table');for(const [key,value]of rows){const tr=node('tr');tr.append(node('th',key),node('td',value));t.append(tr);}parent.append(t);}
  function itemReference(parent,id,catalog,href){
    const item=catalog[id],label=item?.names_en?.map(r=>r.Name).filter(Boolean).join(' / ')||'Предмет '+id;
    const group=node('div');group.className='craft-item-reference';
    for(const image of item?.icon?.images||[]){const a=node('a'),slot=node('span'),img=node('img');a.href=href;slot.className='item-icon';img.src='../../'+image.file;img.alt=label;img.loading='lazy';const backgrounds=item.rarity?.background?.images||[];if(backgrounds.length===1)slot.style.backgroundImage='url("../../'+backgrounds[0].file+'")';slot.append(img);a.append(slot);group.append(a);}
    if(item){const a=node('a',label);a.href=href;group.append(a);}else group.append(node('span',label+' · запись не найдена'));
    parent.append(group);
  }
  let tooltip, tooltipOwner, closeTimer;
  function closeTooltip(){if(tooltip)tooltip.hidden=true;if(tooltipOwner)tooltipOwner.removeAttribute('aria-describedby');tooltipOwner=null;}
  function describe(button,text){
    function show(){
      clearTimeout(closeTimer);
      if(!tooltip){tooltip=node('div');tooltip.id='item-stat-tooltip';tooltip.className='stat-tooltip';tooltip.setAttribute('role','tooltip');tooltip.hidden=true;document.body.append(tooltip);tooltip.onpointerenter=()=>clearTimeout(closeTimer);tooltip.onpointerleave=closeTooltip;document.addEventListener('keydown',e=>{if(e.key==='Escape')closeTooltip();});document.addEventListener('pointerdown',e=>{if(tooltipOwner&&!tooltipOwner.contains(e.target)&&!tooltip.contains(e.target))closeTooltip();});window.addEventListener('scroll',closeTooltip,true);window.addEventListener('resize',closeTooltip);}
      if(tooltipOwner&&tooltipOwner!==button)tooltipOwner.removeAttribute('aria-describedby');
      tooltipOwner=button;button.setAttribute('aria-describedby',tooltip.id);tooltip.textContent=text;tooltip.hidden=false;
      tooltip.style.left='12px';tooltip.style.top='12px';
      const anchor=button.getBoundingClientRect(),box=tooltip.getBoundingClientRect();
      const left=Math.max(12,Math.min(anchor.left,window.innerWidth-box.width-12));
      const below=anchor.bottom+10,top=below+box.height<=window.innerHeight-12?below:Math.max(12,anchor.top-box.height-10);
      tooltip.style.left=left+'px';tooltip.style.top=top+'px';
    }
    button.onpointerenter=show;button.onfocus=show;
    button.onpointerleave=()=>{closeTimer=setTimeout(closeTooltip,120);};button.onblur=closeTooltip;
    button.onclick=show;
  }
  function operations(parent,rows,withSource=true,comparison=null){
    if(!rows.length){parent.append(node('p','Строки параметров для этой группы не найдены.'));return;}
    const list=node('div');list.className='stat-list';parent.append(list);
    for(const operation of rows){
      const key=operation.enum?.name?.split('::').pop(),title=statRu[key]||operation.name?.Name||key||'Параметр '+operation.row.Type;
      const value=operation.row.Min===operation.row.Max?operation.row.Min:operation.row.Min+'–'+operation.row.Max;
      const line=node('div');line.className='stat-line';
      const difference=comparison?ItemStatModel.compare(operation,comparison.part,comparison.base):null;
      let description=(operation.name?.Desc||'').replaceAll('\\n','\n');
      if(difference?.unavailable)description+=(description?'\n\n':'')+'Однозначное сравнение с +0 недоступно. Показано значение выбранного уровня.';
      if(difference?.delta)description+=(description?'\n\n':'')+'Без заточки: '+difference.base+'\nПрибавка: '+difference.delta+'\nИтого: '+difference.total+(difference.added?'\nПараметр добавлен заточкой.':'');
      if(operation.display?.IsPercentage==='1')description+=(description?'\n\n':'')+'Процентный параметр. Показано исходное значение клиента; формула пересчёта не установлена.';
      if(description){const button=node('button');button.type='button';button.className='stat-name';button.append(node('span',title));const info=node('span','ⓘ');info.className='stat-info';info.setAttribute('aria-hidden','true');button.append(info);describe(button,description);line.append(button);}else line.append(node('span',title));
      const values=node('strong');values.className='stat-values';values.append(node('span',difference?.base??value));if(difference?.delta){const bonus=node('span','('+difference.delta+')');bonus.className='stat-bonus';if(difference.delta.startsWith('-'))bonus.classList.add('negative');bonus.title='Итого: '+difference.total;values.append(bonus);}line.append(values);list.append(line);
    }
    if(withSource)raw(parent,rows);
  }
  async function render(card,id,item,manifestSpec,catalog={}){
    closeTooltip();
    const hero=node('div'),portrait=node('div'),intro=node('div');hero.className='product-hero';portrait.className='product-portrait';intro.className='product-intro';
    for(const child of [...card.children]){if(child.tagName==='A'&&child.querySelector('img'))portrait.append(child);else if(child.tagName==='H3'||child.classList.contains('item-rarity')||child.tagName==='P')intro.append(child);}
    hero.append(portrait,intro);card.prepend(hero);
    const root=node('div');root.className='item-full-details';card.append(root);
    root.append(node('p','Загрузка характеристик…'));
    if(!manifest)manifest=json(manifestSpec.file,manifestSpec.sha256);const index=await manifest;
    const data=item.data;root.replaceChildren();
    const descriptions=[...new Set(item.names_en.map(r=>r.Desc).filter(Boolean))];for(const text of descriptions)root.append(node('p',text.replaceAll('\\n','\n').replace(/<\/?(?:SkillEffect|CC)>|<\/>/g,'')));
    const effect=index.effect_types?.[data.EffectType];
    if(index.boxes?.[id]){
      const box=await load(index.boxes[id]),panel=node('section');panel.className='stat-panel box-contents';
      panel.append(node('h3','Содержимое коробки'),node('p','Возможные награды из таблиц клиента. Строки не означают получение всех предметов сразу. Названия режимов коробки и строк подтверждены кодом клиента; условия фактической выдачи и вероятности ещё не подтверждены.'));
      if(box.key_item_id){
        const key=catalog[box.key_item_id],label=key?.names_en?.map(r=>r.Name).filter(Boolean).join(' / ')||'Предмет '+box.key_item_id;
        const line=node('p','Требуемый ключ: '),a=node('a',label);a.href='items.html?item='+encodeURIComponent(box.key_item_id);line.append(a,document.createTextNode(' · количество '+(box.key_count||'не указано')));panel.append(line);
      }
      const modeLabels={Fixed:'Фиксированная',ClassFixed:'Фиксированная по классу',Random:'Случайная',ClassRandom:'Случайная по классу',RandomEach:'Отдельный случайный выбор',Select:'На выбор',ClassSelect:'На выбор по классу'};
      const boxMode=box.reward_group_mode_verified?box.reward_group_mode:null;
      table(panel,[['Группа наград',box.record.RewardGroupId],['Режим коробки',boxMode?(modeLabels[boxMode.name]||boxMode.name)+' · '+boxMode.name+' ('+box.reward_group_type_raw+')':'Не расшифрован ('+box.reward_group_type_raw+')'],['Пути наград',box.paths.length]]);
      const list=node('div'),more=node('button','Показать ещё награды');let shown=0;
      const ordered=[...box.paths].sort((a,b)=>(window.ItemRarity?.compare(catalog[a.item_id],catalog[b.item_id])||0));
      function showMore(){
        const batch=ordered.slice(shown,shown+40);shown+=batch.length;
        for(const path of batch){
          const reward=path.reward_chain.at(-1),target=catalog[path.item_id],row=node('details'),summary=node('summary');
          const label=target?.names_en?.map(r=>r.Name).filter(Boolean).join(' / ')||(path.item_id?'Предмет '+path.item_id:'Награда типа '+reward.Type+' · '+reward.Param);
          const image=target?.icon?.images;
          if(image?.length===1){const slot=node('span');slot.className='item-icon';const bg=target?.rarity?.background?.images;if(bg?.length===1)slot.style.backgroundImage='url("../../'+bg[0].file+'")';const img=node('img');img.src='../../'+image[0].file;img.alt='';img.loading='lazy';slot.append(img);summary.append(slot);}
          summary.append(document.createTextNode(label+' · '+reward.MinCount+'–'+reward.MaxCount));row.append(summary);
          if(path.item_id){const a=node('a','Открыть характеристики предмета');a.href='items.html?item='+encodeURIComponent(path.item_id);row.append(a);}
          const rates=path.reward_chain.map(r=>r.Rate===''?'не указан':r.Rate).join(' → ');
          const modes=path.reward_chain.map(r=>{const code=r.RewardGroup,mode=index.reward_group_types?.[code];return mode?(modeLabels[mode.name]||mode.name)+' · '+mode.name+' ('+code+')':'Не расшифрован ('+(code??'не указан')+')';}).join(' → ');
          table(row,[['Тип награды (код)',reward.Type],['Режимы строк наград по цепочке',modes],['Исходные Rate по цепочке',rates],['Редкость',target?.rarity?.label||'Не определена'],['Шанс, %','Не подтверждён']]);
          raw(row,path);list.append(row);
        }
        more.hidden=shown>=ordered.length;
      }
      more.onclick=showMore;showMore();panel.append(list,more);
      if(box.issues.length)panel.append(node('p','Есть неразрешённые связи: '+box.issues.length+'. Подробности в исходных данных.'));
      if(box.record.UpgradeGroup||box.record.InstallGadgetInfoId)panel.append(node('p','В записи также есть настройки улучшения/установки. Условия их применения ещё не расшифрованы.'));
      raw(panel,box);root.append(panel);
    }
    const effectLabels={None:'Нет эффекта',Effect:'Эффект',ItemBox:'Коробка предметов',Gadget:'Объект',SkillAcquire:'Получение навыка',GachaSummon:'Призыв',SeasonPassPoint:'Очки сезонного пропуска',UnlockCharacterSlot:'Открытие ячейки персонажа',Recovery:'Восстановление',PaidSeasonPassOpen:'Открытие платного сезонного пропуска',BenefitEffect:'Бонусный эффект',PaidAttendanceOpen:'Открытие платных наград за вход',HiddenGrowth:'Скрытое развитие',GachaDirectSummmon:'Прямой призыв',TombDiggerReduceTime:'Сокращение времени TombDigger',QuestStart:'Запуск квеста',FollowerExpGain:'Опыт спутника',FollowerDrainCountRecovery:'Восстановление счётчика спутника',FollowerPotion:'Зелье спутника'};
    if(effect&&effect.name!=='None'){
      const panel=node('section');panel.className='stat-panel';panel.append(node('h3',effectLabels[effect.name]||effect.name));
      table(panel,[['Тип эффекта',effect.name+' · '+data.EffectType],['Параметры из клиента',data.EffectParams||'Не указаны']]);
      panel.append(node('p','Назначение типа подтверждено словарём клиента. Формат параметров, условия применения и итоговое действие ещё требуют проверки.'));
      if(index.item_effect_candidates?.[id])window.SkillEffects?.renderCandidate(panel,index.item_effect_candidates[id]);
      root.append(panel);
    }
    const book=index.skill_books?.[id];
    if(book){
      const section=node('section');section.className='stat-panel';section.append(node('h3','Книга навыка'));
      const catalog=node('a','Все книги навыков');catalog.href='books.html';section.append(catalog);
      section.append(node('p','Источники получения смотрите по ссылке «Источники предмета на карте». Награды области и награды NPC показаны там отдельно; наличие записи не гарантирует выпадение.'));
      if(book.relation_verified){
        if(book.skill){
          const title=book.skill_names_en.map(r=>r.Name).filter(Boolean).join(' / ')||'Навык '+book.skill_id;
          const line=node('p','Навык: '),link=node('a',title);link.href='../atlas/skills.html?skill='+encodeURIComponent(book.skill_id);
          line.append(link,document.createTextNode(' · ID '+book.skill_id));section.append(line);
        }else section.append(node('p','Книга указывает на навык '+book.skill_id+', но его запись не найдена в доступной таблице.'));
        section.append(node('p','Связь подтверждена в проверке клиента «Навык уже изучен». Доступность изучения, требования и успешное получение навыка на сервере ещё не проверены.'));
      }else if(book.candidate_skill){
        const title=book.candidate_names.map(r=>r.Name).filter(Boolean).join(' / ')||'Навык '+book.candidate_skill.Id;
        section.append(node('p','Совпадение ID: '+title+' · '+book.candidate_skill.Id+'. Параметр книги совпадает с ID навыка; изучение этого навыка ещё не подтверждено в коде клиента.'));
      }else section.append(node('p','Связь с изучаемым навыком пока не установлена.'));
      raw(section,book);root.append(section);
    }
    const properties=node('details');properties.className='product-properties';properties.append(node('summary','Все свойства предмета'));
    const enumFields={Type:'EItemType',EquipmentType:'EEquipmentType',ClassInfoId:'EClassType'};
    table(properties,Object.entries(data).filter(([key])=>key!=='provenance').map(([key,value])=>{
      let text=value===''?'Не указано':value;
      if(key==='EffectType')text=effect?(effectLabels[effect.name]||effect.name)+' · '+effect.name+' · '+value:'Тип не расшифрован · '+value;
      const e=index.enums[enumFields[key]]?.[value];if(e)text=e.name.split('::').pop()+' · '+value;
      if(key==='Rarity')text=item.rarity.label+' · '+value;
      return [labels[key]||key,text];
    }));
    const panels=node('div'),stats=node('section');panels.className='product-panels';stats.className='stat-panel';stats.append(node('h3','Характеристики'));panels.append(stats);root.append(panels);
    const enchantRestricted=(index.restrictions?.item_limits?.[data.LimitGroupId]||[]).some(r=>r.kind?.name==='DisableEnchant');
    if(enchantRestricted)stats.append(node('p','В данных указан запрет заточки. Уровни ниже показывают справочные параметры шаблона, а не доступную операцию улучшения.'));
    const enchantSpec=index.enchant_groups[data.ItemEnchantOperationGroupId];
    if(enchantSpec){
      const group=await load(enchantSpec),levels=[...new Set(group.levels.map(x=>x.row.Level))].sort((a,b)=>Number(a)-Number(b));
      const label=node('label','Уровень заточки '),select=node('select'),body=node('div');select.setAttribute('aria-label','Уровень заточки');
      for(const level of levels){const option=node('option','+'+level);option.value=level;select.append(option);}label.className='enchant-control';label.append(select);stats.append(label,node('p','Базовое значение · в скобках прибавка от заточки'),body);
      function show(){closeTooltip();body.replaceChildren();const selected=group.levels.filter(x=>x.row.Level===select.value);for(const part of selected){if(part.row.IsExtra!=='0'||part.row.OperationCategory!=='0')body.append(node('p','Отдельная строка условий: категория '+part.row.OperationCategory+', IsExtra '+part.row.IsExtra+', Index '+(part.row.Index||'—')));operations(body,part.operations,false,{part,base:group.levels.filter(x=>x.row.Level==='0')});}raw(body,selected);}
      select.onchange=show;show();
    }else stats.append(node('p',data.ItemEnchantOperationGroupId?'Связанная группа заточки не найдена.':'Группа характеристик заточки у этого предмета не задана.'));
    if(data.BlessingOperationGroupId){const blessing=node('section');blessing.className='stat-panel blessing-panel';blessing.append(node('h3','Благословение'),node('p','Дополнительные параметры'));panels.append(blessing);const spec=index.blessing_groups[data.BlessingOperationGroupId];if(spec)operations(blessing,(await load(spec)).operations);else blessing.append(node('p','Связанные строки не найдены.'));}
    if(data.PassiveSkillGroupId){
      const passive=node('section');passive.className='stat-panel passive-panel';passive.append(node('h3','Пассивные навыки'));root.append(passive);
      const spec=index.passive_groups?.[data.PassiveSkillGroupId];
      if(spec){
        const group=await load(spec);
        if(!group.skills.length)passive.append(node('p','Указана группа '+data.PassiveSkillGroupId+', но её строки в доступной таблице не найдены.'));
        for(const skill of group.skills){
          const section=node('article');section.className='passive-skill';
          const names=[...new Set(skill.names_en.map(r=>r.Name).filter(Boolean))];
          const heading=node('h4'),skillLink=node('a',names.join(' / ')||'Навык '+skill.id);skillLink.href='../atlas/skills.html?skill='+encodeURIComponent(skill.id);heading.append(skillLink);section.append(heading,node('small','ID '+skill.id+' · группа '+group.group_id));
          const texts=[...new Set(skill.names_en.flatMap(r=>[r.Description,r.EffectDescription]).filter(Boolean))];
          for(const text of texts){const p=node('p',text.replaceAll('\\n','\n').replace(/<\/?(?:SkillEffect|CC)>|<\/>/g,''));p.className='passive-description';section.append(p);}
          if(!texts.length)section.append(node('p','Описание навыка в доступной локализации не найдено.'));
          if(!skill.record)section.append(node('p','Связанная запись навыка не найдена.'));
          for(const candidate of skill.effect_candidates||[])window.SkillEffects?.renderCandidate(section,candidate);
          raw(section,skill);passive.append(section);
        }
        passive.append(node('p','Описание из английской локализации клиента. Указанные в нём проценты и длительности не вычислены из числовых полей. Активация и серверные изменения не проверены.'));
      }else passive.append(node('p','Группа '+data.PassiveSkillGroupId+' не найдена в собранных данных.'));
    }
    if(data.LimitGroupId||data.ItemUseLimitId){
      const section=node('section');section.className='stat-panel passive-panel';section.append(node('h3','Ограничения предмета'));root.append(section);
      const restrictions=index.restrictions||{},kindNames={DisableEnchant:'Запрет заточки',DisableRefinement:'Ограничение улучшения',DisableDisassembly:'Запрет разборки'};
      if(data.LimitGroupId){
        const rows=restrictions.item_limits?.[data.LimitGroupId]||[];
        if(!rows.length)section.append(node('p','Группа ограничений '+data.LimitGroupId+' указана, но связанные строки не найдены.'));
        for(const entry of rows){const name=entry.kind?.name;section.append(node('p',name?(kindNames[name]||name)+' · '+name+' · '+entry.record.LimitType:'Правило не расшифровано · '+entry.record.LimitType));}
        raw(section,{group_id:data.LimitGroupId,rows});
      }
      if(data.ItemUseLimitId){
        const use=restrictions.use_limits?.[data.ItemUseLimitId];
        if(use){
          const modeNames={UseOnly:'Только перечисленные типы',UseExcept:'Кроме перечисленных типов'},mode=use.room_mode?.name;
          table(section,[['Режим типов локаций',mode?(modeNames[mode]||mode)+' · '+mode+' · '+use.record.RoomLimitType:'Не расшифрован · '+use.record.RoomLimitType],
            ['Указанные миры · ID',use.world_ids.length?use.world_ids.join(', '):'Не указаны'],
            ['Указанные типы локаций',use.room_types.length?use.room_types.join(', '):'Не указаны']]);
          raw(section,use);
        }else section.append(node('p','Запись ограничения использования '+data.ItemUseLimitId+' не найдена.'));
      }
      section.append(node('p','Названия правил взяты из парсеров клиента. Как сочетаются списки миров и типов локаций и как сервер применяет ограничения, ещё не проверено. Отсутствие строки не доказывает отсутствие ограничений.'));
    }
    root.append(properties);root.append(node('p','Показаны параметры шаблона клиента. Уровни заточки не складываются. Условия дополнительных строк и эффекты конкретного экземпляра не вычисляются.'));
    if(index.item_crafts?.[id]){
      const data=await load(index.item_crafts[id]),panel=node('section');panel.className='stat-panel craft-origins';
      panel.append(node('h3','Из чего крафтится'),node('p','Материалы по рецептам клиента. Разные исходы показаны отдельно.'));
      const outcomes={SuccessRewardGroupId:'Успех',BigSuccessRewardGroupId:'Большой успех',FailRewardGroupId:'Неудача'},alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
      const recipeName=origin=>origin.names_en.map(r=>r.Name).filter(Boolean).join(' / ')||'Рецепт '+origin.craft.Id;
      const origins=[...data.origins].sort((a,b)=>alphabet.compare(recipeName(a),recipeName(b))||alphabet.compare(a.craft.Id,b.craft.Id)||alphabet.compare(a.outcome,b.outcome));
      const list=node('div'),more=node('button','Показать ещё рецепты');let shown=0,selectedNode;
      const selectedRecipe=new URLSearchParams(location.search).get('recipe'),selectedIndex=origins.findIndex(o=>o.craft.Id===selectedRecipe);
      function showMore(take=40){
        const batch=origins.slice(shown,shown+take);shown+=batch.length;
        for(const origin of batch){
          const recipe=node('article'),caption=node('h4'),reward=origin.reward_chain.at(-1);recipe.className='craft-recipe';
          caption.textContent=recipeName(origin)+' · '+outcomes[origin.outcome];
          const recipeHeader=node('div'),recipeIntro=node('div'),costs=node('div');recipeHeader.className='craft-recipe-header';recipeIntro.className='craft-recipe-intro';costs.className='craft-recipe-costs';recipeIntro.append(caption,node('p','Результат: '+(reward.MinCount===reward.MaxCount?reward.MinCount:reward.MinCount+'–'+reward.MaxCount)+' шт.'));recipeHeader.append(recipeIntro,costs);recipe.append(recipeHeader);
          if(origin.craft.Id===selectedRecipe&&!selectedNode)selectedNode=recipe;
          const conditions=node('details');conditions.append(node('summary','Условия и данные рецепта'));
          table(conditions,[['ID рецепта',origin.craft.Id],['Результат',outcomes[origin.outcome]],['Количество предмета',reward.MinCount+'–'+reward.MaxCount],['Уровень персонажа · CharacterLevel',origin.craft.CharacterLevel||'Не указан'],['FailRate / SuccessRate / BigSuccessRate (исходные)',[origin.craft.FailRate,origin.craft.SuccessRate,origin.craft.BigSuccessRate].map(v=>v===''?'—':v).join(' / ')],['Rate по цепочке (исходные)',origin.reward_chain.map(r=>r.Rate===''?'не указан':r.Rate).join(' → ')]]);
          if(origin.material_link_verified){
            recipe.append(node('h4','Материалы и затраты · '+origin.materials.length));
            const materials=node('div');materials.className='craft-material-grid';recipe.append(materials);
            if(!origin.materials.length)recipe.append(node('p','Связанные строки материалов не найдены. Это не означает бесплатный крафт.'));
            for(const entry of origin.materials){
              const row=entry.record,item=entry.item_target_verified?catalog[entry.item_id]:null,line=node('div'),body=node('div');line.className='craft-material-row';
              if(item){
                const label=item.names_en.map(r=>r.Name).filter(Boolean).join(' / ')||'Предмет '+entry.item_id,a=node('a',label);a.href='items.html?item='+encodeURIComponent(entry.item_id);
                const pictures=node('span');pictures.className='craft-material-icons';
                for(const image of item.icon?.images||[]){const link=node('a'),slot=node('span'),img=node('img');link.href=a.href;slot.className='item-icon';img.src='../../'+image.file;img.alt=label;img.loading='lazy';if(item.rarity?.background?.images?.length===1)slot.style.backgroundImage='url("../../'+item.rarity.background.images[0].file+'")';slot.append(img);link.append(slot);pictures.append(link);}line.append(pictures);body.append(a);
              }else body.append(node('strong',entry.item_target_verified?'Предмет '+entry.item_id+' · запись не найдена':(row.CostType==='1'?'Валюта: ':'Тип затрат '+row.CostType+': ')+({Gold:'Золото',Diamond:'Алмазы',EventDiamond:'Ивент-алмазы'}[row.CostParam]||row.CostParam||'Параметр не указан')));
              body.append(node('p','Количество по строке: '+(row.CostValue===''?'не указано':row.CostValue)));
              if(row.CostEnchantLevel!=='')body.append(node('p','Заточка материала: '+row.CostEnchantLevel+' · значение клиента'));
              line.title='Подгруппа '+row.UsingGroupId+' · строка материала '+row.Id;line.append(body);
              if(!entry.item_target_verified&&row.CostType==='1')costs.append(line);else materials.append(line);
            }
            conditions.append(node('p','Каждая строка показана отдельно. Правила подгрупп, доступность рецепта и фактическое списание сервером не проверены.'));
          }else recipe.append(node('p','Связь со списком материалов не подтверждена.'));
          raw(conditions,origin);recipe.append(conditions);list.append(recipe);
        }
        more.hidden=shown>=origins.length;
      }
      more.onclick=()=>showMore();showMore(origins.length);panel.append(list,more);root.append(panel);
      if(selectedNode)requestAnimationFrame(()=>{selectedNode.scrollIntoView({block:'start'});const summary=selectedNode.querySelector('summary');summary.focus({preventScroll:true});});
    }
    if(index.craft_uses?.[id]){
      const data=await load(index.craft_uses[id]),panel=node('section');panel.className='stat-panel craft-uses';
      const title=use=>use.names_en.map(r=>r.Name).filter(Boolean).join(' / ')||'Рецепт '+use.craft.Id,alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
      const uses=[...data.uses].sort((a,b)=>alphabet.compare(title(a),title(b))||alphabet.compare(a.craft.Id,b.craft.Id));
      panel.append(node('h3','Где используется в крафте · '+uses.length+' рецептов'),node('p','Предмет указан как материал. Количества, заточка и результаты каждой строки показаны отдельно.'));
      const list=node('div'),more=node('button','Показать ещё применения');more.type='button';let shown=0;
      const outcomes={SuccessRewardGroupId:'Успех',BigSuccessRewardGroupId:'Большой успех',FailRewardGroupId:'Неудача'};
      function showMore(){
        const batch=uses.slice(shown,shown+40);shown+=batch.length;
        for(const use of batch){
          const recipe=node('details');recipe.append(node('summary',title(use)+' · рецепт '+use.craft.Id));
          for(const entry of use.material_rows){const row=entry.record;table(recipe,[['Количество этого материала',row.CostValue===''?'Не указано':row.CostValue],['Заточка материала · значение клиента',row.CostEnchantLevel===''?'Не указана':row.CostEnchantLevel],['Подгруппа / строка материала',row.UsingGroupId+' / '+row.Id]]);}
          recipe.append(node('h4','Предметные результаты'));
          if(!use.results.length)recipe.append(node('p','Предметные результаты в каталоге не найдены. Исходные группы наград сохранены ниже.'));
          const label=result=>catalog[result.item_id]?.names_en?.map(r=>r.Name).filter(Boolean).join(' / ')||'Предмет '+result.item_id;
          const results=[...use.results].sort((a,b)=>(window.ItemRarity?.compare(catalog[a.item_id],catalog[b.item_id])||0)||alphabet.compare(label(a),label(b))||alphabet.compare(a.item_id,b.item_id)||alphabet.compare(a.outcome,b.outcome));
          for(const result of results){const line=node('div'),reward=result.reward_chain.at(-1);line.className='craft-result-row';itemReference(line,result.item_id,catalog,'items.html?item='+encodeURIComponent(result.item_id)+'&recipe='+encodeURIComponent(use.craft.Id));line.append(node('p',(outcomes[result.outcome]||result.outcome)+' · количество '+reward.MinCount+'–'+reward.MaxCount));recipe.append(line);}
          raw(recipe,use);list.append(recipe);
        }
        more.hidden=shown>=uses.length;
      }
      more.onclick=showMore;showMore();panel.append(list,more,node('p','Наличие рецепта не подтверждает его доступность и успешный крафт на сервере. Правила подгрупп и шансы не установлены.'));root.append(panel);
      window.CatalogData?.autoMore(more,showMore);
    }
    if(index.box_sources?.[id]?.length){
      const panel=node('section');panel.className='stat-panel';panel.append(node('h3','В каких коробках указан предмет'),node('p','Это записи содержимого коробок из клиента. Наличие записи не гарантирует получение предмета.'));
      const list=node('div'),more=node('button','Показать ещё коробки');let shown=0;
      const boxName=id=>catalog[id]?.names_en?.map(r=>r.Name).filter(Boolean).join(' / ')||'Коробка '+id;
      const alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
      const sources=[...index.box_sources[id]].sort((a,b)=>
        (window.ItemRarity?.compare(catalog[a.box_item_id],catalog[b.box_item_id])||0)
        ||alphabet.compare(boxName(a.box_item_id),boxName(b.box_item_id))
        ||alphabet.compare(a.box_item_id,b.box_item_id));
      function showMore(){
        const batch=sources.slice(shown,shown+40);shown+=batch.length;
        for(const source of batch){
          const box=catalog[source.box_item_id],line=node('p'),label=boxName(source.box_item_id),a=node('a');
          line.className='box-source-row';a.className='box-source-link';a.href='items.html?item='+encodeURIComponent(source.box_item_id);
          const icons=node('span');icons.className='box-source-icons';
          const images=box?.icon?.images||[],backgrounds=box?.rarity?.background?.images;
          for(const image of images){
            const slot=node('span'),img=node('img');slot.className='item-icon';
            if(backgrounds?.length===1)slot.style.backgroundImage='url("../../'+backgrounds[0].file+'")';
            if(images.length>1)slot.title='Вариант изображения: '+image.file;
            img.src='../../'+image.file;img.alt='';img.loading='lazy';
            img.onerror=()=>{img.remove();slot.textContent='?';slot.title='Не удалось загрузить изображение коробки';};
            slot.append(img);icons.append(slot);
          }
          if(!images.length){const slot=node('span','?');slot.className='item-icon';slot.title='Изображение коробки не найдено в доступных данных';icons.append(slot);}
          a.append(icons,node('span',label));const count=node('span','путей награды '+source.path_count);count.className='box-source-count';
          line.append(a,count);list.append(line);
        }
        more.hidden=shown>=sources.length;
      }
      more.onclick=showMore;showMore();panel.append(list,more);root.append(panel);
    }
    raw(root,{item:data.provenance,joins:index.joins,sources:index.sources,native_source:index.native_source,passive_diagnostics:index.passive_diagnostics,effect_sources:index.effect_sources,limit_diagnostics:index.limit_diagnostics,limit_semantics_source:index.limit_semantics_source,limitations:index.limitations});
  }
  return {render};
})();
