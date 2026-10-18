/* Shared source-backed skill card for catalogue and map. */
window.SkillCard=(()=>{
'use strict';
function el(tag,text,className){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;}
function link(text,href){const node=el('a',text);node.href=href;return node;}
const fireConditionNames={ActorType:'Тип действующего персонажа',AddEffect:'Добавление эффекта',
  AggroCountDecreaseForEffect:'Уменьшение счётчика агрессии для эффекта',AggroCountIncrease:'Увеличение счётчика агрессии',AggroCountReset:'Сброс счётчика агрессии',
  AllyNpcDied:'Смерть союзного NPC',Always:'Всегда',AttackSuccess:'Успешная атака',AttackSuccessLowLevel:'Успешная атака · LowLevel',
  ConditionAlwaysBegin:'Служебная граница ConditionAlwaysBegin',ConditionAlwaysEnd:'Служебная граница ConditionAlwaysEnd',
  CriticalSuccess:'Успешный критический удар',Damaged:'Получение урона',DamagedAffliction:'Получение урона · Affliction',
  DamagedCrowdControl:'Получение урона · CrowdControl',DamagedDebuff:'Получение урона · Debuff',DamagedKnockdown:'Получение урона · Knockdown',
  DamagedLowLevel:'Получение урона · LowLevel',DamagedRate:'Получение урона · Rate',DeadlyKillSuccess:'Успешное убийство · Deadly',
  DeadlySuccess:'Успешное срабатывание Deadly',DodgeSuccess:'Успешное уклонение',EnemyNpcDied:'Смерть вражеского NPC',
  HaveBarrier:'Наличие барьера',HaveBuffCategory:'Наличие категории усиления',KillSuccess:'Успешное убийство',Revive:'Воскрешение',
  SelfDied:'Смерть владельца',SelfHpRate:'Доля собственного HP',SelfHpValue:'Значение собственного HP',
  TargetAffliction:'Состояние цели · Affliction',TargetHaveBuffCategory:'Наличие категории усиления у цели',TargetHpRate:'Доля HP цели',
  TargetHpValue:'Значение HP цели',TargetInCollisionArea:'Цель в области столкновения',UseSkill:'Применение навыка',
  UseSkillCategory:'Применение категории навыков',UseSkillDetailType:'Применение подтипа навыка',UseSpecificSkill:'Применение конкретного навыка',
  WeaknessPointZero:'Нулевое значение WeaknessPoint'};
const skillTargetNames={All:'Все',Child:'Дочерний объект',Enemy:'Противник',Friend:'Союзник',Guild:'Гильдия',
  GuildSelfExcept:'Гильдия, кроме себя',MasterParty:'Группа владельца',Others:'Другие',Owner:'Владелец',
  Party:'Группа',PartySelfExcept:'Группа, кроме себя',PartySum:'PartySum',Raid:'Рейд',RaidSelfExcept:'Рейд, кроме себя',Self:'Сам персонаж'};
const skillTargetConditionNames={Character:'Персонаж',Died:'Погибшая цель',Farthest:'Самая дальняя цель',Gadget:'Объект',
  GuildMaster:'Глава гильдии',HaveEffect:'Наличие эффекта',HaveEffectGroup:'Наличие группы эффектов',HighAttackPower:'Высокая атака',
  HighHpRate:'Высокая доля HP',IgnoreJump:'IgnoreJump',LowHpRate:'Низкая доля HP',NotHaveEffect:'Отсутствие эффекта',
  Npc:'NPC',NpcGrade:'Ранг NPC',Random:'Случайный выбор'};
function skillTargetLabel(detail, raw, condition=false) {
  if(!detail?.name)return raw===''||raw==null?'Не указано':'Не расшифровано · '+raw+(detail?.status==='parser_fallback'?' (значение парсера для неизвестного ключа)':'');
  const name=(condition?skillTargetConditionNames:skillTargetNames)[detail.name]||detail.name;
  return name+(name===detail.name?'':' · '+detail.name)+' · '+raw;
}
function facts(parent, pairs) {
    const list=el('dl',undefined,'battleFacts');
    for(const [label,value,hint]of pairs){
      const term=el('dt',label),definition=el('dd',value===''||value==null?'Не указано':String(value));
      if(hint){term.title=hint;definition.title=hint;term.tabIndex=0;}
      list.append(term,definition);
    }
    parent.append(list);
  }

function renderSkillLevels(parent,skill){
  const changes=skill.level_overrides;
  if(!changes?.records.length)return;
  const section=el('section',undefined,'skillLevels');section.append(el('h4','Изменения по уровню навыка'));
  const label=el('label','Сравнить уровень: '),input=el('input'),result=el('div');
  input.type='number';input.min='0';input.max='32767';input.step='1';input.required=true;input.value=changes.records[0].MinLevel;
  label.append(input);section.append(label,result);
  function show(){
    result.replaceChildren();
    try{
      const compared=WorldMapModel.skillValuesAtLevel(skill,input.value===''?NaN:Number(input.value));
      facts(result,['MinCoolTime','MaxCoolTime'].map(field=>[
        field==='MinCoolTime'?'Перезарядка · минимум':'Перезарядка · максимум',
        WorldMapModel.cooldownValue(compared.values[field],skill.cooldown_time_unit)+' · '+compared.origins[field].table+'.'+compared.origins[field].field
      ]));
      const extraNames={Resource:'Ресурс навыка',StackCount:'StackCount · исходный счётчик',MpMin:'MP · исходный минимум',MpMax:'MP · исходный максимум'};
      facts(result,Object.keys(extraNames).filter(field=>Object.hasOwn(compared.values,field)).map(field=>[
        extraNames[field],(compared.values[field]||'Не указано')+' · '+compared.origins[field].table+'.'+compared.origins[field].field
      ]));
      result.append(el('p',compared.selected_record?'Выбрана первая строка SkillLevel с включёнными границами '+compared.selected_record.MinLevel+'–'+compared.selected_record.MaxLevel+'. Нулевые или пустые поля перезарядки возвращают базовое значение.':'Для этого уровня нет подходящей строки SkillLevel; показаны базовые значения.','muted'));
    }catch(error){result.append(el('p',error.message));}
  }
  input.oninput=show;show();
  const raw=el('details');raw.append(el('summary','Все строки изменений · исходные поля'));
  for(const record of changes.records){
    const row=el('section');row.append(el('h4','Уровни '+record.MinLevel+'–'+record.MaxLevel));
    facts(row,Object.entries(record).filter(([field,value])=>field!=='provenance'&&field!=='SkillInfoId'&&field!=='MinLevel'&&field!=='MaxLevel'&&value!=='').map(([field,value])=>[field,value]));
    raw.append(row);
  }
  section.append(raw,el('p','Подтверждены правила замены MinCoolTime/MaxCoolTime, Resource, StackCount и MpMin/MpMax. Остальные Change-поля сохранены без расчёта. Значение счётчика не трактуется как доказанное число зарядов. Формула роста и фактический расход MP, доступность выбранного уровня, модификаторы и итоговая перезарядка в игре не проверены.','muted'));parent.append(section);
}
function renderSkillRestrictions(parent,record){
  const section=el('details',undefined,'skillRestrictions');section.append(el('summary','Класс и ограничения применения'));
  const rawFlag=value=>value==='1'?'Включён · 1':value==='0'?'Выключен · 0':value||'Не указано';
  facts(section,[
    ['Класс · ClassType',record.ClassType,'Исходная строка Skill.ClassType. Точная проверка класса персонажа ещё не восстановлена.'],
    ['Исключённые типы локаций · UnusableRoomType',record.UnusableRoomType,'Список из Skill.UnusableRoomType сохранён в порядке клиента. Серверное применение и сочетание с UsableWorldId не проверены.'],
    ['Миры применения · UsableWorldId',record.UsableWorldId,'Исходное поле Skill.UsableWorldId. Пустая строка не доказывает доступность во всех мирах.'],
    ['Флаг запрета в бою · UnusableCombat',rawFlag(record.UnusableCombat)],
    ['Флаг применения под контролем · UsableWhileCrowdControl',rawFlag(record.UsableWhileCrowdControl)],
    ['Флаг блокировки автоиспользования · LockAutoUse',rawFlag(record.LockAutoUse)],
    ['Группа стоимости повышения уровня',record.SkillLevelUpCostGroupId,'Skill.SkillLevelUpCostGroupId. Это поле повышения уровня, не подтверждённая цена первого изучения.']
  ]);
  section.append(el('p','Показаны исходные настройки применения навыка. Допуск по классу, сочетание ограничений и серверные проверки ещё не восстановлены. Требуемый уровень персонажа и цена первого изучения в доступной записи не установлены.','muted'));
  parent.append(section);
}
function renderSkillImages(parent,skill){
  const icon=skill?.images?.Img,background=skill?.images?.ImgBg;
  if(!icon?.images.length)return;
  const images=el('div',undefined,'skillPortraits');
  for(const image of icon.images){
    const a=link('', '../../'+image.file),slot=el('span',undefined,'skillPortrait'),img=el('img');
    a.target='_blank';a.rel='noopener';
    if(background?.images.length===1)slot.style.backgroundImage='url("../../'+background.images[0].file+'")';
    img.src='../../'+image.file;img.alt='Иконка навыка '+skill.id;img.loading='lazy';
    a.title=image.asset_path;slot.append(img);a.append(slot);images.append(a);
  }
  parent.append(images);
  if(icon.images.length>1)parent.append(el('p','Для Img найдены разные пути ресурса: показаны все варианты.','muted'));
  if(background?.images.length>1)parent.append(el('p','Фон ImgBg неоднозначен и не подставлен.','muted'));
}
function renderSkillDetail(parent,skill,id,showMissingBooks=false){
  const record=skill?.record,box=el('section',undefined,'npcSkill');
  const displayNames=skill?.display_names||[];
  const names=displayNames.length?displayNames.map(n=>n.text):[...new Set((skill?.names_en||[]).map(n=>n.Name).filter(Boolean))];
  renderSkillImages(box,skill);
  box.append(el('h4',names.join(' / ')||'Навык '+id),el('small','ID '+id+(record?.Resource?' · '+record.Resource:'')));
  if(!showMissingBooks){
    box.append(link('Открыть карточку навыка','skills.html?skill='+encodeURIComponent(id)));
  }
  for(const name of displayNames.filter(n=>n.language==='ko'))box.append(el('p',
    (name.translated?'Перевод подписи клиента':'Корейское название клиента')+' · KO: '+name.original+
    (name.source_marked?' · В источнике помечено ###.':''),'muted'));
  for(const text of [...new Set((skill?.names_en||[]).flatMap(n=>[n.Description,n.EffectDescription]).filter(Boolean))]){
    const description=el('p'),parts=text.replaceAll('\\n','\n').split(/(<(?:SkillEffect[0-9]*|CC)>|<\/>)/g);let emphasis=false;
    for(const part of parts){if(/^<(?:SkillEffect[0-9]*|CC)>$/.test(part))emphasis=true;else if(part==='</>')emphasis=false;else description.append(el(emphasis?'strong':'span',part));}
    box.append(description);
    if(/\{[^}]+\}/.test(text))box.append(el('p','В описании сохранены подстановки клиента в фигурных скобках; их значения ещё не рассчитаны.','muted'));
  }
  if(skill?.books?.length)renderSkillBooks(box,skill.books);
  if(skill?.passive_items?.length)renderSkillBooks(box,skill.passive_items,true);
  if(!record){box.append(el('p','Запись навыка в доступной таблице не найдена.'));parent.append(box);return;}
  if(!names.length)box.append(el('p','Название в доступных английской и корейской таблицах клиента не задано.', 'muted'));
  const overview=box,parameters=el('details',undefined,'skillParameters');parameters.append(el('summary','Параметры и действия навыка'));overview.append(parameters);const body=el('div');parameters.append(body);
  // Keep source parameters accessible without pushing the map below the full technical card.
  renderSkillParameters(body,skill,record);parent.append(overview);
}
function renderSkillParameters(box,skill,record){
  renderSkillRestrictions(box,record);
  renderSkillLevels(box,skill);
  const condition=skill.fire_condition;
  const conditionLabel=condition?.name ? (fireConditionNames[condition.name]||condition.name)+' · '+record.FireCondition : 'Не расшифровано · '+record.FireCondition;
  facts(box,[['Базовая перезарядка · минимум / максимум',[record.MinCoolTime,record.MaxCoolTime].map(v=>WorldMapModel.cooldownValue(v,skill.cooldown_time_unit)).join(' / ')],
    ['TotalTime · исходное значение',record.TotalTime,'Поле Skill.TotalTime из таблицы клиента. Единицы и связь с длительностью выполнения навыка ещё не подтверждены. Это не перезарядка.'],['Дальность применения',record.MaxCastDistance],['Дальность ИИ',record.AiMaxCastDistance],
    ['Расход MP · минимум / максимум',[record.MpMin,record.MpMax].map(v=>v||'—').join(' / ')],
    ['Цель навыка',skillTargetLabel(skill.target,record.TargetType)],['Условие применения',conditionLabel]]);
  if(condition?.name)box.append(el('p','Ключ клиента: '+condition.name+'. Название подтверждено; точная проверка условия ещё не восстановлена.','muted'));
  if(condition?.status==='parser_fallback')box.append(el('p','Код 43 совпадает со значением, возвращаемым парсером для неизвестного ключа. Его поведение при применении навыка не установлено.','muted'));
  if(condition?.parameters.some(v=>v!==''&&v!=='0'))facts(box,[['Параметры условия · исходные 1 / 2 / 3',condition.parameters.map(v=>v===''?'—':v).join(' / ')]]);
  const operations=skill.operations||[];
  for(const operation of operations){
    const row=operation.record,key=operation.operation_enum?.name.split('::').pop();
    const effect=el('div',undefined,'skillEffect');effect.append(el('strong',key==='Damage'?'Нанесение урона':key||'Действие '+row.OperationType));
    facts(effect,[['Тип действия',row.OperationType],['Цель действия',skillTargetLabel(operation.target,row.TargetType)],
      ['Выбор цели',skillTargetLabel(operation.target_condition,row.TargetConditionType,true)],
      ['Индекс попадания',row.HitIndex],['Параметры 1 / 2 / 3 / 4',[row.OperationParam1,row.OperationParam2,row.OperationParam3,row.OperationParam4].map(v=>v||'—').join(' / ')]]);
    window.SkillEffects?.renderCandidate(effect,operation.effect_candidate);box.append(effect);
  }
  if(skill.cooldown_time_unit==='milliseconds')box.append(el('p','Базовая перезарядка переведена в секунды по коду таймера клиента. Итоговое время с учётом зарядов и модификаторов монстра не рассчитано.','muted'));
  box.append(el('p','Названия целей подтверждены словарями клиента; точные правила выбора ещё не восстановлены. Длительность и параметры действий сохранены в исходных единицах. Формула урона, смысл параметров условий и единицы остальных длительностей ещё не восстановлены.', 'muted'));
  const raw=el('details');raw.append(el('summary','Исходные строки навыка'),el('pre',JSON.stringify(skill,null,2)));box.append(raw);
}

function renderSkillBooks(parent,books,passive=false){
  const section=el('section',undefined,'skillBooks');section.append(el('h4',(passive?'Предметы с этим пассивным навыком':'Книги изучения')+' · '+books.length));
  if(!books.length){section.append(el('p','Подтверждённые ссылки на книги в доступных данных не найдены.','muted'));parent.append(section);return;}
  const alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
  const sorted=[...books].sort((a,b)=>ItemRarity.compare(a,b)||alphabet.compare(a.label,b.label)||alphabet.compare(a.item_id,b.item_id));
  for(const book of sorted){
    const row=el('div',undefined,'skillBook'),info=el('div'),icons=el('span',undefined,'skillBookIcons');
    const product='../loot/items.html?item='+encodeURIComponent(book.item_id);
    for(const image of book.icon?.images||[]){
      const a=link('',product),slot=el('span',undefined,'item-icon'),img=el('img');
      const backgrounds=book.rarity?.background?.images||[];
      if(backgrounds.length===1)slot.style.backgroundImage='url("../../'+backgrounds[0].file+'")';
      img.src='../../'+image.file;img.alt=book.label;img.loading='lazy';slot.append(img);a.append(slot);icons.append(a);
    }
    if(!icons.childNodes.length)icons.append(el('span','?','item-icon'));
    info.append(link(book.label,product),el('p',(book.rarity?.label||'Редкость не определена')+' · ID '+book.item_id,'muted'),
      link('Источники на карте','index.html?item='+encodeURIComponent(book.item_id)));
    if(passive)info.append(el('p','Группа пассивов '+book.group_id+' · строк SkillSet: '+book.set_records.length,'muted'));
    row.append(icons,info);section.append(row);
  }
  section.append(el('p',passive
    ?'Подтверждены связи таблиц Item.PassiveSkillGroupId → SkillSet.GroupId → Skill.Id. Условия активации пассива и серверные изменения ещё не проверены. Подробные свойства и ограничения смотрите в карточке предмета.'
    :'Связь книги с целевым навыком подтверждена кодом клиента. Условия изучения и фактическая доступность источников ещё не проверены. Коробки и крафт смотрите в карточке книги.','muted'));
  parent.append(section);
}

return {render:renderSkillDetail,facts,images:renderSkillImages};
})();
