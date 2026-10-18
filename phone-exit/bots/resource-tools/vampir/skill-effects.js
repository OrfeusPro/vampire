/* Deliberately separate ID matches from proven skill/effect relations. */
window.SkillEffects=(()=>{
  const el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
  function renderCandidate(parent,candidate){
    if(!candidate)return;
    const box=el('details');box.className='skill-effect-candidate';
    box.append(el('summary','Связь-кандидат с эффектом '+candidate.effect_id+' · не подтверждена'));
    box.append(el('p',candidate.origin==='item'
      ?'Item.EffectParams совпадает с ID эффекта. Связь в коде ещё не доказана; запись ниже не считается установленным эффектом предмета.'
      :'Параметр 1 действия Effect совпадает с ID эффекта. Назначение параметра в коде ещё не доказано; запись ниже не считается установленным эффектом навыка.'));
    const effect=candidate.effect;
    if(!effect){box.append(el('p','Определение с этим ID в доступной таблице не найдено.'));parent.append(box);return;}
    const row=effect.record,type=effect.type_enum?.name.split('::').pop();
    const actionNames={None:'Не задано',Stun:'Оглушение',Fear:'Страх',Frozen:'Заморозка',Blind:'Ослепление',
      Silence:'Безмолвие',Sleep:'Сон',Stealth:'Скрытность',Invisible:'Невидимость',KnockBack:'Отбрасывание',
      KnockDown:'Сбивание с ног',KnockUp:'Подбрасывание',Unmovable:'Запрет движения',UnusableHpPotion:'Запрет зелий HP',
      UnusableEvasionSkill:'Запрет навыка уклонения',NpcInvincible:'Неуязвимость NPC',MindControl:'Контроль разума'};
    const action=effect.action;
    const actionLabel=action?.name?(actionNames[action.name]||action.name)+(actionNames[action.name]?' · '+action.name:'')+' · '+row.ActionType:
      'Не расшифровано · '+(row.ActionType||'—')+(action?.status==='parser_fallback'?' (значение парсера для неизвестного ключа)':'');
    function ruleLabel(rule){return rule?.name?rule.name+' · '+rule.value:'Не расшифровано · '+(rule?.value||'—')+(rule?.status==='parser_fallback'?' (значение парсера для неизвестного ключа)':'');}
    const list=el('dl');
    for(const [label,value]of [['Тип',type?type+' · '+row.Type:row.Type],['Подтип · BuffType',ruleLabel(effect.buff_type)],
      ['Режим наложения · OverlayType',ruleLabel(effect.overlay_type)],['Действие · ActionType',actionLabel],
      ['Параметр действия · без интерпретации',row.ActionParam],['Длительность · исходное поле',row.Duration],
      ['MinDuration / MaxDuration',[row.MinDuration,row.MaxDuration].map(v=>v===''?'—':v).join(' / ')],
      ['DurationGrowthRate · исходное поле',row.DurationGrowthRate],
      ['Период · исходное поле',row.Period],['Число слоёв',row.StackCount],['Типы локаций активации',row.EffectActivateRoomType],
      ['Исключённые типы локаций',row.ExceptRoomType],['ItemUseLimitId',row.ItemUseLimitId],
      ['При истечении · исходное поле',row.ApplyEffectOnExpiration],['Параметр истечения · без интерпретации',row.ApplyEffectOnExpirationParam1]]){list.append(el('dt',label),el('dd',value===''||value==null?'Не указано':value));}
    box.append(list);
    if(effect.timing?.duration_outside_bounds)box.append(el('p','Duration находится вне MinDuration / MaxDuration. Все поля показаны отдельно; правило выбора длительности в коде ещё не восстановлено.'));
    for(const action of effect.operations){
      const name=action.operation_enum?.name.split('::').pop(),labels={Stun:'Оглушение',DamageMultiplier:'Множитель урона'};
      box.append(el('p','Действие эффекта: '+(labels[name]?labels[name]+' · ':'')+(name||'Не расшифровано')+' · '+action.record.OperationType));
      box.append(el('p','Параметры 1–5: '+[1,2,3,4,5].map(i=>action.record['OperationParam'+i]||'—').join(' / ')));
    }
    box.append(el('p','Имена режимов подтверждены парсерами. Накопление, обновление длительности, приоритет и действия по истечении не вычисляются. Единицы времени и масштаб параметров неизвестны.'));
    const raw=el('details');raw.append(el('summary','Исходные строки эффекта'),el('pre',JSON.stringify(candidate,null,2)));box.append(raw);parent.append(box);
  }
  return {renderCandidate};
})();
