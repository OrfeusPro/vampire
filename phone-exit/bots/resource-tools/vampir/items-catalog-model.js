/* Filters describe explicit client fields; they never evaluate item activation. */
const ItemsCatalogModel=(()=>{
  const labels={None:'Нет эффекта',Effect:'Эффект',ItemBox:'Коробка предметов',Gadget:'Объект',SkillAcquire:'Получение навыка',GachaSummon:'Призыв',SeasonPassPoint:'Очки сезонного пропуска',UnlockCharacterSlot:'Открытие ячейки персонажа',Recovery:'Восстановление',PaidSeasonPassOpen:'Платный сезонный пропуск',BenefitEffect:'Бонусный эффект',PaidAttendanceOpen:'Платные награды за вход',HiddenGrowth:'Скрытое развитие',GachaDirectSummmon:'Прямой призыв',TombDiggerReduceTime:'Сокращение времени TombDigger',QuestStart:'Запуск квеста',FollowerExpGain:'Опыт спутника',FollowerDrainCountRecovery:'Восстановление счётчика спутника',FollowerPotion:'Зелье спутника'};
  const declared=value=>value!==undefined&&value!==null&&String(value).trim()!=='';
  function flags(item){const data=item.data||{};return {passive:declared(data.PassiveSkillGroupId),limits:declared(data.LimitGroupId)||declared(data.ItemUseLimitId)};}
  function matches(item,filters={}){
    const f=flags(item);
    if(filters.effect&&filters.effect!=='all'&&item.data?.EffectType!==filters.effect)return false;
    for(const key of ['passive','limits'])if(filters[key]==='yes'&&!f[key]||filters[key]==='no'&&f[key])return false;
    return true;
  }
  function effectLabel(value,types={}){const entry=types[value];return entry?(labels[entry.name]||entry.name)+' · '+value:declared(value)?'Тип не расшифрован · '+value:'Тип не указан';}
  function sourceNpcIds(origins=[]){return [...new Set(origins.map(row=>row.npc_id).filter(Boolean).map(String))];}
  function matchesSource(origins,source='all'){const hasNpc=sourceNpcIds(origins).length>0;return source==='npcs'?hasNpc:source==='no-npcs'?!hasNpc:true;}
  function bookKind(book){return book?.relation_verified===true&&book.target&&['active','passive'].includes(book.kind)?book.kind:'unknown';}
  function matchesBookKind(book,kind='all'){return kind==='all'||bookKind(book)===kind;}
  function bookSkillName(book){return [...new Set((book?.target?.display_names||[]).map(n=>n.text).filter(Boolean))].join(' / ')||'Навык '+book?.target?.id;}
  function sourceMapUrl(id){return '../atlas/world.html?item='+encodeURIComponent(id);}
  return {flags,matches,effectLabel,sourceNpcIds,matchesSource,bookKind,matchesBookKind,bookSkillName,sourceMapUrl};
})();
if(typeof module!=='undefined')module.exports=ItemsCatalogModel;
