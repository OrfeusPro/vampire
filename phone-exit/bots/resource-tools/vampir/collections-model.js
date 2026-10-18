(function(root,factory){if(typeof module==='object'&&module.exports)module.exports=factory();else root.CollectionsModel=factory();})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';
  const alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
  const order=new Map(['5','4','3','2','1','0','100','101'].map((id,i)=>[id,i]));
  const ascending=new Map(['0','1','2','3','4','5','100','101'].map((id,i)=>[id,i]));
  const bonusName=b=>b.name?.Name||b.enum?.name?.split('::').pop()||'Параметр '+b.row.Type;
  const bonusValue=b=>b.row.Min===b.row.Max?b.row.Min:b.row.Min+'–'+b.row.Max;
  const ordinal=value=>/^\d+$/.test(String(value))&&Number.isSafeInteger(Number(value))?Number(value):Infinity;
  const compareOrdinal=(a,b)=>a===b?0:a<b?-1:1;
  function compare(a,b,sort){
    if(sort==='name')return alphabet.compare(a.name,b.name)||alphabet.compare(a.id,b.id);
    if(sort==='rank')return (order.get(a.row.Rarity)??8)-(order.get(b.row.Rarity)??8)||alphabet.compare(a.name,b.name)||alphabet.compare(a.id,b.id);
    if(sort!=='source')return (ascending.get(a.row.Rarity)??8)-(ascending.get(b.row.Rarity)??8)
      ||compareOrdinal(ordinal(a.row.DisplayOrder),ordinal(b.row.DisplayOrder));
    // Equal DisplayOrder retains the CSV sequence (stable Array.sort), not a guessed game tie-break.
    return compareOrdinal(ordinal(a.row.CollectionTabId),ordinal(b.row.CollectionTabId))
      ||compareOrdinal(ordinal(a.row.DisplayOrder),ordinal(b.row.DisplayOrder));
  }
  function select(entries,items,filters={}){
    const q=(filters.q||'').trim().toLocaleLowerCase();
    return entries.filter(e=>(!filters.tab||filters.tab==='all'||e.row.CollectionTabId===filters.tab)
      &&(!filters.rarity||filters.rarity==='all'||e.row.Rarity===filters.rarity)
      &&(!filters.bonus||filters.bonus==='all'||e.bonuses.some(b=>b.row.Type===filters.bonus))
      &&(!q||[e.id,e.name,...e.requirements.flatMap(r=>[r.row.CollectParam,items[r.item_id]?.name||'']),...e.bonuses.map(bonusName)].join(' ').toLocaleLowerCase().includes(q)))
      .sort((a,b)=>compare(a,b,filters.sort));
  }
  return {select,bonusName,bonusValue};
});
