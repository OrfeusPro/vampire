const SkillsCatalogModel=(()=>{
  function isPlaceholder(entry){
    const names=(entry.display_names||[]).map(n=>(n.text||'').trim()).filter(Boolean);
    return names.length>0&&names.every(name=>/^\d{4}-\d{2}-\d{2} Registered$/i.test(name));
  }
  function matchesRelation(entry,relation='all'){
    const npcs=entry.all_npc_ids||entry.npc_ids||[];
    if(relation==='npcs')return npcs.length>0;
    if(npcs.length)return false;
    if(relation==='service')return isPlaceholder(entry);
    if(isPlaceholder(entry))return false;
    if(relation==='books')return entry.book_count>0;
    if(relation==='items')return entry.passive_item_count>0;
    return relation==='all';
  }
  const alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
  function compare(a,b,metadata={},sort='rank'){
    if(sort!=='name'){
      const grade=entry=>{const raw=metadata[entry.id]?.rarity_raw;return raw!==undefined&&raw!==null&&String(raw).trim()!==''&&/^[0-5]$/.test(String(raw))?Number(raw):null;};
      const x=grade(a),y=grade(b);
      if(x===null&&y!==null)return 1;if(x!==null&&y===null)return -1;
      if(x!==null&&y!==null&&x!==y)return sort==='rank-asc'?x-y:y-x;
    }
    const name=entry=>entry.display_names?.map(n=>n.text).join(' / ')||'Навык '+entry.id;
    return alphabet.compare(name(a),name(b))||alphabet.compare(String(a.id),String(b.id));
  }
  return {matchesRelation,isPlaceholder,compare};
})();
if(typeof module!=='undefined')module.exports=SkillsCatalogModel;
