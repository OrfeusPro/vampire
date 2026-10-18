(function(root,factory){if(typeof module==='object'&&module.exports)module.exports=factory();else root.AttributesModel=factory();})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';
  const number=v=>/^\d+$/.test(String(v))?Number(v):Infinity;
  const cmp=(a,b)=>a===b?0:a<b?-1:1;
  function select(entries,filters={}){
    const q=(filters.q||'').trim().toLocaleLowerCase();
    return entries.filter(e=>(!filters.tab||filters.tab==='all'||e.tab_id===filters.tab)
      &&(!filters.unit||filters.unit==='all'||(filters.unit==='percent'?e.row.IsPercentage==='1':e.row.IsPercentage==='0'))
      &&(!q||[e.id,e.name,e.description,e.enum?.name,e.row.StatType].join(' ').toLocaleLowerCase().includes(q)))
      .sort((a,b)=>cmp(number(a.tab_id),number(b.tab_id))||cmp(number(a.group?.GroupOrder),number(b.group?.GroupOrder))
        ||cmp(number(a.row.DisplayOrder),number(b.row.DisplayOrder))||cmp(number(a.id),number(b.id)));
  }
  function neighborhood(entries,relations,id){
    const known=new Set(entries.map(e=>e.id)),valid=relations.filter(r=>known.has(r.source)&&known.has(r.target));
    return {incoming:valid.filter(r=>r.kind==='modifier'&&r.target===id),
      outgoing:valid.filter(r=>r.kind==='modifier'&&r.source===id),
      opposed:valid.filter(r=>r.kind==='opposed'&&(r.source===id||r.target===id))};
  }
  function weightedContribution(value,weight){
    if(weight===''||weight===null||weight===undefined)return {status:'unknown_weight'};
    if(!/^-?\d+$/.test(String(value))||!/^-?\d+$/.test(String(weight)))return {status:'invalid'};
    const v=Number(value),w=Number(weight);
    if(!Number.isInteger(v)||v< -2147483648||v>2147483647||w< -32768||w>32767)return {status:'invalid'};
    const result=Math.floor(Math.fround(Math.fround(v)*Math.fround(w)));
    if(result< -2147483648||result>2147483647)return {status:'out_of_range'};
    return {status:'known',result:result===0?0:result};
  }
  return {select,neighborhood,weightedContribution};
});
