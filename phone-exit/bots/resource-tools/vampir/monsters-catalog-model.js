(function(root){
  'use strict';
  function level(row){return /^\d+$/.test(row.level)?Number(row.level):null;}
  function select(rows,options){
    const q=(options.query||'').trim().toLowerCase(),min=options.min==null||options.min===''?null:Number(options.min),max=options.max==null||options.max===''?null:Number(options.max);
    const alphabet=new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
    return rows.filter(row=>{
      const value=level(row);
      return (!q||(row.id+' '+row.name+' '+row.world_ids.join(' ')).toLowerCase().includes(q))
        &&(!options.images||options.images==='all'||(options.images==='yes'?!!row.portraits?.images?.length:!row.portraits?.images?.length))
        &&(!options.dropsOnly||row.drop_item_count>0)
        &&(!options.world||options.world==='all'||row.world_ids.includes(options.world))
        &&(min===null||value!==null&&value>=min)&&(max===null||value!==null&&value<=max);
    }).sort((a,b)=>{
      const x=level(a),y=level(b);
      return (options.sort==='name'?0:x===null&&y!==null?1:y===null&&x!==null?-1:options.sort==='level-desc'?(y??0)-(x??0):(x??0)-(y??0))
        ||alphabet.compare(a.name,b.name)||alphabet.compare(a.id,b.id);
    });
  }
  const api={select,level};root.MonstersCatalogModel=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
