(function(root){
  'use strict';
  function matches(info,key){
    if(key==='all')return true;
    if(key==='unknown')return !info||info.status==='unknown'||info.status==='conflict';
    return info?.status==='all'||info?.status==='specified'&&info.keys.includes(key);
  }
  function label(info,classes){
    if(info?.status==='all')return 'Все классы';
    if(info?.status==='conflict')return 'Данные класса расходятся';
    if(info?.status!=='specified')return 'Класс не указан';
    return info.keys.map(key=>classes.find(c=>c.key===key)?.label||key).join(' / ');
  }
  const api={matches,label};root.CatalogClasses=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
