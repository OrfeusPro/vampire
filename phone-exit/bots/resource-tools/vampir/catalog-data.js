window.CatalogData={async json(url,hash){const response=await fetch(url,{cache:'no-cache'});if(!response.ok)throw Error(url+' · HTTP '+response.status);const bytes=await response.arrayBuffer();if(hash){const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(v=>v.toString(16).padStart(2,'0')).join('');if(digest!==hash)throw Error('Изменился SHA256: '+url);}return JSON.parse(new TextDecoder().decode(bytes));},node(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}};

CatalogData.restoreList=function(grid){const key=()=>"vampir-list:"+location.pathname+location.search;try{const y=Number(sessionStorage.getItem(key()));if(y>0)requestAnimationFrame(()=>window.scrollTo(0,y));}catch{}grid.addEventListener("click",event=>{if(!event.target.closest("a"))return;try{sessionStorage.setItem(key(),String(window.scrollY));}catch{}});};

CatalogData.classData=async function(){const spec=await CatalogData.json('../catalog-classes-manifest.json');return CatalogData.json('../'+spec.file,spec.sha256);};
CatalogData.classOptions=function(select,data){for(const item of data.classes){const option=CatalogData.node('option',item.label+' · '+item.key);option.value=item.key;select.append(option);}};
CatalogData.autoMore=function(button,load){
  let busy=false;
  function check(){
    if(busy||button.hidden||document.hidden||!button.getClientRects().length)return;
    const rect=button.getBoundingClientRect();if(rect.top>innerHeight+400||rect.bottom<0)return;
    busy=true;requestAnimationFrame(()=>{try{load();}finally{busy=false;requestAnimationFrame(check);}});
  }
  if('IntersectionObserver' in window){const observer=new IntersectionObserver(check,{rootMargin:'400px'});observer.observe(button);}
  window.addEventListener('scroll',check,{passive:true});check();
};

CatalogData.syncListLinks=function(grid,limit){for(const a of grid.querySelectorAll('a[href]')){const url=new URL(a.href);if(url.pathname!==location.pathname||!url.searchParams.has('item')&&!url.searchParams.has('skill')&&!url.searchParams.has('npc'))continue;if(limit>60)url.searchParams.set('limit',String(limit));else url.searchParams.delete('limit');a.href=url;}};
