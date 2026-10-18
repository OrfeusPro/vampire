/* Shared navigation; URLs are relative to the maps directory, independent of viewer. */
(() => {
  const base=new URL('./',document.currentScript.src);
  const style=document.createElement('link');style.rel='stylesheet';style.href=new URL('catalog-nav.css',base);document.head.append(style);
  const nav=document.createElement('nav');nav.className='catalog-nav';nav.setAttribute('aria-label','Разделы справочника');
  const path=location.pathname;
  const sections=[['Карта','atlas/index.html',/\/atlas\/(?:index|world)\.html$/],
    ['Монстры','atlas/monsters.html',/(?:\/atlas\/monsters|\/loot\/index)\.html$/],
    ['Предметы','loot/items.html',/\/loot\/items\.html$/],
    ['Книги','loot/books.html',/\/loot\/books\.html$/],
    ['Навыки','atlas/skills.html',/\/atlas\/skills\.html$/]];
  for(const [name,url,match]of sections){const a=document.createElement('a');a.textContent=name;a.href=new URL(url,base);if(match.test(path))a.setAttribute('aria-current','page');nav.append(a);}
  const host=document.querySelector('header');if(host){const old=host.querySelector('nav');if(old)old.remove();host.append(nav);}
})();
