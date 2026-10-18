'use strict';
(()=>{
  const $=id=>document.getElementById(id),{node,json}=CatalogData,params=new URLSearchParams(location.search);
  const translations={Default:'Основные',DMG:'Урон',Support:'Поддержка','Special.':'Особые'};
  let data;
  const clean=s=>(s||'').replaceAll('\\r\\n','\n').replaceAll('\\n','\n');
  function statUrl(id){const p=new URLSearchParams(location.search);p.set('stat',id);return 'index.html?'+p;}
  function showDetail(id){
    const entry=data.entries.find(e=>e.id===id);if(!entry)throw Error('Характеристика не найдена: '+id);
    $('listing').hidden=true;$('statDetail').hidden=false;document.title=entry.name+' · Характеристики Vampir';
    const host=$('statDetail'),back=node('a','← Все характеристики','button'),p=new URLSearchParams(params);p.delete('stat');back.href='index.html'+(p.size?'?'+p:'');host.append(back,node('h2',entry.name+' · ID '+id));
    host.append(node('p',clean(entry.description)||'Описание в клиенте не найдено.','stat-description'));
    if(entry.row.IsPercentage==='1'&&data.percentage_format?.verified){
      const units=node('div',undefined,'stat-units');units.append(node('strong','Масштаб отображения: 100 → 1%'),node('p','Найдена ветка форматирования клиента: исходное целое значение × 0,01 (float32), затем знак %. Например, 150 отображается как 1,50%. Это перевод единиц отображения, а не формула итогового шанса или урона.','muted'));
      const source=node('a','Код преобразования и проверки');source.href=data.percentage_format.evidence_file;units.append(source);host.append(units);
    }
    if(entry.display_format?.kind==='scaled_number'&&data.display_routes?.verified){
      const format=entry.display_format,divisor=Math.round(1/format.scale),units=node('div',undefined,'stat-units');
      units.append(node('strong','Масштаб отображения: '+divisor+' → 1'),node('p','Для этой характеристики клиент отдельно масштабирует исходное целое значение (float32). Знак % не добавляется. Дробная часть отображается с '+format.decimals+' '+(format.decimals===1?'знаком':'знаками')+' после запятой. Это формат числа, а не формула влияния на шанс или урон.','muted'));
      const source=node('a','Ветки кода и проверки');source.href=data.display_routes.evidence_file;units.append(source);host.append(units);
    }
    const binding=entry.stat_binding;
    if(binding?.status==='mapped')host.append(node('p','Стат клиента: '+binding.enum.name+' · '+binding.value+'. Это привязка поля StatType, не формула расчёта.','muted'));
    else if(binding?.status==='sentinel')host.append(node('p','StatType = EStat::Max ('+binding.value+') — служебная граница enum. Отдельный стат расчёта этим полем не указан.','stat-binding-note'));
    host.append(node('p','Связи по описаниям клиента. Стрелка показывает направление влияния на величину или эффект; она не доказывает изменение хранимого значения другого стата. Численные формулы пока не восстановлены.','muted'));
    const neighborhood=AttributesModel.neighborhood(data.entries,data.relations||[],id),byId=new Map(data.entries.map(e=>[e.id,e]));
    const tree=node('div',undefined,'stat-tree');
    function branch(title,relations,direction){
      const column=node('section',undefined,'stat-branch');column.append(node('h3',title));
      if(!relations.length)column.append(node('p','Подтверждённые связи пока не найдены. Это не означает, что зависимостей нет.','muted'));
      for(const r of relations){const other=byId.get(direction==='in'?r.source:r.target),card=node('article',undefined,'stat-edge'),a=node('a',other.name+' · '+other.id);a.href=statUrl(other.id);card.append(a,node('p',r.explanation),node('small','Формула неизвестна · источник: описание клиента'));
        const evidence=node('details');evidence.append(node('summary','Подтверждение'),node('p',clean(r.evidence.statement)),node('pre',JSON.stringify(r.evidence,null,2)));card.append(evidence);column.append(card);
      }return column;
    }
    const center=node('div',undefined,'stat-root');center.append(node('small','Выбранная характеристика'),node('strong',entry.name),node('span','ID '+id));
    tree.append(branch('Влияет на выбранную величину →',neighborhood.incoming,'in'),center,branch('→ Влияет на величину / эффект',neighborhood.outgoing,'out'));host.append(tree);
    if(neighborhood.opposed.length){const box=node('section',undefined,'stat-interactions');box.append(node('h3','Взаимодействие с противником'));
      for(const r of neighborhood.opposed){const other=byId.get(r.source===id?r.target:r.source),a=node('a',other.name+' · '+other.id),card=node('article',undefined,'stat-edge');a.href=statUrl(other.id);card.append(a,node('p',r.explanation),node('small','Формула неизвестна · участники могут быть разными персонажами'));const proof=node('details');proof.append(node('summary','Источник'),node('p',clean(r.evidence.statement)),node('pre',JSON.stringify(r.evidence,null,2)));card.append(proof);box.append(card);}host.append(box);
    }
    const actions=node('div',undefined,'detail-actions'),collections=node('a','Коллекции с этим бонусом','button');collections.href='../collections/index.html?bonus='+encodeURIComponent(id);actions.append(collections);host.append(actions);
    if(data.weight_math?.native_blocks_verified){
      const panel=node('section',undefined,'stat-weight'),title=node('h3','Вес параметра при сравнении предметов');panel.append(title);
      panel.append(node('p','Клиент использует найденный расчёт в сравнении предметов: значение × CombatPowerWeight, затем округление вниз (float32). Ниже — отдельный вклад, а не полная оценка предмета или общая боевая мощь персонажа.','muted'));
      const context=data.weight_math.item_comparison_context;
      if(context?.verified){const details=node('details');details.append(node('summary','Как используется оценка'),node('p','После проверок допуска клиент сравнивает оценки выбранного предмета и предмета из соответствующего слота. Большая оценка считается лучше; равные — нет. Без предмета для сравнения результат положительный только при успешных предыдущих проверках. Конкретный виджет индикатора ещё не установлен.'));
        const source=node('a','Код сравнения и изолированные проверки');source.href=context.evidence_file;details.append(source);panel.append(details);}
      const weight=entry.row.CombatPowerWeight;
      if(weight==='')panel.append(node('p','Вес в таблице не указан. Расчёт недоступен.','muted'));
      else{panel.append(node('p','CombatPowerWeight: '+weight));const label=node('label','Значение параметра для проверки'),input=node('input'),result=node('p',undefined,'weight-result');input.type='number';input.step='1';input.min='-2147483648';input.max='2147483647';input.value='1';label.append(input);panel.append(label,result);
        function calculate(){const value=AttributesModel.weightedContribution(input.value,weight);result.textContent=value.status==='known'?'Взвешенный вклад: '+value.result:value.status==='out_of_range'?'Результат вне диапазона int32.':'Введите целое число в диапазоне int32.';}
        input.oninput=calculate;calculate();
      }
      const proof=node('a','Код и результаты изолированных проверок');proof.href=data.weight_math.evidence_file;panel.append(proof,node('small','Проверяется только арифметический блок. Полный расчёт статов и состояние персонажа не воспроизводятся.'));host.append(panel);
    }
    if(data.detail_protocol?.schema_verified){
      const panel=node('details',undefined,'stat-protocol');panel.append(node('summary','Зацепка: детализация значений по категориям'),node('p','В коде клиента найден формат подробных данных стата: значения по категориям и дополнительные значения. Названия категорий и данные персонажа пока не извлечены. Сам формат не раскрывает формулы зависимостей.','muted'));
      const a=node('a','Схема и проверки чтения/записи');a.href=data.detail_protocol.evidence_file;panel.append(a);host.append(panel);
    }
    const raw=node('details');raw.append(node('summary','Исходные поля характеристики'),node('pre',JSON.stringify(entry,null,2)));host.append(raw);
  }
  function icon(kind){
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('aria-hidden','true');
    const path=document.createElementNS(svg.namespaceURI,'path');
    const paths={collections:'M4 4h11v14H4z M8 8h4 M8 12h4 M8 21h12V8 M17 3l4 4 M17 7l4-4',source:'M8 4 1 12l7 8 M16 4l7 8-7 8 M14 3l-4 18',hidden:'M3 3l18 18 M9.8 5.2A11 11 0 0 1 12 5c6 0 10 7 10 7a19 19 0 0 1-4 4.5 M6.2 6.2A20 20 0 0 0 2 12s4 7 10 7a11 11 0 0 0 5-1.3 M9.9 9.9a3 3 0 0 0 4.2 4.2'};
    path.setAttribute('d',paths[kind]);
    path.setAttribute('fill','none');path.setAttribute('stroke','currentColor');path.setAttribute('stroke-width','1.6');path.setAttribute('stroke-linecap','round');path.setAttribute('stroke-linejoin','round');svg.append(path);return svg;
  }
  function render(){
    const q=$('search').value.trim(),tab=$('tab').value,unit=$('unit').value,p=new URLSearchParams();if(q)p.set('q',q);if(tab!=='all')p.set('tab',tab);if(unit!=='all')p.set('unit',unit);
    history.replaceState(null,'','index.html'+(p.size?'?'+p:'')+location.hash);
    const rows=AttributesModel.select(data.entries,{q,tab,unit});$('count').textContent=rows.length+' из '+data.entries.length+' характеристик';$('grid').replaceChildren();
    const sections=new Map();for(const entry of rows){
      let section=sections.get(entry.tab_id);
      if(!section){section=node('section',undefined,'attribute-column');const t=data.tabs.find(t=>t.Id===entry.tab_id),label=t?(translations[t.Name]||t.Name):'Без назначенной группы',h=node('h2',label);if(t)h.append(node('small',t.Name));section.append(h);sections.set(entry.tab_id,section);$('grid').append(section);}
      const article=node('article',undefined,'attribute');article.id='attribute-'+entry.id;
      const head=node('div',undefined,'attribute-heading'),h=node('h3'),a=node('a',entry.name),description=node('span',clean(entry.description)||'Описание в локализации не найдено.','attribute-tooltip');
      description.id='description-'+entry.id;description.setAttribute('role','tooltip');a.href=statUrl(entry.id);a.setAttribute('aria-describedby',description.id);h.append(a,node('span','ID '+entry.id,'attribute-id'),description);
      const collections=node('a',undefined,'attribute-action');collections.href='../collections/index.html?bonus='+encodeURIComponent(entry.id);collections.title='Коллекции с этим бонусом';collections.setAttribute('aria-label','Коллекции с бонусом '+entry.name);collections.append(icon('collections'));
      const source=node('button',undefined,'attribute-action');source.type='button';source.title='Поля и источник';source.setAttribute('aria-label','Поля и источник: '+entry.name);source.setAttribute('aria-expanded','false');source.setAttribute('aria-controls','source-'+entry.id);source.append(icon('source'));
      const flags=node('span',undefined,'attribute-flags');
      function flag(label,cls,content){const mark=node('span',undefined,'attribute-flag '+cls);mark.title=label;mark.setAttribute('aria-label',label);mark.setAttribute('role','img');mark.tabIndex=0;mark.append(content);flags.append(mark);}
      if(entry.row.IsPercentage==='1')flag('Процентный параметр · в найденной функции отображения 100 → 1%','percentage',node('span','%'));
      if(entry.row.InvisibleStat==='1')flag('Скрыт в интерфейсе клиента','hidden-stat',icon('hidden'));
      head.append(h,flags,collections,source);article.append(head);
      const previous=section.lastElementChild;if(previous?.dataset.group!==undefined&&previous.dataset.group!==(entry.row.DisplayGroupId||''))article.classList.add('group-break');article.dataset.group=entry.row.DisplayGroupId||'';
      const raw=node('div',undefined,'attribute-raw');raw.id='source-'+entry.id;raw.hidden=true;raw.append(node('pre',JSON.stringify({parameter:entry.row,enum:entry.enum,stat_binding:entry.stat_binding,group:entry.group,localization:entry.name_source},null,2)));source.onclick=()=>{raw.hidden=!raw.hidden;source.setAttribute('aria-expanded',String(!raw.hidden));};article.append(raw);section.append(article);
    }
    if(!rows.length)$('grid').append(node('p','Ничего не найдено. Измените поиск или фильтры.','empty'));
  }
  (async()=>{const manifest=await json('manifest.json');data=await json(manifest.file,manifest.sha256);
    for(const t of data.tabs){const option=node('option',(translations[t.Name]||t.Name)+' · '+(manifest.statistics.by_tab[t.Id]||0));option.value=t.Id;$('tab').append(option);}
    const option=node('option','Без назначенной группы · '+manifest.statistics.unassigned);option.value='unassigned';$('tab').append(option);
    $('search').value=params.get('q')||'';for(const k of ['tab','unit'])if([...$(k).options].some(o=>o.value===params.get(k)))$(k).value=params.get(k);
    if(params.has('stat'))showDetail(params.get('stat'));else render();for(const k of ['search','tab','unit']){$(k).disabled=false;$(k)[k==='search'?'oninput':'onchange']=render;}
    if(/^#attribute-\d+$/.test(location.hash))document.getElementById(location.hash.slice(1))?.scrollIntoView();
  })().catch(error=>{$('error').textContent='Не удалось загрузить характеристики: '+error.message;});
})();
