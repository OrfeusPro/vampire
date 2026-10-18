"""Build an offline, paged resource gallery; no phone commands or external assets."""
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
rows = json.loads((ROOT / 'archive-image-latest.json').read_text('utf-8'))
for row in rows:
    path = row['asset_path']
    row['category'] = 'Карты мира' if '/Map/WorldMap/' in path else 'Локальные карты' if '/Map/LocalMap/' in path else 'Миникарты' if '/Map/MiniMap/' in path else 'Интерфейс'
rows.insert(0, dict(asset_path='Nocturne — собранная карта мира', category='Собранная карта', file='maps/nocturne-preview.jpg', original='maps/nocturne-world.png', width=10240, height=10240, source='25 original tiles; see maps/nocturne-world.json'))
if any(not (ROOT / row['file']).is_file() for row in rows):
    raise ValueError('Missing gallery image')
html = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Vampir — ресурсы и карты</title><style>
body{margin:0;background:#10151f;color:#e7edf4;font:15px system-ui}header{padding:24px;position:sticky;top:0;background:#10151ff5;z-index:2}h1{margin:0 0 8px}p{color:#a8b8c9}input,select,button{font:inherit;color:inherit;background:#243044;border:1px solid #40526b;padding:10px;border-radius:8px;margin:4px}input{width:min(480px,70vw)}main{padding:24px;display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:16px}article{background:#192332;padding:12px;border-radius:10px;overflow:hidden}img{width:100%;height:210px;object-fit:contain;background:#0c1118}a{color:#62e7bc}small{display:block;overflow-wrap:anywhere;color:#a8b8c9;margin:6px 0}footer{padding:24px}</style>
<header><h1>Vampir · карты и ресурсы</h1><p>Локальная библиотека. Координаты мира и переходы ещё не проверены на Android.</p><select id="category"><option value="">Все категории</option></select><input id="search" placeholder="Название, внутренний путь или архив"><span id="count"></span></header><main id="grid"></main><footer><button id="more">Показать ещё</button><a href="maps/nocturne-world.json">Происхождение карты Nocturne</a></footer>
<script id="data" type="application/json">__DATA__</script><script>
const rows=JSON.parse(document.getElementById('data').textContent),category=document.getElementById('category'),search=document.getElementById('search'),grid=document.getElementById('grid'),more=document.getElementById('more');let limit=48;
for(const c of [...new Set(rows.map(r=>r.category))]){const option=document.createElement('option');option.value=c;option.textContent=c;category.append(option)}
function render(){grid.replaceChildren();const q=search.value.toLowerCase(),selected=rows.filter(r=>(!category.value||r.category===category.value)&&(!q||JSON.stringify(r).toLowerCase().includes(q)));document.getElementById('count').textContent=Math.min(limit,selected.length)+' / '+selected.length;more.hidden=selected.length<=limit;for(const r of selected.slice(0,limit)){const card=document.createElement('article'),link=document.createElement('a'),img=document.createElement('img'),title=document.createElement('strong'),meta=document.createElement('small');link.href=r.original||r.file;link.target='_blank';link.rel='noopener';img.src=r.file;img.loading='lazy';img.alt=r.asset_path;title.textContent=r.asset_path.split('/').pop();meta.textContent=r.width+'×'+r.height+' · '+r.source+' · '+r.asset_path;link.append(img);card.append(link,title,meta);grid.append(card)}}
category.onchange=search.oninput=()=>{limit=48;render()};more.onclick=()=>{limit+=48;render()};category.value='Собранная карта';render();</script></html>'''
if (ROOT / 'maps/atlas/index.json').is_file():
    html = html.replace('<h1>Vampir · карты и ресурсы</h1>', '<h1>Vampir · карты и ресурсы</h1><a href="maps/atlas/index.html">Атлас миров, точек, NPC и квестов</a>')
if (ROOT / 'maps/loot/index.json').is_file():
    html = html.replace('<h1>Vampir · карты и ресурсы</h1>', '<h1>Vampir · карты и ресурсы</h1><a href="maps/loot/index.html">Предметы, изображения и добыча NPC</a> · ')
html = html.replace('__DATA__', json.dumps(rows, ensure_ascii=False).replace('</', '<\\/'))
(ROOT / 'index.html').write_text(html, encoding='utf-8')
(ROOT / 'gallery-catalog.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
print('Gallery ready:', len(rows), 'images; all paths verified')
