"""Build the local review gallery from saved extraction metadata."""
import json
import os
import re
from pathlib import Path

root = Path(os.environ.get('PHONEEXIT_RF_RESOURCES', r'F:\PhoneExit Resources\RF Online Next'))
rows = json.loads((root / 'reference-gallery-catalog.json').read_text('utf-8'))
raw = json.loads((root / 'archive-image-latest.json').read_text('utf-8'))
map_meta = json.loads((root / 'maps/novus-world.json').read_text('utf-8'))
rows.insert(0, {'id': 'novus', 'label': 'Novus — исходная карта мира',
               'category': 'Карта Novus (PAK)', 'file': 'maps/novus-world.png',
               'preview': 'maps/novus-world-preview.png', 'source': 'assembled original map tiles',
               'width': map_meta['width'], 'height': map_meta['height']})
for item in raw:
    rows.append({**item, 'id': len(rows), 'label': item['asset_path'].rsplit('/', 1)[-1],
                 'category': 'Плитки карт (PAK)' if 'WorldMapTileTex' in item['asset_path']
                 else 'Плитки обзорных карт (PAK)' if 'RegionMapTileTex' in item['asset_path']
                 else 'Текстуры интерфейса (PAK)'})
html = (root / 'index.html').read_text('utf-8')
html = re.sub(r'const rows=.*?;const category=',
              lambda _: 'const rows=' + json.dumps(rows, ensure_ascii=False).replace('</', '<\\/')
              + ';const category=', html, count=1)
html = re.sub(r'<header>.*?</header>', '''<header><h1>RF Online Next · исходные ресурсы</h1>
<p>Карта Novus собрана из оригинальных плиток PAK. Рядом — извлечённые текстуры
интерфейса, карты других зон и прежние материалы справки. Для использования
в боте нужно отдельно проверить распознавание и привязку координат.</p>
<select id="category"><option value="">Все категории</option></select>
<input id="search" placeholder="Имя ресурса, архив или номер"><span id="count"></span></header>''', html, count=1, flags=re.S)
if 'id="more"' not in html:
    html = html.replace('<dialog id="preview">', '<div style="padding:20px 28px"><button id="more">Показать ещё</button></div><dialog id="preview">')
    html = html.replace('function render(){', 'let limit=60;function render(){')
    html = html.replace("selected.length+' изображений'", "Math.min(limit,selected.length)+' из '+selected.length+' изображений'")
    html = html.replace('for(const r of selected){', 'document.getElementById("more").hidden=selected.length<=limit;for(const r of selected.slice(0,limit)){')
    html = html.replace('img.src=r.file;', 'img.src=r.preview||r.file;')
    html = html.replace('category.onchange=render;search.oninput=render;', 'category.onchange=()=>{limit=60;render()};search.oninput=()=>{limit=60;render()};document.getElementById("more").onclick=()=>{limit+=60;render()};')
    html = html.replace('preview.close();render();', 'preview.close();category.value="Карта Novus (PAK)";render();')
(root / 'index.html').write_text(html, encoding='utf-8')
(root / 'gallery-catalog.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
missing = [r['file'] for r in rows if not (root / r['file']).exists()]
if missing:
    raise RuntimeError('Gallery contains missing files: ' + str(missing[:5]))
print('Gallery built:', len(rows), 'items; all image files present')
