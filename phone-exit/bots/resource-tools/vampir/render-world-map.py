"""Render a standalone data-map PNG from the same verified scene as the viewer."""
import hashlib
import json
import math
import os
from collections import defaultdict
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def main(root=ROOT):
    folder = root / 'maps/atlas'
    manifest = json.loads((folder / 'nocturne-manifest.json').read_text('utf-8'))
    raw = (folder / manifest['file']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['sha256']:
        raise ValueError('Changed scene')
    scene = json.loads(raw)
    original = root / scene['projection']['atlas_image']
    with original.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != scene['projection']['atlas_sha256']:
            raise ValueError('Changed map background')
    Image.MAX_IMAGE_PIXELS = 150_000_000
    terrain = Image.open(original).convert('RGB')
    top, bottom = 210, 185
    image = Image.new('RGB', (10240, 10240 + top + bottom), '#10151f')
    image.paste(terrain, (0, top)); del terrain
    draw = ImageDraw.Draw(image)
    font_path = 'C:/Windows/Fonts/segoeui.ttf'
    fonts = {size: ImageFont.truetype(font_path, size) for size in [27, 32, 34, 40, 60]}
    draw.text((65, 25), 'Vampir · Nocturne — большая карта', font=fonts[60], fill='#eef3fa')
    s = scene['stats']
    draw.text((65, 110), f"36 миров · 17 488 записей NPC · 669 объектов, включая 40 порталов · 207 мировых точек · 5 535 квестовых целей", font=fonts[34], fill='#b9c7d9')
    draw.text((65, 159), 'Все слои · совпадающие / соседние записи объединены числом · подробные связи в интерактивном атласе и JSON', font=fonts[27], fill='#a5b6ca')
    matrix = scene['projection']['world_to_pixel']
    def pixel(p):
        return (p['x'] * matrix[0][0] + matrix[0][2], p['y'] * matrix[1][1] + matrix[1][2] + top)
    colors = dict(NpcSpawn='#84b9ef', QuestTask='#ff8da5', GadgetSpawn='#bda1e3', WorldSpot='#62e7bc', Waypoint='#d7a7ff', Area='#f4d48b')
    groups = defaultdict(list)
    for p in scene['points']:
        x, y = pixel(p)
        key = (p['type'], math.floor(x / 60), math.floor(y / 60)) if p['type'] != 'Area' else (p['key'],)
        groups[key].append((x, y, p))
    for kind in colors:
        for members in groups.values():
            if members[0][2]['type'] != kind:
                continue
            x = sum(m[0] for m in members) / len(members)
            y = sum(m[1] for m in members) / len(members)
            count = len(members)
            radius = 20 if count > 1 else 9
            if kind == 'Waypoint':
                draw.polygon([(x, y - 24), (x + 24, y), (x, y + 24), (x - 24, y)], fill=colors[kind], outline='#131a25', width=3)
            elif kind == 'QuestTask':
                draw.rectangle((x - radius, y - radius, x + radius, y + radius), fill=colors[kind], outline='#131a25', width=3)
            else:
                draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=colors[kind], outline='#131a25', width=3)
            if count > 1:
                text = str(count); bounds = draw.textbbox((0, 0), text, font=fonts[27])
                draw.text((x - (bounds[2] - bounds[0]) / 2, y - 19), text, font=fonts[27], fill='#10151f')
    occupied, labels = [], 0
    for p in sorted((p for p in scene['points'] if p['type'] == 'Area'), key=lambda p: p['anchor'] != 'Waypoint→GadgetSpawn'):
        x, y = pixel(p); text = p['label']
        bounds = draw.textbbox((x + 15, y - 22), text, font=fonts[32])
        box = [bounds[0] - 8, bounds[1] - 6, bounds[2] + 8, bounds[3] + 6]
        if box[2] > 10230 or box[0] < 0 or any(not (box[2] < b[0] or box[0] > b[2] or box[3] < b[1] or box[1] > b[3]) for b in occupied):
            continue
        occupied.append(box); labels += 1
        draw.rounded_rectangle(box, radius=5, fill='#182126')
        draw.text((x + 15, y - 22), text, font=fonts[32], fill='#ffe7b5')
    y = top + 10240 + 25
    legend = [('NpcSpawn', 'NPC'), ('Area', 'Область'), ('Waypoint', 'Портал'), ('GadgetSpawn', 'Объект'), ('WorldSpot', 'Мировая точка'), ('QuestTask', 'Цель квеста')]
    x = 65
    for kind, label in legend:
        draw.ellipse((x, y + 10, x + 25, y + 35), fill=colors[kind]); draw.text((x + 40, y), label, font=fonts[32], fill='#d2dce8'); x += 490
    draw.text((65, y + 60), 'Координаты — данные клиента. Контексты и условия появления не вычислены. Маршруты и проценты выпадения не подтверждены.', font=fonts[27], fill='#a5b6ca')
    draw.text((65, y + 105), 'Проекция проверена по 7 областям значков одного исторического кадра. Источники: nocturne.json / nocturne-manifest.json / projection.json.', font=fonts[27], fill='#a5b6ca')
    target = folder / 'nocturne-overview.png'
    pending = folder / 'nocturne-overview.pending.png'
    image.save(pending, compress_level=3)
    pending.replace(target)
    image.thumbnail((2200, 2300), Image.Resampling.LANCZOS)
    image.save(folder / 'nocturne-overview-preview.jpg', quality=90)
    report = dict(scene_sha256=manifest['sha256'], image=str(target), size=[10240, 10240 + top + bottom],
        sha256=hashlib.sha256(target.read_bytes()).hexdigest(), records=len(scene['points']),
        rendered_groups=len(groups), rendered_area_labels=labels,
        note='Data visualization, all source points included in clusters; not runtime visibility or walkability.')
    (folder / 'nocturne-overview.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
