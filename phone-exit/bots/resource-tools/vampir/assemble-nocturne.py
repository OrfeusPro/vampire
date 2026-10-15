"""Assemble the 25 WorldMap tiles; preserve the measured image layout, not world XY."""
import hashlib
import itertools
import json
import os
import re
from pathlib import Path
import numpy as np
from PIL import Image

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def main():
    catalog = json.loads((ROOT / 'map-image-catalog.json').read_text('utf-8'))
    tiles = {}
    edges = {}
    for row in catalog:
        found = re.search(r'/WorldMap/Field/Nocturne/Nocturne_(-?\d+)_(-?\d+)$', row['asset_path'])
        if not found:
            continue
        key = tuple(map(int, found.groups()))
        if key in tiles:
            raise ValueError('Duplicate selected tile')
        tiles[key] = row
        with Image.open(ROOT / row['file']) as image:
            pixels = np.asarray(image.convert('RGB'), dtype=np.float32)
            edges[key] = dict(left=pixels[:, 0].copy(), right=pixels[:, -1].copy(), top=pixels[0].copy(), bottom=pixels[-1].copy())
    if set(tiles) != set(itertools.product(range(-2, 3), repeat=2)):
        raise ValueError('Incomplete Nocturne grid')
    candidates = []
    for swap, sx, sy in itertools.product((False, True), (-1, 1), (-1, 1)):
        layout = {}
        for x, y in tiles:
            a, b = (y, x) if swap else (x, y)
            layout[(sx * a + 2, sy * b + 2)] = (x, y)
        errors = []
        for (x, y), key in layout.items():
            if (x + 1, y) in layout:
                errors.append(float(np.abs(edges[key]['right'] - edges[layout[(x + 1, y)]]['left']).mean()))
            if (x, y + 1) in layout:
                errors.append(float(np.abs(edges[key]['bottom'] - edges[layout[(x, y + 1)]]['top']).mean()))
        candidates.append(dict(swap=swap, sx=sx, sy=sy, seam_mae=float(np.mean(errors))))
    candidates.sort(key=lambda r: r['seam_mae'])
    best = candidates[0]
    out = ROOT / 'maps'
    out.mkdir(exist_ok=True)
    size = 2048
    canvas = Image.new('RGB', (size * 5, size * 5))
    sources = []
    for (x, y), row in sorted(tiles.items()):
        a, b = (y, x) if best['swap'] else (x, y)
        px, py = (best['sx'] * a + 2) * size, (best['sy'] * b + 2) * size
        with Image.open(ROOT / row['file']) as image:
            if image.size != (size, size):
                raise ValueError('Mixed tile resolutions')
            canvas.paste(image.convert('RGB'), (px, py))
        sources.append(dict(**row, tile=[x, y], atlas_rect=[px, py, px + size, py + size]))
    master = out / 'nocturne-world.png'
    canvas.save(master)
    canvas.thumbnail((2048, 2048), Image.Resampling.LANCZOS)
    canvas.save(out / 'nocturne-preview.jpg', quality=92)
    metadata = dict(image=master.name, size=[size * 5, size * 5], sha256=hashlib.sha256(master.read_bytes()).hexdigest(),
                    layout=best, orientation_candidates=candidates, sources=sources,
                    method='Tile coordinate names; choose image arrangement by adjacent edge MAE; no tile rotation',
                    world_coordinates_verified=False, android_verified=False, navigation_verified=False,
                    limitations=['Image layout does not establish world XY, reachability, labels or teleport destinations.'])
    (out / 'nocturne-world.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Nocturne', metadata['size'], 'layout', best, 'runner-up', candidates[1], flush=True)


if __name__ == '__main__':
    main()
