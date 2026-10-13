"""Import game resources only: never accounts, device records or credentials."""
import argparse
import hashlib
import json
import shutil
import importlib.util
from pathlib import Path
import yaml

parser = argparse.ArgumentParser()
parser.add_argument('--source', required=True)
args = parser.parse_args()
source = Path(args.source).resolve()
target = Path(__file__).parent / 'lordnine'
config = yaml.safe_load((source / 'config.yaml').read_text('utf-8-sig'))
vision = config['vision']
safe = {key: config[key] for key in ('game', 'tap_points', 'timeouts', 'routes') if key in config}
safe['auto_dismantle'] = {key: value for key, value in config['auto_dismantle'].items()
                         if key not in ('aliases', 'device_ids')}
safe['vision'] = {key: value for key, value in vision.items()
                  if 'ocr' not in key.lower() and 'tesseract' not in key.lower()
                  and not key.startswith('rapidocr') and not key.endswith('_dir')}
spec = importlib.util.spec_from_file_location('lordnine_presets', source / 'src/l9bot/games/lordnine/vision_presets.py')
presets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(presets)
safe['vision']['templates'] = presets.prepare_templates(safe['vision']['templates'])
(target / 'imported.json').write_text(json.dumps(safe, ensure_ascii=False, indent=2), 'utf-8')
for name, src in [('templates', source / 'templates/lordnine'),
                  ('maps', source / 'assets/lordnine/maps/farm')]:
    dest = target / name
    dest.mkdir(exist_ok=True)
    for file in sorted(src.rglob('*')):
        if file.is_file() and file.suffix.lower() in ('.png', '.jpg', '.json'):
            out = dest / file.relative_to(src)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, out)
            if name == 'maps' and file.name == 'index.json':
                index = json.loads(out.read_text('utf-8-sig'))
                for item in index.get('maps', []):
                    for key in list(item):
                        if key.startswith('source_window'):
                            del item[key]
                out.write_text(json.dumps(index, ensure_ascii=False, indent=2), 'utf-8')
digest = hashlib.sha256((source / 'src/l9bot/games/lordnine/state_machine.py').read_bytes()).hexdigest()
(target / 'source.json').write_text(json.dumps({'source': 'MultiBot', 'stateMachineSha256': digest,
    'recognition': 'templates-only', 'imported': ['game', 'tap_points', 'timeouts', 'routes',
    'auto_dismantle', 'vision', 'templates', 'maps']}, indent=2), 'utf-8')
print('Imported Lord Nine game settings, templates and maps; no personal records.')
shutil.copyfile(source / 'assets/lordnine/maps/map_navigation_marker_template.png', target / 'templates/map_navigation_marker_template.png')
for name in ('map_navigation_player_arrow_vmos_http.png', 'map_navigation_player_arrow_vmos_http_alt.png', 'map_navigation_player_arrow_vmos_http_large.png'):
    shutil.copyfile(source / 'assets/lordnine/maps' / name, target / 'templates' / name)
