"""Serve the shared prototype with its retained generated presentation assets."""
from collections import OrderedDict
import hashlib
import json
import mimetypes
from pathlib import Path
from threading import RLock
from urllib.parse import unquote

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'vampir/ui-prototype'
SELECTOR = HERE.parent / 'resource-tools/vampir/knowledge/console-prototype-assets.json'


class PrototypeAssets:
    CACHE_BUDGET = 64 * 2**20

    def __init__(self, root, token):
        self.root, self.token = Path(root).resolve(), token
        self.source = {path.name: path.read_bytes() for path in SOURCE.iterdir()
                       if path.suffix in ('.js', '.css', '.html') and '.test.' not in path.name}
        self.selected = json.loads(SELECTOR.read_bytes())
        self.snapshot = (self.root / self.selected['snapshot']).resolve()
        if not self.snapshot.is_relative_to(self.root / 'maps/ui-prototype/snapshots'):
            raise ValueError('Некорректный путь ресурсов прототипа')
        manifest, digest = self.read(self.snapshot / 'manifest.json', 2**21)
        if digest != self.selected['manifest_sha256']:
            raise ValueError('Сохранённые ресурсы прототипа изменились')
        self.generated = dict(json.loads(manifest)['generated_files'], **{'manifest.json':digest})
        if 'textures.json' in self.generated:
            textures, texture_sha = self.read(self.snapshot / 'textures.json',2**21)
            if texture_sha != self.generated['textures.json']:
                raise ValueError('Изменился каталог изображений прототипа')
            for image in json.loads(textures).values():
                name, expected = image['url'], image['sha256']
                if (not name.startswith('assets/')
                        or name in self.generated and self.generated[name] != expected):
                    raise ValueError('Некорректная привязка изображения прототипа')
                self.generated[name] = expected
        self.cache = OrderedDict()
        self.cache_bytes = 0
        self.lock = RLock()

    @staticmethod
    def read(path, budget):
        with path.open('rb') as stream:
            data = stream.read(budget + 1)
        if len(data) > budget:
            raise ValueError('Ресурс прототипа превышает лимит')
        return data, hashlib.sha256(data).hexdigest()

    def get(self, route):
        with self.lock:
            return self._get(route)

    def _get(self, route):
        name = unquote(route.removeprefix('/prototype/'))
        relative = Path(name)
        if not name or relative.is_absolute() or any(p in ('.', '..') for p in relative.parts) or '\\' in name:
            return None
        if name in self.source:
            data = self.source[name]
            if relative.suffix == '.html':
                data = data.replace(b'<head>', b'<head><meta name="console-token" content="' + self.token.encode() + b'">', 1)
            return data, self.mime(name)
        if name not in self.cache:
            reference = self.selected.get({'local-map-projection.json': 'projection', 'world-atlas.jpg': 'atlas'}.get(name))
            if reference:
                path = (self.root / reference['file']).resolve()
                if not path.is_relative_to(self.root / 'maps'):
                    return None
                data, digest = self.read(path, 2**21)
                if digest != reference['sha256']:
                    raise ValueError('Изменился ресурс карты')
            else:
                path = (self.snapshot / name).resolve()
                if (not path.is_relative_to(self.snapshot) or name not in self.generated
                        or relative.suffix not in ('.json', '.png', '.jpg', '.webp')):
                    return None
                data, digest = self.read(path, 16 * 2**20)
                if digest != self.generated[name]:
                    raise ValueError('Изменился сохранённый ресурс прототипа')
            while self.cache and self.cache_bytes + len(data) > self.CACHE_BUDGET:
                _, removed = self.cache.popitem(last=False)
                self.cache_bytes -= len(removed[0])
            self.cache[name] = data, self.mime(name)
            self.cache_bytes += len(data)
        else:
            self.cache.move_to_end(name)
        return self.cache[name]

    @staticmethod
    def mime(name):
        return (mimetypes.guess_type(name)[0] or 'application/octet-stream') + ('; charset=utf-8' if name.endswith(('.js', '.json', '.html', '.css')) else '')
