"""SHA-bound reference atlas tiles and research navigation, never a movement gate."""
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re

SHA = re.compile(r'[0-9a-f]{64}')
TILE_SIZE = 2048
ATLAS_SIZE = 10240
POINT_TYPES = ('Area', 'Waypoint', 'NpcSpawn', 'GadgetSpawn', 'WorldSpot', 'QuestTask')


def require(value, message):
    if not value:
        raise ValueError(message)


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


class AtlasAssets:
    """Compact presentation manifest plus an explicit, bounded file allowlist.

    The console reader verifies each allowlisted payload SHA on cache insertion.
    Navigation bytes and decoded PNG data are deliberately not loaded here.
    """
    def __init__(self, root, selector):
        self.root = Path(root).resolve()
        require(type(selector) is dict and set(selector) == {'scene', 'scene_manifest', 'navigation_manifest'},
                'Некорректный набор источников слоёв карты')
        pointers = {}
        for name in ('scene', 'scene_manifest', 'navigation_manifest'):
            pointer = selector[name]
            require(type(pointer) is dict and set(pointer) == {'file', 'sha256'}
                    and type(pointer['sha256']) is str and SHA.fullmatch(pointer['sha256']),
                    'Некорректная привязка источника карты')
            path = self.path(pointer['file'], 'maps/atlas')
            require(path.suffix == '.json', 'Источник карты должен быть JSON')
            pointers[name] = path
        scene = self.read_json(pointers['scene'], selector['scene']['sha256'], 32 * 2**20)
        original = self.read_json(pointers['scene_manifest'], selector['scene_manifest']['sha256'], 2**20)
        navigation = self.read_json(pointers['navigation_manifest'], selector['navigation_manifest']['sha256'], 2**20)
        require(original.get('file') == pointers['scene'].name
                and original.get('sha256') == selector['scene']['sha256'],
                'Опись не соответствует источнику карты')
        require(scene.get('schema_version') == 1 and scene.get('navigation_ready') is False,
                'Слои карты должны оставаться исследовательскими')
        projection = scene.get('projection', {})
        require(type(projection) is dict and projection.get('navigation_ready') is False
                and projection.get('size') == [ATLAS_SIZE, ATLAS_SIZE]
                and type(projection.get('map_ids')) is list and len(projection['map_ids']) == 2
                and all(type(value) is str for value in projection['map_ids'])
                and set(projection['map_ids']) == {'10', '11'},
                'Поддерживается только справочный атлас Map10/11')
        center, distance, bounds = (projection.get(key) for key in ('center', 'ground_distance', 'world_bounds'))
        require(type(center) is list and len(center) == 2 and all(number(v) for v in center)
                and number(distance) and 0 < distance <= 10**9
                and type(bounds) is list and bounds == [center[0] - distance / 2, center[1] - distance / 2,
                                                       center[0] + distance / 2, center[1] + distance / 2],
                'Границы атласа не соответствуют проекции')
        background = scene.get('background', {})
        require(type(background) is dict and type(background.get('tiles')) is list
                and len(background['tiles']) == 25, 'Нужны все 25 частей справочного атласа')
        preview_sha = background.get('preview_sha256')
        require(type(preview_sha) is str and SHA.fullmatch(preview_sha), 'Отсутствует SHA общего изображения атласа')
        self.files = {}
        tiles, cells, paths = [], set(), set()
        for index, tile in enumerate(background['tiles']):
            require(type(tile) is dict and tile.get('width') == TILE_SIZE and tile.get('height') == TILE_SIZE,
                    'Некорректный размер части атласа')
            rect = tile.get('atlas_rect')
            require(type(rect) is list and len(rect) == 4 and all(type(value) is int for value in rect),
                    'Некорректные границы части атласа')
            left, top, right, bottom = rect
            require(0 <= left < right <= ATLAS_SIZE and 0 <= top < bottom <= ATLAS_SIZE
                    and right - left == bottom - top == TILE_SIZE
                    and left % TILE_SIZE == top % TILE_SIZE == 0,
                    'Границы части должны использовать LTRB и сетку 5 × 5')
            require((left, top) not in cells, 'Повторная ячейка атласа')
            cells.add((left, top))
            path = self.path(tile.get('file'), 'archive-images')
            require(path.suffix == '.png' and path not in paths, 'Повторный или неподдержанный файл части атласа')
            paths.add(path)
            expected = tile.get('sha256')
            require(type(expected) is str and SHA.fullmatch(expected), 'Отсутствует SHA части атласа')
            route = 'atlas-tiles/' + str(index) + '.png'
            self.files[route] = dict(path=path, sha256=expected, budget=8 * 2**20)
            tiles.append(dict(file=route, atlas_rect=rect, sha256=expected, source_file=tile['file']))
        require(cells == {(x, y) for x in range(0, ATLAS_SIZE, TILE_SIZE)
                          for y in range(0, ATLAS_SIZE, TILE_SIZE)}, 'Атлас покрыт не полностью')
        pointer = scene.get('navigation_overlay')
        require(type(pointer) is dict and pointer == navigation
                and navigation.get('runtime_selection_verified') is False
                and type(navigation.get('sha256')) is str and SHA.fullmatch(navigation['sha256']),
                'Опись навигационной сетки не соответствует карте')
        nav_path = self.path('maps/atlas/' + str(navigation.get('file', '')), 'maps/atlas')
        require(nav_path.parent == pointers['navigation_manifest'].parent and nav_path.suffix == '.json',
                'Некорректный путь навигационной сетки')
        stats = navigation.get('stats')
        require(type(stats) is dict and {'tiles', 'surface_polygons'} <= set(stats)
                and all(type(value) is int and 0 <= value <= 2_000_000 for value in stats.values()),
                'Некорректная статистика навигационной сетки')
        self.files['atlas-navigation.json'] = dict(path=nav_path, sha256=navigation['sha256'], budget=16 * 2**20)
        self.points = self.point_snapshot(scene, selector['scene'])
        point_stats = json.loads(self.points)['stats']
        result = dict(schema=1, kind='reference_atlas_layers', navigation_ready=False,
            projection={key: projection[key] for key in ('size', 'center', 'ground_distance', 'map_ids', 'world_bounds')},
            background=dict(preview='world-atlas.jpg', preview_sha256=preview_sha, tiles=tiles),
            navigation=dict(file='atlas-navigation.json', sha256=navigation['sha256'], stats=stats,
                            runtime_selection_verified=False),
            points=dict(file='atlas-points.json',sha256=hashlib.sha256(self.points).hexdigest(),
                        count=point_stats['points'],counts=point_stats['counts']),
            sources=selector,
            limits=['Сохранённые части атласа и сетка не подтверждают активную версию игры.',
                    'Все высоты сетки показаны вместе; фактическая проходимость не проверена.'])
        self.manifest = (json.dumps(result, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')

    @staticmethod
    def point_snapshot(scene, source):
        catalog, points = scene.get('npcs', {}), scene.get('points', [])
        require(type(catalog) is dict and len(catalog) <= 10_000
                and type(points) is list and len(points) <= 32_000, 'Превышен лимит точек атласа')
        rows, omitted_coords, omitted_records, omitted_types = [], 0, 0, 0
        counts = {kind:0 for kind in POINT_TYPES}
        for point in points:
            if type(point) is not dict or point.get('type') not in POINT_TYPES:
                omitted_types += 1
                continue
            if not all(number(point.get(key)) for key in ('x', 'y')):
                omitted_coords += 1
                continue
            if (not all(type(point.get(key)) is str and re.fullmatch(r'\d{1,20}',point[key])
                        for key in ('id', 'world_id'))
                    or point.get('key') != point['type'] + ':' + point['id']
                    or type(point.get('label')) is not str or len(point['label']) > 256):
                omitted_records += 1
                continue
            row = dict(type=point['type'],**{key:point[key] for key in ('key','id','label','world_id','x','y')})
            if point['type'] == 'NpcSpawn':
                npc_id = point.get('npc_id')
                if type(npc_id) is not str or not re.fullmatch(r'\d{1,20}',npc_id):
                    omitted_records += 1
                    continue
                metadata = catalog.get(npc_id)
                level = metadata.get('level') if type(metadata) is dict else None
                if not (type(level) is int and 0 <= level <= 1_000_000
                        or type(level) is str and re.fullmatch(r'\d{1,6}',level)):
                    level = None
                row.update(npc_id=npc_id,level=level)
            if type(point.get('loot_count')) is int and 0 <= point['loot_count'] <= 100_000:
                row['loot_count'] = point['loot_count']
            rows.append(row);counts[point['type']] += 1
        value = dict(schema=1,kind='reference_atlas_points',coordinate_space='world_xy',runtime_visibility_verified=False,
            points=rows,stats=dict(points=len(rows),counts=counts,omitted_nonfinite_coordinates=omitted_coords,
                                   omitted_invalid_records=omitted_records,omitted_unknown_types=omitted_types),source=source,
            limits=['Позиции и названия взяты из сохранённых таблиц, а не из живой видимости персонажа.'])
        raw = (json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8')
        require(len(raw) <= 16 * 2**20, 'Превышен лимит данных точек атласа')
        return raw

    def path(self, value, category):
        require(type(value) is str and value and '\\' not in value and ':' not in value,
                'Некорректный путь ресурса карты')
        relative = PurePosixPath(value)
        require(not relative.is_absolute() and not any(part in ('.', '..') for part in relative.parts),
                'Ресурс карты находится вне разрешённого каталога')
        path = (self.root / relative).resolve()
        require(path.is_relative_to(self.root / category) and path.is_file(),
                'Ресурс карты находится вне разрешённого каталога или отсутствует')
        return path

    @staticmethod
    def read_json(path, expected, budget):
        with path.open('rb') as stream:
            raw = stream.read(budget + 1)
        require(len(raw) <= budget and hashlib.sha256(raw).hexdigest() == expected,
                'Изменился источник слоёв карты или превышен лимит')
        value = json.loads(raw)
        require(type(value) is dict, 'Некорректная структура источника карты')
        return value
