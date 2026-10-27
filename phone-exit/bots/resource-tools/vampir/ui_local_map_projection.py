"""Publish local atlas math from unchanged map data, without current widget claims."""
import hashlib
import json
from pathlib import Path

AUDIT = 'code-clues/map-projection-11316/0b26af0a29fcf9f968e9d6f01fd7b3bc198a2e15d944007d93915b34a662c677/manifest.json'
AUDIT_SHA = '0b26af0a29fcf9f968e9d6f01fd7b3bc198a2e15d944007d93915b34a662c677'
ARCHIVE_SHA = '15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4'
CLIENT = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
CLIENT_SHA = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
TABLES = {'World':'c782ba8bd2c11a82382082da8a0e5487f4479d8605d795455cfc6e987f862c8c',
          'Map':'a17dcb5015fa7e1fca8b052bd59d6d65bd077fcf40901719c70bb06e0749b7b4'}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(root, *, client_path=CLIENT):
    root = Path(root)
    inputs = {}
    def tracked(relative, expected=None):
        path = root / relative
        digest = sha(path)
        if expected is not None and digest != expected:
            raise ValueError('Изменился источник локального атласа: ' + relative)
        inputs[relative] = digest
        return path
    audit = json.loads(tracked(AUDIT, AUDIT_SHA).read_text('utf-8'))
    archive = Path(audit['installed_archive']['path'])
    if audit['installed_archive']['sha256'] != ARCHIVE_SHA or sha(archive) != ARCHIVE_SHA:
        raise ValueError('Изменился установленный PAK локальной карты')
    inputs[str(archive)] = ARCHIVE_SHA
    if sha(client_path) != CLIENT_SHA:
        raise ValueError('Изменился контекст клиента локального атласа')
    inputs[str(client_path)] = CLIENT_SHA
    if {k:audit['tables'][k]['sha256'] for k in TABLES} != TABLES:
        raise ValueError('Изменились исходные таблицы локального атласа')
    projection = json.loads(tracked('maps/atlas/projection.json', audit['atlas_projection_sha256']).read_text('utf-8'))
    assembly = json.loads(tracked('maps/nocturne-world.json').read_text('utf-8'))
    image = tracked('maps/' + assembly['image'], assembly['sha256'])
    if (projection['atlas_sha256'] != assembly['sha256'] or projection['size'] != assembly['size']
            or any(projection[k] != audit[k] for k in ('size','center','ground_distance','map_ids'))):
        raise ValueError('Геометрия локального атласа не соответствует данным')
    worlds = audit['worlds']
    if (not worlds or any(not k.isascii() or not k.isdecimal() or v not in audit['map_ids']
                          for k,v in worlds.items())):
        raise ValueError('Неизвестная связь мира с локальной картой')
    spec = dict(schema=1,kind='local_atlas',formula='centered_positive_xy_v1',
        archive_data_verified=True,current_native_widget_math_verified=False,
        client_context_sha256=CLIENT_SHA,archive_sha256=ARCHIVE_SHA,
        data_evidence=dict(file=AUDIT,sha256=AUDIT_SHA,tables=audit['tables']),
        atlas=dict(file=str(image.relative_to(root)),sha256=assembly['sha256']),
        worlds=dict(worlds),map_ids=list(audit['map_ids']),size=list(audit['size']),
        center=list(audit['center']),ground_distance=audit['ground_distance'],
        limitations=['Локальная проекция серверной цели входа на справочный атлас.',
            'SHA клиента обозначает контекст сборки UI, а не проверенную identity работающего owner.',
            'Сохранность PAK подтверждает данные, но не native математику виджета 1.13.18.',
            'Коррекция движком, фактическое движение и навигация не подтверждены.'])
    return spec, inputs
