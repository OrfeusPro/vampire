"""Verify fresh class CSV, current native bindings and lookup without network."""
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
RELEASE = '2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08'
INDEX = 'a4dd6f81f00ad3c4c84b560ca008960315aa5a84655860a517c4d69c16e98896/65fc8722324efe5d0988c9d81420e89db5c309db2eb5de5d4552b16fe1022016'
TABLES = '54728d7a6bef3dfa8ea916b45f29fd1ec972e5e1a5ec1a25688b9a654ca1f7f2'
CLASS_SHA = '620725b3322e37b612107286ca60d72908cccfdb32449b6a2e135e4ad3c4c8bc'
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(path):
    if digest(path) != path.parent.name: raise ValueError('Creation class manifest hash changed')
    return json.loads(path.read_text('utf-8'))


def run():
    release_path = ROOT / 'release-snapshots' / RELEASE / 'manifest.json'
    release = checked(release_path)
    if release['exe']['sha256'] != SHA or digest(release['exe']['path']) != SHA:
        raise ValueError('Creation class installed EXE changed')
    index_path = release_path.parent / 'record-indexes' / INDEX / 'manifest.json'
    index = checked(index_path)
    tables_path = index_path.parent / 'table-snapshots' / TABLES / 'manifest.json'
    tables = checked(tables_path)
    source = tables['source']
    if source != index['source'] or digest(source['path']) != source['sha256']:
        raise ValueError('Creation class source archive changed')
    if not any(r['path'] == source['path'] and r.get('current', {}).get('sha256') == source['sha256'] for r in release['files']):
        raise ValueError('Creation class archive is not in release snapshot')
    matches = [row for row in tables['tables'] if row['sha256'] == CLASS_SHA]
    if len(matches) != 1 or digest(matches[0]['file']) != CLASS_SHA:
        raise ValueError('Current creation class CSV not unambiguous')
    with Path(matches[0]['file']).open(encoding='utf-8-sig', newline='') as stream:
        rows = [dict(id=int(row['Id']), type=int(row['Type']), default_gender=int(row['DefaultGender']), key=row['Resource']) for row in csv.DictReader(stream)]
    expected = {'DarkMage': 1, 'Reaper': 2, 'Gunner': 3, 'SwordMan': 4, 'Fighter': 5}
    if (len(rows) != 5 or {r['key']: r['type'] for r in rows} != expected or len({r['id'] for r in rows}) != 5
            or any(not 0 < r['id'] <= 0xffffffff or r['default_gender'] not in (0, 1) for r in rows)):
        raise ValueError('Creation class CSV choices changed')
    spec = importlib.util.spec_from_file_location('verified_create_lookup', HERE / 'replay-release-create-class-lookup.py')
    lookup = importlib.util.module_from_spec(spec); spec.loader.exec_module(lookup)
    # Use the same source-checked PE helper as the replay, without running UI.
    spec = importlib.util.spec_from_file_location('verified_create_native', HERE / 'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    raw = Path(release['exe']['path']).read_bytes(); image = native.Image(raw)
    def bytes_at(address, size): return raw[image.offset(address - image.pe.base):][:size]
    bindings = ((0x14b1bdfd0, 0x1499777f0), (0x14b1bdfd8, 0x149977828),
        (0x149977828 + 0x48, 0x145897850), (0x149977828 + 0x50, 0x1458b76d0))
    if any(struct.unpack('<Q', bytes_at(at, 8))[0] != value for at, value in bindings):
        raise ValueError('Creation class table binding changed')
    if bytes_at(0x1499777e0, 10) != b'ClassInfo\0' or bytes_at(0x148a36908, 5) != b'Type\0':
        raise ValueError('Creation class native field names changed')
    if (bytes_at(0x14994fe58, 7) != b'Gunner\0'
            or bytes_at(0x1457baad8, 7) != bytes.fromhex('488d1579531904')
            or bytes_at(0x1457baaf7, 5) != bytes.fromhex('c644242303')):
        raise ValueError('Creation class Gunner converter binding changed')
    replay_path, replay = lookup.run(class_rows=rows)
    observed = {r['selected_type']: r['row_id'] for r in replay['cases'] if r['provided_data']}
    if any(observed[row['type']] != row['id'] for row in rows):
        raise ValueError('Creation class current data lookup differs')
    report = dict(source_sha256=SHA, tool_sha256=digest(Path(__file__)),
        release_manifest_sha256=RELEASE, archive_sha256=source['sha256'], class_csv_sha256=CLASS_SHA,
        record_index_sha256=index_path.parent.name, table_snapshot_sha256=TABLES, entry=matches[0]['entry'],
        classes=rows, native_replay=str(replay_path), native_replay_sha256=digest(replay_path),
        network_used=False, native_cases=len(replay['cases']),
        limits=['Current source archive and CSV fully hashed; semantic table/field binding is static evidence.',
            'Native lookup runs on rows populated from CSV, not on a live engine table cache.',
            'No appearance producer, final packet, server validation or character creation.'])
    audit = native.ROOT / 'code-clues/release-creation-classes'
    spec = importlib.util.spec_from_file_location('verified_create_audit', HERE / 'audit-client-release.py')
    save = importlib.util.module_from_spec(spec); spec.loader.exec_module(save)
    path = save.save_snapshot(audit, report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), classes=report['classes'], native_cases=report['native_cases'])))
