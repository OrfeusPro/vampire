"""Compare four explicit message components with an authenticated current PAK directory.

No EXE execution, UI input, authentication, network or runtime profile changes.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
DIRECTORY = 'b8ee52f76aecb1ecb7544de13a59e2355b7a32b44d1da1fb6426e650f17f9a04'
SOURCE = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
NAMES = ('WBP_MessageBoxConfirmPopup', 'WBP_MessageBoxPopup',
         'WBP_SystemMessageBoxPopup', 'WBP_SystemMessageUI')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def compare_exports(catalog, asset, body):
    """Exact range equality permits reuse; changed bytes remain unexplained."""
    if hashlib.sha256(asset).hexdigest() != catalog['asset_sha256']:
        raise ValueError('Package header changed; old export offsets cannot be reused')
    rows = []
    for old in [catalog['root_export'], *catalog['controls']]:
        start = old['offset'] - len(asset)
        size = old['size']
        if not 0 <= start <= len(body) or not 0 <= size <= len(body) - start:
            raise ValueError('Component export exceeds body')
        sha = hashlib.sha256(body[start:start + size]).hexdigest()
        rows.append(dict(name=old['name'], export=old.get('export', old.get('index')),
            type=old['type'], size=size, sha256=sha, previous_sha256=old['sha256'],
            unchanged=sha == old['sha256']))
    return rows


def verify(root=ROOT):
    path = Path(root) / 'resource-config-snapshots' / DIRECTORY / 'manifest.json'
    if digest(path) != DIRECTORY:
        raise ValueError('Message directory manifest changed')
    manifest = json.loads(path.read_text('utf-8'))
    if manifest['exe_sha256'] != SOURCE or not manifest['authoritative_directory_for_archive']:
        raise ValueError('Message directory source differs')
    if digest(manifest['source_exe']) != SOURCE:
        raise ValueError('Installed EXE changed')
    for name, field in (('directory.json', 'directory_paths_file_sha256'),
                        ('encoded-entries.bin', 'encoded_entries_file_sha256')):
        if digest(path.parent / name) != manifest[field]:
            raise ValueError('Message directory material changed')
    directory = json.loads((path.parent / 'directory.json').read_text('utf-8'))
    entries = {row['path']: row for row in directory['entries']}
    if len(entries) != len(directory['entries']):
        raise ValueError('Ambiguous message directory')
    encoded = (path.parent / 'encoded-entries.bin').read_bytes()
    inventory = HERE / 'knowledge/evidence/updates/ERROR-COMPONENTS-INVENTORY.json'
    prior = json.loads(inventory.read_text('utf-8'))
    core = load('message_entry_core', HERE / 'recover-pak-game-config.py')
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    reader = load('message_entry_reader', reader_path)
    if (digest(reader_path) != manifest['dependencies']['reader_sha256'] or
            digest(reader.ROOT / 'tools/oodle-data-shared.dll') != manifest['dependencies']['oodle_sha256']):
        raise ValueError('Message decoder dependencies changed')
    archive = Path(manifest['source_archive']['path'])
    before = archive.stat()
    if digest(archive) != manifest['archive_sha256']:
        raise ValueError('Message archive changed')
    results = []
    with archive.open('rb') as stream:
        for name in NAMES:
            candidates = [row for row in prior['components'] if row['name'] == name
                          and Path(row['catalog_path']).name.startswith('pakchunk500-Windows-')]
            if len(candidates) != 1:
                raise ValueError('Ambiguous previous message catalog')
            previous = candidates[0]
            if digest(previous['catalog_path']) != previous['catalog_sha256']:
                raise ValueError('Previous message catalog changed')
            catalog = json.loads(Path(previous['catalog_path']).read_text('utf-8'))
            parts, evidence = [], []
            for suffix in ('.uasset', '.uexp'):
                filename = 'RED/UI/Common/MessageBox/' + name + suffix
                decoded = core.decode_small_entry(encoded, entries[filename]['encoded_entry_offset'])
                header = reader.header(stream, decoded['offset'], manifest['main_index']['offset'])
                if (not header or header['encrypted'] or
                        any(header[k] != decoded[k] for k in ('size', 'usize', 'method', 'encrypted')) or
                        not 0 < header['usize'] <= 1048576):
                    raise ValueError('Unsupported message record')
                payload = reader.decode(stream, header)
                if payload is None or len(payload) != header['usize']:
                    raise ValueError('Incomplete message payload')
                parts.append(payload)
                evidence.append(dict(path=filename, offset=decoded['offset'],
                    sha256=hashlib.sha256(payload).hexdigest(), bytes=len(payload)))
            exports = compare_exports(catalog, *parts)
            results.append(dict(name=name, parts=evidence, exports=exports,
                previous_catalog_sha256=previous['catalog_sha256'],
                whole_body_unchanged=hashlib.sha256(parts[1]).hexdigest() == catalog['body_sha256']))
    after = archive.stat()
    if ((before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or digest(archive) != manifest['archive_sha256']):
        raise ValueError('Message archive changed during verification')
    return dict(schema=1, source_sha256=SOURCE, directory_sha256=DIRECTORY,
        archive_sha256=manifest['archive_sha256'], tool_sha256=digest(Path(__file__)),
        previous_inventory_sha256=digest(inventory), components=results,
        network_used=False, profile_activated=False,
        limits=['Patch variant only; active mount/variant and screen geometry unverified.',
                'Exact export equality only; changed bytes do not identify their meaning.',
                'No numeric error binding, live UI, callbacks or translation lookup executed.'])


if __name__ == '__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    report = verify()
    audit = load('message_component_save', HERE / 'audit-client-release.py')
    path = audit.save_snapshot(ROOT / 'knowledge/message-component-checks', report)
    print(json.dumps(dict(report=str(path), sha256=path.parent.name,
        components=[dict(name=c['name'], unchanged=sum(x['unchanged'] for x in c['exports']),
            exports=len(c['exports'])) for c in report['components']])))
