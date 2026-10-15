"""Recover serialized UserWidget paths; retain unknown trailing properties as opaque.

No screen recognition, visibility or native transition is inferred from an asset link.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


canvas = load('deferred_reader', 'decode-canvas-slots.py')
native = load('deferred_native', 'extract-ui-properties.py')


def decode_prefix(data, names):
    reader = canvas.Reader(data)
    header = reader.header()
    if not header or header[0][0] != 0:
        return dict(status='no_explicit_UserWidget', header=header,
                    whole_export_decoded=False)
    if header[0][1]:
        return dict(status='serialized_zero_UserWidget', header=header,
                    whole_export_decoded=False)
    start = reader.pos

    def fname():
        index, number = reader.read('<ii')
        if not 0 <= index < len(names) or not 0 <= number <= 1000000:
            raise ValueError('Invalid or unsupported soft-path FName')
        name = names[index] + ('_' + str(number - 1) if number else '')
        return dict(name=name, index=index, number=number)

    package, asset = fname(), fname()
    size = reader.read('<i')
    if not -4096 <= size <= 4096:
        raise ValueError('Unbounded soft-path subobject string')
    length = size if size >= 0 else -size * 2
    if reader.pos + length > len(data):
        raise ValueError('Truncated soft-path subobject string')
    raw = data[reader.pos:reader.pos + length]
    reader.pos += length
    terminator = b'\0' if size >= 0 else b'\0\0'
    if size and not raw.endswith(terminator):
        raise ValueError('Unterminated soft-path subobject string')
    subpath = raw[:-len(terminator)].decode('utf-8' if size >= 0 else 'utf-16le') if size else ''
    if (not package['name'].startswith('/Game/') or
            not asset['name'].startswith(('WBP_', 'ZBP_')) or
            asset['name'] not in (package['name'].rsplit('/', 1)[-1],
                                  package['name'].rsplit('/', 1)[-1] + '_C')):
        raise ValueError('Unsupported UserWidget path shape')
    return dict(status='explicit_asset_path', header=header,
                property_name='UserWidget', property_schema_index=0,
                package=package, asset=asset, subpath=subpath,
                path=package['name'] + '.' + asset['name'],
                value_byte_range=[start, reader.pos],
                opaque_tail_byte_range=[reader.pos, len(data)],
                opaque_tail_sha256=hashlib.sha256(data[reader.pos:]).hexdigest(),
                whole_export_decoded=False)


def main():
    executable = json.loads((ROOT / 'code-clues/ui-properties.json').read_text(encoding='utf-8'))
    data = Path(executable['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != executable['sha256']:
        raise ValueError('Native executable changed')
    schema = native.extract(data,
        ['UserWidget', 'DeferredResourceObject', 'UnderlyingType', 'CachePolicy', 'AsyncLoad'],
        [18, 16, 0, 30, 76], anchor_index=1)
    schema.update(serialized_property_indices=[0, 1, 3, 4], nested_descriptor_indices=[2])
    directory = ROOT / 'ui-layout-study'
    catalog_dir = ROOT / 'ui-catalog'
    catalog = json.loads((catalog_dir / 'index.json').read_text(encoding='utf-8'))
    targets = {}
    for window in catalog['windows']:
        for path in window['paths']:
            targets.setdefault(path, []).append(window['file'])
    rows, failures = [], []
    for item in json.loads((directory / 'index.json').read_text(encoding='utf-8')):
        if 'file' not in item:
            continue
        report = json.loads((directory / item['file']).read_text(encoding='utf-8'))
        panels = [e for e in report['exports'] if e['type'] == 'NkDeferredPanel']
        if not panels:
            continue
        asset = (directory / item['file'].replace('.json', '.uasset')).read_bytes()
        body = (directory / item['file'].replace('.json', '.uexp')).read_bytes()
        if (hashlib.sha256(asset).hexdigest() != report['asset_sha256'] or
                hashlib.sha256(body).hexdigest() != report['body_sha256']):
            raise ValueError('Changed cooked source: ' + item['file'])
        for panel in panels:
            offset = panel['offset'] - len(asset)
            raw = body[offset:offset + panel['size']]
            if offset < 0 or len(raw) != panel['size'] or hashlib.sha256(raw).hexdigest() != panel['sha256']:
                raise ValueError('Changed panel export')
            provenance = dict(file=item['file'], export=panel['index'], name=panel['name'],
                offset=panel['offset'], size=panel['size'], sha256=panel['sha256'],
                source=report['source'], entry=report['entry'],
                asset_sha256=report['asset_sha256'], body_sha256=report['body_sha256'])
            try:
                decoded = decode_prefix(raw, report['names'])
                if decoded['status'] == 'explicit_asset_path':
                    decoded['catalog_targets'] = targets.get(decoded['package']['name'], [])
                rows.append(dict(provenance=provenance, decoded=decoded))
            except (ValueError, UnicodeError) as error:
                failures.append(dict(provenance=provenance, error=str(error)))
    result = dict(native_schema=dict(source=executable['source'], sha256=executable['sha256'], **schema),
        panels=rows, failures=failures, runtime_binding_verified=False,
        limitations=['Only first explicitly serialized UserWidget path decoded; remaining bytes retained as opaque.',
                     'Asset reference does not establish runtime instantiation, visibility or input state.',
                     'Omitted/zero property does not resolve inherited/archetype defaults.'])
    target = ROOT / 'ui-geometry/deferred-panels.json'
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(panels=len(rows), explicit_paths=sum(r['decoded']['status'] == 'explicit_asset_path' for r in rows),
        failures=len(failures), examples=failures[:2], array_offset=schema['array_offset'])))


if __name__ == '__main__':
    main()
