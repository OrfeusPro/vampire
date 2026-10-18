"""Extract cooked WidgetBlueprint export trees, with bounded serialization ranges.

Does not guess unversioned-property schemas or runtime screen coordinates.
"""
import hashlib
import importlib.util
import json
import os
import re
import struct
import argparse
import csv
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
HERE = Path(__file__).resolve().parent


def exports(asset, body, max_exports=10000):
    if asset[:4] != bytes.fromhex('c1832a9e'):
        raise ValueError('Not a legacy cooked package')
    size = struct.unpack_from('<i', asset, 32)[0]
    if not 0 < size < 4096:
        raise ValueError('Unsupported package summary')
    summary = 36 + size
    count, position = struct.unpack_from('<ii', asset, summary + 4)
    if not 0 < count < 100000:
        raise ValueError('Invalid name count')
    names = []
    for _ in range(count):
        n = struct.unpack_from('<i', asset, position)[0]
        position += 4
        if not 0 < abs(n) < 65536:
            raise ValueError('Invalid name')
        length = n if n > 0 else -n * 2
        raw = asset[position:position + length]
        if len(raw) != length:
            raise ValueError('Truncated name')
        names.append(raw[:-1].decode('utf-8') if n > 0 else raw[:-2].decode('utf-16le'))
        position += length + 4
    ec, eo, ic, io = struct.unpack_from('<iiii', asset, summary + 28)
    if not 0 < ec <= max_exports or not 0 <= ic <= 10000 or eo + ec * 96 > len(asset) or io + ic * 32 > len(asset):
        raise ValueError('Unsupported export/import table layout')
    result = []
    for i in range(ec):
        pos = eo + i * 96
        cls, _, _, outer, ni, number, _ = struct.unpack_from('<iiiiiiI', asset, pos)
        length, offset = struct.unpack_from('<qq', asset, pos + 28)
        if not 0 <= ni < len(names) or not 0 <= outer <= ec or not -ic <= cls <= ec:
            raise ValueError('Invalid object reference')
        if length < 0 or offset < len(asset) or offset + length > len(asset) + len(body):
            raise ValueError('Export range outside body')
        typename = names[struct.unpack_from('<i', asset, io + (-cls - 1) * 32 + 20)[0]] if cls < 0 else 'local_export_' + str(cls)
        data = body[offset - len(asset):offset - len(asset) + length]
        row = dict(index=i + 1, name=names[ni] + ('_' + str(number - 1) if number else ''),
                   type=typename, outer=outer, offset=offset, size=length, sha256=hashlib.sha256(data).hexdigest())
        if typename.endswith('Slot'):
            row['serialized_hex'] = data.hex()
            row['geometry_decoded'] = False
        result.append(row)
    if sum(e['size'] for e in result) + 4 != len(body):
        raise ValueError('Export body not fully accounted for')
    for row in result:
        row['parent'] = result[row['outer'] - 1]['name'] if row['outer'] else None
    return dict(names=names, exports=result, geometry_schema_verified=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tutorial-controls', action='store_true')
    parser.add_argument('--npc-shop', action='store_true', help='Include NPC shop and its buy/list widgets')
    parser.add_argument('--message-boxes', action='store_true', help='Include standard message/confirmation popup candidates')
    parser.add_argument('--popups', action='store_true', help='Include all discovered WBP popup and common message resources')
    parser.add_argument('--all-widgets', action='store_true', help='Include all discovered UI WidgetBlueprint references')
    args = parser.parse_args()
    wanted = set()
    if args.tutorial_controls:
        with (ROOT / 'table-study/pakchunk1-Windows-1556.csv').open(encoding='utf-8-sig', newline='') as stream:
            for row in csv.DictReader(stream):
                wanted.add(row['WBPName'])
    spec = importlib.util.spec_from_file_location('vampir_reader', HERE.parent / 'rfnext' / 'scan-pak.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    out = ROOT / 'ui-layout-study'
    out.mkdir(exist_ok=True)
    reports = []
    for folder in sorted((ROOT / 'pak-extracted').iterdir()):
        rows = json.loads((folder / 'entries.json').read_text('utf-8'))
        source = json.loads((folder / 'source.json').read_text('utf-8'))
        with Path(source['path']).open('rb') as stream:
            for row in rows[:-1]:
                paths = [p for p in row.get('paths', []) if re.search(r'/UI/(Tutorial/WBP_Tutorial|GameUI/.*Quest|Quest/.*Main|Skill/.*Active)', p)
                         or p.rsplit('/', 1)[-1] in wanted
                         or (args.npc_shop and '/UI/NpcShop/WBP_' in p)
                         or (args.message_boxes and p.rsplit('/', 1)[-1] in (
                             'WBP_MessageBoxConfirmPopup', 'WBP_MessageBoxPopup', 'WBP_SystemMessageBoxPopup'))
                         or (args.popups and '/UI/' in p and p.rsplit('/', 1)[-1].startswith('WBP_') and
                             ('Popup' in p.rsplit('/', 1)[-1] or '/Common/MessageBox/' in p))
                         or (args.all_widgets and '/UI/' in p and p.rsplit('/', 1)[-1].startswith('WBP_'))]
                if not paths or row.get('encrypted'):
                    continue
                following = rows[row['entry'] + 1]
                if following.get('encrypted') or following.get('uasset') or following.get('uncompressed', 0) > 16 * 1024 * 1024:
                    continue
                try:
                    asset = reader.decode(stream, reader.header(stream, row['offset'], rows[-1]['index_offset']))
                    body = reader.decode(stream, reader.header(stream, following['offset'], rows[-1]['index_offset']))
                    report = exports(asset, body)
                    report.update(source=source, entry=row['entry'], body_entry=following['entry'], paths=paths,
                                  asset_sha256=hashlib.sha256(asset).hexdigest(), body_sha256=hashlib.sha256(body).hexdigest())
                    file = folder.name + '-' + str(row['entry'])
                    (out / (file + '.uasset')).write_bytes(asset)
                    (out / (file + '.uexp')).write_bytes(body)
                    (out / (file + '.json')).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
                    reports.append(dict(file=file + '.json', paths=paths, exports=len(report['exports']), source=source['path']))
                except Exception as error:
                    reports.append(dict(paths=paths, source=source['path'], entry=row['entry'], error=type(error).__name__))
    (out / 'index.json').write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Widget packages parsed', sum('file' in r for r in reports), 'skipped', sum('error' in r for r in reports))


if __name__ == '__main__':
    main()
