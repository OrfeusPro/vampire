"""Join cooked superclass imports, native class registration and vtable slots."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fader_manager', HERE / 'build-ui-manager-code.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
native, ROOT = manager.native, manager.ROOT


def superclass(asset, report, root_index):
    string_size = struct.unpack_from('<i', asset, 32)[0]
    if not 0 < string_size < 4096:
        raise ValueError('Unsupported package summary')
    summary = 36 + string_size
    ec, eo, ic, io = struct.unpack_from('<iiii', asset, summary + 28)
    if not 1 <= root_index <= ec or eo + ec * 96 > len(asset) or io + ic * 32 > len(asset):
        raise ValueError('Invalid import/export bounds')
    root_offset = eo + (root_index - 1) * 96
    reference = struct.unpack_from('<i', asset, root_offset + 4)[0]
    chain, seen = [], set()
    while reference:
        if reference in seen or not -ic <= reference < 0:
            raise ValueError('Unsupported or cyclic superclass import')
        seen.add(reference)
        offset = io + (-reference - 1) * 32
        outer, ni, number = struct.unpack_from('<iii', asset, offset + 16)
        if not 0 <= ni < len(report['names']) or number != 0:
            raise ValueError('Invalid superclass import name')
        chain.append(dict(reference=reference, offset=offset, name_index=ni,
                          name=report['names'][ni], outer=outer, bytes=asset[offset:offset + 32].hex()))
        reference = outer
    if len(chain) != 2 or not chain[1]['name'].startswith('/Script/'):
        raise ValueError('Expected native class with script package')
    return dict(root_export=root_index, superclass_field_offset=root_offset + 4,
                path=chain[1]['name'] + '.' + chain[0]['name'], import_chain=chain)


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/ui-transition-code.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native source changed')
    image = native.Image(data)
    addresses = (0x144a2cf50, 0x144a33370, 0x144a47960)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {row['address']: row for part in fragments for row in part['instructions']}
    checks = [(0x144a2cf96, 'lea', 'rdx, [rip + 0x4bc362d]'),
              (0x144a2cfa5, 'lea', 'rcx, [rip + 0x4bbdf04]'),
              (0x144a2cfb7, 'lea', 'rax, [rip + 0x63b2]'),
              (0x144a33391, 'lea', 'rax, [rip + 0x4bc1e48]'),
              (0x144a33398, 'mov', 'qword ptr [rbx], rax')]
    anchors = [manager.verify_anchor(rows, *check) for check in checks]
    for address, text in [(0x144a2cf96, 'NkFaderUI'), (0x144a2cfa5, '/Script/NkUMG')]:
        pointer = rows[address]['rip_references'][0]
        offset = image.offset(pointer - image.pe.base)
        raw = (text + '\0').encode('utf-16le')
        if data[offset:offset + len(raw)] != raw:
            raise ValueError('Native registration name changed')
    if rows[0x144a2cfb7]['rip_references'] != [0x144a33370]:
        raise ValueError('Native initializer reference changed')
    vtable = rows[0x144a33391]['rip_references'][0]
    slots = []
    for relative, target in [(0x530, 0x144a4c440), (0x570, 0x144a4ca20)]:
        offset = image.offset(vtable + relative - image.pe.base)
        if struct.unpack_from('<Q', data, offset)[0] != target:
            raise ValueError('Fader vtable target changed')
        slots.append(dict(slot_offset=relative, file_offset=offset, target=target, bytes=data[offset:offset + 8].hex()))
    variants = []
    for item in source['image_fader_widget_candidates']:
        file = item['catalog_file']
        catalog = json.loads((ROOT / 'ui-catalog' / file).read_text(encoding='utf-8'))
        report = json.loads((ROOT / 'ui-layout-study' / file).read_text(encoding='utf-8'))
        asset = (ROOT / 'ui-layout-study' / file.replace('.json', '.uasset')).read_bytes()
        if hashlib.sha256(asset).hexdigest() != item['asset_sha256'] or report['asset_sha256'] != item['asset_sha256']:
            raise ValueError('Cooked source changed')
        link = superclass(asset, report, catalog['root_export']['index'])
        expected = '/Script/NkUMG.' + ('NkFaderUI' if item['name'] == 'WBP_FaderUI' else 'NkMediaPlayerUI')
        if link['path'] != expected:
            raise ValueError('Widget superclass changed')
        variants.append(dict(resource=item, superclass=link,
            matches_native_fader_class=link['path'] == '/Script/NkUMG.NkFaderUI'))
    output = ROOT / 'code-clues/fader-class-link.json'
    output.write_text(json.dumps(dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
        anchors=anchors, native_class='/Script/NkUMG.NkFaderUI', vtable_address=vtable,
        vtable_slots=slots, variants=variants,
        limitations=['Cooked superclass and native registration/vtable relation proven for Windows build.',
                     'Specific instance creation, override invocation order, Android asset parity and screen pixels unverified.']),
        ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(variants=len(variants), fader_variants=sum(v['matches_native_fader_class'] for v in variants),
                         vtable=hex(vtable), slots=len(slots))))


if __name__ == '__main__':
    main()
