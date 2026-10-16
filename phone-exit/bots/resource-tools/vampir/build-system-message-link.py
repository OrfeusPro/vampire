"""Join error-message path, native text binding and cooked system-message UI."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('message_class', HERE / 'build-fader-class-link.py')
classes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(classes)
native, ROOT = classes.native, classes.ROOT


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source_path = ROOT / 'code-clues/packet-result-guard.json'
    source_bytes = source_path.read_bytes()
    source = json.loads(source_bytes)
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    addresses = (0x144a1c510, 0x144a61920, 0x144a64490, 0x144a7acb0, 0x144a832e0)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    checks = [
        (0x144a1c639, 'mov', 'rdi, qword ptr [rip + 0x6b032a0]'),
        (0x144a1c640, 'cmp', 'byte ptr [rdi + 0x260], bl'),
        (0x144a1c6c6, 'call', '0x144a18d60'),
        (0x144a1c718, 'mov', 'rdx, rsi'),
        (0x144a1c71b, 'mov', 'rcx, rdi'),
        (0x144a1c71e, 'call', '0x144a832e0'),
        (0x144a6198e, 'mov', 'qword ptr [r11 - 0x30], rax'),
        (0x144a644b8, 'mov', 'qword ptr [rbx], rax'),
        (0x144a644c9, 'mov', 'qword ptr [rbx + 0xa00], rdi'),
        (0x144a7ace5, 'call', '0x1435ff340'),
        (0x144a7ad1d, 'mov', 'qword ptr [rdi + 0xa00], rbx'),
        (0x144a7ad41, 'call', '0x1435ff340'),
        (0x144a7ad91, 'call', '0x1435ff340'),
        (0x144a7adc0, 'mov', 'qword ptr [rdi + 0xa08], rbx'),
        (0x144a832e6, 'mov', 'rdi, qword ptr [rcx + 0xa00]'),
        (0x144a832f0, 'je', '0x144a8332f'),
        (0x144a83318, 'call', 'rbx'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed system message path changed: ' + hex(address))
    literals = []
    for address, text in [
            (0x144a1c542, 'FNkSystemMessageProcessor::AddSystemMessage()'),
            (0x144a1c6a0, 'Common/MessageBox/WBP_SystemMessageUI'),
            (0x144a61966, 'NkSystemMessageUI'), (0x144a61975, '/Script/NkUMG'),
            (0x144a7acc8, 'TextMessage'),
            (0x144a7ad24, 'CommonMessageNotifyLightUI'),
            (0x144a7ad74, 'ImageBackGround')]:
        row = rows[address]
        offset = image.offset(row['rip_references'][0] - image.pe.base)
        raw = (text + '\0').encode('utf-16le')
        if data[offset:offset + len(raw)] != raw:
            raise ValueError('System message literal changed')
        literals.append(dict(text=text, file_offset=offset, bytes=raw.hex(), instruction=row))
    if rows[0x144a61987]['rip_references'] != [0x144a64490]:
        raise ValueError('Class initializer changed')
    if rows[0x144a644af]['rip_references'] != [0x149603550]:
        raise ValueError('Native vtable changed')
    slot_offset = image.offset(0x149603550 + 0x530 - image.pe.base)
    if struct.unpack_from('<Q', data, slot_offset)[0] != 0x144a7acb0:
        raise ValueError('Text binder vtable slot changed')
    index_path = ROOT / 'ui-catalog/index.json'
    index = json.loads(index_path.read_text(encoding='utf-8'))
    variants = []
    for item in index['windows']:
        if item['name'] not in ('WBP_SystemMessageUI', 'WBP_CommonMessageNotifyLightUI'):
            continue
        filename = item['file']
        catalog_path = ROOT / 'ui-catalog' / filename
        layout_path = ROOT / 'ui-layout-study' / filename
        catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
        layout = json.loads(layout_path.read_text(encoding='utf-8'))
        asset = (ROOT / 'ui-layout-study' / filename.replace('.json', '.uasset')).read_bytes()
        body = (ROOT / 'ui-layout-study' / filename.replace('.json', '.uexp')).read_bytes()
        for key, payload in [('asset_sha256', asset), ('body_sha256', body)]:
            if hashlib.sha256(payload).hexdigest() != catalog[key] or catalog[key] != layout[key]:
                raise ValueError('Cooked variant changed: ' + filename)
        combined = asset + body
        for export in [catalog['root_export']] + catalog['controls']:
            offset, size = export['offset'], export['size']
            if hashlib.sha256(combined[offset:offset + size]).hexdigest() != export['sha256']:
                raise ValueError('Cooked export hash mismatch')
        superclass = classes.superclass(asset, layout, catalog['root_export']['index'])
        controls = {r['name']: r['type'] for r in catalog['controls']}
        if item['name'] == 'WBP_SystemMessageUI':
            if (superclass['path'] != '/Script/NkUMG.NkSystemMessageUI' or
                    controls.get('TextMessage') != 'NkRichTextBlock' or
                    controls.get('CommonMessageNotifyLightUI') != 'WBP_CommonMessageNotifyLightUI_C'):
                raise ValueError('System message class/controls changed')
        elif controls.get('ImageBackGround') != 'Image':
            raise ValueError('Nested message background changed')
        variants.append(dict(file=filename, name=item['name'],
            catalog_sha256=hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
            layout_sha256=hashlib.sha256(layout_path.read_bytes()).hexdigest(),
            source=catalog['source'], entry=catalog['entry'], resource_paths=catalog['resource_paths'],
            asset_sha256=catalog['asset_sha256'], body_sha256=catalog['body_sha256'],
            superclass=superclass, controls=catalog['controls'], decoded_slots=catalog['decoded_slots'],
            absolute_screen_geometry_verified=False))
    if len(variants) != 4 or sum(v['name'] == 'WBP_SystemMessageUI' for v in variants) != 2:
        raise ValueError('Reviewed message variants changed')
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
                  guard_report_sha256=hashlib.sha256(source_bytes).hexdigest(),
                  catalog_index_sha256=hashlib.sha256(index_path.read_bytes()).hexdigest(),
                  anchors=[rows[a] for a, _, _ in checks], literals=literals,
                  native_class='/Script/NkUMG.NkSystemMessageUI', native_vtable=0x149603550,
                  binder_slot=0x530, binder=0x144a7acb0, text_field=0xa00,
                  text_writer=0x144a832e0, variants=variants,
                  runtime_actions_enabled=False,
                  limitations=['System-message path, not proof that every error is an OK dialog.',
                               'TextMessage has no decoded parent slot; do not invent its absolute rectangle.',
                               'Local layout is not Android DPI, runtime positioning or animation state.',
                               'Nested widget class names match; active Android archive selection unverified.',
                               'No clicks, runtime state, screenshots or process memory used.'])
    output = ROOT / 'code-clues/system-message-link.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(anchors=len(checks), literals=len(literals), variants=len(variants),
                          fragments=len(fragments), text_field='0xa00', runtime_actions_enabled=False)))


if __name__ == '__main__':
    main()
