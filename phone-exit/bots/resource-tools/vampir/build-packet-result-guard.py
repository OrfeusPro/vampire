"""Keep result guard branches, compact switch data and localization provenance."""
import csv
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('guard_spans', HERE / 'build-lock-predicate-code.py')
spans = importlib.util.module_from_spec(spec)
spec.loader.exec_module(spans)
native, ROOT = spans.native, spans.native.ROOT


def checked_compact_dispatch(target_bytes, selector_bytes, base, boundaries):
    if len(target_bytes) != 16 or len(selector_bytes) != 227:
        raise ValueError('Unexpected compact dispatch size')
    targets = [base + rva for rva in struct.unpack('<4I', target_bytes)]
    if any(t not in boundaries for t in targets):
        raise ValueError('Dispatch target not an instruction boundary')
    if any(s >= len(targets) for s in selector_bytes):
        raise ValueError('Selector outside target table')
    return [dict(result=0x519 + index, selector=selector, target=targets[selector])
            for index, selector in enumerate(selector_bytes)]


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    function = image.containing(0x1467a8e10)
    if function is None or function[:2] != (0x67a8e10, 0x67a931b):
        raise ValueError('Guard runtime extent changed')
    code = spans.decode_span(image, 0x1467a8e10, 0x1467a9228)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)]
        for a in (0x145f8a7a0, 0x144a279d0)})
    rows = {r['address']: r for f in [code] + fragments for r in f['instructions']}
    checks = [
        (0x1467a8e32, 'mov', 'ebx, ecx'),
        (0x1467a8e39, 'cmp', 'byte ptr [rax + 8], 1'),
        (0x1467a8e3d, 'jne', '0x1467a8e50'),
        (0x1467a8e43, 'test', 'ebx, ebx'),
        (0x1467a8e45, 'jne', '0x1467a9202'),
        (0x1467a8e4b, 'jmp', '0x1467a91da'),
        (0x1467a8e76, 'test', 'ebx, ebx'),
        (0x1467a8e78, 'je', '0x1467a91d6'),
        (0x1467a9007, 'cmp', 'eax, 0xe2'),
        (0x1467a901b, 'movzx', 'eax, byte ptr [rdx + rax + 0x67a9238]'),
        (0x1467a9023, 'mov', 'ecx, dword ptr [rdx + rax*4 + 0x67a9228]'),
        (0x1467a902d, 'jmp', 'rcx'),
        (0x1467a9142, 'cmp', 'ebx, 0x1197'),
        (0x1467a914e, 'je', '0x1467a91cf'),
        (0x1467a91d1, 'call', '0x145f8a7a0'),
        (0x1467a91e4, 'mov', 'al, 1'),
        (0x1467a91f9, 'call', '0x145f8a7a0'),
        (0x1467a920c, 'xor', 'al, al'),
        (0x145f8a7b6, 'cmp', 'ecx, 0x2a'),
        (0x145f8a8b5, 'call', '0x144a279d0'),
        (0x144a279da, 'cmp', 'dword ptr [rdx + 8], 1'),
        (0x144a279e4, 'jle', '0x144a27a25'),
        (0x144a279e6, 'cmp', 'byte ptr [rcx + 0x2c4], 1'),
        (0x144a279ed, 'je', '0x144a27a25'),
        (0x144a27a20, 'jmp', '0x144a1c510'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed result guard changed: ' + hex(address))
    target_offset, selector_offset = image.offset(0x67a9228), image.offset(0x67a9238)
    target_bytes = data[target_offset:target_offset + 16]
    selector_bytes = data[selector_offset:selector_offset + 227]
    dispatch = checked_compact_dispatch(target_bytes, selector_bytes, image.pe.base,
                                       {r['address'] for r in code['instructions']})
    if [r['target'] for r in dispatch if r['selector'] == 1] != [0x1467a902f] * 2:
        raise ValueError('Reviewed asset-message paths changed')
    keys = []
    for address, key in [(0x1467a8eb2, 'NAME_SLANDER'),
                         (0x1467a8fb6, 'GUILDINVENTORY_SLOT_FULL'),
                         (0x1467a9093, 'ASSET_MAXVALUE_ERROR_MAIL'),
                         (0x1467a9137, 'GUILD_INVITE_NOTUSER_MESSAGE'),
                         (0x1467a916d, 'CHAT_SPAM_MSG')]:
        row = rows[address]
        offset = image.offset(row['rip_references'][0] - image.pe.base)
        encoding = 'ascii' if key == 'NAME_SLANDER' else 'utf-16le'
        raw = (key + '\0').encode(encoding)
        if data[offset:offset + len(raw)] != raw:
            raise ValueError('Localization key literal changed')
        keys.append(dict(key=key, file_offset=offset, encoding=encoding, bytes=raw.hex(), instruction=row))
    tables = json.loads((ROOT / 'table-study/index-pakchunk1-Windows.json').read_text(encoding='utf-8'))['tables']
    meta = next(r for r in tables if r['entry'] == 405)
    path = ROOT / 'table-study' / meta['file']
    if hashlib.sha256(path.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('Localization CSV changed')
    with path.open(encoding='utf-8-sig', newline='') as stream:
        localized = {}
        for index, row in enumerate(csv.DictReader(stream), 2):
            if row['Key'] in {k['key'] for k in keys}:
                if row['Key'] in localized:
                    raise ValueError('Duplicate localization key')
                localized[row['Key']] = dict(csv_record=index, row=row)
    for key in keys:
        if key['key'] not in localized:
            raise ValueError('Unresolved localized message')
        key['localization'] = localized[key['key']]
    report = dict(source=source['source'], sha256=source['sha256'], code=code, fragments=fragments,
                  anchors=[rows[a] for a, _, _ in checks], localization_source=meta, keys=keys,
                  embedded_data=dict(target_file_offset=target_offset, targets=target_bytes.hex(),
                                     selector_file_offset=selector_offset, selectors=selector_bytes.hex(),
                                     decoded_dispatch=dispatch),
                  observations=dict(normal_zero_result_continues=True,
                                    normal_4503_calls_error_helper_then_continues=True,
                                    mode_flag_equal_1_nonzero_result_blocks=True),
                  runtime_evaluator_enabled=False,
                  limitations=['Mode flag name and code4503 symbolic meaning are unknown.',
                               'Helper/UI call does not guarantee a visible popup: text and manager guards apply.',
                               'Specific WBP/layout of the generic message path not bound yet.',
                               'Only static client behavior; no network, Android, player state or automated retry.'])
    output = ROOT / 'code-clues/packet-result-guard.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(anchors=len(checks), code_instructions=len(code['instructions']),
                          dispatch_entries=len(dispatch), localized_keys=len(keys),
                          fragments=len(fragments), runtime_evaluator_enabled=False)))


if __name__ == '__main__':
    main()
