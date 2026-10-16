"""Link named unlock result handlers through tail wrappers to state updates."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('packet_calls', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native, ROOT = calls.native, calls.ROOT
span_spec = importlib.util.spec_from_file_location('packet_spans', HERE / 'build-lock-predicate-code.py')
spans = importlib.util.module_from_spec(span_spec)
span_spec.loader.exec_module(spans)


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    functions = (0x146763cd0, 0x146763da0)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in functions})
    wrappers = [spans.decode_span(image, 0x145ce8e20, 0x145ce8e2c),
                spans.decode_span(image, 0x145ce8e30, 0x145ce8e3b)]
    rows = {r['address']: r for f in fragments + wrappers for r in f['instructions']}
    checks = [
        (0x146763cda, 'mov', 'rbx, r8'),
        (0x146763d6c, 'call', '0x1467a8e10'),
        (0x146763d71, 'test', 'al, al'), (0x146763d73, 'je', '0x146763d89'),
        (0x146763d75, 'call', '0x145cdf220'),
        (0x146763d7a, 'lea', 'rdx, [rbx + 0x18]'),
        (0x146763d7e, 'mov', 'r8b, 1'),
        (0x146763d84, 'call', '0x145ce8e20'),
        (0x146763daa, 'mov', 'rbx, r8'),
        (0x146763e3c, 'call', '0x1467a8e10'),
        (0x146763e41, 'test', 'al, al'), (0x146763e43, 'je', '0x146763e56'),
        (0x146763e45, 'call', '0x145cdf220'),
        (0x146763e4a, 'lea', 'rdx, [rbx + 0x18]'),
        (0x146763e51, 'call', '0x145ce8e30'),
        (0x145ce8e20, 'movzx', 'r9d, r8b'),
        (0x145ce8e24, 'mov', 'r8b, 1'),
        (0x145ce8e27, 'jmp', '0x145ced700'),
        (0x145ce8e30, 'xor', 'r9d, r9d'),
        (0x145ce8e33, 'xor', 'r8d, r8d'),
        (0x145ce8e36, 'jmp', '0x145ced700'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed packet path changed: ' + hex(address))
    literals = []
    for address, text in [
            (0x146763ce4, 'PktContentsUnlockListReadResultHandler::OnHandler()'),
            (0x146763db4, 'PktContentsUnlockRequestResultHandler::OnHandler()')]:
        row = rows[address]
        if row['mnemonic'] != 'lea' or len(row['rip_references']) != 1:
            raise ValueError('Handler name reference changed')
        offset = image.offset(row['rip_references'][0] - image.pe.base)
        expected = (text + '\0').encode('utf-16le')
        if data[offset:offset + len(expected)] != expected:
            raise ValueError('Handler name literal changed')
        literals.append(dict(text=text, file_offset=offset, encoding='utf-16le',
                             bytes=expected.hex(), instruction=row))
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(calls.direct_call_candidates(data, section['raw'], section['raw_size'],
                                                        image.pe.address, {0x145ce8e20, 0x145ce8e30}))
    if set(candidates) != {(0x146763d84, 0x145ce8e20), (0x146763e51, 0x145ce8e30)}:
        raise ValueError('Reviewed wrapper caller set changed')
    for address, target in candidates:
        if not calls.checked_call(rows[address], target):
            raise ValueError('Caller is not a decoded direct call')
    state_path = ROOT / 'code-clues/lock-state-code.json'
    state = json.loads(state_path.read_text(encoding='utf-8'))
    if any(state[k] != source[k] for k in ('source', 'sha256')):
        raise ValueError('Mixed state executable version')
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
                  wrappers=wrappers, anchors=[rows[a] for a, _, _ in checks], literals=literals,
                  state_report_sha256=hashlib.sha256(state_path.read_bytes()).hexdigest(),
                  result_paths=[dict(handler=functions[0], packet_array_offset=24,
                                     wrapper=0x145ce8e20, replace=True, fourth_argument=1),
                                dict(handler=functions[1], packet_array_offset=24,
                                     wrapper=0x145ce8e30, replace=False, fourth_argument=0)],
                  update_target=0x145ced700, runtime_evaluator_enabled=False,
                  limitations=['Exact transport/dispatcher registration and packet serialization not reconstructed.',
                               'Named result handlers call a guard; its full success/error contract remains unknown.',
                               'Fourth update argument meaning is unknown; preserve observed values.',
                               'These paths receive results; they do not show how to send unlock requests.',
                               'No packet injection, network request, game execution or Android test.'])
    output = ROOT / 'code-clues/lock-packet-links.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(anchors=len(checks), handlers=len(fragments), wrappers=len(wrappers),
                          named_result_paths=len(literals), runtime_evaluator_enabled=False)))


if __name__ == '__main__':
    main()
