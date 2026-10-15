"""Verified direct callers of easing stop; distinguish cleanup from completion."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('stop_call_reader', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native, ROOT = calls.native, calls.ROOT


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/ui-transition-code.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(calls.direct_call_candidates(data, section['raw'], section['raw_size'],
                image.pe.address, {0x1445d2690}))
    roots = {image.roots[function] for address, _ in candidates
             if (function := image.containing(address)) is not None}
    fragments = native.decode_ranges(image, roots)
    rows = {row['address']: (fragment, index, row) for fragment in fragments
            for index, row in enumerate(fragment['instructions'])}
    verified, unresolved = [], []
    for address, target in candidates:
        found = rows.get(address)
        if not found or not calls.checked_call(found[2], target):
            unresolved.append(dict(address=address, target=target))
        else:
            fragment, index, row = found
            verified.append(dict(instruction=row, root_begin_rva=fragment['root_begin_rva'],
                context=fragment['instructions'][max(0, index - 10):index + 18]))
    checks = [(0x1445d10b6, 'cmp', 'byte ptr [rcx + 0x44], 0'),
              (0x1445d10cc, 'call', '0x1445d2690'),
              (0x1445d10d8, 'mov', 'qword ptr [rbx + 0x10], 0'),
              (0x1445d10e0, 'mov', 'qword ptr [rbx + 0xe0], 0'),
              (0x1445bf7f3, 'call', 'qword ptr [rax + 0x10]'),
              (0x1445c04c9, 'call', 'qword ptr [rax + 0x10]'),
              (0x1445d347a, 'call', '0x1445d2690')]
    anchors = []
    for address, mnemonic, operands in checks:
        found = rows.get(address)
        if found is None or (found[2]['mnemonic'], found[2]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed stop caller changed: ' + hex(address))
        anchors.append(found[2])
    output = ROOT / 'code-clues/easing-stop-links.json'
    output.write_text(json.dumps(dict(source=source['source'], sha256=source['sha256'],
        callers=verified, unresolved_candidates=unresolved, fragments=fragments, anchors=anchors,
        reset_to_easing_stop_verified=False,
        limitations=['Direct E8 callers only; indirect/tail paths not indexed here.',
                     'Stop wrapper clears handle; cleanup slot +0x10 differs from completion invocation slot +8.',
                     'Cleanup virtual method names not reconstructed; do not call them successful completion.',
                     'Window reset-to-easing-stop path remains unresolved; no Android execution.']),
        ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(callers=len(verified), unresolved=len(unresolved), roots=len(roots),
                         fragments=len(fragments), reset_to_stop_verified=False)))


if __name__ == '__main__':
    main()
