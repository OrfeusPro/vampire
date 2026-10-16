"""Bind unlock handler registration and direct condition-readiness callers."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('registration_calls', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
span_spec = importlib.util.spec_from_file_location('registration_spans', HERE / 'build-lock-predicate-code.py')
spans = importlib.util.module_from_spec(span_spec)
span_spec.loader.exec_module(spans)
native, ROOT = calls.native, calls.ROOT


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(calls.direct_call_candidates(data, section['raw'], section['raw_size'],
                                                        image.pe.address, {0x145ced600}))
    event_roots = {image.roots[image.containing(a)] for a, _ in candidates if image.containing(a)}
    fragments = native.decode_ranges(image, event_roots | {image.roots[image.containing(0x1467a7250)]})
    # Decode the factory from its unwind boundary to verify selected span boundaries,
    # but keep only its relevant block in the report (the full factory has 18k instructions).
    factory = native.decode_ranges(image, {image.roots[image.containing(0x146792b1b)]})
    factory_rows = {r['address']: r for f in factory for r in f['instructions']}
    if 0x146792b1b not in factory_rows or 0x146792bb1 not in factory_rows:
        raise ValueError('Factory block boundaries changed')
    block = spans.decode_span(image, 0x146792b1b, 0x146792bb1)
    leaves = [spans.decode_span(image, a, b) for a, b in
              [(0x1456e99f0, 0x1456e9a0b), (0x1456e9ab0, 0x1456e9acb),
               (0x1456f8560, 0x1456f8566), (0x1456f8580, 0x1456f8586)]]
    rows = {r['address']: r for f in fragments + [block] + leaves for r in f['instructions']}
    checks = [
        (0x146792b34, 'mov', 'qword ptr [rdi], rax'),
        (0x146792b4e, 'call', '0x1456e99f0'),
        (0x146792b58, 'mov', 'r8, rdi'), (0x146792b5b, 'mov', 'rdx, rax'),
        (0x146792b61, 'call', '0x1467a7250'),
        (0x146792b7f, 'mov', 'qword ptr [rdi], rax'),
        (0x146792b99, 'call', '0x1456e9ab0'),
        (0x146792ba3, 'mov', 'r8, rdi'), (0x146792ba6, 'mov', 'rdx, rax'),
        (0x146792bac, 'call', '0x1467a7250'),
        (0x1467a7285, 'call', 'qword ptr [rax + 0x28]'),
        (0x1467a7291, 'mov', 'word ptr [rsp + 0x48], ax'),
        (0x1467a72a5, 'call', '0x14678e3e0'),
        (0x1456f8560, 'mov', 'eax, 0x3ef'),
        (0x1456f8580, 'mov', 'eax, 0x3f1'),
        (0x145d05a0d, 'mov', 'dl, 3'), (0x145d05a1f, 'mov', 'dl, 8'),
        (0x145d73f28, 'movzx', 'edx, r8b'),
        (0x145d7dc8c, 'xor', 'edx, edx'),
        (0x14675ebfe, 'mov', 'dl, 3'), (0x14675ec10, 'mov', 'dl, 7'),
        (0x14676d782, 'mov', 'dl, 7'),
        (0x145d05a0a, 'mov', 'r8b, 1'), (0x145d05a1c, 'mov', 'r8b, 1'),
        (0x145d73f22, 'mov', 'r8b, 1'), (0x145d7dc89, 'mov', 'r8b, 1'),
        (0x14675ebfb, 'mov', 'r8b, 1'), (0x14675ec0d, 'mov', 'r8b, 1'),
        (0x14676d77f, 'mov', 'r8b, 1'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed registration/event changed: ' + hex(address))
    sites = [(0x145d05a12, 3), (0x145d05a24, 8), (0x145d73f2c, 1),
             (0x145d7dc91, 0), (0x14675ec03, 3), (0x14675ec15, 7), (0x14676d787, 7)]
    if set(candidates) != {(a, 0x145ced600) for a, _ in sites}:
        raise ValueError('Reviewed setter direct callers changed')
    for address, _ in sites:
        if not calls.checked_call(rows[address], 0x145ced600):
            raise ValueError('Unverified event call')
    names = []
    for address, text, encoding in [
            (0x14675e9d3, 'PktCharacterSelectResultHandler::OnHandler()', 'utf-16le'),
            (0x14676d684, 'PktEngravingResultHandler::OnHandler()', 'utf-16le'),
            (0x1467a72fb, 'PacketDispatcher::_AddPacketHandler', 'ascii')]:
        row = rows[address]
        offset = image.offset(row['rip_references'][0] - image.pe.base)
        expected = (text + '\0').encode(encoding)
        if data[offset:offset + len(expected)] != expected:
            raise ValueError('Named diagnostic changed')
        names.append(dict(text=text, encoding=encoding, file_offset=offset,
                          bytes=expected.hex(), instruction=row))
    registrations = []
    for ref, vtable, handler, constructor, packet_vtable, id_getter, packet_id in [
            (0x146792b2d, 0x149d81a40, 0x146763cd0, 0x1456e99f0, 0x1498dca80, 0x1456f8560, 1007),
            (0x146792b78, 0x149d81a58, 0x146763da0, 0x1456e9ab0, 0x1498dcb88, 0x1456f8580, 1009)]:
        if rows[ref]['rip_references'] != [vtable]:
            raise ValueError('Handler table reference changed')
        if struct.unpack_from('<Q', data, image.offset(vtable - image.pe.base) + 16)[0] != handler:
            raise ValueError('Handler method slot changed')
        if rows[constructor]['rip_references'] != [packet_vtable]:
            raise ValueError('Packet constructor vtable changed')
        if struct.unpack_from('<Q', data, image.offset(packet_vtable - image.pe.base) + 40)[0] != id_getter:
            raise ValueError('Packet identifier slot changed')
        registrations.append(dict(handler_vtable=vtable, on_handler=handler, method_slot=16,
                                  packet_constructor=constructor, packet_vtable=packet_vtable,
                                  packet_id_getter=id_getter, packet_id=packet_id))
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
                  factory_block=block, leaves=leaves, named_diagnostics=names,
                  anchors=[rows[a] for a, _, _ in checks], registrations=registrations,
                  direct_readiness_calls=[dict(instruction=rows[a], type=t, ready=True) for a, t in sites],
                  runtime_evaluator_enabled=False,
                  limitations=['Direct E8 setter callers only; tail/indirect event paths not covered.',
                               'Other three event root names not proven; keep addresses without invented labels.',
                               'Dispatcher insertion linked, complete receive-and-dispatch path not yet reconstructed.',
                               'Message identifiers are static evidence only, not a bot network API.',
                               'No requests sent, packets injected, or Android/player state read.'])
    output = ROOT / 'code-clues/lock-registration-events.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(anchors=len(checks), registrations=len(registrations),
                          readiness_calls=len(sites), fragments=len(fragments),
                          named_diagnostics=len(names), runtime_evaluator_enabled=False)))


if __name__ == '__main__':
    main()
