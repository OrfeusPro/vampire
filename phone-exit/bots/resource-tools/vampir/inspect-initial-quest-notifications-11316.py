"""Inspect three explicit packet IDs seen at world entry. Static only, no game IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
IDS = (1827, 1840, 1854)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(image):
    native = load('build-native-entry-code')
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned Capstone required')
    raw = image.data
    text = next(s for s in image.pe.sections if s['name'] == '.text')
    rdata = next(s for s in image.pe.sections if s['name'] == '.rdata')
    start, end = rdata['raw'], rdata['raw'] + rdata['raw_size']
    packets = []
    for packet_id in IDS:
        code = b'\xb8' + struct.pack('<I', packet_id) + b'\xc3'
        candidates = []
        offset = raw.find(code, text['raw'], text['raw'] + text['raw_size'])
        while offset >= 0:
            getter = image.pe.address(offset)
            at = raw.find(struct.pack('<Q', getter), start, end)
            while at >= 0:
                table_at = at - 0x28
                if at % 8 == 0 and start <= table_at and table_at + 64 <= end:
                    slots = struct.unpack_from('<8Q', raw, table_at)
                    if all(image.pe.base + text['rva'] <= v < image.pe.base + text['rva'] + text['raw_size'] for v in slots):
                        name_range = image.containing(slots[7])
                        if name_range is None:
                            raise ValueError('Name method requires reviewed unwind boundaries')
                        name_fragments = native.decode_ranges(image, {image.roots[name_range]})
                        names = []
                        for fragment in name_fragments:
                            for instruction in fragment['instructions']:
                                if instruction['mnemonic'] != 'lea':
                                    continue
                                for literal in instruction['rip_references']:
                                    literal_offset = image.offset(literal - image.pe.base)
                                    name_bytes = raw[literal_offset:literal_offset + 128].split(b'\0', 1)[0]
                                    if name_bytes.startswith(b'Pkt') and name_bytes.isascii():
                                        names.append((name_bytes.decode('ascii'), literal))
                        if len(names) == 1:
                            name, literal = names[0]
                            candidates.append(dict(packet_id=packet_id, name=name,
                                id_getter=hex(getter), id_bytes=code.hex(), table=hex(image.pe.address(table_at)),
                                slots=[hex(v) for v in slots], table_bytes=raw[table_at:table_at + 64].hex(),
                                name_fragments=name_fragments, literal=hex(literal)))
                at = raw.find(struct.pack('<Q', getter), at + 1, end)
            offset = raw.find(code, offset + 1, text['raw'] + text['raw_size'])
        if len(candidates) != 1:
            raise ValueError(f'Expected one named table candidate for {packet_id}, got {len(candidates)}')
        packets.extend(candidates)
    targets = {int(p['table'], 16): {} for p in packets}
    refs = native.rip_candidates(image, targets)
    roots = {image.roots[f] for at, _ in refs if (f := image.containing(at)) is not None}
    if len(roots) > 12:
        raise ValueError('Explicit constructor owner budget exceeded')
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for packet in packets:
        table = int(packet['table'], 16)
        checked = []
        for at, target in refs:
            if target != table:
                continue
            instruction = rows.get(at)
            if instruction and instruction['mnemonic'] == 'lea' and instruction['rip_references'] == [table]:
                checked.append(dict(instruction=instruction,
                    owner=hex(image.pe.base + image.roots[image.containing(at)][0])))
        packet['table_references'] = checked
        packet['unwindless_reference_sites'] = [hex(at) for at, target in refs if target == table and image.containing(at) is None]
    # Explicit constructor call proves which nested reader the shared packet
    # reader dispatches to. A similar outer reader alone is insufficient.
    anchors = {
        0x145828a10: '40534883ec20488d05a3ca1304488bd94889014883c110e844a0f7ff488bc34883c4205bc3',
        0x1457a2a70: '488d0599611a0448890133c0488941084889411048894118488bc1c3',
    }
    for at, expected in anchors.items():
        content = bytes.fromhex(expected)
        offset = image.offset(at - image.pe.base)
        if raw[offset:offset + len(content)] != content:
            raise ValueError('Quest sync constructor binding differs')
    tables = {
        0x149948c10: (0x1457860a0, 0x141403ab0, 0x1457ab010, 0x141403ab0, 0x1457a66b0, 0x14578af60),
        0x149948bc8: (0x1457860e0, 0x141403ab0, 0x1457ab110, 0x141403ab0, 0x1457a67b0, 0x14578afc0),
        0x149949cf8: (0x141b0aa50, 0x1457a9aa0, 0x1457a8b00),
    }
    for at, expected in tables.items():
        if struct.unpack_from('<' + 'Q' * len(expected), raw, image.offset(at - image.pe.base)) != expected:
            raise ValueError('Quest sync nested table differs')
    return dict(packets=packets, constructor_fragments=fragments,
        quest_sync=dict(packet_constructor='0x145828a10', nested_constructor='0x1457a2a70',
            nested_offset='0x10', nested_reader='0x1457a66b0',
            anchors={hex(k): v for k, v in anchors.items()},
            tables={hex(k): [hex(v) for v in values] for k, values in tables.items()}))


def run():
    native, audit = load('build-native-entry-code'), load('audit-client-release')
    source = native.ROOT / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('Current snapshot differs')
    result = inspect(native.Image(raw))
    result.update(source_sha256=SHA, source=str(source), tool_sha256=audit.sha256(Path(__file__)), network_used=False,
        limits=['Only IDs 1827 / 1840 / 1854 and their named table candidates are inspected.',
            'ID getter, name-method literal and eight code slots do not establish reader field semantics.',
            'Constructor references are bounded whole-unwind LEA sites; stores must be reviewed separately.',
            'Unwindless references are reported as sites, not guessed function starts.',
            'No packet bodies, process memory, authentication or game commands are read or sent.'])
    path = audit.save_snapshot(native.ROOT / 'code-clues/initial-quest-notifications-11316', result)
    return path, result


if __name__ == '__main__':
    path, result = run()
    print(json.dumps(dict(report=str(path), packets=[dict(packet_id=p['packet_id'], name=p['name'],
        table=p['table'], reader=p['slots'][4]) for p in result['packets']])))
