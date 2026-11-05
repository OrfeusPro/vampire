"""Trace references to one explicit current packet factory; static, no game IO."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
FACTORY = 0x14575ee40
TABLE = 0x149dc7ca0
OWNERS = {0x1467b62f0, 0x1467c6e70}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run():
    native = load('factory_links_native', HERE / 'build-native-entry-code.py')
    windows = load('factory_links_windows', HERE / 'build-entry-window-code.py')
    audit = load('factory_links_audit', HERE / 'audit-client-release.py')
    source = native.ROOT / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    if audit.sha256(source) != SHA:
        raise ValueError('Factory source changed')
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    image = native.Image(source.read_bytes())
    candidates, pointers = [], []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates += windows.direct_call_candidates(image.data, section['raw'],
                section['raw_size'], image.pe.address, {FACTORY})
        if section['name'] in ('.rdata', '.data'):
            end = section['raw'] + section['raw_size']
            at = image.data.find(struct.pack('<Q', FACTORY), section['raw'], end)
            while at >= 0:
                pointers.append(image.pe.address(at))
                at = image.data.find(struct.pack('<Q', FACTORY), at + 1, end)
    if candidates or pointers != [TABLE]:
        raise ValueError('Factory reference inventory changed')
    refs = native.rip_candidates(image, {TABLE: {}})
    roots = {image.roots[f] for at, target in refs
        if (f := image.containing(at)) is not None}
    if {image.pe.base + root[0] for root in roots} != OWNERS:
        raise ValueError('Factory table owners changed')
    fragments = native.decode_ranges(image, roots,
        functions=[f for f in image.ranges if image.roots[f] in roots])
    rows = {row['address']: row for f in fragments for row in f['instructions']}
    checked = []
    for at, target in refs:
        row = rows.get(at)
        if row is None or row['mnemonic'] != 'lea' or row['rip_references'] != [target]:
            raise ValueError('Factory table reference is not a checked LEA')
        checked.append(row)
    offset = image.offset(TABLE - image.pe.base)
    expected = {
        0x1467bb5c9: '488d0528b66003',  # handler table LEA
        0x1467bb5d0: '488907',          # handler vptr store
        0x1467bb5d8: 'b988000000',      # packet allocation size
        0x1467bb5ea: 'e8d1e406ff',      # actual result constructor
        0x1467bb5f4: '4c8bc7',         # R8 = handler
        0x1467bb5f7: '488bd0',         # RDX = packet
        0x1467bb5fa: '488bce',         # RCX = dispatcher
        0x1467bb5fd: 'e84e170100',      # registration
    }
    if any(rows.get(at, {}).get('bytes') != value for at, value in expected.items()):
        raise ValueError('Quest result registration changed')
    if rows[0x1467bb5c9]['rip_references'] != [0x149dc6bf8]:
        raise ValueError('Quest handler table changed')
    handler_offset = image.offset(0x149dc6bf8 - image.pe.base)
    handler_slots = struct.unpack_from('<3Q', image.data, handler_offset)
    if handler_slots != (0x1414097a0, 0x14153bab0, 0x141403c50):
        raise ValueError('Quest handler slots changed')
    leaves = []
    for at, code in ((0x14153bab0, '488b0148ff6010'), (0x141403c50, 'c20000'),
                     (0x145835650, 'b80a070000c3')):
        raw_offset = image.offset(at - image.pe.base)
        if image.data[raw_offset:raw_offset + len(bytes.fromhex(code))].hex() != code:
            raise ValueError('Explicit leaf entry bytes changed')
        leaves.append(dict(address=hex(at), bytes=code))
    report = dict(source_sha256=SHA, tool_sha256=audit.sha256(Path(__file__)),
        factory=hex(FACTORY), direct_e8_candidate_count=0, table=hex(TABLE),
        slots=[hex(value) for value in struct.unpack_from('<5Q', image.data, offset)],
        table_hex=image.data[offset:offset + 40].hex(), references=checked,
        quest_result_registration=dict(packet_constructor='0x145829ac0', packet_id=1802,
            handler_table='0x149dc6bf8', handler_slots=[hex(value) for value in handler_slots],
            instructions=[rows[at] for at in sorted(expected)], leaf_entries=leaves),
        fragments=fragments, limits=[
            'Only E8 rel32 candidates and exact qword pointers in .rdata/.data were inventoried.',
            'No absence claim for indirect calls, tail jumps, encoded pointers or inline code.',
            'Only two explicit LEA owners decoded; no call-tree expansion or native execution.',
            'Quest registration statically pairs the known result constructor with a default no-op handler.',
            'Explicit leaf entries are checked only through their terminating JMP/RET bytes; no guessed unwind extent.',
            'No live replacement/binding, quest application handler or request field semantics established.'])
    path = audit.save_snapshot(native.ROOT / 'code-clues/release-packet-factory-links', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), slots=report['slots'],
        references=[hex(row['address']) for row in report['references']])))
