"""Source-bound lobby packet names, tables and static lifecycle edges."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_binding_calls', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native = calls.native
NAMES = ('PktLobbyVersion', 'PktLobbyVersionResult', 'PktLobbyServerListRead',
    'PktLobbyServerListReadResult')
SOURCE_SHA = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


def build():
    if native.capstone.__version__ != '5.0.6': raise ValueError('Use pinned Capstone 5.0.6')
    upstream_path = native.ROOT / 'code-clues/lobby-login-path.json'
    upstream = json.loads(upstream_path.read_text('utf-8'))
    raw = Path(upstream['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA or upstream['source_sha256'] != SOURCE_SHA:
        raise ValueError('Client changed; refresh lobby bindings')
    image = native.Image(raw)
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    cs.detail = True
    literals = {}
    for name in NAMES:
        found = list(re.finditer(re.escape((name + '\0').encode('ascii')), raw))
        if len(found) != 1: raise ValueError('Ambiguous packet literal ' + name)
        literals[image.pe.address(found[0].start())] = name
    candidates = native.rip_candidates(image, literals)
    roots = {image.roots[f] for a, _ in candidates if (f := image.containing(a)) is not None}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    packets, anchors = [], []

    def proof(address, size):
        offset = image.offset(address - image.pe.base)
        data = raw[offset:offset + size]
        if len(data) != size: raise ValueError('Incomplete source span')
        value = dict(address=address, file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest())
        anchors.append(value)
        return value

    for address, name in literals.items():
        refs = [a for a, t in candidates if t == address and a in rows and
            rows[a]['mnemonic'] == 'lea' and rows[a]['rip_references'] == [address]]
        if len(refs) != 1: raise ValueError('Ambiguous packet name getter ' + name)
        name_getter = image.pe.base + image.roots[image.containing(refs[0])][0]
        locations = []
        for section in image.pe.sections:
            if section['name'] != '.rdata': continue
            for match in re.finditer(re.escape(struct.pack('<Q', name_getter)),
                    raw[section['raw']:section['raw'] + section['raw_size']]):
                offset = section['raw'] + match.start()
                if offset % 8 == 0: locations.append(offset)
        if len(locations) != 1: raise ValueError('Ambiguous packet table ' + name)
        table_offset = locations[0] - 0x38
        table = image.pe.address(table_offset)
        slots = struct.unpack_from('<8Q', raw, table_offset)
        stores = []
        for a, _ in native.rip_candidates(image, {table}):
            off = image.offset(a - image.pe.base)
            ins = list(cs.disasm(raw[off:off + 40], a))
            if len(ins) < 2: continue
            first = ins[0]
            if (first.mnemonic, first.op_str.split(',')[0]) != ('lea', 'rax'): continue
            for following in ins[1:4]:
                if (following.mnemonic, following.op_str) == ('mov', 'qword ptr [rcx], rax'):
                    stores.append(proof(a, following.address + following.size - a))
                    break
                _, writes = following.regs_access()
                if any(cs.reg_name(reg) in ('rax', 'eax', 'rcx', 'ecx') for reg in writes): break
        if not stores: raise ValueError('No object table installation ' + name)
        off = image.offset(slots[5] - image.pe.base)
        getter = list(cs.disasm(raw[off:off + 6], slots[5]))
        # Nested records have no packet ID; retain their actual instructions.
        packet_id = None
        if len(getter) == 2 and getter[0].mnemonic == 'mov' and getter[0].op_str.startswith('eax, ') and getter[1].mnemonic == 'ret':
            packet_id = getter[0].operands[1].imm
        proof(table, 64)
        proof(slots[5], 6)
        packets.append(dict(name=name, name_getter=name_getter, name_reference=rows[refs[0]],
            vtable=table, table_installations=stores, writer=slots[2], reader=slots[4],
            id_getter=slots[5], packet_id=packet_id))
    # Method is reached virtually; direct CALL scanning cannot find this edge.
    method_tables = []
    for section in image.pe.sections:
        if section['name'] != '.rdata': continue
        for match in re.finditer(re.escape(struct.pack('<Q', 0x1467a9360)),
                raw[section['raw']:section['raw'] + section['raw_size']]):
            offset = section['raw'] + match.start()
            if offset % 8 == 0:
                # Context only; table start/slot must be proven by constructor.
                method_tables.append(proof(image.pe.address(offset) - 0x48, 0x70))
    peer_table = 0x149d84d78
    construction = native.decode_ranges(image, {image.roots[image.containing(0x1467a79e0)]})
    construction_rows = {r['address']: r for f in construction for r in f['instructions']}
    install = [construction_rows[a] for a, target in native.rip_candidates(image, {peer_table})
        if a in construction_rows and construction_rows[a]['rip_references'] == [peer_table]]
    if len(install) != 1 or install[0]['mnemonic'] != 'lea': raise ValueError('Lobby peer table binding changed')
    after = [r for r in construction_rows.values() if install[0]['address'] < r['address'] < install[0]['address'] + 16]
    if not any(r['mnemonic'] == 'mov' and r['operands'] == 'qword ptr [rbx], rax' for r in after):
        raise ValueError('Lobby peer table installation changed')
    peer_anchor = proof(peer_table, 0x48)
    peer_slots = struct.unpack('<9Q', bytes.fromhex(peer_anchor['bytes']))
    if (peer_slots[1], peer_slots[7], peer_slots[8]) != (0x1467aa090, 0x1467a9360, 0x1467aae20):
        raise ValueError('Lobby peer virtual methods changed')
    return dict(schema_version=1, source=upstream['source'], source_sha256=SOURCE_SHA,
        upstream_sha256=hashlib.sha256(upstream_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), packets=packets,
        name_fragments=fragments, anchors=anchors, lobby_login_pointer_contexts=method_tables,
        peer_construction_fragments=construction, peer_table=peer_anchor, peer_table_load=install[0],
        limitations=['Static packet table bindings, not wire schemas or a live lobby session.',
            'Table installations may include constructors and destructors; no constructor boundary is inferred.',
            'Method-pointer context is not proof of a table start or virtual slot.'])


if __name__ == '__main__':
    report = build()
    out = native.ROOT / 'code-clues/lobby-server-bindings.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(out), sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
        packets=[dict(name=p['name'], id=p['packet_id'], reader=hex(p['reader']), writer=hex(p['writer'])) for p in report['packets']])))
