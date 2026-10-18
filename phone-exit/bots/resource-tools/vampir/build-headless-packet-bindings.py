"""Version-bound packet vtables, ID getters, constructors and receive registrations.

Static evidence only. Reader/writer slot targets are not a wire codec.
"""
import hashlib
import importlib.util
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('packet_calls', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native = calls.native

# Reviewed entrypoints: validated through direct calls and object-vptr installation.
CONSTRUCTORS = {
    'PktLogin': 0x1456d4c80, 'PktLoginResult': 0x1456d4da0,
    'PktLobbyLogin': 0x145744fa0, 'PktLobbyLoginResult': 0x145745000,
    'PktCharacterListRead': 0x1456d4780, 'PktCharacterListReadResult': 0x1456d47a0,
    'PktCharacterSelect': 0x1456d4850, 'PktCharacterSelectResult': 0x1456d4a40,
    'PktPing': 0x1456d5040, 'PktPingResult': 0x1456d5060,
}
# name, constructor call, registration call, handler-table LEA, registration function
REGISTRATIONS = [
    ('PktLoginResult', 0x14678ece7, 0x14678ecfa, 0x14678ecc6, 0x1467a7250),
    ('PktPingResult', 0x14678ef3f, 0x14678ef52, 0x14678ef1e, 0x1467a7250),
    ('PktCharacterListReadResult', 0x14678f2c3, 0x14678f2d6, 0x14678f2a2, 0x1467a7250),
    ('PktCharacterSelectResult', 0x14678f3ef, 0x14678f402, 0x14678f3ce, 0x1467a7250),
    ('PktLobbyLoginResult', 0x14678e7f7, 0x14678e80a, 0x14678e7d6, 0x1467a7150),
]


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    index_path = native.ROOT / 'code-clues/headless-network-index.json'
    index = json.loads(index_path.read_text('utf-8'))
    data = Path(index['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != index['sha256']:
        raise ValueError('Client changed; rebuild the source index')
    image = native.Image(data)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    anchors, leaves = [], []

    def proof(address, size, role):
        offset = image.offset(address - image.pe.base)
        content = data[offset:offset + size]
        row = dict(address=address, file_offset=offset, bytes=content.hex(),
                   sha256=hashlib.sha256(content).hexdigest(), role=role)
        anchors.append(row)
        return row

    def leaf(address):
        offset = image.offset(address - image.pe.base)
        ins = []
        for i in decoder.disasm(data[offset:offset + 128], address):
            ins.append(i)
            if i.mnemonic == 'ret':
                break
            if i.group(native.capstone.CS_GRP_JUMP) or i.group(native.capstone.CS_GRP_CALL):
                raise ValueError('Expected bounded straight-line leaf: ' + hex(address))
        if not ins or ins[-1].mnemonic != 'ret':
            raise ValueError('Missing leaf return')
        size = ins[-1].address + ins[-1].size - address
        row = proof(address, size, 'leaf at verified call/vtable target')
        leaves.append(row)
        return ins

    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates += calls.direct_call_candidates(data, section['raw'], section['raw_size'],
                                                        image.pe.address, set(CONSTRUCTORS.values()))
    roots = {image.roots[f] for a, _ in candidates if (f := image.containing(a)) is not None}
    roots |= {image.roots[image.containing(a)] for a in (0x1467a7150, 0x1467a7250)}
    fragments = []
    for root in sorted(roots):
        fragments += native.decode_ranges(image, {root})
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    checked_calls = [dict(instruction=rows[a], target=t) for a, t in candidates
                     if calls.checked_call(rows.get(a), t)]
    packets = []
    for name, constructor in CONSTRUCTORS.items():
        refs = [x for x in index['xrefs'] if x['symbol'] == name]
        if len(refs) != 1:
            raise ValueError('Ambiguous name root: ' + name)
        name_getter = image.pe.base + refs[0]['root_begin_rva']
        locations = []
        for section in image.pe.sections:
            if section['name'] != '.rdata':
                continue
            for match in re.finditer(re.escape(struct.pack('<Q', name_getter)),
                                     data[section['raw']:section['raw'] + section['raw_size']]):
                offset = section['raw'] + match.start()
                if offset % 8 == 0:
                    locations.append(offset)
        if len(locations) != 1:
            raise ValueError('Ambiguous vtable name slot: ' + name)
        # Offset is a hypothesis until the constructor stores this exact base into [this].
        table_offset = locations[0] - 0x38
        table = image.pe.address(table_offset)
        targets = struct.unpack_from('<8Q', data, table_offset)
        source_calls = [c['instruction'] for c in checked_calls if c['target'] == constructor]
        if not source_calls:
            raise ValueError('Constructor entry has no verified direct caller: ' + name)
        function = image.containing(constructor)
        if function is None:
            ctor = leaf(constructor)
        else:
            ctor_fragments = native.decode_ranges(image, {image.roots[function]})
            fragments += ctor_fragments
            ctor = list(decoder.disasm(data[image.offset(constructor-image.pe.base):
                                           image.offset(constructor-image.pe.base)+48], constructor))
        installation = None
        for pos, i in enumerate(ctor):
            if i.mnemonic != 'lea' or i.op_str.split(',')[0] != 'rax':
                continue
            refs_ = [i.address+i.size+o.mem.disp for o in i.operands
                     if o.type == native.X86_OP_MEM and o.mem.base == native.X86_REG_RIP]
            if refs_ != [table]:
                continue
            for following in ctor[pos+1:pos+4]:
                if following.mnemonic == 'mov' and following.op_str == 'qword ptr [rcx], rax':
                    installation = [proof(i.address, i.size, 'vtable LEA'),
                                    proof(following.address, following.size, 'object vptr store')]
                    break
                _, writes = following.regs_access()
                if any(decoder.reg_name(reg) in ('rax', 'eax', 'rcx', 'ecx') for reg in writes):
                    break
        if installation is None:
            raise ValueError('Vtable installation not proven: ' + name)
        getter = leaf(targets[5])
        if [(i.mnemonic, i.op_str.split(',')[0]) for i in getter] != [('mov', 'eax'), ('ret', '')]:
            raise ValueError('ID getter is not MOV EAX,imm; RET')
        packet_id = getter[0].operands[1].imm
        if not 0 <= packet_id <= 65535:
            raise ValueError('ID outside dispatcher word key')
        proof(table, 64, 'packet vtable slots 0..0x38')
        for target in (targets[2], targets[4]):
            if not any(s['name'] == '.text' and image.pe.base+s['rva'] <= target <
                       image.pe.base+s['rva']+s['raw_size'] for s in image.pe.sections):
                raise ValueError('Serialization slot outside code')
            proof(target, 16, 'serialization entry bytes; full body not reconstructed')
        packets.append(dict(name=name, packet_id=packet_id, vtable=table, constructor=constructor,
                            constructor_calls=source_calls, vptr_installation=installation,
                            name_getter=name_getter, name_slot=0x38, id_getter=targets[5], id_slot=0x28,
                            writer_slot=0x10, writer=targets[2], reader_slot=0x20, reader=targets[4],
                            wire_schema_verified=False))
    registrations = []
    for name, constructor_call, register_call, handler_lea, register_function in REGISTRATIONS:
        if not calls.checked_call(rows.get(constructor_call), CONSTRUCTORS[name]):
            raise ValueError('Registration constructor call changed')
        if not calls.checked_call(rows.get(register_call), register_function):
            raise ValueError('Registration function changed')
        lea = rows[handler_lea]
        if lea['mnemonic'] != 'lea' or len(lea['rip_references']) != 1:
            raise ValueError('Handler table LEA changed')
        handler_table = lea['rip_references'][0]
        proof(handler_table, 24, 'handler vtable through OnHandler slot')
        on_handler = struct.unpack_from('<Q', data, image.offset(handler_table-image.pe.base)+16)[0]
        handler_reg, this_reg = ('rsi', 'rdi') if name == 'PktLobbyLoginResult' else ('rdi', 'rsi')
        before = [i for i in rows.values() if register_call-9 <= i['address'] < register_call]
        if [(i['mnemonic'], i['operands']) for i in sorted(before, key=lambda i:i['address'])] != [
                ('mov', 'r8, '+handler_reg), ('mov', 'rdx, rax'), ('mov', 'rcx, '+this_reg)]:
            raise ValueError('Packet/handler registration arguments changed')
        registers = [i for i in rows.values() if handler_lea < i['address'] < constructor_call]
        if not any(i['mnemonic']=='mov' and i['operands']=='qword ptr ['+handler_reg+'], rax'
                   for i in registers):
            raise ValueError('Handler vptr store missing')
        registrations.append(dict(name=name, constructor_call=rows[constructor_call],
                                  registration_call=rows[register_call], handler_lea=lea,
                                  handler_vtable=handler_table, on_handler=on_handler,
                                  registration_function=register_function,
                                  dispatcher_context='lobby_factory' if name == 'PktLobbyLoginResult' else 'game_factory'))
    # Both registration implementations take the object's slot+0x28 and store AX as a word key.
    for call_address, key_store in [(0x1467a7185,0x1467a7191),(0x1467a7285,0x1467a7291)]:
        if (rows[call_address]['mnemonic'],rows[call_address]['operands']) != ('call','qword ptr [rax + 0x28]'):
            raise ValueError('Dispatcher ID slot changed')
        if (rows[key_store]['mnemonic'],rows[key_store]['operands']) != ('mov','word ptr [rsp + 0x48], ax'):
            raise ValueError('Dispatcher key width changed')
    fragments = list({f['begin_rva']: f for f in fragments}.values())
    report = dict(schema_version=1, source=index['source'], sha256=index['sha256'],
                  index_sha256=hashlib.sha256(index_path.read_bytes()).hexdigest(),
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  capstone_version=native.capstone.__version__, packets=packets,
                  registrations=registrations, fragments=fragments, leaves=leaves, data_anchors=anchors,
                  statistics=dict(packets=len(packets), registrations=len(registrations),
                                  fragments=len(fragments), leaves=len(leaves),
                                  verified_constructor_calls=len(checked_calls)),
                  network_ready=False, limitations=[
                      'Selected version-bound bindings, not complete packet schemas or a network client.',
                      'Writer/reader slots follow the existing packet hierarchy; primitive encoding is unknown.',
                      'Identical IDs in lobby/game types must not be collapsed into one global lookup.',
                      'Factory labels denote static registration paths, not proven runtime connection selection.',
                      'No traffic, game execution, secrets or live memory used.'])
    output = native.ROOT/'code-clues/headless-packet-bindings.json'
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(output),**report['statistics'],
                          ids={p['name']:p['packet_id'] for p in packets},network_ready=False)))


if __name__ == '__main__':
    main()
