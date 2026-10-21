"""Native result factory slice, constructor/getters and registration-key prefix."""
import json
from pathlib import Path
import struct
import importlib.util

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    env = load('packet_binding_env', HERE / 'replay-release-nested-read-thunk.py')
    native = load('packet_binding_native', HERE / 'build-native-entry-code.py')
    audit = load('packet_binding_audit', HERE / 'audit-client-release.py')
    if env.capstone.__version__ != '5.0.6' or env.unicorn.__version__ != '2.1.4':
        raise ValueError('Pinned native tools required')
    root = native.ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
    evidence = root / 'details/run-36c407109687/details.json'
    evidence_sha = '1d414ee4ce052123a9cfa6a833bcacd5b3576a2c6b2224c1e7ab90e2aa778e17'
    if audit.sha256(evidence) != evidence_sha:
        raise ValueError('Factory Ghidra evidence changed')
    method_evidence = root / 'details/run-ab4ca396be23/details.json'
    method_sha = '64a07328ba5dc14b901dc01005a8515a0a102a893eb750d4e3fa309a92040767'
    if audit.sha256(method_evidence) != method_sha:
        raise ValueError('Registration/getter Ghidra evidence changed')
    sha = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
    source = native.ROOT / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    if audit.sha256(source) != sha:
        raise ValueError('Source changed')
    raw = source.read_bytes()
    image = native.Image(raw)
    ctor, table, id_getter, name_getter = 0x1456d84f0, 0x14992a968, 0x1456e5ee0, 0x1456e70b0
    factory_start, factory_stop = 0x1467b6940, 0x1467b698b
    register, key_stop, allocator = 0x1467ccd50, 0x1467ccd9c, 0x14690a090
    handler_table, handler = 0x149dc8800, 0x146797990
    cs = env.capstone.Cs(env.capstone.CS_ARCH_X86, env.capstone.CS_MODE_64)
    cs.detail = True
    ranges, leaves, instructions = [], [], []
    for a in (ctor, id_getter, name_getter):
        offset = image.offset(a - image.pe.base)
        rows = []
        for ins in cs.disasm(raw[offset:offset + 256], a):
            rows.append(ins)
            if ins.mnemonic == 'ret':
                break
            allowed = ('push', 'sub', 'mov', 'lea', 'call', 'add', 'pop') if a == name_getter else ('mov', 'lea', 'xor')
            if ins.mnemonic not in allowed:
                raise ValueError('Unreviewed packet leaf')
            if ins.mnemonic == 'call' and ins.op_str != '0x141426a30':
                raise ValueError('Unexpected packet name assignment')
        if not rows or rows[-1].mnemonic != 'ret':
            raise ValueError('Packet leaf bound')
        length = rows[-1].address + rows[-1].size - a
        ranges.append((a, a + length))
        leaves.append(dict(address=hex(a), file_offset=offset, bytes=raw[offset:offset + length].hex()))
        instructions.extend(rows)
    factory = next(p for p in json.loads(evidence.read_text('utf-8'))['pairs']
                   if p['old_analyst_name'] == 'CharacterList_ResultRegistrationFactory')['new']
    ghidra_rows = {int(r['address'], 16): r for r in factory['instructions']}
    for begin, end in ((factory_start, factory_stop), (register, key_stop)):
        offset = image.offset(begin - image.pe.base)
        rows = list(cs.disasm(raw[offset:offset + end - begin], begin))
        if sum(i.size for i in rows) != end - begin:
            raise ValueError('Registration slice boundary')
        if begin == factory_start:
            for ins in rows:
                if ghidra_rows.get(ins.address, {}).get('bytes') != ins.bytes.hex():
                    raise ValueError('Factory differs from Ghidra instructions')
        ranges.append((begin, end))
        instructions.extend(rows)
    words = struct.unpack_from('<8Q', raw, image.offset(table - image.pe.base))
    if (words[2], words[4], words[5], words[7]) != (0x1456e9390, 0x1456dcf00, id_getter, name_getter):
        raise ValueError('Packet vtable slots changed')
    if struct.unpack_from('<Q', raw, image.offset(handler_table - image.pe.base) + 16)[0] != handler:
        raise ValueError('Handler table changed')
    pages = {p for a, b in ranges for p in range(a & ~4095, (b + 4095) & ~4095, 4096)}
    pages.update((table & ~4095, handler_table & ~4095, allocator & ~4095, 0x141426a30 & ~4095))
    for ins in instructions:
        for operand in ins.operands:
            if operand.type == native.X86_OP_MEM and operand.mem.base == native.X86_REG_RIP:
                pages.add((ins.address + ins.size + operand.mem.disp) & ~4095)
    uc, x = env.unicorn.Uc(env.unicorn.UC_ARCH_X86, env.unicorn.UC_MODE_64), env.x
    for page in sorted(pages):
        uc.mem_map(page, 4096)
        offset = image.offset(page - image.pe.base)
        uc.mem_write(page, raw[offset:offset + 4096])
    scratch = 0x20000000
    uc.mem_map(scratch, 0x10000)
    heap, allocations, captured, name_literals = [0], [], [], []
    phase = ['factory']
    def finish():
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def hook(machine, address, size, unused):
        if address == 0x141426a30:
            destination, literal = machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)
            if literal != 0x14992a9b8 or not scratch <= destination <= scratch + 0x10000 - 16:
                raise ValueError('Packet name storage fixture bound')
            name_literals.append(literal)  # Capture const-char input; do not invent the string object's layout.
            machine.reg_write(x.UC_X86_REG_RAX, destination)
            finish()
        elif address == allocator and phase[0] == 'factory':
            count = machine.reg_read(x.UC_X86_REG_RCX)
            if count not in (8, 0x48):
                raise ValueError('Unexpected packet factory allocation')
            pointer = heap[0] + 16
            machine.mem_write(heap[0], b'\xa5' * (count + 32))
            heap[0] += (count + 47) & ~15
            allocations.append((pointer, count))
            machine.reg_write(x.UC_X86_REG_RAX, pointer)
            finish()
        elif address == register and phase[0] == 'factory':
            captured.append(tuple(machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)))
            finish()  # Backend registration fixture; actual key prefix executes separately below.
        elif not any(a <= address and address + size <= b for a, b in ranges):
            raise ValueError('Unreviewed packet binding execution ' + hex(address))
    uc.hook_add(env.unicorn.UC_HOOK_CODE, hook)
    def invoke(address, a, b=0):
        stack, stop = scratch + 0x8000, scratch + 0xf000
        uc.mem_write(stack, struct.pack('<Q', stop))
        uc.reg_write(x.UC_X86_REG_RSP, stack)
        uc.reg_write(x.UC_X86_REG_RCX, a)
        uc.reg_write(x.UC_X86_REG_RDX, b)
        uc.emu_start(address, stop, count=1024)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Getter budget')
        return uc.reg_read(x.UC_X86_REG_RAX)
    cases = []
    for displacement in (0, 0x200, 0x400):
        heap[0] = scratch + 0x1000 + displacement
        allocations.clear(); captured.clear(); phase[0] = 'factory'
        context, stack = scratch + 0x6000, scratch + 0x8000
        uc.reg_write(x.UC_X86_REG_RSI, context)
        uc.reg_write(x.UC_X86_REG_RBX, 0)
        uc.reg_write(x.UC_X86_REG_RSP, stack)
        uc.emu_start(factory_start, factory_stop, count=2048)
        if len(captured) != 1 or len(allocations) != 2:
            raise ValueError('Factory capture arity')
        ctx, packet, owner = captured[0]
        if ctx != context or int.from_bytes(uc.mem_read(packet, 8), 'little') != table or int.from_bytes(uc.mem_read(owner, 8), 'little') != handler_table:
            raise ValueError('Factory packet/handler bindings')
        if any(bytes(uc.mem_read(p - 16, 16)) != b'\xa5' * 16 or bytes(uc.mem_read(p + size, 16)) != b'\xa5' * 16 for p, size in allocations):
            raise ValueError('Constructor wrote outside allocated packet/handler')
        packet_id = invoke(id_getter, packet)
        destination = scratch + 0x7000
        if invoke(name_getter, packet, destination) != destination:
            raise ValueError('Packet name getter return differs')
        name_address = name_literals[-1]
        offset = image.offset(name_address - image.pe.base)
        data = raw[offset:offset + 256]
        end = data.index(b'\0')
        name = data[:end].decode('ascii')
        if packet_id != 102 or name != 'PktCharacterListReadResult':
            raise ValueError('Compiled packet ID/name differs')
        phase[0] = 'key-prefix'
        for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, context),
                           (x.UC_X86_REG_RDX, packet), (x.UC_X86_REG_R8, owner)):
            uc.reg_write(reg, value)
        uc.emu_start(register, key_stop, count=2048)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        key = int.from_bytes(uc.mem_read(sp + 0x48, 2), 'little')
        if uc.reg_read(x.UC_X86_REG_RIP) != key_stop or key != packet_id:
            raise ValueError('Registration word key differs')
        cases.append(dict(displacement=displacement, packet_id=packet_id, packet_name=name,
                          registration_word_key=key, packet_handler_pair_captured=True, canaries_intact=True))
    report = dict(schema=1, source=str(source), source_sha256=sha, tool_sha256=audit.sha256(Path(__file__)),
        capstone_version=env.capstone.__version__, unicorn_version=env.unicorn.__version__,
        dependencies={p: audit.sha256(HERE / p) for p in ('build-native-entry-code.py', 'extract-native-enums.py', 'requirements-native.txt')},
        ghidra_factory_sha256=evidence_sha, ghidra_methods_sha256=method_sha, method_code=leaves,
        slices=[dict(start=hex(a), end_exclusive=hex(b), bytes=raw[image.offset(a-image.pe.base):image.offset(a-image.pe.base)+b-a].hex()) for a, b in ranges if a in (factory_start, register)],
        vtable=hex(table), reader=hex(words[4]), writer=hex(words[2]), handler_vtable=hex(handler_table), handler=hex(handler),
        register=hex(register), cases=cases, native_execution=True, compatibility='not_established',
        limits=['Actual factory slice installs handler/packet pair; allocator/backend/name storage are explicit fixtures.',
                'Actual packet constructor, ID/name getters and registration prefix through uint16 key execute.',
                'Backend insertion, handler execution, whole dispatch/lifecycle and live session unproven.'])
    target = audit.save_snapshot(root / 'packet-binding-replay', report)
    print(json.dumps(dict(report=str(target), sha256=audit.sha256(target), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
