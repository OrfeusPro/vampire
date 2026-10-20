"""Actual selected-character continuation -> conditional PktOptionSet capture.

Bounded record lookup/storage/transport captures; no socket or live account.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('option_send_base', HERE / 'replay-character-select-derived-manager.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
PREPARE, BASE_APPLY, TABLE, SEND = 0x145758a70, 0x1455967f0, 0x1498f3fd0, 0x3000f0e0
ITEM_CTOR, ITEM_TABLE = 0x1457891a0, 0x1498ec270

spec = importlib.util.spec_from_file_location('option_wire_base', HERE / 'replay-login-packet-writer.py')
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


class WriterEmulator(wire.Emulator):
    def __init__(self):
        super().__init__()
        manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
        names = {'OptionSet_Write', 'OptionSet_ArrayWrite', 'OptionSet_ItemWrite'}
        functions = [f for f in manifest['functions'] if f['name'] in names]
        if len(functions) != 3:
            raise ValueError('Missing Ghidra option wire sources')
        self.option_writer_ranges = [r for f in functions for r in f['ranges']]
        for r in self.option_writer_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset'] + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Option wire source changed')
            self.ranges.append((lo, hi))
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                if not any(a <= page <= b for a, b, _ in self.uc.mem_regions()):
                    self.uc.mem_map(page, 4096)
                    off = self.image.offset(page - self.image.pe.base)
                    self.uc.mem_write(page, self.raw[off:off + 4096])
        for table in (TABLE, ITEM_TABLE):
            page = table & ~4095
            if not any(a <= page <= b for a, b, _ in self.uc.mem_regions()):
                self.uc.mem_map(page, 4096)
                off = self.image.offset(page - self.image.pe.base)
                self.uc.mem_write(page, self.raw[off:off + 4096])
        address = 0x144aa6c90
        off = self.image.offset(address - self.image.pe.base)
        raw = self.raw[off:off + 16]
        cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        instructions = list(cs.disasm(raw, address))
        if sum(i.size for i in instructions) != 16 or [(i.mnemonic, i.op_str) for i in instructions] != [
                ('mov', 'rax, qword ptr [rdx]'), ('mov', 'r8, rdx'), ('mov', 'rdx, rcx'),
                ('mov', 'rcx, r8'), ('jmp', 'qword ptr [rax + 0x10]')]:
            raise ValueError('Reviewed archive object-writer tail jump changed')
        self.object_writer_leaf = dict(address=address, file_offset=off, bytes=raw.hex())
        self.ranges.append((address, address + 16))
        page = address & ~4095
        if not any(a <= page <= b for a, b, _ in self.uc.mem_regions()):
            self.uc.mem_map(page, 4096)
            off = self.image.offset(page - self.image.pe.base)
            self.uc.mem_write(page, self.raw[off:off + 4096])
        off = self.image.offset(ITEM_TABLE + 0x10 - self.image.pe.base)
        if struct.unpack_from('<Q', self.raw, off)[0] != 0x145787410:
            raise ValueError('Option item writer table binding changed')

    def encode_items(self, items):
        if len(items) > 8:
            raise ValueError('Bounded option writer fixture supports at most eight items')
        self.heap, self.copy_sizes, self.io_entries = self.scratch + 0x10000, [], []
        packet, archive, array, buffer = [self.scratch + n for n in (0x1000, 0x2000, 0x4000, 0x8000)]
        self.uc.mem_write(packet, struct.pack('<Q8xQII', TABLE, array if items else 0, len(items), len(items)))
        for i, (index, value) in enumerate(items):
            self.uc.mem_write(array + i * 16, struct.pack('<QB3xI', ITEM_TABLE, index, value))
        self.call(0x144aa62f0, archive, 1)
        self.uc.mem_write(archive + 0x18, struct.pack('<QQQ', buffer, buffer, buffer + 8192))
        self.uc.mem_write(archive + 0x30, struct.pack('<III', 8192, 0, 0))
        stack, stop = self.scratch + 0x30000, self.scratch + 0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for register, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, packet), (x.UC_X86_REG_RDX, archive)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(0x145730250, stop, count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Option writer instruction budget')
        size = int.from_bytes(self.uc.mem_read(archive + 0x34, 4), 'little')
        if not 0 <= size <= 8192:
            raise ValueError('Option writer exceeded output fixture')
        payload = bytes(self.uc.mem_read(buffer, size))
        expected = struct.pack('<H', len(items)) + b''.join(struct.pack('<BI', *item) for item in items)
        if self.uc.reg_read(x.UC_X86_REG_AL) != 1 or payload != expected:
            raise ValueError('Actual whole option writer body mismatch')
        return dict(items=[list(i) for i in items], payload_hex=payload.hex(), size=size, returned=1)


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
        names = {'CharacterSelect_PostManagerDerived60', 'CharacterSelect_PostManagerBaseApply',
                 'CharacterSelect_PostManagerPacketPrepare'}
        functions = [f for f in manifest['functions'] if f['name'] in names]
        self.option_ranges = [r for f in functions for r in f['ranges']]
        if len(functions) != 3:
            raise ValueError('Missing option application sources')
        for r in self.option_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset'] + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Option application source changed')
            self.ranges.append((lo, hi))
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_source_page(page)
        off = self.image.offset(ITEM_CTOR - self.image.pe.base)
        raw = self.raw[off:off + 21]
        if raw.hex() != '488d05c9301604885108488901488bc14489410cc3':
            raise ValueError('Option item constructor changed')
        self.item_constructor = dict(address=ITEM_CTOR, file_offset=off, bytes=raw.hex())
        self.ranges.append((ITEM_CTOR, ITEM_CTOR + 21))
        off = self.image.offset(TABLE - self.image.pe.base)
        raw = self.raw[off:off + 64]
        self.packet_table = dict(address=TABLE, file_offset=off, bytes=raw.hex())
        getter, name = [struct.unpack_from('<Q', raw, o)[0] for o in (0x28, 0x38)]
        off = self.image.offset(getter - self.image.pe.base)
        if self.raw[off:off + 6] != bytes.fromhex('b8f6060000c3') or name != 0x14576d910:
            raise ValueError('Option packet ID/name slots changed')
        fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(name)]})
        rows = {r['address']: r for f in fragments for r in f['instructions']}
        if rows[0x14576d919]['rip_references'] != [0x1498f4020]:
            raise ValueError('Option packet name reference changed')
        off = self.image.offset(0x1498f4020 - self.image.pe.base)
        name_bytes = b'PktOptionSet\0'
        if self.raw[off:off + len(name_bytes)] != name_bytes:
            raise ValueError('Option packet name changed')
        self.packet_binding = dict(packet_id=1782, name='PktOptionSet', id_getter=getter,
                                   id_bytes='b8f6060000c3', name_fragments=fragments)
        self.option_hooks = {0x145595b80, 0x144aaa9d0, 0x144aaaaa0, 0x1414314e0,
                             0x1457311a0, 0x145758f80, 0x1456b1640, 0x1456b2340,
                             0x145d16660, SEND}
        for address in (*self.option_hooks, ITEM_CTOR, ITEM_TABLE, TABLE):
            self.map_source_page(address & ~4095)
        self.spec = {}
        self.option_descriptors = set()

    def construct_manager(self):
        super().construct_manager()
        self.option_descriptors = set()
        self.allocations = 0
        self.uc.mem_write(self.context + 0xa564, struct.pack('<I', self.spec.get('old_value', 0)))
        self.uc.mem_write(self.context + 0x1f038, bytes([self.spec.get('server', 1), self.spec.get('kind', 0)]))
        self.uc.mem_write(self.context + 0x14000, struct.pack('<Q', self.context + 0x14800))
        self.uc.mem_write(self.context + 0x14838, struct.pack('<Q', SEND))

    def hook(self, uc, address, size, user):
        if self.handler_phase and address == base.APPLY:
            self.events.append(dict(action='native_derived_apply'))
            # Bypass only the parent's explicit slot60 capture.
            return base.base.Emulator.hook(self, uc, address, size, user)
        if self.handler_phase and address == BASE_APPLY:
            self.events.append(dict(action='native_base_apply'))
        if self.handler_phase and address == PREPARE:
            self.events.append(dict(action='native_option_packet_prepare'))
        if self.handler_phase and address == base.LOOKUP:
            a, b = uc.reg_read(x.UC_X86_REG_RCX), uc.reg_read(x.UC_X86_REG_RDX) & 255
            pointer = self.context + 0x1f000 if b == 27 and self.spec.get('record', True) else 0
            self.option_descriptors.add(a)
            uc.mem_write(a, struct.pack('<QQ', b, pointer))
            self.finish(a)
            return
        if self.handler_phase and address == 0x141482990:
            a = uc.reg_read(x.UC_X86_REG_RCX)
            if a in self.option_descriptors:
                pointer = int.from_bytes(uc.mem_read(a + 8, 8), 'little')
                if pointer not in (0, self.context + 0x1f000):
                    raise ValueError('Option descriptor fixture changed')
                self.finish(pointer)
                return
        if self.handler_phase and address in self.option_hooks:
            a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
            result = 0
            if address == 0x144aaa9d0:
                result = self.context + 0x14000
            elif address == 0x144aaaaa0:
                result = int(self.spec.get('connected', True))
            elif address == 0x1414314e0:
                if b != 1:
                    raise ValueError('Only one-item option allocation is supported')
                if self.allocations >= 2:
                    raise ValueError('Unexpected option allocation count')
                pointer = self.context + 0x1c800 + self.allocations * 0x100
                self.allocations += 1
                uc.mem_write(a, struct.pack('<Q', pointer))
                uc.mem_write(a + 12, struct.pack('<I', 1))
            elif address == 0x1457311a0:
                if c != 1:
                    raise ValueError('Only one option item copy is supported')
                raw = bytes(uc.mem_read(b, 16))
                if int.from_bytes(raw[:8], 'little') != ITEM_TABLE:
                    raise ValueError('Option copied item has unexpected table')
                uc.mem_write(a, raw)
                result = a
            elif address == SEND:
                if a != self.context + 0x14000 or int.from_bytes(uc.mem_read(b, 8), 'little') != TABLE:
                    raise ValueError('Option send receiver/packet table mismatch')
                pointer, count, capacity = struct.unpack('<QII', uc.mem_read(b + 16, 16))
                if (count, capacity) != (1, 1):
                    raise ValueError('Option packet must contain exactly one prepared item')
                index = uc.mem_read(pointer + 8, 1)[0]
                value = int.from_bytes(uc.mem_read(pointer + 12, 4), 'little')
                self.events.append(dict(action='option_send_capture', packet_id=1782, index=index,
                                        value=value, packet_flag=uc.mem_read(b + 10, 1)[0]))
            elif address == 0x145d16660:
                self.events.append(dict(action='profile_apply_capture', index=b & 255, value=c & 0xffffffff))
            # Cache invalidation and fresh one-item cleanup are boundaries.
            self.finish(result)
            return
        return super().hook(uc, address, size, user)


def build():
    em = Emulator()
    specs = [dict(value=0), dict(value=1), dict(value=255), dict(value=1, old_value=1),
             dict(value=1, record=False), dict(value=1, server=0), dict(value=1, connected=False),
             dict(value=1, kind=2), dict(value=1, code=1), dict(value=1, code=0x1197, gate=1)]
    cases = []
    for spec in specs:
        em.spec = spec
        em.secondary_value = spec['value']
        case = em.execute_manager(code=spec.get('code', 0), gate_state=spec.get('gate', 0), mode='empty')
        case['spec'] = spec
        case['option27'] = int.from_bytes(em.uc.mem_read(em.context + 0xa564, 4), 'little')
        accepted = not spec.get('code', 0)
        changed = accepted and spec.get('old_value', 0) != spec['value']
        send = changed and spec.get('record', True) and spec.get('server', 1) and spec.get('connected', True) and spec.get('kind', 0) != 2
        events = [e for e in case['events'] if e['action'] == 'option_send_capture']
        if len(events) != int(bool(send)) or (events and (events[0]['index'], events[0]['value']) != (27, spec['value'])):
            raise ValueError('Conditional option packet mismatch')
        if case['option27'] != (spec['value'] if accepted else spec.get('old_value', 0)):
            raise ValueError('Actual base option application mismatch')
        cases.append(case)
    writer = WriterEmulator()
    writer_inputs = [(), ((27, 0),), ((27, 1),), ((27, 255),),
                     ((0, 0xffffffff), (255, 0x80000000)),
                     tuple((i * 31 % 256, i * 0x11111111 & 0xffffffff) for i in range(8))]
    writer_cases = [writer.encode_items(items) for items in writer_inputs]
    for case in cases:
        sends = [e for e in case['events'] if e['action'] == 'option_send_capture']
        if sends:
            case['wire'] = writer.encode_items(((sends[0]['index'], sends[0]['value']),))
    return dict(source=em.bindings['source'], sha256=em.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-character-select-derived-manager.py').read_bytes()).hexdigest(),
                writer_dependency_sha256=hashlib.sha256((HERE / 'replay-login-packet-writer.py').read_bytes()).hexdigest(),
                writer_ranges=writer.option_writer_ranges, object_writer_leaf=writer.object_writer_leaf,
                writer_cases=writer_cases,
                ranges=em.option_ranges, item_constructor=em.item_constructor,
                packet_table=em.packet_table, binding=em.packet_binding, cases=cases,
                network_ready=False, world_move_trigger_verified=False,
                limitations=['Actual ID110/derived manager/base option apply/packet preparation and item constructor execute.',
                             'Lookup/accessor, allocation, 16-byte item copy, cache/profile effects, cleanup and send transport are captures.',
                             'Captured one-item values are serialized in a separate native writer emulator; no shared transport or socket.',
                             'PktOptionSet is an option update; no ID201 trigger or live world entry proved.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/character-select-option-send-replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), cases=len(report['cases']),
                          sha256=hashlib.sha256(output.read_bytes()).hexdigest())))
