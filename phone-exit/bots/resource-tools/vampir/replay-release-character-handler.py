"""New EXE whole list -> native gate/predicate/handler, explicit engine fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
HANDLER, GATE, PREDICATE = 0x146797990, 0x1467cee40, 0x145c9c0d0
EXIT, POLICY, OWNER_NEXT = 0x30009000, 0x30009010, 0x30009020


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Emulator:
    def __init__(self):
        extensions = load('handler_release_extensions', HERE / 'replay-release-character-extensions.py')
        self.h = h = extensions.make_harness(extra_addresses=(HANDLER, PREDICATE), extra_leaves=(0x1456e5ee0,))
        self.phase = False
        self.events, self.trace, self.gate_ranges = [], {}, []
        for relative, sha in (
            ('run-ab4ca396be23', '64a07328ba5dc14b901dc01005a8515a0a102a893eb750d4e3fa309a92040767'),
            ('run-7862c6b69a2a', '9d9837e711ae068aff760f3b5efe743c78d1d944e18de2be167b807274712f25')):
            if h.audit.sha256(h.comparison / 'details' / relative / 'details.json') != sha:
                raise ValueError('Reviewed handler Ghidra evidence changed')
        root = h.image.roots[h.image.containing(GATE)]
        for begin, end, unwind in h.image.ranges:
            if h.image.roots[(begin, end, unwind)] != root:
                continue
            start, stop = h.image.pe.base + begin, h.image.pe.base + end
            off = h.image.offset(begin)
            self.gate_ranges.append(dict(begin=start, end=stop, file_offset=off,
                sha256=hashlib.sha256(h.raw[off:off + end - begin]).hexdigest()))
            h.ranges.append((start, stop))
            for page in range(start & ~4095, (stop + 4095) & ~4095, 4096):
                self.map_source(page)
        self.context = 0x23000000
        h.uc.mem_map(self.context, 0x10000)
        h.uc.mem_map(EXIT & ~4095, 4096)
        self.hooks = (0x141426c10, 0x141426a30, 0x141433420, 0x141403c50, 0x141483160,
            0x145596560, 0x145fd5370, 0x145c9bc00, 0x1456d6f70, 0x1456e7e90, 0x1456d66e0,
            0x145ca6570, 0x14563f000, 0x14563a3d0, 0x14641af90, 0x145ca5fc0,
            0x1445d3910, 0x14546f350, 0x144a79200, 0x14560c570, 0x145619e00,
            0x144ab1f90, 0x144ab2880, 0x1445d3890, 0x1454fd260, EXIT, POLICY, OWNER_NEXT)
        for address in self.hooks:
            if address > h.image.pe.base:
                self.map_source(address & ~4095)
                self.map_source((address & ~4095) + 4096)
            previous = h.fixtures.get(address)
            def dispatch(machine, original=previous):
                if self.phase:
                    self.fixture(machine)
                elif original is not None:
                    original(machine)
                else:
                    raise ValueError('Handler fixture reached by reader')
            h.fixtures[address] = dispatch
        self.map_source(0x14992a968 & ~4095)
        table = h.image.offset(0x14992a968 - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, table + 0x28)[0] != 0x1456e5ee0:
            raise ValueError('Packet ID vtable binding changed')
        self.map_source(0x149672698 & ~4095)
        self.map_source(0x14b2f314b & ~4095)
        self.sentinel = int.from_bytes(h.uc.mem_read(0x149672698, 8), 'little')
        h.uc.hook_add(h.env.unicorn.UC_HOOK_CODE, self.observe)

    def map_source(self, page):
        h = self.h
        if any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
            return
        offset = h.image.offset(page - h.image.pe.base)
        h.uc.mem_map(page, 4096)
        h.uc.mem_write(page, h.raw[offset:offset + 4096])

    def observe(self, machine, address, size, unused):
        if not self.phase:
            return
        h, x = self.h, self.h.x
        if address == GATE:
            self.events.append(dict(action='native_gate', code=machine.reg_read(x.UC_X86_REG_ECX),
                                    packet_id=machine.reg_read(x.UC_X86_REG_EDX)))
        if not any(r['begin'] <= address < r['end'] for r in self.gate_ranges):
            return
        cs = h.env.capstone.Cs(h.env.capstone.CS_ARCH_X86, h.env.capstone.CS_MODE_64)
        cs.detail = True
        data = bytes(machine.mem_read(address, size))
        rows = list(cs.disasm(data, address))
        offset = h.image.offset(address - h.image.pe.base)
        if len(rows) != 1 or rows[0].size != size or data != h.raw[offset:offset + size]:
            raise ValueError('Gate executed bytes differ from source')
        ins = rows[0]
        refs = [ins.address + ins.size + op.mem.disp for op in ins.operands
            if op.type == h.env.capstone.x86_const.X86_OP_MEM
            and op.mem.base == h.env.capstone.x86_const.X86_REG_RIP]
        self.trace[address] = dict(address=address, file_offset=offset, bytes=data.hex(),
                                  mnemonic=ins.mnemonic, operands=ins.op_str, rip_references=refs)
        for ref in refs:
            self.map_source(ref & ~4095)

    def fixture(self, machine):
        h, x, ctx = self.h, self.h.x, self.context
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        def event(action, **values):
            self.events.append(dict(action=action, **values))
        if address in (0x141426c10, 0x141426a30, 0x141433420):
            if not h.scratch + 0x2f000 <= a <= h.scratch + 0x30000:
                raise ValueError('Diagnostic string fixture stack bound')
            machine.mem_write(a, bytes(16))
            result = a
        elif address in (0x141403c50, 0x141483160):
            pass
        elif address == 0x145596560:
            result = ctx + 0x6000
        elif address == 0x145fd5370:
            event('gate_error_capture', code=a & 0xffffffff)
        elif address == 0x145c9bc00:
            result = ctx + 0x1000
        elif address == 0x1456d6f70:
            event('old_list_cleanup_capture', count=b)
        elif address == 0x1456e7e90:
            if a != ctx + 0x1070 or b > 4:
                raise ValueError('State list allocation bound')
            machine.mem_write(a, struct.pack('<Q', h.allocate(b * 0x170) if b else 0))
            machine.mem_write(a + 12, struct.pack('<I', b))
        elif address == 0x1456d66e0:
            if c > 4 or (c and not all(h.scratch <= p <= h.scratch + 0x40000 - c * 0x170 for p in (a, b))):
                raise ValueError('State list copy bound')
            if c:
                machine.mem_write(a, bytes(machine.mem_read(b, c * 0x170)))
            event('list_copy_capture', count=c)
        elif address == 0x145ca6570:
            event('state_tail40_capture', raw64=b)
        elif address == 0x14563f000:
            result = ctx + 0x7000
        elif address == 0x14563a3d0:
            event('negative_tail28_warning_capture')
        elif address == 0x14641af90:
            result = ctx + 0x3000 if self.options['ui_present'] else 0
        elif address == 0x145ca5fc0:
            event('selection_ui_reset_capture')
        elif address == 0x1445d3910:
            result = 0
        elif address == 0x14546f350:
            result = ctx + 0x4000 if self.options['owner_present'] else 0
        elif address == 0x144a79200:
            event('ui_finish_capture')
        elif address == 0x14560c570:
            result = ctx + 0x5000
        elif address == 0x145619e00:
            event('selection_event_capture', event=b & 255)
        elif address == 0x144ab1f90:
            result = ctx + 0xb000
        elif address == 0x144ab2880:
            event('transport_flag_capture', value=b)
        elif address == 0x1445d3890:
            result = ctx + 0x8000 if self.options['policy_present'] else 0
        elif address == 0x1454fd260:
            result = ctx + 0xa000
        elif address == POLICY:
            result = self.options['policy']
            event('policy_virtual_capture', value=result)
        elif address == EXIT:
            event('selection_exit_capture')
        elif address == OWNER_NEXT:
            event('owner_a00_capture')
        else:
            raise ValueError('Unknown handler fixture')
        h.finish(result)

    def execute(self, body, options):
        h, x, ctx = self.h, self.h.x, self.context
        self.phase = False
        decoded = h.read_list(body)
        if decoded['accepted'] != 1 or decoded['consumed'] != len(body):
            raise ValueError('Complete body required before handler')
        self.options, self.events = options, []
        h.uc.mem_write(ctx, bytes(0x10000))
        previous = options.get('previous_ids', ())
        if previous:
            if len(previous) > 4:
                raise ValueError('Previous state fixture count bound')
            pointer = h.allocate(len(previous) * 0x170)
            h.uc.mem_write(pointer, bytes(len(previous) * 0x170))
            for index, value in enumerate(previous):
                h.uc.mem_write(pointer + index * 0x170 + 8, struct.pack('<Q', value))
            h.uc.mem_write(ctx + 0x1070, struct.pack('<QIIII', pointer, len(previous), len(previous), 55, 66))
        # Packet vptr fixture uses the independently verified new-release table.
        h.uc.mem_write(h.list_packet, struct.pack('<Q', 0x14992a968))
        for offset, value in ((0x5000, ctx + 0x5100), (0x5138, EXIT), (0x4000, ctx + 0x4200),
                (0x4c00, OWNER_NEXT), (0x8000, ctx + 0x9000), (0x8010, ctx + 0xa200),
                (0xa230, ctx + 0xa400), (0xa408, ctx + 0xa030), (0x9a18, POLICY)):
            h.uc.mem_write(ctx + offset, struct.pack('<Q', value))
        for offset, value in ((0xa238, 1), (0xa038, 1), (0x33f8, -9)):
            h.uc.mem_write(ctx + offset, struct.pack('<i', value))
        h.uc.mem_write(0x14b2f314b, bytes([options['policy_disabled']]))
        h.uc.mem_write(ctx + 0x6008, bytes([options['gate_state']]))
        self.phase = True
        stack, stop = h.scratch + 0x30000, h.scratch + 0x3f000
        h.uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, ctx),
                           (x.UC_X86_REG_RDX, 0x12345678), (x.UC_X86_REG_R8, h.list_packet)):
            h.uc.reg_write(reg, value)
        try:
            h.uc.emu_start(HANDLER, stop, count=250000)
        except h.env.unicorn.UcError as error:
            raise ValueError('Handler memory fault at ' + hex(h.uc.reg_read(x.UC_X86_REG_RIP))) from error
        if h.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Handler instruction budget')
        pointer, count = struct.unpack('<QI', bytes(h.uc.mem_read(ctx + 0x1070, 12)))
        if count > 4:
            raise ValueError('State count bound')
        source_pointer = int.from_bytes(h.uc.mem_read(h.list_packet + 0x18, 8), 'little')
        copied_bytes_match = count == decoded['count'] and (count == 0 or
            bytes(h.uc.mem_read(pointer, count * 0x170)) == bytes(h.uc.mem_read(source_pointer, count * 0x170)))
        return dict(options=options, decoded=decoded, events=self.events.copy(), state=dict(count=count,
            raw80=int.from_bytes(h.uc.mem_read(ctx + 0x1080, 4), 'little'),
            raw84=int.from_bytes(h.uc.mem_read(ctx + 0x1084, 4), 'little'),
            record_raw8=[int.from_bytes(h.uc.mem_read(pointer + i * 0x170 + 8, 8), 'little') for i in range(count)]),
            copied_record_bytes_match=copied_bytes_match,
            selected_index=struct.unpack('<i', bytes(h.uc.mem_read(ctx + 0x33f8, 4)))[0] if options['ui_present'] else None)


def main():
    em = Emulator()
    h = em.h
    wire = load('handler_record_wire', HERE / 'replay-character-list-reader.py')
    extensions = load('handler_extension_wire', HERE / 'replay-character-list-extensions.py')
    default = dict(gate_state=0, policy_disabled=False, policy_present=True, policy=1, ui_present=True, owner_present=True)
    cases = []
    def run(body, options):
        row = em.execute(body, options)
        packet = row['decoded']
        applied = packet['result_code'] == 0 and not options['policy_disabled'] and options['policy_present'] and options['policy'] == 1
        events = row['events']
        if [e for e in events if e['action'] == 'native_gate'] != [dict(action='native_gate', code=packet['result_code'], packet_id=102)]:
            raise ValueError('Native gate arguments differ')
        ids = [r['u64'][0] for r in packet['records']]
        previous = options.get('previous_ids', ())
        expected_ids = ids if applied else list(previous)
        if row['state']['record_raw8'] != expected_ids or row['state']['count'] != len(expected_ids):
            raise ValueError('Applied character list differs')
        if applied and not row['copied_record_bytes_match']:
            raise ValueError('Whole record storage copy differs')
        if row['state']['raw80'] != (packet['tail'][1] if applied else 55 if previous else 0) or row['state']['raw84'] != (packet['tail'][0] & 0xffffffff if applied else 66 if previous else 0):
            raise ValueError('State scalar copies differ')
        preferred = packet['tail'][2]
        selected = ids.index(preferred) if preferred != em.sentinel and preferred in ids else 0
        expected_index = (selected if applied else -9) if options['ui_present'] else None
        if row['selected_index'] != expected_index:
            raise ValueError('Preferred index differs')
        expected_events = dict(selection_exit_capture=int(packet['result_code'] != 0),
            selection_ui_reset_capture=int(applied and options['ui_present']),
            owner_a00_capture=int(applied and options['owner_present']), ui_finish_capture=int(applied),
            selection_event_capture=int(applied), transport_flag_capture=int(applied),
            negative_tail28_warning_capture=int(applied and packet['tail'][0] >= 2**63), state_tail40_capture=int(applied))
        for action, count in expected_events.items():
            if sum(e['action'] == action for e in events) != count:
                raise ValueError('Unexpected handler event: ' + action)
        cleanup = [e for e in events if e['action'] == 'old_list_cleanup_capture']
        if cleanup != ([dict(action='old_list_cleanup_capture', count=len(previous))] if applied else []):
            raise ValueError('Previous list cleanup differs')
        if applied:
            for item in (dict(action='state_tail40_capture', raw64=packet['tail'][3]),
                         dict(action='selection_event_capture', event=6), dict(action='transport_flag_capture', value=0)):
                if item not in events:
                    raise ValueError('Handler event argument differs')
        row['expected_behavior_checked'] = True
        cases.append(row)
    def body(ids, preferred, code=0, raw28=0x8000000000000001):
        return struct.pack('<IIH', code, 207, len(ids)) + b''.join(wire.record_bytes(value=v) for v in ids) + struct.pack('<QIQQ', raw28, 23, preferred, 0x123456789abcdef)
    for ids in ((), (11,), (11, 22, 33), (11, 22, 22, 33), (11, 0, 22)):
        for preferred in (em.sentinel, 11, 22, 33, 99):
            run(body(ids, preferred), dict(default, name='ids-' + str(ids) + '-preferred-' + str(preferred)))
    for update in (dict(name='policy-zero', policy=0), dict(name='policy-two', policy=2), dict(name='policy-four', policy=4),
            dict(name='policy-disabled', policy_disabled=True), dict(name='policy-absent', policy_present=False),
            dict(name='ui-absent', ui_present=False), dict(name='owner-absent', owner_present=False), dict(name='gate-state1', gate_state=1)):
        run(body((11, 22, 33), 22), dict(default, **update))
    for code in (1, 14, 22, 37, 54, 9400, 9818, 9819, 90021, 0xffffffff):
        run(body((11, 22), 22, code=code), dict(default, name='code-' + str(code)))
    run(body((11, 22), 22, raw28=7), dict(default, name='positive-tail28'))
    run(extensions.list_bytes(((0xffffffff, 255, 65535),), extensions.optional_bytes(((1, 255, 2, 3, 4, 5), (1, 1, 6, 7, 8, 9))), count=2),
        dict(default, name='with-nested-extensions'))
    for name, ids, code, updates in (
            ('replace-nonempty', (11, 22, 33), 0, {}), ('clear-nonempty', (), 0, {}),
            ('policy-keeps-nonempty', (11, 22), 0, dict(policy=2)),
            ('error-keeps-nonempty', (11, 22), 14, {}),
            ('gate-state1-error-keeps-nonempty', (11, 22), 14, dict(gate_state=1))):
        run(body(ids, 22, code=code), dict(default, name=name, previous_ids=(77, 88), **updates))
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        dependencies={p: h.audit.sha256(HERE / p) for p in ('replay-release-character-extensions.py', 'replay-release-character-list.py',
            'replay-release-fstring-input.py', 'replay-release-archive-input.py', 'replay-character-list-reader.py', 'replay-character-list-extensions.py',
            'replay-release-nested-read-thunk.py', 'build-native-entry-code.py', 'requirements-native.txt')},
        ghidra_evidence={p: h.audit.sha256(h.comparison / 'details' / p / 'details.json') for p in ('run-ab4ca396be23', 'run-7862c6b69a2a')},
        capstone_version=h.env.capstone.__version__, unicorn_version=h.env.unicorn.__version__,
        fragments=h.fragments, leaves=h.leaves, gate_ranges=em.gate_ranges,
        gate_trace=[em.trace[a] for a in sorted(em.trace)], fixtures=[hex(a) for a in em.hooks], sentinel=em.sentinel,
        cases=cases, native_execution=True, compatibility='not_established', network_ready=False,
        limits=['Actual new-release body/record/extension readers then handler, gate and predicate execute in one emulator.',
            'Packet vptr, previous state and synthetic engine type metadata/policy are fixtures; no real engine lifecycle.',
            'Diagnostics, singleton getters, state array allocation/copy/cleanup, UI/owner/events/transport setter are captures or fixtures.',
            'Only tested result codes; secondary engine condition uses a null fixture. Unknown execution targets fail.',
            'No full dispatch, live login, actual character selection, position or Android proof.'])
    target = h.audit.save_snapshot(h.comparison / 'character-handler-replay', report)
    print(json.dumps(dict(report=str(target), sha256=h.audit.sha256(target), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
