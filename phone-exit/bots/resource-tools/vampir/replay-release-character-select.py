"""Continuous new-release ID102 -> state -> indexed selection -> ID109 body."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SETTER, INDEXED, SELECT, WRITER = 0x145ca6570, 0x145d5a570, 0x145db0e30, 0x1456e9550
STATE, LOOKUP, CONSTRUCTOR = 0x145c9bc00, 0x145c9abd0, 0x1456d85a0
WRITE64, WRITE32, WRITER_RETURN = 0x3000b000, 0x3000b010, 0x3000b020


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load('select_release_handler', HERE / 'replay-release-character-handler.py')


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__(extra_addresses=(SETTER, INDEXED, SELECT, WRITER), extra_leaves=(STATE, CONSTRUCTOR))
        h = self.h
        self.evidence = {}
        for name, expected in (('run-9eb39947f076', '28ff65921df52644773fbf071da56affe1a349b94cc1b4de85007c16c68a38ab'),
                ('run-90cef8d92d6e', '5e072c4e5c8243cded716807c22f4b0f28364da56b548beb90aa8cac71aeb8d3'),
                ('run-d44249673b72', 'a36a67359571ec08597700915fedb4eed931140d8541b58803932b854aef6151')):
            actual = h.audit.sha256(h.comparison / 'details' / name / 'details.json')
            if actual != expected:
                raise ValueError('Reviewed selection Ghidra evidence changed')
            self.evidence[name] = actual
        # Ghidra has no function objects for these leaves. Validate reviewed bytes
        # and execute all signed bounds branches, rather than inventing a function.
        off = h.image.offset(LOOKUP - h.image.pe.base)
        lookup = h.raw[off:off + 34]
        if lookup.hex() != '85d2781b488b0d0d9695053b51787d0f4863c24869c07001000048034170c333c0c3':
            raise ValueError('Reviewed lookup leaf changed')
        h.ranges.append((LOOKUP, LOOKUP + len(lookup)))
        self.lookup_leaf = dict(address=hex(LOOKUP), file_offset=off, bytes=lookup.hex())
        self.map_source(LOOKUP & ~4095)
        off = h.image.offset(STATE - h.image.pe.base)
        getter = h.raw[off:off + 8]
        if getter[:3] != b'\x48\x8b\x05' or getter[-1] != 0xc3:
            raise ValueError('State getter instruction changed')
        self.state_global = STATE + 7 + struct.unpack_from('<i', getter, 3)[0]
        if LOOKUP + 11 + struct.unpack_from('<i', lookup, 7)[0] != self.state_global:
            raise ValueError('Lookup and getter use different state globals')
        # This singleton slot is in the PE's zero-initialized virtual tail.
        rva = self.state_global - h.image.pe.base
        if not any(s['rva'] + s['raw_size'] <= rva and rva + 8 <= s['rva'] + s['size'] for s in h.image.pe.sections):
            raise ValueError('State singleton no longer in reviewed PE virtual tail')
        page = self.state_global & ~4095
        if not any(lo <= page <= hi for lo, hi, permissions in h.uc.mem_regions()):
            h.uc.mem_map(page, 4096)
        off = h.image.offset(CONSTRUCTOR - h.image.pe.base)
        constructor = h.raw[off:off + 30]
        if constructor[:3] != b'\x48\x8d\x05' or constructor[-1] != 0xc3:
            raise ValueError('Select constructor changed')
        self.packet_table = CONSTRUCTOR + 7 + struct.unpack_from('<i', constructor, 3)[0]
        off = h.image.offset(self.packet_table - h.image.pe.base)
        words = struct.unpack_from('<6Q', h.raw, off)
        if words[2] != WRITER:
            raise ValueError('Select vtable writer binding differs')
        self.packet_id_getter = words[5]
        off = h.image.offset(self.packet_id_getter - h.image.pe.base)
        id_code = h.raw[off:off + 6]
        if id_code != bytes.fromhex('b86d000000c3'):
            raise ValueError('Select ID getter differs')
        h.ranges.append((self.packet_id_getter, self.packet_id_getter + 6))
        self.id_leaf = dict(address=hex(self.packet_id_getter), file_offset=off, bytes=id_code.hex())
        self.map_source(self.packet_id_getter & ~4095)
        self.map_source(self.packet_table & ~4095)
        # Execute the state getter and setter in both handler and selection phases.
        del h.fixtures[STATE]
        del h.fixtures[SETTER]
        h.uc.mem_map(WRITE64 & ~4095, 4096)
        self.additional_hooks = (0x145c9c3d0, 0x1445d7f20, 0x1445d3da0, 0x145c8dc00,
            0x145617210, 0x144aaf870, 0x144aafc50, 0x1456b7990, WRITE64, WRITE32, WRITER_RETURN)
        for address in self.additional_hooks:
            if address > h.image.pe.base:
                self.map_source(address & ~4095)
                self.map_source((address & ~4095) + 4096)
            original = h.fixtures.get(address)
            def fixture(machine, prior=original):
                if self.phase:
                    self.select_fixture(machine)
                elif prior is not None:
                    prior(machine)
                else:
                    raise ValueError('Selection fixture reached by reader')
            h.fixtures[address] = fixture
        self.map_source(0x1496726a0 & ~4095)
        self.raw18_constant = int.from_bytes(h.uc.mem_read(0x1496726a0, 4), 'little')
        if self.raw18_constant != 0:
            raise ValueError('Indexed caller raw32 constant changed')
        h.uc.hook_add(h.env.unicorn.UC_HOOK_CODE, self.entries)

    def entries(self, machine, address, size, unused):
        if self.phase and address in (SETTER, INDEXED, SELECT, LOOKUP, WRITER):
            self.events.append(dict(action='selection_native_entry', address=hex(address)))

    def select_fixture(self, machine):
        h, x, ctx = self.h, self.h.x, self.context
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x145c9c3d0:
            machine.mem_write(b, bytes(16))
            result = b
        elif address == 0x1445d7f20:
            self.events.append(dict(action='persistence_capture'))
        elif address == 0x1445d3da0:
            result = ctx + 0x3000 if self.selection['ui_present'] else 0
        elif address == 0x145c8dc00:
            result = ctx + 0xa000
        elif address == 0x145617210:
            if a != ctx + 0x5000 or c & 0xffffffff != self.raw18_constant:
                raise ValueError('Selection base receiver/constant changed')
            self.events.append(dict(action='base_selection_capture', raw64=b, raw32=c & 0xffffffff))
        elif address == 0x144aaf870:
            result = ctx + 0xc000
        elif address == 0x1456b7990:
            self.events.append(dict(action='select_packet_cleanup_capture'))
        elif address == 0x144aafc50:
            sp = machine.reg_read(x.UC_X86_REG_RSP)
            timeout = struct.unpack('<f', bytes(machine.mem_read(sp + 0x28, 4)))[0]
            if a != ctx + 0xc000 or c != 110 or d != self.sentinel or timeout != 0:
                raise ValueError('Select handoff arguments differ')
            if int.from_bytes(machine.mem_read(b, 8), 'little') != self.packet_table:
                raise ValueError('Constructed select packet vtable differs')
            self.events.append(dict(action='select_handoff_capture', kind=c, opaque_argument=d, timeout=timeout,
                raw10=int.from_bytes(machine.mem_read(b + 0x10, 8), 'little'),
                raw18=int.from_bytes(machine.mem_read(b + 0x18, 4), 'little'),
                raw20=int.from_bytes(machine.mem_read(b + 0x20, 8), 'little')))
            # Explicit boundary fixture: invoke actual packet writer instead of
            # pending-request bookkeeping, wrapper, framing, queue or socket.
            self.handoff_return = int.from_bytes(machine.mem_read(sp, 8), 'little')
            machine.mem_write(sp, struct.pack('<Q', WRITER_RETURN))
            machine.reg_write(x.UC_X86_REG_RCX, b)
            machine.reg_write(x.UC_X86_REG_RDX, ctx + 0xd000)
            machine.reg_write(x.UC_X86_REG_RIP, WRITER)
            return
        elif address in (WRITE64, WRITE32):
            if a != ctx + 0xd000:
                raise ValueError('Output fixture receiver differs')
            width = 8 if address == WRITE64 else 4
            accepted = len(self.output) + width <= self.selection['capacity']
            self.writes.append(dict(width=width, value=b & ((1 << (8 * width)) - 1), accepted=accepted))
            if accepted:
                self.output.extend((b & ((1 << (8 * width)) - 1)).to_bytes(width, 'little'))
            result = int(accepted)
        elif address == WRITER_RETURN:
            self.writer_result = machine.reg_read(x.UC_X86_REG_AL)
            machine.reg_write(x.UC_X86_REG_RIP, self.handoff_return)
            return
        else:
            raise ValueError('Unknown selection fixture')
        h.finish(result)

    def invoke(self, entry, a=0, b=0, c=0):
        h, x = self.h, self.h.x
        stack, stop = h.scratch + 0x30000, h.scratch + 0x3f000
        h.uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, a), (x.UC_X86_REG_RDX, b), (x.UC_X86_REG_R8, c)):
            h.uc.reg_write(reg, value)
        try:
            h.uc.emu_start(entry, stop, count=100000)
        except h.env.unicorn.UcError as error:
            raise ValueError('Selection memory fault at ' + hex(h.uc.reg_read(x.UC_X86_REG_RIP))) from error
        if h.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Selection instruction budget')
        return h.uc.reg_read(x.UC_X86_REG_RAX)

    def select(self, body, options):
        h, ctx = self.h, self.context
        self.selection = options
        h.uc.mem_write(self.state_global, struct.pack('<Q', ctx + 0x1000))
        row = self.execute(body, dict(gate_state=0, policy_disabled=False, policy_present=True,
                                      policy=1, ui_present=True, owner_present=True))
        initial_f0 = int.from_bytes(h.uc.mem_read(ctx + 0x10f0, 8), 'little')
        if initial_f0 != row['decoded']['tail'][3]:
            raise ValueError('Accepted list did not populate rawF0')
        if 'changed_f0' in options:
            self.invoke(SETTER, ctx + 0x1000, options['changed_f0'])
        current_f0 = int.from_bytes(h.uc.mem_read(ctx + 0x10f0, 8), 'little')
        expected_f0 = options.get('changed_f0', initial_f0)
        if current_f0 != expected_f0:
            raise ValueError('Updated rawF0 differs')
        persistence = sum(e['action'] == 'persistence_capture' for e in self.events)
        if persistence != int(expected_f0 != initial_f0 and initial_f0 != self.sentinel):
            raise ValueError('rawF0 persistence condition differs')
        index = options.get('index', row['selected_index'])
        h.uc.mem_write(ctx + 0x3010, struct.pack('<Q', ctx + 0xa200))
        h.uc.mem_write(ctx + 0x33f8, struct.pack('<i', index))
        h.uc.mem_write(ctx + 0x5150, struct.pack('<Q', SELECT))  # Synthetic controller slot.
        h.uc.mem_write(ctx + 0xa238, struct.pack('<i', options['type_count']))
        h.uc.mem_write(ctx + 0xa408, struct.pack('<Q', ctx + 0xa030 if options['type_match'] else 0))
        h.uc.mem_write(0x14b2f314b, bytes([options['disabled']]))
        h.uc.mem_write(ctx + 0xd000, struct.pack('<Q', ctx + 0xd100))
        h.uc.mem_write(ctx + 0xd1b8, struct.pack('<Q', WRITE64))
        h.uc.mem_write(ctx + 0xd1c8, struct.pack('<Q', WRITE32))
        self.output, self.writes, self.writer_result = bytearray(), [], None
        self.invoke(INDEXED)
        packet_id = self.invoke(self.packet_id_getter) & 0xffff
        if packet_id != 109:
            raise ValueError('Native select packet ID differs')
        return dict(options=options, decoded=row['decoded'], initial_index=row['selected_index'], index=index,
            initial_raw_f0=initial_f0, current_raw_f0=current_f0, packet_id=packet_id,
            events=self.events.copy(), body_hex=self.output.hex(), writes=self.writes, writer_result=self.writer_result)


def main():
    em = Emulator()
    h = em.h
    wire = load('select_release_wire', HERE / 'replay-character-list-reader.py')
    from vampir_core.character_select import CharacterSelectPayload
    defaults = dict(ui_present=True, type_count=1, type_match=True, disabled=False, capacity=20)
    cases = []
    def run(ids, preferred, **changes):
        options = dict(defaults, **changes)
        body = struct.pack('<IIH', 0, 207, len(ids)) + b''.join(wire.record_bytes(value=value) for value in ids) + struct.pack('<QIQQ', 1, 23, preferred, 0x8877665544332211)
        result = em.select(body, options)
        index = result['index']
        allowed = not options['disabled'] and options['ui_present'] and options['type_count'] >= 1 and options['type_match'] and 0 <= index < len(ids)
        handoffs = [e for e in result['events'] if e['action'] == 'select_handoff_capture']
        if len(handoffs) != int(allowed):
            raise ValueError('Indexed caller acceptance differs')
        if allowed:
            decoded = h.decode_character_list(body, max_payload_size=4096, max_characters=4, max_extension_items=128)
            expected = CharacterSelectPayload.from_character_list(decoded, index, state_raw_f0=result['current_raw_f0']).encode(max_payload_size=20)
            copied = 20 if options['capacity'] >= 20 else 12 if options['capacity'] >= 12 else 8 if options['capacity'] >= 8 else 0
            if bytes.fromhex(result['body_hex']) != expected[:copied] or result['writer_result'] != int(options['capacity'] >= 20):
                raise ValueError('Native writer differs from portable body/budget behavior')
            attempts = [8] if options['capacity'] < 8 else [8, 4] if options['capacity'] < 12 else [8, 4, 8]
            if [item['width'] for item in result['writes']] != attempts:
                raise ValueError('Native writer did not stop at the first scalar refusal')
            handoff = handoffs[0]
            if (handoff['raw10'], handoff['raw18'], handoff['raw20']) != (ids[index], 0, result['current_raw_f0']):
                raise ValueError('CharacterSelect raw field sources differ')
        elif result['body_hex'] or result['writes'] or result['writer_result'] is not None:
            raise ValueError('Refused index reached writer')
        result['expected_behavior_checked'] = True
        cases.append(result)
    for ids, preferred in (((), 0), ((11,), 11), ((11, 22, 33), 22), ((11, 22, 33), 33),
            ((11, 22, 22, 33), 22), ((11, 0, 22), 0), ((0,), 0), ((2**64 - 1,), 99)):
        run(ids, preferred)
    for changes in (dict(index=-1), dict(index=3), dict(index=2**31 - 1), dict(index=0),
            dict(ui_present=False), dict(type_count=0), dict(type_match=False), dict(disabled=True),
            dict(changed_f0=0), dict(changed_f0=2**64 - 1), dict(changed_f0=0x8877665544332211)):
        run((11, 22, 33), 22, **changes)
    for capacity in (0, 7, 8, 11, 12, 19):
        run((11, 22, 33), 22, capacity=capacity)
    report = dict(schema=1, source=str(h.source), source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        dependencies={p: h.audit.sha256(HERE / p) for p in ('replay-release-character-handler.py', 'replay-release-character-extensions.py',
            'replay-release-character-list.py', 'replay-release-fstring-input.py', 'replay-release-archive-input.py',
            'replay-release-nested-read-thunk.py', 'replay-character-list-reader.py', 'build-native-entry-code.py', 'requirements-native.txt')},
        portable_builder_sha256=h.audit.sha256(HERE.parents[1] / 'vampir-shared/vampir_core/character_select.py'),
        ghidra_evidence={**em.evidence, **{p: h.audit.sha256(h.comparison / 'details' / p / 'details.json')
            for p in ('run-ab4ca396be23', 'run-7862c6b69a2a')}},
        fragments=h.fragments, leaves=h.leaves, lookup_leaf=em.lookup_leaf, id_leaf=em.id_leaf,
        gate_ranges=em.gate_ranges, gate_trace=[em.trace[a] for a in sorted(em.trace)],
        state_global=hex(em.state_global), packet_vtable=hex(em.packet_table), raw18_constant=em.raw18_constant,
        fixtures=[hex(a) for a in (*em.hooks, *em.additional_hooks) if a not in (STATE, SETTER)],
        capstone_version=h.env.capstone.__version__, unicorn_version=h.env.unicorn.__version__,
        cases=cases, native_execution=True, compatibility='not_established', network_ready=False,
        limits=['Continuous actual new-release ID102 body/handler/setter -> indexed record lookup -> service -> packet constructor/writer.',
            'Engine/type/UI/controller slot, container storage and persistence are fixtures/captures; real engine lifecycle is not executed.',
            'Handoff is an explicit capture/redirect into actual writer, whose scalar output archive is a bounded fixture.',
            'No actual request bookkeeping, framing/CRC/XOR, queue, socket, server selection result, position or Android proof.'])
    target = h.audit.save_snapshot(h.comparison / 'character-select-replay', report)
    print(json.dumps(dict(report=str(target), sha256=h.audit.sha256(target), cases=len(cases)), indent=2))


if __name__ == '__main__':
    main()
