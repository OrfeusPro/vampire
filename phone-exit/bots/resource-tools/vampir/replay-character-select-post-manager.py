"""Actual ID110 -> constructed post-selection manager and callback refresh.

Manager policy queries and absent configuration backend are explicit captures.
Callback objects are fixtures, never assumed to be world-move packet senders.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('post_manager_base', HERE / 'replay-selection-status.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
CTOR, VALUE, REFRESH, VIRTUAL58 = 0x1455808c0, 0x145596150, 0x14558d3f0, 0x1455910d0
GETTER, GLOBAL, TABLE, CALLBACK = 0x14558ee60, 0x14b573528, 0x1498ab150, 0x3000f0d0
HANDLER = 0x14675e9a0


class Emulator(base.Emulator):
    def __init__(self):
        self.defer_handler = False
        super().__init__()
        manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
        names = {'CharacterSelect_PostManagerConstruct', 'CharacterSelect_PostManagerValue',
                 'CharacterSelect_PostManagerRefresh', 'CharacterSelect_PostManagerVirtual58'}
        self.manager_ranges = [r for f in manifest['functions'] if f['name'] in names for r in f['ranges']]
        if len(self.manager_ranges) != 4:
            raise ValueError('Missing manager Ghidra ranges')
        for r in self.manager_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset'] + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Post-selection manager source changed')
            self.ranges.append((lo, hi))
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_source_page(page)
        off = self.image.offset(GETTER - self.image.pe.base)
        raw = self.raw[off:off + 8]
        if raw != bytes.fromhex('488b05c146fe05c3') or GETTER + 7 + struct.unpack_from('<i', raw, 3)[0] != GLOBAL:
            raise ValueError('Post-selection singleton getter changed')
        self.getter_leaf = dict(address=GETTER, file_offset=off, bytes=raw.hex())
        self.ranges.append((GETTER, GETTER + 8))
        off = self.image.offset(TABLE - self.image.pe.base)
        table = self.raw[off:off + 0x70]
        if (struct.unpack_from('<Q', table, 0x58)[0], struct.unpack_from('<Q', table, 0x60)[0]) != (VIRTUAL58, 0x1455967f0):
            raise ValueError('Post-selection manager slot changed')
        self.table = dict(address=TABLE, file_offset=off, bytes=table.hex())
        self.query = struct.unpack_from('<Q', table, 0x38)[0]
        self.manager_hooks = {self.query, 0x144aa3f40, CALLBACK}
        for a in (*self.manager_hooks, GETTER, GLOBAL, TABLE):
            self.map_source_page(a & ~4095)
        self.getters.pop(GETTER)
        self.handler_hooks.remove(GETTER)
        for address in (VALUE, REFRESH):
            self.actions.remove(address)
            self.handler_hooks.remove(address)

    def invoke(self, address, receiver):
        stack, stop = self.scratch + 0x30000, self.scratch + 0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, receiver)
        self.uc.emu_start(address, stop, count=500000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Post-selection instruction budget')

    def hook(self, uc, address, size, user):
        if self.defer_handler and address == HANDLER:
            self.defer_handler = False
            uc.reg_write(x.UC_X86_REG_RIP, self.scratch + 0x3f000)
            uc.emu_stop()
            return
        if self.handler_phase and address in (VALUE, VIRTUAL58, REFRESH):
            if uc.reg_read(x.UC_X86_REG_RCX) != self.context + 0xa000:
                raise ValueError('Post-selection manager receiver changed')
            self.events.append(dict(action='native_post_manager', address=address))
        if self.handler_phase and address in self.manager_hooks:
            a, b = uc.reg_read(x.UC_X86_REG_RCX), uc.reg_read(x.UC_X86_REG_RDX)
            result = 0
            if address == self.query:
                if a != self.context + 0xa000 or not 0 <= b <= 204:
                    raise ValueError('Manager per-entry query arguments')
                self.query_count += 1
            elif address == 0x144aa3f40:
                self.config_count += 1
            else:
                index = (a - (self.context + 0x18000)) // 16
                if a != self.context + 0x18000 + index * 16 or not 0 <= index <= 204:
                    raise ValueError('Manager callback receiver mismatch')
                self.events.append(dict(action='post_manager_callback_capture', index=index, value=b & 0xffffffff))
            self.finish(result)
            return
        return super().hook(uc, address, size, user)

    def execute_manager(self, code=0, gate_state=0, mode='empty'):
        fixture = dict(gate_state=gate_state, metadata=False, platform=False, ui_present=False,
                       ui_same=False, service_flag=0)
        body = base.base.base.profile_body('', code)
        self.defer_handler = True
        prepared = self.execute(body, fixture)
        self.invoke(CTOR, self.context + 0xa000)
        if int.from_bytes(self.uc.mem_read(GLOBAL, 8), 'little') != self.context + 0xa000:
            raise ValueError('Constructor did not bind actual manager singleton')
        if int.from_bytes(self.uc.mem_read(self.context + 0xa000, 8), 'little') != TABLE:
            raise ValueError('Constructor did not install actual manager table')
        initial = bytes(self.uc.mem_read(self.context + 0xa050, 205 * 0x30))
        if any(initial[i * 0x30] != 205 or initial[i * 0x30 + 0x18:i * 0x30 + 0x1a] != b'\0\0'
               for i in range(205)):
            raise ValueError('Manager fresh records changed')
        records = []
        for i in range(205):
            present = mode != 'empty'
            enabled = mode != 'disabled'
            count = 0 if mode == 'zero-count' else 1
            pointer = 0 if mode == 'null-pointer' else self.context + 0x18000 + i * 16
            if present:
                record = self.context + 0xa050 + i * 0x30
                self.uc.mem_write(record + 4, struct.pack('<I', 1000 + i))
                self.uc.mem_write(record + 0x19, bytes([int(enabled)]))
                self.uc.mem_write(record + 0x20, struct.pack('<QI', pointer, count))
                if pointer:
                    self.uc.mem_write(pointer, struct.pack('<Q', self.context + 0x1d000))
                records.append(dict(index=i, enabled=enabled, count=count, pointer_present=bool(pointer), value=1000 + i))
        self.uc.mem_write(self.context + 0x1d060, struct.pack('<Q', CALLBACK))
        self.uc.mem_write(self.context + 0xc728, struct.pack('<Q', 7))
        self.events, self.gate_return = [], None
        self.query_count, self.config_count = 0, 0
        stack = self.scratch + 0x30000
        self.uc.mem_write(stack, struct.pack('<Q', self.scratch + 0x3f000))
        self.uc.reg_write(x.UC_X86_REG_RSP, stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.context)
        self.uc.reg_write(x.UC_X86_REG_RDX, 0x12345678)
        self.uc.reg_write(x.UC_X86_REG_R8, self.scratch + 0x1000)
        self.uc.emu_start(HANDLER, self.scratch + 0x3f000, count=500000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.scratch + 0x3f000:
            raise ValueError('ID110 post-manager instruction budget')
        raw = int.from_bytes(self.uc.mem_read(self.context + 0xc728, 8), 'little')
        decoded_raw = int.from_bytes(self.uc.mem_read(self.scratch + 0x1020, 8), 'little')
        return dict(code=code, gate_state=gate_state, mode=mode, records=records, decoded_raw20=decoded_raw,
                    raw2728=raw, queries=self.query_count, config_queries=self.config_count,
                    status30=self.uc.mem_read(self.context + 0x5030, 1)[0],
                    events=self.events.copy(), decoded=prepared['decoded'])


def build():
    em = Emulator()
    cases = [em.execute_manager(mode=mode) for mode in ('empty', 'active', 'disabled', 'zero-count', 'null-pointer')]
    cases += [em.execute_manager(code=code, gate_state=gate, mode='active') for code, gate in ((1, 0), (0x1197, 0), (0x1197, 1))]
    for case in cases:
        accepted = case['code'] == 0 or (case['code'] == 0x1197 and case['gate_state'] == 0)
        if (case['queries'], case['config_queries']) != ((205, 205) if accepted else (0, 0)):
            raise ValueError('Post-selection virtual58 traversal mismatch')
        expected = [dict(action='post_manager_callback_capture', index=i, value=1000 + i)
                    for i in range(205) if i not in (146, 147)] if accepted and case['mode'] == 'active' else []
        if [e for e in case['events'] if e['action'] == 'post_manager_callback_capture'] != expected:
            raise ValueError('Post-selection refresh gating mismatch')
        if case['raw2728'] != (case['decoded_raw20'] if accepted else 7):
            raise ValueError('Post-selection raw ID storage mismatch')
    fragments = native.decode_ranges(em.image, {em.image.roots[em.image.containing(0x145c8c380)]})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    if (rows[0x145c8c400]['direct_target'] != GETTER or
            rows[0x145c8c425]['operands'] != 'qword ptr [r10 + 0x60]'):
        raise ValueError('Rejected reserve-caller candidate changed')
    return dict(source=em.bindings['source'], sha256=em.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-selection-status.py').read_bytes()).hexdigest(),
                ranges=em.manager_ranges, getter=em.getter_leaf, table=em.table, cases=cases,
                other_manager_candidate=fragments,
                network_ready=False, reserve_trigger_verified=False,
                limitations=['Actual ID110 reader/handler/status and manager constructor/getter/value/virtual58/refresh execute.',
                             'Per-entry query returns false; configuration backend absent. Other configuration paths are untested.',
                             'Callback receivers are fixtures; identities and actual callback implementations are not established.',
                             'No ID201 trigger, live session, world position or engine loading verified.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/character-select-post-manager-replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), cases=len(report['cases']),
                          sha256=hashlib.sha256(output.read_bytes()).hexdigest())))
