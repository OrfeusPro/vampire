"""Native wrapper construction/reset -> initial Login fields; no external IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('initial_login_policy', HERE / 'replay-login-policy-inputs.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.base.x
WRAPPER_START, WRAPPER_END = 0x1467a7ab4, 0x1467a7b27
RESET = 0x14556a750


class Replay(base.Replay):
    def __init__(self, raw, image, fragments, leaves, fixture, globals_):
        super().__init__(raw, image, fragments, leaves, fixture, globals_)
        self.targets.update({0x144280630, 0x141421dd0})
        for address in (0x144280630, 0x141421dd0):
            page = address & ~4095
            if not any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                self.uc.mem_map(page, 4096)

    def hook(self, uc, address, size, user):
        if address == WRAPPER_END:
            uc.emu_stop()
            return
        if address in (0x144280630, 0x141421dd0):
            a = uc.reg_read(x.UC_X86_REG_RCX)
            if address == 0x141421dd0: self.fwrite(a, '')
            self.events.append(dict(action='bounded_primitive_hook', address=address))
            rsp = uc.reg_read(x.UC_X86_REG_RSP)
            target = int.from_bytes(uc.mem_read(rsp, 8), 'little')
            uc.reg_write(x.UC_X86_REG_RAX, a)
            uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(x.UC_X86_REG_RIP, target)
            return
        super().hook(uc, address, size, user)

    def capture(self):
        self.uc.mem_write(self.wrapper, bytes([self.fixture['poison']]) * 0x190)
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RAX, self.wrapper)
        # The whole caller establishes R15=0 before this allocation branch.
        self.uc.reg_write(x.UC_X86_REG_R15, 0)
        self.uc.emu_start(WRAPPER_START, self.stop, count=4096)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != WRAPPER_END: raise ValueError('Wrapper constructor slice did not finish')
        initial_text = self.fread(self.wrapper + 0x100)
        # Restore the fixture peer and model the already proven lobby copies.
        self.uc.mem_write(self.wrapper + 0x10, struct.pack('<Q', self.peer))
        self.fwrite(self.wrapper + 0xf0, 'lobby-first-fixture')
        self.fwrite(self.wrapper + 0xe0, 'lobby-second-fixture')
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.policy)
        self.uc.emu_start(0x145556120, self.stop, count=4096)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop: raise ValueError('Policy constructor did not return')
        vtable = int.from_bytes(self.uc.mem_read(self.policy, 8), 'little')
        reset = int.from_bytes(self.uc.mem_read(vtable + 8, 8), 'little')
        if reset != RESET: raise ValueError('Policy virtual reset binding changed')
        self.uc.mem_write(self.policy + 0x18, bytes([self.fixture['poison']]))
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.policy)
        self.uc.emu_start(reset, self.stop, count=4096)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop: raise ValueError('Policy reset did not return')
        result = super().capture()
        result['initial_wrapper_text'] = initial_text
        return result


def build():
    path = native.ROOT / 'code-clues/login-policy-inputs-replay.json'
    prior = json.loads(path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['source_sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    fields_path = native.ROOT / 'code-clues/login-packet-fields-replay.json'
    fields = json.loads(fields_path.read_text('utf-8'))
    roots = {image.roots[image.containing(a)] for a in (0x1467a79e0, 0x144aaa530, RESET)}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    slot_address = 0x1498a9618 + 8
    slot_offset = image.offset(slot_address - image.pe.base)
    slot_bytes = raw[slot_offset:slot_offset + 8]
    if int.from_bytes(slot_bytes, 'little') != RESET: raise ValueError('Source policy vtable slot changed')
    zero = [r for r in rows.values() if r['address'] < WRAPPER_START and r['mnemonic'] == 'xor' and r['operands'] == 'r15d, r15d']
    if len(zero) != 1: raise ValueError('Wrapper zero-register source changed')
    default = dict(prior['cases'][0]['fixture'], policy_byte=7, mode_byte=0, manager68_byte=0)
    cases = [Replay(raw, image, fields['fragments'] + prior['constructor_fragments'] + fragments,
        fields['leaves'] + prior['leaves'], dict(default, name=f'initial-poison-{p}', poison=p), fields['globals']).capture()
        for p in (0, 127, 255)]
    for c in cases:
        p = c['packet']
        if c['initial_wrapper_text'] != '' or p['strings']['0x88'] != '' or p['bytes']['0x124'] != 7:
            raise ValueError('Initial Login context differs from native construction/reset')
        if (p['strings']['0x10'], p['strings']['0x20']) != ('lobby-first-fixture', 'lobby-second-fixture'):
            raise ValueError('Lobby fields lost')
    return dict(source=prior['source'], source_sha256=prior['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        fields_sha256=hashlib.sha256(fields_path.read_bytes()).hexdigest(), fragments=fragments,
        zero_register_source=zero[0], cases=cases,
        reset_slot=dict(vtable=hex(0x1498a9618), offset=8, address=hex(slot_address),
            file_offset=slot_offset, bytes=slot_bytes.hex(), target=hex(RESET),
            sha256=hashlib.sha256(slot_bytes).hexdigest()),
        limitations=['Actual derived-wrapper slice with base constructor, full policy reset and Login preparation.',
            'Wrapper slice starts after allocation with source-bound R15=0; not full peers/TLS initialization.',
            'Base object helper and reset string assignments bounded hooks; SDK/string/handoff fixtures inherited.',
            'Explicit initial/reset context; no proof every game lifecycle path chooses reset or preserves initial text.',
            'No game launch, network, Login writer or server acceptance.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/login-initial-context-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
