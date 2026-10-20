"""Execute Login preparation with actual policy getter leaves; synthetic state."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('policy_login_base', HERE / 'replay-login-packet-fields.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native = base.native
LEAVES = {0x145564550: 8, 0x145cb2f60: 8, 0x145cb95e0: 8, 0x144ff8cd0: 5,
    0x145ca7240: 48}


class Replay(base.Replay):
    def __init__(self, raw, image, fragments, leaves, fixture, globals_):
        super().__init__(raw, image, fragments, leaves, fixture, globals_)
        policy_global = next(r['rip_references'][0] for leaf in leaves if leaf['address'] == 0x145564550
            for r in leaf['instructions'] if r['rip_references'])
        mode_global = next(r['rip_references'][0] for leaf in leaves if leaf['address'] == 0x145cb2f60
            for r in leaf['instructions'] if r['rip_references'])
        self.policy = self.allocate(0xb0)
        self.mode = self.allocate(0x40)
        self.uc.mem_write(policy_global, struct.pack('<Q', self.policy))
        self.uc.mem_write(mode_global, struct.pack('<Q', self.mode))
        self.uc.mem_write(self.policy + 0x18, bytes([fixture['policy_byte']]))
        self.uc.mem_write(self.mode + 8, bytes([fixture['mode_byte']]))
        # A separate fixture object avoids overlap with the auth pointer at +38.
        manager68 = self.allocate(0x40)
        self.uc.mem_write(manager68 + 0x39, bytes([fixture['manager68_byte']]))
        self.uc.mem_write(self.manager + 0x68, struct.pack('<Q', manager68 if fixture['manager68_present'] else 0))
        self.uc.mem_write(self.manager + 0x48, struct.pack('<Q', self.manager if fixture['manager48_present'] else 0))

    def hook(self, uc, address, size, user):
        if address in LEAVES:
            self.events.append(dict(action='native_policy_entry', address=address))
        super().hook(uc, address, size, user)

    def capture(self):
        if 'constructor_poison' in self.fixture:
            poison = self.fixture['constructor_poison']
            self.uc.mem_write(self.policy, bytes([poison]) * 0xb0)
            self.uc.mem_write(self.mode, bytes([poison]) * 0x40)
            for address, obj in ((0x145556120, self.policy), (0x145ca7240, self.mode)):
                self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
                self.uc.reg_write(base.x.UC_X86_REG_RSP, self.stack)
                self.uc.reg_write(base.x.UC_X86_REG_RCX, obj)
                self.uc.emu_start(address, self.stop, count=4096)
                if self.uc.reg_read(base.x.UC_X86_REG_RIP) != self.stop:
                    raise ValueError('Constructor did not return')
            self.constructor_values = dict(policy_byte=self.uc.mem_read(self.policy + 0x18, 1)[0],
                mode_byte=self.uc.mem_read(self.mode + 8, 1)[0])
        result = super().capture()
        if hasattr(self, 'constructor_values'): result['after_constructors'] = self.constructor_values
        return result


def build():
    prior_path = native.ROOT / 'code-clues/login-packet-fields-replay.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    cs.detail = True
    leaves = []
    for address, length in LEAVES.items():
        offset = image.offset(address - image.pe.base)
        data = raw[offset:offset + length]
        rows = []
        for i in cs.disasm(data, address):
            refs = [i.address + i.size + op.mem.disp for op in i.operands
                if op.type == native.capstone.x86_const.X86_OP_MEM and op.mem.base == native.capstone.x86_const.X86_REG_RIP]
            rows.append(dict(address=i.address, bytes=i.bytes.hex(), mnemonic=i.mnemonic,
                operands=i.op_str, rip_references=refs))
        if sum(len(bytes.fromhex(r['bytes'])) for r in rows) != length or rows[-1]['mnemonic'] != 'ret':
            raise ValueError('Policy leaf boundary changed')
        leaves.append(dict(address=address, file_offset=offset, bytes=data.hex(),
            sha256=hashlib.sha256(data).hexdigest(), instructions=rows))
    default = dict(prior['cases'][0]['fixture'], selector=3, policy_byte=0, mode_byte=0,
        manager68_byte=0, manager68_present=True, manager48_present=False)
    fixtures = []
    for policy in (0, 7, 255):
        for mode in (0, 3, 255):
            for flag in (0, 1, 7, 255):
                fixtures.append(dict(default, name=f'policy-{policy}-mode-{mode}-flag-{flag}',
                    policy_byte=policy, mode_byte=mode, manager68_byte=flag))
    fixtures.extend([dict(default, name='sdk-disabled', sdk_enabled=False, mode_byte=3, manager68_byte=255),
        dict(default, name='manager-absent', manager_present=False, mode_byte=3, manager68_byte=255),
        dict(default, name='manager68-absent', manager68_present=False, mode_byte=3, manager68_byte=255),
        dict(default, name='manager48-present', manager48_present=True)])
    fixtures.extend(dict(default, name=f'constructors-poison-{v}', constructor_poison=v,
        policy_byte=v, mode_byte=0) for v in (0, 127, 255))
    ctor_fragments = native.decode_ranges(image, {image.roots[image.containing(0x145556120)]})
    cases = [Replay(raw, image, prior['fragments'] + ctor_fragments, prior['leaves'] + leaves, f, prior['globals']).capture() for f in fixtures]
    for case in cases:
        f, packet = case['fixture'], case['packet']
        expected_mode = int(f['sdk_enabled'] and f['mode_byte'] == 3)
        expected_flag = f['manager68_byte'] if f['sdk_enabled'] and f['manager_present'] and f['manager68_present'] else 0
        if (packet['bytes']['0x124'], packet['bytes']['0x130'], packet['bytes']['0x131']) != (f['policy_byte'], expected_mode, expected_flag):
            raise ValueError('Native Login policy differs from expected independent model: ' + f['name'] + ' ' +
                str((packet['bytes'], case.get('after_constructors'))))
        expected_metadata = 'collector-fixture' if f['sdk_enabled'] and f['manager_present'] and f['manager48_present'] else ''
        if packet['strings']['0xd8'] != expected_metadata: raise ValueError('Metadata gate changed')
    return dict(schema_version=1, source=prior['source'], source_sha256=prior['sha256'],
        upstream_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        base_tool_sha256=hashlib.sha256((HERE / 'replay-login-packet-fields.py').read_bytes()).hexdigest(),
        leaves=leaves, constructor_fragments=ctor_fragments, cases=cases, native_execution=True,
        limitations=['Whole Login preparation prefix and constructor; real singleton/flag leaves.',
            'Three cases execute constructors on poisoned objects; other state is explicit fixtures.',
            'Policy byte +18 is preserved by constructor; subsequent configuration writes not resolved.',
            'SDK accessors use existing fixtures; strings/collector/handoff remain bounded hooks.',
            'No game launch, network, policy backend initialization, writer or UI cleanup.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/login-policy-inputs-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
