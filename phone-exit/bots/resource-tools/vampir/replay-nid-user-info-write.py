"""Whole UserInfo writer with marked fields and captured map insertion.

SDK getters and variant/map/string backends are explicit bounded fixtures.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_writer_platform', HERE / 'replay-version-platform-context.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
WRITE = 0x144551060


class Replay(base.Replay):
    def __init__(self, raw, image, source, platform, fragments, fixture):
        super().__init__(raw, image, source, fragments, platform['members'], False)
        self.allowed = {r['address'] for f in fragments for r in f['instructions']}
        self.case = fixture
        self.info, self.target = self.allocate(0x250), self.allocate(0x80)
        self.initial = {}
        for offset in range(0, 0x250, 16):
            value = '' if fixture.get('empty') or offset in fixture.get('omit', []) else 'field-' + format(offset, '03x')
            if offset == 0x170 and fixture.get('unicode'): value = 'Ж界'
            self.string(self.info + offset, value)
            self.initial[hex(offset)] = value
        self.variants, self.pairs, self.getters = {}, [], []
        self.uc.mem_write(0x14b4f2060, b'\0')  # No diagnostic/log branch.
        hooks = (0x1444e5350, 0x1444e3ac0, 0x1444e5ff0, 0x14446eed0, 0x1444baf90,
                 0x141420f70, 0x141421150, 0x14146c5a0, 0x14143c260, 0x14446eff0)
        for page in {p & ~4095 for a in hooks for p in (a, a + 64)}:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            offset = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[offset:offset + 4096])

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x1444e5350:
            self.string(a, 'auxiliary-fixture'); result = a
        elif address in (0x1444e3ac0, 0x1444e5ff0):
            self.string(a, 'getter-' + hex(address)); result = a
            self.getters.append(hex(address))
        elif address == 0x14446eed0:
            self.variants[a] = self.text(b)
            uc.mem_write(a, bytes(32)); result = a  # Variant with no shared control block.
        elif address == 0x14446eff0:
            self.variants[a] = dict(constructor=hex(address), raw_rdx=b)
            uc.mem_write(a, bytes(32)); result = a  # Uninterpreted variant constructor capture.
        elif address == 0x1444baf90:
            if a != self.target or d != 0: raise ValueError('UserInfo map insert owner/mode changed')
            key_ptr, value_ptr = struct.unpack('<QQ', bytes(uc.mem_read(c, 16)))
            self.pairs.append(dict(key=self.text(key_ptr), value=self.variants[value_ptr]))
            uc.mem_write(b, bytes(4)); result = b
        elif address == 0x141420f70:
            self.string(a, self.literal(b, 1)); result = a
        elif address == 0x141421150:
            self.string(a, self.literal(b, 2)); result = a
        elif address == 0x14143c260:
            self.string(a, self.text(b)); result = a
        elif address == 0x14146c5a0: pass
        else: return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def capture(self):
        self.call(WRITE, self.info, self.target, self.case['mode'])
        keys = [p['key'] for p in self.pairs]
        if len(set(keys)) != len(keys): raise ValueError('Unexpected duplicate UserInfo map insertion')
        mapping = [dict(key=p['key'], offset='0x' + p['value'][6:])
                   for p in self.pairs if isinstance(p['value'], str) and p['value'].startswith('field-')]
        return dict(fixture=self.case, initial_fields=self.initial, pairs=self.pairs,
                    field_mapping=mapping, getter_captures=self.getters,
                    overwritten_fields={hex(o): self.text(self.info + o) for o in (0x50, 0x70)})


def build():
    root = native.ROOT / 'code-clues'
    source = json.loads((root / 'headless-device-identity.json').read_text('utf-8'))
    platform = json.loads((root / 'version-platform-context-replay.json').read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(WRITE)]})
    fixtures = [dict(mode=mode, **extra) for mode in (0, 1) for extra in
                ({}, dict(empty=True), dict(omit=[0xa0, 0xb0, 0x230, 0x240]), dict(unicode=True),
                 dict(omit=[0x230]), dict(omit=[0x240]))]
    cases = [Replay(raw, image, source, platform, fragments, fixture).capture() for fixture in fixtures]
    return dict(source=source['source'], source_sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-version-platform-context.py').read_bytes()).hexdigest(),
                fragments=fragments, cases=cases,
                limitations=['Whole native writer entry/return and field pointer/gates execute; marked UserInfo fields are fixtures.',
                             'SDK/system getters, map insert, variant ownership/string construction and cleanup are captured fixtures.',
                             'No sources of live UserInfo values, SDK initialization, process memory, game launch or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/nid-user-info-write-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         cases=len(report['cases']), mapping=report['cases'][6]['field_mapping'])))
