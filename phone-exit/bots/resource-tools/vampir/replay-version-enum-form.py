"""Execute real enum object ctor -> SetMembers prefix -> Version lookup.

Package/object discovery and the setter's post-store registration are excluded.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('enum_form_base', HERE / 'replay-version-platform-context.py')
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)
native, x = platform.native, platform.x
CTOR, SETTER, TABLE = 0x1416bf350, 0x1417202f0, 0x1489e4b80


class Replay(platform.Replay):
    def __init__(self, raw, image, source, fragments, members):
        super().__init__(raw, image, source, fragments, members, False)
        self.input = self.base + 0xa000
        self.uc.mem_write(self.input, struct.pack('<QII', self.base + 0x9000, len(members), len(members)))
        for address in (0x1417c5f20, 0x1414314e0, 0x1487a2e19):
            page = address & ~4095
            if not any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                self.uc.mem_map(page, 4096)
            self.uc.mem_write(address, b'\xc3')  # Bounded translated block for a captured external call.

    def hook(self, uc, address, size, user):
        if address not in (0x1417c5f20, 0x1414314e0):
            return super().hook(uc, address, size, user)
        if address == 0x1414314e0:
            a, b = uc.reg_read(x.UC_X86_REG_RCX), uc.reg_read(x.UC_X86_REG_RDX)
            if a != self.enum + 0x40 or b > 32: raise ValueError('Enum array resize receiver/bound changed')
            count = int.from_bytes(uc.mem_read(a + 8, 4), 'little')
            uc.mem_write(a, struct.pack('<QII', self.allocate(max(16, b * 16)), count, b))
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, 0)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def setter_prefix(self, end, form, flags, descriptor):
        # Execute the factory's actual argument loads and virtual dispatch.
        descriptor_copy = bytearray(descriptor)
        descriptor_copy[0x2f], descriptor_copy[0x2e] = form, flags
        self.uc.mem_write(self.base + 0xb000, bytes(descriptor_copy))
        self.uc.mem_write(self.stack + 0x40, bytes(self.uc.mem_read(self.input, 16)))
        for reg, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RCX, self.enum),
                (x.UC_X86_REG_R13, self.enum), (x.UC_X86_REG_R12, self.base + 0xb000)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(0x1417cc4c2, end, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != end: raise ValueError('Enum setter prefix budget')


def build():
    baseline = native.ROOT / 'code-clues/version-platform-context-replay.json'
    if hashlib.sha256(baseline.read_bytes()).hexdigest() != '6ebea4f461c443fd7d73681d5c0b5b801e9d71b81d00a12df3a9df92436423fe':
        raise ValueError('Platform descriptor baseline changed')
    source = json.loads(baseline.read_text('utf-8'))
    base_source = json.loads((native.ROOT / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    if base_source['sha256'] != source['source_sha256']: raise ValueError('Replay base source differs')
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['source_sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    slot_offset = image.offset(TABLE + 0x2f8 - image.pe.base)
    slot = raw[slot_offset:slot_offset + 8]
    if struct.unpack('<Q', slot)[0] != SETTER: raise ValueError('Enum virtual slot changed')
    addresses = (CTOR, SETTER, platform.SELECTOR, platform.PLATFORM, platform.LOOKUP, platform.VALUE, 0x1417cc270)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for address, mnemonic, operand in ((0x1417cc4cb, 'movzx', 'r9d, byte ptr [r12 + 0x2e]'),
            (0x1417cc4d4, 'movzx', 'r8d, byte ptr [r12 + 0x2f]'),
            (0x1417cc4df, 'call', 'qword ptr [rax + 0x2f8]')):
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operand):
            raise ValueError('Enum factory argument/virtual-dispatch binding changed')
    store = next(r for r in rows.values() if r['address'] >= SETTER and r['address'] < SETTER + 0x100 and
        r['mnemonic'] == 'mov' and r['operands'].startswith('byte ptr [rdi + 0x51],'))
    end = store['address'] + len(bytes.fromhex(store['bytes']))
    descriptor_offset = source['record']['file_offset']
    descriptor = raw[descriptor_offset:descriptor_offset + 48]
    if descriptor.hex() != source['record']['bytes']: raise ValueError('Enum descriptor bytes changed')
    source_form, source_flags = descriptor[0x2f], descriptor[0x2e]
    cases = []
    for form, flags in ((source_form, source_flags), (0, 0), (1, 0), (2, 1)):
        em = Replay(raw, image, base_source, fragments, source['members'])
        em.call(CTOR, em.enum)
        if int.from_bytes(em.uc.mem_read(em.enum, 8), 'little') != TABLE: raise ValueError('Enum ctor table changed')
        if bytes(em.uc.mem_read(em.enum + 0x50, 1)) != b'\0': raise ValueError('Enum ctor default form changed')
        em.setter_prefix(end, form, flags, descriptor)
        actual_form, actual_flags = bytes(em.uc.mem_read(em.enum + 0x50, 2))
        if (actual_form, actual_flags) != (form, flags): raise ValueError('Enum setter argument mapping changed')
        selector = em.call(platform.SELECTOR)
        em.call(platform.LOOKUP, em.enum, em.output, selector)
        output = em.text(em.output)
        if output != ('Windows' if form else 'ENnOsType::Windows'): raise ValueError('Source enum platform label changed')
        cases.append(dict(form=form, flags=flags, source_descriptor_case=form == source_form and flags == source_flags,
            output=output, selector=selector, object_form=actual_form, object_flags=actual_flags))
    return dict(source=source['source'], source_sha256=source['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE / 'replay-version-platform-context.py').read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(baseline.read_bytes()).hexdigest(),
        vtable_slot=dict(table=hex(TABLE), offset='0x2f8', file_offset=slot_offset, bytes=slot.hex()),
        descriptor=source['record'], factory_prefix_start='0x1417cc4c2', setter_prefix_end=hex(end), fragments=fragments, cases=cases,
        limitations=['Actual ctor, factory argument loads/virtual dispatch, setter prefix through form/flags stores, selector and lookup/value.',
            'Base object ctor, array allocation/copy, name pool/string helpers are fixtures.',
            'No full reflection construction, optional max-member append or post-setter registration.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/version-enum-form-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
