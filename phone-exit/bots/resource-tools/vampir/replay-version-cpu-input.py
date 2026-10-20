"""Execute the complete reviewed CPU-buffer initializer and both Version getters.

CPUID is a synthetic instruction fixture; ASCII FString construction, CPU feature
predicate and security cookie are bounded hooks. No host fingerprint is read.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cpu_device_base', HERE / 'replay-device-key-lifecycle.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.guid.source.config.native, base.x
INITIALIZE, FIRST, SECOND = 0x140ff54a0, 0x1415c1460, 0x1415c1440


class Replay(base.Replay):
    def __init__(self, raw, image, source, fragments, fixture):
        super().__init__(raw, image, source, {})
        self.cpu_fixture = fixture
        self.rows = {r['address']: r for f in fragments for r in f['instructions']}
        self.allowed.update(self.rows)
        pages = {p & ~4095 for row in self.rows.values() for p in (row['address'], *row['rip_references'])}
        pages.add(0x1415bd9b0 & ~4095)
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: offset = image.offset(page - image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.uc.mem_write(0x14b058cb0, bytes((int(fixture['enabled']),)))
        self.uc.mem_write(0x14b058cb2, b'previous\0'.ljust(13, b'\0'))
        self.uc.mem_write(0x14b058cbf, b'previous-brand\0'.ljust(64, b'\0'))

    def ascii(self, pointer, bound=128):
        data = bytearray()
        for i in range(bound):
            value = bytes(self.uc.mem_read(pointer + i, 1))
            if value == b'\0': return data.decode('ascii')
            data.extend(value)
        raise ValueError('CPU string fixture bound')

    def hook(self, uc, address, size, user):
        row = self.rows.get(address)
        if row and row['mnemonic'] == 'cpuid':
            leaf = uc.reg_read(x.UC_X86_REG_EAX)
            if uc.reg_read(x.UC_X86_REG_ECX) != 0: raise ValueError('Unexpected CPUID subleaf')
            fixture = self.cpu_fixture
            if leaf == 0:
                vendor = fixture['vendor'].encode('ascii')
                if len(vendor) != 12: raise ValueError('CPUID vendor fixture length')
                ebx, edx, ecx = struct.unpack('<III', vendor)
                values = (1, ebx, ecx, edx)
            elif leaf == 0x80000000: values = (fixture['max_extended'], 0, 0, 0)
            elif 0x80000002 <= leaf <= 0x80000004:
                brand = fixture['brand'].encode('ascii').ljust(48, b'\0')
                if len(brand) != 48: raise ValueError('CPUID brand fixture length')
                offset = (leaf - 0x80000002) * 16
                values = struct.unpack('<IIII', brand[offset:offset + 16])
            elif leaf in (1, 0x80000006): values = (0, 0, 0, 0)
            else: raise ValueError('Unexpected CPUID leaf')
            self.events.append(dict(action='cpuid_fixture', leaf=hex(leaf)))
            for reg, value in zip((x.UC_X86_REG_EAX, x.UC_X86_REG_EBX, x.UC_X86_REG_ECX, x.UC_X86_REG_EDX), values):
                uc.reg_write(reg, value)
            uc.reg_write(x.UC_X86_REG_RIP, address + size)
            return
        if address in (0x141420f70, 0x1415bd9b0):
            result = 0
            if address == 0x141420f70:
                output, pointer = (uc.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX))
                self.string(output, self.ascii(pointer))
                result = output
            else: self.events.append(dict(action='cpu_feature_predicate_fixture'))
            uc.reg_write(x.UC_X86_REG_RAX, result)
            stack = uc.reg_read(x.UC_X86_REG_RSP)
            uc.reg_write(x.UC_X86_REG_RIP, struct.unpack('<Q', bytes(uc.mem_read(stack, 8)))[0])
            uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
            return
        super().hook(uc, address, size, user)

    def call(self, address):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.output)
        self.uc.emu_start(address, self.stop, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop: raise ValueError('CPU replay instruction budget')


def build():
    path = native.ROOT / 'code-clues/headless-device-identity.json'
    source = json.loads(path.read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (INITIALIZE, FIRST, SECOND)})
    fixtures = [dict(enabled=True, vendor='GenuineIntel', brand='Fixture CPU Brand', max_extended=0x80000004),
        dict(enabled=True, vendor='AuthenticAMD', brand='  Fixture padded CPU  ', max_extended=0x80000004),
        dict(enabled=True, vendor='GenuineIntel', brand='', max_extended=0x80000001),
        dict(enabled=False, vendor='GenuineIntel', brand='Unused fixture', max_extended=0x80000004)]
    cases = []
    for fixture in fixtures:
        em = Replay(raw, image, source, fragments, fixture)
        em.call(INITIALIZE)
        expected = (fixture['vendor'], fixture['brand'] if fixture['max_extended'] >= 0x80000004 else '') if fixture['enabled'] else ('previous', 'previous-brand')
        actual = (em.ascii(0x14b058cb2), em.ascii(0x14b058cbf))
        if actual != expected: raise ValueError('CPU buffer mapping differs')
        outputs = []
        for getter in (FIRST, SECOND):
            em.call(getter)
            if em.uc.reg_read(x.UC_X86_REG_RAX) != em.output: raise ValueError('CPU getter return differs')
            outputs.append(em.text(em.output))
        if tuple(outputs) != expected: raise ValueError('CPU getter text differs')
        cases.append(dict(fixture=fixture, getter_outputs=outputs, events=em.events))
    return dict(source=source['source'], source_sha256=source['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE / 'replay-device-key-lifecycle.py').read_bytes()).hexdigest(),
        fragments=fragments, cases=cases,
        limitations=['Synthetic CPUID, FString constructor, feature predicate and cookie hooks.',
            'Formatting/trim, initialization caller ordering and actual host CPUID are not executed.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/version-cpu-input-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
