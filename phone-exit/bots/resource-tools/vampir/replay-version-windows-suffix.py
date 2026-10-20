"""Execute the whole Windows suffix getter with explicit OS/TLS/CRT fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('suffix_base', HERE / 'replay-device-key-lifecycle.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.guid.source.config.native, base.x
GETTER = 0x1415c3960


class Replay(base.Replay):
    def __init__(self, raw, image, source, fragments, fixture):
        super().__init__(raw, image, source, {})
        self.suffix_fixture = fixture
        self.rows = {r['address']: r for f in fragments for r in f['instructions']}
        self.allowed.update(self.rows)
        hooks = (0x14879656c, 0x148796500, 0x1487a2e25, 0x141458e60, 0x141421150)
        pages = {p & ~4095 for r in self.rows.values() for p in (r['address'], *r['rip_references'])}
        pages.update(a & ~4095 for a in hooks)
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: offset = image.offset(page - image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.gs = 0x30000000
        self.uc.mem_map(self.gs, 0x110000)
        self.uc.reg_write(x.UC_X86_REG_GS_BASE, self.gs)
        self.uc.mem_write(self.gs + 0x58, struct.pack('<Q', self.gs + 0x1000))
        self.uc.mem_write(self.gs + 0x1000, struct.pack('<Q', self.gs + 0x2000))
        tls_index = self.rows[0x1415c3987]['rip_references'][0]
        self.uc.mem_write(tls_index, struct.pack('<I', 0))
        self.uc.mem_write(0x14b2cda00, struct.pack('<i', 1))
        self.uc.mem_write(self.gs + 0x2000 + 0x101184, struct.pack('<i', 1 if fixture.get('cached') else 0))
        self.uc.mem_write(0x14b2cd900, (fixture.get('cached', '') + '\0').encode('utf-16le'))
        for instruction, stub in ((0x1415c39f4, self.base + 0x7200), (0x1415c3a22, self.base + 0x7300)):
            slot = self.rows[instruction]['rip_references'][0]
            self.uc.mem_write(slot, struct.pack('<Q', stub))

    def wide(self, pointer, bound=128):
        data = bytearray()
        for i in range(bound):
            value = bytes(self.uc.mem_read(pointer + i * 2, 2))
            if value == b'\0\0': return data.decode('utf-16le')
            data.extend(value)
        raise ValueError('Windows suffix string bound')

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        a, b, c, d = [uc.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        result = 0
        fixture = self.suffix_fixture
        if address == 0x14879656c:
            if a != 0x14b2cda00: raise ValueError('TLS guard destination changed')
            uc.mem_write(a, struct.pack('<i', -1))
            self.events.append(dict(action='tls_init_header_fixture'))
        elif address == 0x148796500:
            if a != 0x14b2cda00: raise ValueError('TLS footer destination changed')
            uc.mem_write(a, struct.pack('<i', 2))
            uc.mem_write(self.gs + 0x2000 + 0x101184, struct.pack('<i', 2))
            self.events.append(dict(action='tls_init_footer_fixture'))
        elif address == self.base + 0x7200:
            uc.mem_write(a, bytes(48))
            self.events.append(dict(action='GetNativeSystemInfo_fixture'))
        elif address == self.base + 0x7300:
            if int.from_bytes(uc.mem_read(a, 4), 'little') != 0x11c: raise ValueError('OSVERSIONINFOEX size changed')
            major, minor, build, product, suite_mask = fixture['version']
            uc.mem_write(a + 4, struct.pack('<III', major, minor, build))
            uc.mem_write(a + 0x114, struct.pack('<HH', 0x1234, 0x5678))  # Distinct service pack sentinels.
            uc.mem_write(a + 0x118, struct.pack('<HBB', suite_mask, product, 0))
            result = int(fixture.get('version_ok', True))
            self.events.append(dict(action='GetVersionExW_fixture', returned=result))
        elif address == 0x1487a2e25:
            if b != 0 or c != 0x118: raise ValueError('OS structure memset changed')
            uc.mem_write(a, bytes(c))
            result = a
        elif address == 0x141458e60:
            if a != 0x14b2cd900 or b != 0x80 or self.wide(c) != '%d.%d.%d.%d.%d.%s':
                raise ValueError('Windows suffix format changed')
            values = [d & 0xffffffff] + [int.from_bytes(uc.mem_read(stack + offset, 4), 'little') for offset in (0x28, 0x30, 0x38, 0x40)]
            pointer = int.from_bytes(uc.mem_read(stack + 0x48, 8), 'little')
            label = self.wide(pointer)
            signed = lambda value: value if value < 0x80000000 else value - 0x100000000
            text = '.'.join(str(signed(value)) for value in values) + '.' + label
            if len(text) >= b: raise ValueError('Suffix formatting fixture overflow')
            uc.mem_write(a, (text + '\0').encode('utf-16le'))
            result = len(text)
            self.events.append(dict(action='format_fixture', values=values, label=label))
        elif address == 0x141421150:
            self.string(a, self.wide(b))
            result = a
        elif address == 0x148796040:
            result = uc.reg_read(x.UC_X86_REG_RAX)  # Cookie check preserves the return value.
        else:
            return super().hook(uc, address, size, user)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def suffix(self):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.output)
        self.uc.emu_start(GETTER, self.stop, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop: raise ValueError('Suffix instruction budget')
        if self.uc.reg_read(x.UC_X86_REG_RAX) != self.output: raise ValueError('Suffix descriptor return changed')
        return self.text(self.output)


def build():
    source_path = native.ROOT / 'code-clues/headless-device-identity.json'
    source = json.loads(source_path.read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(GETTER)]})
    fixtures = [dict(version=[10, 0, 19045, 1, 0]), dict(version=[10, 0, 26100, 3, 2]),
        dict(version=[6, 2, 9200, 1, 0]), dict(version=[0, 0, 0, 0, 0]),
        dict(version=[0xffffffff, 0x80000000, 0x7fffffff, 255, 65535]),
        dict(version=[10, 0, 26100, 1, 0], version_ok=False),
        dict(version=[0, 0, 0, 0, 0], cached='cached-suffix-fixture')]
    cases = []
    for fixture in fixtures:
        em = Replay(raw, image, source, fragments, fixture)
        output = em.suffix()
        major, minor, build_number, product, suite_mask = fixture['version']
        signed = lambda value: value if value < 0x80000000 else value - 0x100000000
        expected = fixture.get('cached', f'{signed(major)}.{signed(minor)}.{signed(build_number)}.{product}.{suite_mask}.64bit' if fixture.get('version_ok', True) else '')
        if output != expected: raise ValueError('Windows suffix output differs: ' + repr(output))
        first_events = em.events.copy()
        repeated = em.suffix()
        if repeated != output or em.events != first_events: raise ValueError('Windows suffix cache changed')
        cases.append(dict(fixture=fixture, output=output, repeated=repeated, events=first_events))
    return dict(source=source['source'], source_sha256=source['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE / 'replay-device-key-lifecycle.py').read_bytes()).hexdigest(),
        fragments=fragments, cases=cases, limitations=[
            'Full native getter; OSVERSIONINFOEX and TLS guard are isolated fixtures.',
            'Formatting, memset, FString constructor and cookie are bounded hooks.',
            'No actual OS query, Windows manifest compatibility, thread racing or runtime profile.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/version-windows-suffix-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
