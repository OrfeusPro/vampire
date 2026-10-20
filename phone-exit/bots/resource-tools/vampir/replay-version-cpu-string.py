"""Full CPU initializer -> getters -> native trimming -> Version text formatter.

CPUID/CRT/allocator fixtures are isolated; all game getter/trim branches run.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cpu_text_base', HERE / 'replay-version-cpu-input.py')
cpu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpu)
base, native, x = cpu.base, cpu.native, cpu.x
GETTER = 0x1414476a0


class Replay(cpu.Replay):
    def __init__(self, raw, image, source, fragments, fixture):
        super().__init__(raw, image, source, fragments, fixture)
        self.format_calls = []
        hooks = (0x141421150, 0x14142d840, 0x1487a2e1f, 0x141432130, 0x141428640, 0x14142f610)
        for page in {address & ~4095 for address in hooks}:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
        self.space_hook = self.base + 0x7400
        self.space_calls = 0
        trim_roots = {0x14342b0, 0x1434530}
        for fragment in fragments:
            if fragment['root_begin_rva'] not in trim_roots: continue
            for row in fragment['instructions']:
                if row['mnemonic'] == 'call' and row['direct_target'] is None and row['rip_references']:
                    self.uc.mem_write(row['rip_references'][0], struct.pack('<Q', self.space_hook))

    def wide(self, pointer):
        data = bytearray()
        for i in range(256):
            value = bytes(self.uc.mem_read(pointer + i * 2, 2))
            if value == b'\0\0': return data.decode('utf-16le')
            data.extend(value)
        raise ValueError('CPU formatter literal bound')

    def hook(self, uc, address, size, user):
        if address not in (0x141421150, 0x14142d840, 0x1487a2e1f, 0x141432130,
                0x141428640, 0x14142f610, self.space_hook):
            return super().hook(uc, address, size, user)
        a, b, c, d = [uc.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        result = 0
        if address == 0x141421150:
            self.string(a, self.wide(b)); result = a
        elif address == 0x14142d840:
            fmt = self.wide(b)
            if fmt not in ('%s|%s', '%s|%s|%s'): raise ValueError('CPU formatter pattern changed')
            values = [self.wide(c), self.wide(d)]
            if fmt == '%s|%s|%s':
                pointer = int.from_bytes(uc.mem_read(stack + 0x28, 8), 'little')
                values.append(self.wide(pointer))
            self.string(a, '|'.join(values)); result = a
            self.format_calls.append(dict(format=fmt, arguments=values))
        elif address == self.space_hook:
            self.space_calls += 1
            # Explicit ASCII CRT classification fixture; no Unicode/locale claim.
            result = int(a & 0xffff in (9, 10, 11, 12, 13, 32))
        elif address == 0x1487a2e1f:
            if not 0 <= c <= 8192: raise ValueError('CPU memmove fixture bound')
            uc.mem_write(a, bytes(uc.mem_read(b, c))); result = a
        elif address == 0x141432130:
            pass  # Capacity shrink fixture: native count/NUL edits already occurred.
        elif address == 0x141428640:
            result = self.text(a).find(self.wide(b)) & 0xffffffff
        elif address == 0x14142f610:
            old = self.wide(c)
            new = self.wide(d)
            self.string(b, self.text(a).replace(old, new)); result = b
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)


def build():
    source_path = native.ROOT / 'code-clues/headless-device-identity.json'
    source = json.loads(source_path.read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    roots = (cpu.INITIALIZE, cpu.FIRST, cpu.SECOND, GETTER, 0x1414344c0, 0x1414342b0, 0x141434530)
    fragments = native.decode_ranges(image, {image.roots[image.containing(address)] for address in roots})
    fixtures = [dict(vendor='GenuineIntel', brand='Fixture CPU Brand'),
        dict(vendor='AuthenticAMD', brand='  Fixture padded CPU  '),
        dict(vendor='GenuineIntel', brand='\t\r\nFixture spaced CPU\t\r\n'),
        dict(vendor='GenuineIntel', brand=' \t\r\n'),
        dict(vendor='GenuineIntel', brand=''),
        dict(vendor='GenuineIntel', brand='Unknown'),
        dict(vendor='GenuineIntel', brand='Fixture|CPU|Brand'),
        dict(vendor='GenuineIntel', brand='Not queried', max_extended=0x80000001),
        dict(vendor='GenuineIntel', brand='Not queried', enabled=False)]
    cases = []
    for options in fixtures:
        fixture = dict(enabled=True, max_extended=0x80000004)
        fixture.update(options)
        em = Replay(raw, image, source, fragments, fixture)
        em.call(cpu.INITIALIZE)
        vendor, brand = (fixture['vendor'], fixture['brand'] if fixture['max_extended'] >= 0x80000004 else '') if fixture['enabled'] else ('previous', 'previous-brand')
        em.call(GETTER)
        output = em.text(em.output)
        expected = vendor.strip(' \t\r\n\v\f') + '|' + brand.strip(' \t\r\n\v\f')
        if output != expected: raise ValueError('CPU formatted output differs: ' + repr(output))
        if len(em.format_calls) != 1 or em.format_calls[0]['format'] != '%s|%s': raise ValueError('Unexpected CPU formatter branch')
        cases.append(dict(fixture=fixture, output=output, format_calls=em.format_calls, space_calls=em.space_calls))
    return dict(source=source['source'], source_sha256=source['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE / 'replay-version-cpu-input.py').read_bytes()).hexdigest(),
        fragments=fragments, cases=cases, limitations=[
            'CPUID, ASCII iswspace, FString constructor/allocation, memmove, capacity shrink and printf are fixtures.',
            'Full actual initializer/getters/trim/move/format branch; not host CPUID or general CRT Unicode behavior.',
            'Compiled third input is Unknown; alternate third-input branches are not claimed as exercised.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/version-cpu-string-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
