"""Native version replacement and compiled platform object -> CDN label."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('preparation_url', HERE / 'build-headless-cdn-url.py')
url = importlib.util.module_from_spec(spec)
spec.loader.exec_module(url)
REPLACE, STRING_COPY, STRING_REPLACE = 0x1445daf80, 0x1445d8e60, 0x1445de490
MEMCHR, MEMCMP, COOKIE = 0x1487a2e61, 0x1487a2e49, 0x148796040
GETTER, VALUE, INIT = 0x1445e75b0, 0x141484e40, 0x1445eae1b


class PreparationEmulator:
    def __init__(self, raw, image, fragments):
        self.raw, self.image = raw, image
        self.ping, self.x = url.settings.ping, url.settings.ping.x
        self.uc = self.ping.unicorn.Uc(self.ping.unicorn.UC_ARCH_X86, self.ping.unicorn.UC_MODE_64)
        self.scratch, self.stack, self.stop = 0x20000000, 0x20030000, 0x2003f000
        self.uc.mem_map(self.scratch, 0x80000)
        roots = {image.roots[image.containing(a)][0] for a in (REPLACE, STRING_COPY, STRING_REPLACE)}
        self.allowed = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                        for f in fragments if f['root_begin_rva'] in roots]
        self.allowed += [(INIT, 0x1445eae42), (GETTER, GETTER + 14), (VALUE, VALUE + 6),
                         (0x14563f555, 0x14563f580)]
        pages = {a & ~4095 for lo, hi in self.allowed for a in range(lo, hi + 4095, 4096)}
        pages.update(a & ~4095 for a in [url.MALLOC, url.FREE, url.COPY, url.MOVE, MEMCHR, MEMCMP, COOKIE,
                                        0x14b4f39c8, 0x149504608])
        for f in fragments:
            for row in f['instructions']:
                if any(lo <= row['address'] < hi for lo, hi in self.allowed):
                    pages.update(a & ~4095 for a in row['rip_references'])
        for page in sorted(pages):
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.uc.hook_add(self.ping.unicorn.UC_HOOK_CODE, self.hook)
        self.cursor, self.allocations, self.calls = self.scratch + 0x40000, {}, []
        self.platform_code_fixture = None

    def allocate(self, size):
        if not 0 < size <= 4096 or self.cursor + size + 32 >= self.scratch + 0x70000:
            raise ValueError('Preparation heap budget exceeded')
        pointer = self.cursor
        self.cursor += (size + 31) & ~31
        self.allocations[pointer] = size
        return pointer

    def bounded(self, pointer, length):
        if not 0 <= length <= 4096 or not self.scratch <= pointer <= self.scratch + 0x80000 - length:
            raise ValueError('Preparation memory fixture bounds exceeded')

    def hook(self, machine, address, size, user):
        override_platform = address == VALUE and self.platform_code_fixture is not None
        if any(lo <= address < hi for lo, hi in self.allowed) and not override_platform:
            return
        x = self.x
        a, b, c = [machine.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8]]
        result = machine.reg_read(x.UC_X86_REG_RAX)
        kind = None
        if override_platform:
            result, kind = self.platform_code_fixture, 'explicit_platform_return_fixture'
        elif address == url.MALLOC:
            result, kind = self.allocate(a), 'allocate'
        elif address == url.FREE:
            if a not in self.allocations:
                raise ValueError('Free outside owned preparation heap')
            del self.allocations[a]
            kind = 'free'
        elif address in (url.COPY, url.MOVE):
            self.bounded(a, c)
            self.bounded(b, c)
            if c:
                machine.mem_write(a, bytes(machine.mem_read(b, c)))
            result, kind = a, 'memmove' if address == url.MOVE else 'memcpy'
        elif address == MEMCHR:
            self.bounded(a, c)
            offset = bytes(machine.mem_read(a, c)).find(bytes([b & 255]))
            result, kind = (a + offset if offset >= 0 else 0), 'memchr'
        elif address == MEMCMP:
            self.bounded(a, c)
            self.bounded(b, c)
            left, right = bytes(machine.mem_read(a, c)), bytes(machine.mem_read(b, c))
            result = next((p - q for p, q in zip(left, right) if p != q), 0) & 0xffffffff
            kind = 'memcmp'
        elif address == COOKIE:
            kind = 'cookie_check_preserve_rax'
        else:
            raise ValueError('Unreviewed preparation target ' + hex(address))
        self.calls.append(dict(kind=kind))
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RAX, result)
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, ret)

    def put(self, address, value):
        data = value.encode('ascii')
        if len(data) > 512 or b'\0' in data:
            raise ValueError('Version fixture exceeds local budget')
        if len(data) <= 15:
            self.uc.mem_write(address, (data + b'\0').ljust(16, b'\0') + struct.pack('<QQ', len(data), 15))
        else:
            pointer = self.allocate(len(data) + 1)
            self.uc.mem_write(pointer, data + b'\0')
            self.uc.mem_write(address, struct.pack('<QQQQ', pointer, 0, len(data), len(data)))

    def text(self, address):
        length, capacity = struct.unpack('<QQ', bytes(self.uc.mem_read(address + 16, 16)))
        pointer = struct.unpack('<Q', bytes(self.uc.mem_read(address, 8)))[0] if capacity > 15 else address
        self.bounded(pointer, length + 1)
        data = bytes(self.uc.mem_read(pointer, length + 1))
        if not data.endswith(b'\0'):
            raise ValueError('Unterminated std::string fixture')
        return data[:-1].decode('ascii')

    def run(self, start, stop=None, **registers):
        x = self.x
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        for name, value in registers.items():
            self.uc.reg_write(getattr(x, 'UC_X86_REG_' + name.upper()), value)
        target = self.stop if stop is None else stop
        self.uc.emu_start(start, target, count=32768)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != target:
            raise ValueError('Preparation instruction budget exceeded')

    def version(self, value):
        base = self.scratch
        for address, text in [(base + 0x1000, value), (base + 0x1100, '.'), (base + 0x1200, '_')]:
            self.put(address, text)
        self.run(REPLACE, rcx=base + 0x2000, rdx=base + 0x1000, r8=base + 0x1100, r9=base + 0x1200)
        return dict(app_version=value, result=self.text(base + 0x2000), input_after=self.text(base + 0x1000),
                    calls=list(self.calls), acquisition_proven=False)

    def platform(self, code_fixture=None):
        if code_fixture is not None and (type(code_fixture) is not int or not 0 <= code_fixture <= 0xffffffff):
            raise ValueError('Invalid uint32 platform fixture')
        self.platform_code_fixture = code_fixture
        self.run(INIT, stop=0x1445eae42)
        self.run(GETTER)
        code = self.uc.reg_read(self.x.UC_X86_REG_EAX)
        self.run(0x14563f555, stop=0x14563f580)
        label = url.settings.utf16(self.raw, self.image, self.uc.reg_read(self.x.UC_X86_REG_RDX))
        return dict(code=code, label=label, calls=list(self.calls), compiled_initialization_only=True,
                    return_code_fixture=code_fixture)


def build():
    prior_path = url.settings.config.native.ROOT / 'code-clues/headless-cdn-url.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = url.settings.config.native.Image(raw)
    roots = {image.roots[image.containing(a)] for a in [REPLACE, STRING_COPY, STRING_REPLACE, 0x14563f080, 0x1445eadd0]}
    fragments = url.settings.config.native.decode_ranges(image, roots)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    imports_module = url.settings.load('preparation_imports', HERE / 'build-object-zero-init-code.py')
    imports = []
    for address, expected_name in [(MEMCHR, 'memchr'), (MEMCMP, 'memcmp')]:
        offset = image.offset(address - image.pe.base)
        if raw[offset:offset + 2] != b'\xff\x25':
            raise ValueError('CRT import thunk changed')
        target = address + 6 + struct.unpack_from('<i', raw, offset + 2)[0]
        imported = imports_module.import_at(raw, image, target)
        if imported['name'] != expected_name:
            raise ValueError('Unexpected preparation CRT import')
        imports.append(dict(address=address, **imported))
    if rows[0x1445eae31]['rip_references'] != [0x1495045d0]:
        raise ValueError('Platform vtable constructor changed')
    anchors = []
    for address, size in [(GETTER, 14), (VALUE, 6), (0x149504608, 8)]:
        offset = image.offset(address - image.pe.base)
        data = raw[offset:offset + size]
        anchors.append(dict(address=address, file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    literals = []
    for row in rows.values():
        for address in row['rip_references']:
            literal = url.settings.config.read_literal(raw, image, address)
            if literal:
                literals.append(dict(instruction=row['address'], **literal))
    versions = ['', '1', '.', '..', '.1.', '1.2.3', '1..2', '1_2_3', 'v.1-build.5',
                '1 2.3', 'a/b.c', 'a?b.c', 'x' * 15 + '.0', 'x' * 32, 'x.' * 100]
    cases = [PreparationEmulator(raw, image, fragments).version(value) for value in versions]
    if any(case['result'] != case['app_version'].replace('.', '_') or
           case['input_after'] != case['app_version'] for case in cases):
        raise ValueError('Native version replacement differs')
    platform = PreparationEmulator(raw, image, fragments).platform()
    if (platform['code'], platform['label']) != (2, 'window'):
        raise ValueError('Compiled platform chain differs')
    platform_cases = [PreparationEmulator(raw, image, fragments).platform(value)
                      for value in [0, 1, 2, 3, 255, 0x80000000, 0xffffffff]]
    if any(case['label'] != ('ios' if case['code'] == 1 else 'window' if case['code'] == 2 else 'android')
           for case in platform_cases):
        raise ValueError('Native platform branch differs')
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                url_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, anchors=anchors, imports=imports, literals=literals,
                version_cases=cases, platform=platform, platform_cases=platform_cases, network_ready=False,
                limitations=['Version replacement loop/copy/replace native; allocator/free/CRT search/compare/copy/cookie are bounded shims.',
                    'Explicit printable ASCII AppVersion fixtures; UTF16 conversion and actual source version remain unproven.',
                    'Compiled platform object initialization/getter/label branch executed, not a live process.',
                    'Seven other platform branch cases use explicit return-value fixtures, not other platform binaries.',
                    'Actual base URLs/prefix/config acquisition/HTTP callback order remain unproven.'])


if __name__ == '__main__':
    report = build()
    target = url.settings.config.native.ROOT / 'code-clues/headless-cdn-preparation.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          version_cases=len(report['version_cases']), platform=report['platform']), indent=2))
