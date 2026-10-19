"""Native SDK version/BuildCode getters with explicit constructor/copy shims."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bootstrap_settings', HERE / 'build-headless-sdk-settings.py')
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)
native = settings.config.native
VERSION, BUILD = 0x144524390, 0x14452b820
INITIALIZERS = (0x1411b3220, 0x1411b3250, 0x1411b3280)
GLOBALS = (0x14b4f1658, 0x14b4f1668, 0x14b4f1678)


class Emulator:
    def __init__(self, raw, image, fragments):
        ping = settings.ping
        self.x, self.raw, self.image = ping.x, raw, image
        self.uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
        self.scratch, self.stack, self.stop = 0x20000000, 0x20030000, 0x2003f000
        self.uc.mem_map(self.scratch, 0x40000)
        self.allowed = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                        for f in fragments if f['root_begin_rva'] in {a - image.pe.base for a in (VERSION, BUILD, *INITIALIZERS)}]
        pages = {a & ~4095 for lo, hi in self.allowed for a in range(lo, hi + 4095, 4096)}
        pages.update(a & ~4095 for a in (settings.STRING, 0x1414313d0, 0x1487a2e19, 0x1487964ac, *GLOBALS))
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
        self.cursor, self.events = self.scratch + 0x10000, []
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)

    def allocate(self, count):
        if not 1 <= count <= 256 or self.cursor + 512 >= self.scratch + 0x20000:
            raise ValueError('Bootstrap fixture allocation budget exceeded')
        pointer = self.cursor
        self.cursor += 512
        return pointer

    def hook(self, machine, address, size, user):
        if any(lo <= address < hi for lo, hi in self.allowed):
            return
        x = self.x
        a, b, c = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == settings.STRING:
            text = settings.utf16(self.raw, self.image, b)
            payload = (text + '\0').encode('utf-16le')
            pointer = self.allocate(len(payload))
            machine.mem_write(pointer, payload)
            machine.mem_write(a, struct.pack('<QII', pointer, len(payload) // 2, len(payload) // 2))
            machine.reg_write(x.UC_X86_REG_RAX, a)
            self.events.append(dict(kind='FString_constructor_shim', value=text))
        elif address == 0x1414313d0:
            if a != self.scratch + 0x1000 or not 1 <= b <= 128:
                raise ValueError('Unexpected getter allocation')
            pointer = self.allocate(b * 2)
            machine.mem_write(a, struct.pack('<Q', pointer))
            machine.mem_write(a + 12, struct.pack('<I', b))
            self.events.append(dict(kind='FString_allocation_shim', units=b))
        elif address == 0x1487a2e19:
            if not 0 < c <= 256 or not all(self.scratch <= p < self.scratch + 0x40000 - c for p in (a, b)):
                raise ValueError('Getter copy exceeds fixture bounds')
            machine.mem_write(a, bytes(machine.mem_read(b, c)))
            machine.reg_write(x.UC_X86_REG_RAX, a)
            self.events.append(dict(kind='bounded_copy_shim', bytes=c))
        elif address == 0x1487964ac:
            self.events.append(dict(kind='atexit_registration_capture'))
        else:
            raise ValueError('Unreviewed bootstrap target ' + hex(address))
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, ret)

    def run(self, address, **registers):
        x = self.x
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        for name, value in registers.items():
            self.uc.reg_write(getattr(x, 'UC_X86_REG_' + name.upper()), value)
        self.uc.emu_start(address, self.stop, count=1024)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('Bootstrap instruction budget exceeded')

    def text(self, address):
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(address, 16)))
        if not 1 <= count <= capacity <= 128 or not self.scratch <= pointer < self.scratch + 0x40000 - count * 2:
            raise ValueError('Invalid bootstrap FString fixture')
        payload = bytes(self.uc.mem_read(pointer, count * 2))
        if not payload.endswith(b'\0\0'):
            raise ValueError('Unterminated bootstrap FString')
        return payload[:-2].decode('utf-16le')


def replay(raw, image, fragments):
    emu = Emulator(raw, image, fragments)
    for address in INITIALIZERS:
        emu.run(address)
    defaults = [dict(address=a, value=emu.text(a)) for a in GLOBALS]
    cases = []
    for code in range(256):
        # Reuse immutable initialized source strings; reclaim only getter outputs.
        emu.cursor = emu.scratch + 0x12000
        emu.events = []
        destination = emu.scratch + 0x1000
        emu.uc.mem_write(destination - 8, b'\xaa' * 32)
        emu.run(BUILD, rcx=destination, rdx=code)
        if bytes(emu.uc.mem_read(destination - 8, 8)) != b'\xaa' * 8 or bytes(emu.uc.mem_read(destination + 16, 8)) != b'\xaa' * 8:
            raise ValueError('Build getter crossed output bounds')
        cases.append(dict(build_code=code, value=emu.text(destination), guards_unchanged=True,
                          calls=list(emu.events)))
    emu.events = []
    emu.run(VERSION, rcx=emu.scratch + 0x1000)
    return dict(initialized_globals=defaults, cases=cases,
                sdk_version=emu.text(emu.scratch + 0x1000), version_calls=emu.events)


def build():
    prior_path = native.ROOT / 'code-clues/headless-sdk-config.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('SDK bootstrap source changed')
    image = native.Image(raw)
    roots = {image.roots[image.containing(a)] for a in (VERSION, BUILD, *INITIALIZERS, 0x1444f3bb3, 0x1444f5675)}
    fragments = native.decode_ranges(image, roots)
    literals = []
    for f in fragments:
        for row in f['instructions']:
            if row['address'] in (0x144524396, 0x1411b3224, 0x1411b3254, 0x1411b3284):
                literals.append(dict(instruction=row['address'], **settings.config.read_literal(raw, image, row['rip_references'][0])))
    values = replay(raw, image, fragments)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=fragments,
        literals=literals, replay=values, network_ready=False, active_build_code_verified=False,
        limitations=['Native compiled initializers/getters executed; FString construction/allocation/copy and atexit are explicit shims.',
            'All byte inputs tested; default initializer globals only, late writes not excluded.',
            'RefreshSDKConstants/RequestGMC2 callers are static evidence; full URL builder/HTTP not executed.',
            'BuildCode is not game AppVersion or SDKZone; active settings and response decoding remain unresolved.'])


if __name__ == '__main__':
    report = build()
    target = native.ROOT / 'code-clues/headless-sdk-bootstrap-values.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                         cases=len(report['replay']['cases']), sdk_version=report['replay']['sdk_version']), indent=2))
