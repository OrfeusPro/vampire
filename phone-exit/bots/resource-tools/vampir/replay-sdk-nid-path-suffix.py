"""Native NID path byte transform/AES/hex on synthetic sub and NM device key."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_suffix_lifecycle', HERE / 'replay-device-key-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
native, x = lifecycle.guid.source.config.native, lifecycle.x
BEGIN, END = 0x14454cb97, 0x14454cc9c
AES = 0x14151ecc0


class Replay(lifecycle.Replay):
    def __init__(self, raw, image, base_report, fragments, wrapper, fixture):
        super().__init__(raw, image, base_report, {})
        self.input_fixture = fixture
        rows = [r for f in fragments for r in f['instructions']
                if f['root_begin_rva'] in (AES - image.pe.base, 0x1429460)
                or BEGIN <= r['address'] < END]
        self.allowed.update(r['address'] for r in rows)
        self.allowed.update(i['address'] for i in wrapper['instructions'])
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (0x141525480, 0x14b051830, 0x141431680,
                                        0x141435320, 0x14142d840, 0x141432550, 0x141424430))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.uc.mem_write(0x14b051830, struct.pack('<Q', AES))  # Explicit AES-NI dispatch fixture.
        self.string(0x14b4f1ee0, 'old-suffix-fixture')
        self.string(self.stack + 0x60, fixture['sub'])
        self.string(self.stack + 0x50, fixture['nm_key'])
        self.empty = self.allocate(2)
        self.uc.mem_write(self.empty, b'\0\0')
        self.buffer = None
        self.before = None

    def hook(self, uc, address, size, user):
        if address == 0x141525480:
            a, b = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
            self.before = bytes(uc.mem_read(a, b)).hex()
        if address in self.allowed:
            return
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if address == 0x141431680:
            count = struct.unpack('<I', bytes(uc.mem_read(a + 8, 4)))[0]
            if not 0 < count <= 1024:
                raise ValueError('NID suffix byte allocation fixture bound')
            self.buffer = self.allocate(count + 32)
            uc.mem_write(a, struct.pack('<QII', self.buffer, count, count + 32))
        elif address == 0x141435320:
            # Explicit wide-to-ANSI fixture for known ASCII device-key inputs.
            data = (self.input_fixture['nm_key'] + '\0').encode('ascii')
            key = self.allocate(len(data))
            uc.mem_write(key, data)
            uc.mem_write(a + 0x80, struct.pack('<Q', 0))
            uc.mem_write(a + 0x88, struct.pack('<Q', key))
            result = a
        elif address == 0x141432550:
            old, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(a, 16)))
            new = self.allocate((b + 1) * 2)
            if old and capacity:
                uc.mem_write(new, bytes(uc.mem_read(old, min(capacity, b + 1) * 2)))
            uc.mem_write(a, struct.pack('<QII', new, count, b + 1))
        elif address == 0x14142d840:
            literal = bytes(uc.mem_read(b, 10)).decode('utf-16le').rstrip('\0')
            if literal != '%02X' or c > 255:
                raise ValueError('NID suffix byte formatter fixture contract changed')
            self.string(a, format(c, '02X'))
            result = a
        elif address == 0x141424430:
            value = bytes(uc.mem_read(b, c * 2)).decode('utf-16le')
            self.string(a, self.text(a) + value)
            result = a
        else:
            return super().hook(uc, address, size, user)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture(self):
        for register, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RBP, self.stack + 0x100),
                                (x.UC_X86_REG_R14, 0), (x.UC_X86_REG_RSI, self.empty)):
            self.uc.reg_write(register, value)
        # Short inputs jump past the suffix construction; stop there without logs/cleanup.
        uc = self.uc
        def stop_on_reject(uc, address, size, user):
            if address == 0x14454cd24:
                uc.emu_stop()
        # Fetch requires the destination page mapped, even when stopped by code hook.
        uc.hook_add(lifecycle.unicorn.UC_HOOK_CODE, stop_on_reject)
        self.allowed.add(0x14454cd24)
        uc.emu_start(BEGIN, END, count=20000)
        rip = uc.reg_read(x.UC_X86_REG_RIP)
        if rip not in (END, 0x14454cd24):
            raise ValueError('NID suffix instruction budget exceeded at ' + hex(rip))
        return dict(fixture=self.input_fixture, transformed_hex=self.before,
                    suffix=self.text(0x14b4f1ee0), replaced=rip == END)


def build():
    root = native.ROOT
    path = root / 'code-clues/sdk-storage-auth-path-replay.json'
    prior = json.loads(path.read_text('utf-8'))
    base_report = json.loads((root / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('NID suffix EXE changed')
    image = native.Image(raw)
    fragments = [f for f in prior['fragments'] if f['root_begin_rva'] == 0x454c7a0]
    fragments += native.decode_ranges(image, {image.roots[image.containing(a)] for a in
                                             (AES, 0x14150a520, 0x141429460, 0x141435320, 0x1411b31f0)})
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    offset = image.offset(0x141525480 - image.pe.base)
    data = raw[offset:offset + 0x13]
    instructions = list(cs.disasm(data, 0x141525480))
    if sum(i.size for i in instructions) != len(data) or instructions[-1].mnemonic != 'jmp':
        raise ValueError('NID suffix dispatch wrapper boundary changed')
    wrapper = dict(address=0x141525480, file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(),
                   instructions=[dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str) for i in instructions])
    literals = []
    for fragment in fragments:
        for row in fragment['instructions']:
            if row['mnemonic'] == 'lea':
                for ref in row['rip_references']:
                    if lit := lifecycle.guid.source.config.read_literal(raw, image, ref):
                        literals.append(dict(instruction=row['address'], **lit))
    fixtures = [dict(sub='B' * n, nm_key='0123456789ABCDEFFEDCBA9876543210') for n in (0, 31, 32, 48, 64)]
    fixtures.append(dict(sub='C' * 32, nm_key='FEDCBA98765432100123456789ABCDEF'))
    cases = [Replay(raw, image, base_report, fragments, wrapper, f).capture() for f in fixtures]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                source_report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=fragments, literals=literals, wrapper=wrapper, cases=cases,
                native_execution=True, user_storage_read=False,
                limitations=[
                    'Native caller byte transform, AES-NI implementation and hex writer control flow execute on synthetic data.',
                    'AES-NI dispatch pointer is explicit fixture; CPUID/dispatcher branch selection not executed.',
                    'ASCII key conversion, FString allocation/append/%02X formatting/free remain fixtures.',
                    'sub/nmDeviceKey values explicit fixtures; JWT decode, actual auth context and SetupServiceSettingPath entry not executed.',
                    'No actual identities, tokens, profiles, registry or network read; no full Save/Load.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-nid-path-suffix-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
