"""SDK query-parameter provenance and native GMC2 UTF16 XOR evidence."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('values_config', HERE/'build-headless-sdk-config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
native = config.native
DECRYPT, APPEND = 0x1444ddf50, 0x1414242a0


class SDKValuesEmulator:
    def __init__(self):
        spec = importlib.util.spec_from_file_location('values_ping', HERE/'build-headless-ping-codec.py')
        ping = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ping)
        from unicorn import x86_const as x
        self.x, self.ping = x, ping
        self.base = ping.PingEmulator()
        self.raw, self.image, self.uc = self.base.raw, self.base.image, self.base.uc
        self.fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(a)] for a in
            [DECRYPT, 0x1444f38e0, 0x144524390, 0x14452b820, 0x1411b3220, 0x1411b3250, 0x1411b3280]})
        self.base.ranges.extend((self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva']) for f in self.fragments)
        rows = {i['address']: i for f in self.fragments for i in f['instructions']}
        self.log_flag = rows[0x1444ddf61]['rip_references'][0]
        pages = {p for begin, end in self.base.ranges for p in range(begin&~4095, (end+4095)&~4095, 4096)}
        pages.update(a&~4095 for a in [self.log_flag, APPEND])
        regions = list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            try:
                off = self.image.offset(page-self.image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, self.raw[off:off+4096])
        self.uc.mem_write(self.log_flag, b'\0')
        # Install the capture before the existing guard so it sees the redirected RET.
        self.base.ranges.append((APPEND, APPEND+32))
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)
        self.literals = []
        for address in [0x144524396, 0x1411b3224, 0x1411b3254, 0x1411b3284]:
            literal = config.read_literal(self.raw, self.image, rows[address]['rip_references'][0])
            if not literal:
                raise ValueError('SDK parameter literal missing')
            self.literals.append(dict(**literal, instruction=rows[address]))

    def hook(self, uc, address, size, user):
        if address != APPEND:
            return
        x = self.x
        if uc.reg_read(x.UC_X86_REG_RCX) != self.base.scratch+0x1000 or len(self.output_units) >= 2048:
            raise ValueError('Synthetic wchar append outside bounds')
        self.output_units.append(uc.reg_read(x.UC_X86_REG_RDX)&65535)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(stack, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, stack+8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def decrypt(self, units, key_units):
        if len(units) > 2048 or len(key_units) > 512 or (units and not key_units):
            raise ValueError('Native evidence bounds or empty modulo divisor')
        b = self.base.scratch
        self.output_units = []
        self.base.copy_sizes, self.base.io_entries = [], []
        self.uc.mem_write(b+0x2000, struct.pack('<QI', b+0x8000, len(units)))
        self.uc.mem_write(b+0x3000, struct.pack('<QI', b+0xa000, len(key_units)+1))
        self.uc.mem_write(b+0x8000, struct.pack('<'+'H'*len(units), *units) or b'\0\0')
        self.uc.mem_write(b+0xa000, struct.pack('<'+'H'*len(key_units), *key_units)+b'\0\0')
        # Ping's generic helper uses a small instruction budget; use a larger explicit bound here.
        stack, stop = b+0x30000, b+0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in [(self.x.UC_X86_REG_RCX, 0), (self.x.UC_X86_REG_RDX, b+0x1000),
                           (self.x.UC_X86_REG_R8, b+0x2000), (self.x.UC_X86_REG_R9, b+0x3000),
                           (self.x.UC_X86_REG_RSP, stack)]:
            self.uc.reg_write(reg, value)
        self.uc.emu_start(DECRYPT, stop, count=100000)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP) != stop:
            raise ValueError('Native SDK decrypt instruction budget exceeded')
        expected = [value ^ key_units[i % len(key_units)] for i, value in enumerate(units)]
        if self.output_units != expected:
            raise ValueError('Native SDK UTF16 XOR mismatch')
        return dict(input_units=list(units), test_key_units=list(key_units), output_units=self.output_units.copy())


def main():
    emulator = SDKValuesEmulator()
    cases = []
    for key in [[], [1], [0x1234, 0xabcd], [0x41, 0x432, 0xffff], [0xd83d, 0xde00]]:
        sizes = [0] if not key else [0, 1, 2, 3, 7, 16, 255, 512, 1024, 2048]
        for size in sizes:
            units = [(i*257+0x1234)&65535 for i in range(size)]
            cases.append(emulator.decrypt(units, key))
    # Synthetic JSON fixture only; no server response, secret config or live key.
    text = '{"authTokenUrl":"https://auth.invalid/","clientId":"synthetic"}'
    clear = list(struct.unpack('<'+'H'*(len(text.encode('utf-16le'))//2), text.encode('utf-16le')))
    key = [ord(c) for c in 'synthetic-key']
    encrypted = [value ^ key[i % len(key)] for i, value in enumerate(clear)]
    case = emulator.decrypt(encrypted, key)
    if case['output_units'] != clear:
        raise ValueError('Synthetic JSON fixture differs')
    cases.append(case)
    report = dict(schema_version=1, source=emulator.base.bindings['source'], sha256=emulator.base.bindings['sha256'],
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=emulator.fragments,
                  literals=emulator.literals, cases=cases, statistics=dict(native_xor_cases=len(cases)), network_ready=False,
                  limitations=['Actual DecryptXOR loop executed; wchar append replaced by bounded code-unit capture.',
                      'Logging disabled by explicit synthetic flag; no allocator/FString append/network execution.',
                      'Key inputs are synthetic; live DECKEY/encConstants acquisition and outer response decode unresolved.',
                      'Getters/initializer provenance is static; active settings and later mutations unresolved.',
                      'UTF16 units kept exact, including surrogates; text validity handled separately.'])
    path = native.ROOT/'code-clues/headless-sdk-values.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps(dict(output=str(path), **report['statistics'], literals=[l['text'] for l in emulator.literals])))


if __name__ == '__main__':
    main()
