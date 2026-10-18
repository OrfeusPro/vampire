"""Native secret-list assembly, bounded string/crypto shims; no network."""
import base64
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
START = 0x1444ddc10
STOPS = {0x1444dddc4: 'assembled', 0x1444dde17: 'empty_chunk', 0x1444dde2e: 'empty_list'}
SHIMS = {0x141421150: 'construct', 0x14142bbc0: 'mid', 0x14142c810: 'split',
         0x141424430: 'append', 0x141424420: 'append', 0x14147d580: 'free', 0x14451d5c0: 'decrypt'}


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE/file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class SecretListEmulator:
    def __init__(self):
        ping = module('list_ping', 'build-headless-ping-codec.py')
        self.config = module('list_config', 'build-headless-sdk-config.py')
        self.base = ping.PingEmulator()
        self.uc, self.image, self.raw, self.x = self.base.uc, self.base.image, self.base.raw, ping.x
        self.fragments = ping.native.decode_ranges(self.image, {self.image.roots[self.image.containing(START)]})
        rows = {i['address']: i for f in self.fragments for i in f['instructions']}
        self.flag = rows[0x1444ddc30]['rip_references'][0]
        self.base.ranges += [(self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva']) for f in self.fragments]
        self.base.ranges += [(a, a+1) for a in SHIMS]
        pages = {a & ~4095 for begin, end in self.base.ranges for a in range(begin, end+4095, 4096)}
        pages.update(a & ~4095 for row in rows.values() for a in row['rip_references'])
        regions = list(self.uc.mem_regions())
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            try:
                off = self.image.offset(page-self.image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, self.raw[off:off+4096])
        self.uc.mem_write(self.flag, b'\0')
        sys.path.insert(0, str(HERE.parents[1]/'vampir-shared'))
        from vampir_core.sdk_secret import decrypt_sdk_secret_chunk
        self.decrypt = decrypt_sdk_secret_chunk
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)

    def allocate(self, size):
        if size < 1 or self.heap+size > self.base.scratch+0x28000:
            raise ValueError('Synthetic FString heap budget exceeded')
        address = self.heap
        self.heap += (size+15)&~15
        self.allocations.add(address)
        return address

    def text(self, address):
        pointer, count = struct.unpack('<QI', bytes(self.uc.mem_read(address, 12)))
        if not 0 <= count <= 8193 or (count and not self.base.scratch <= pointer < self.heap):
            raise ValueError('Synthetic FString outside bounds')
        data = bytes(self.uc.mem_read(pointer, (count-1)*2)) if count else b''
        return data.decode('utf-16le', 'surrogatepass')

    def put(self, address, text):
        data = text.encode('utf-16le', 'surrogatepass')
        if len(data) > 16384:
            raise ValueError('Synthetic FString exceeds bound')
        pointer, count = (self.allocate(len(data)+2), len(data)//2+1) if text else (0, 0)
        if pointer:
            self.uc.mem_write(pointer, data+b'\0\0')
        self.uc.mem_write(address, struct.pack('<QII', pointer, count, count))

    def literal(self, address):
        data = bytearray()
        for index in range(128):
            unit = bytes(self.uc.mem_read(address+index*2, 2))
            if unit == b'\0\0':
                return data.decode('utf-16le')
            data.extend(unit)
        raise ValueError('Unbounded native literal')

    def hook(self, uc, address, size, user):
        x = self.x
        if address in STOPS:
            self.outcome = STOPS[address]
            self.assembled = self.text(uc.reg_read(x.UC_X86_REG_RDX)) if self.outcome == 'assembled' else None
            uc.emu_stop()
            return
        kind = SHIMS.get(address)
        if kind is None:
            return
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = a
        if kind == 'construct':
            self.put(a, self.literal(b))
        elif kind == 'mid':
            data = self.text(a).encode('utf-16le', 'surrogatepass')
            self.put(b, data[c*2:(c+d)*2].decode('utf-16le', 'surrogatepass'))
            result = b
        elif kind == 'split':
            delimiter = self.literal(c)
            parts = self.text(a).split(delimiter)
            if d & 255:
                parts = [part for part in parts if part]
            if len(parts) > 16:
                raise ValueError('Synthetic list item budget exceeded')
            pointer = self.allocate(16*len(parts)) if parts else 0
            for index, part in enumerate(parts):
                self.put(pointer+index*16, part)
            uc.mem_write(b, struct.pack('<QII', pointer, len(parts), len(parts)))
            result = len(parts)
        elif kind == 'decrypt':
            ciphertext, key = self.text(a), self.text(b)
            self.chunk_inputs.append(ciphertext)
            try:
                plain = self.decrypt(ciphertext, key).removesuffix(b'\0').decode('utf-8')
            except (ValueError, UnicodeError):
                plain = ''
            self.put(c, plain)
        elif kind == 'append':
            if c > 8192:
                raise ValueError('Synthetic append exceeds bound')
            text = bytes(uc.mem_read(b, c*2)).decode('utf-16le', 'surrogatepass')
            self.put(a, self.text(a)+text)
        elif kind == 'free':
            if a not in self.allocations:
                raise ValueError('Free outside synthetic allocations')
            self.allocations.remove(a)
        self.calls.append(kind)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(stack, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RSP, stack+8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def run(self, text, key_body):
        if len(text) > 2048 or len(key_body) > 8192:
            raise ValueError('Synthetic input exceeds bound')
        b, x = self.base.scratch, self.x
        self.heap, self.allocations = b+0x10000, set()
        self.outcome, self.assembled, self.chunk_inputs, self.calls = None, None, [], []
        self.put(b+0x1000, text)
        self.put(b+0x2000, key_body)
        stack = b+0x30000
        for reg, value in [(x.UC_X86_REG_RCX, 0), (x.UC_X86_REG_RDX, b+0x1000),
                           (x.UC_X86_REG_R8, b+0x2000), (x.UC_X86_REG_R9, b+0x3000), (x.UC_X86_REG_RSP, stack)]:
            self.uc.reg_write(reg, value)
        self.uc.emu_start(START, b+0x3f000, count=100000)
        if self.outcome is None:
            raise ValueError('Native list did not reach a bounded capture point')
        return dict(input=text, outcome=self.outcome, assembled=self.assembled,
                    chunks=self.chunk_inputs.copy(), shims=self.calls.copy())


def main():
    import cryptography
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    if cryptography.__version__ != '48.0.0':
        raise ValueError('Use pinned cryptography analysis dependency')
    emulator = SecretListEmulator()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    body = base64.b64encode(der).decode('ascii')
    cases = []
    for fragments in [[], ['"clientId":"synthetic"'], ['"one":1', '"two":2'],
                      ['"name":"Карта 😀"', '"flag":true', '"items":[1,2]'],
                      ['"tail":1\0'], [''], ['"ok":1', ''], ['"notJson":'], ['"same":1', '"same":2']]:
        chunks = [base64.b64encode(key.public_key().encrypt(text.encode('utf-8'),
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('ascii')
                  for text in fragments]
        text = json.dumps(chunks, separators=(',', ':'))
        case = emulator.run(text, body)
        if fragments and all(fragment.removesuffix('\0') for fragment in fragments):
            expected = '{'+','.join(fragment.removesuffix('\0') for fragment in fragments)+'}'
            if case['outcome'] != 'assembled' or case['assembled'] != expected or case['chunks'] != chunks:
                raise ValueError('Native secret-list assembly differs')
        elif fragments and case['outcome'] != 'empty_chunk':
            raise ValueError('Empty native chunk was not rejected')
        elif not fragments and case['outcome'] != 'empty_list':
            raise ValueError('Empty native list branch differs')
        cases.append(dict(**case, fixture_plaintexts_utf8_hex=[fragment.encode('utf-8').hex() for fragment in fragments]))
    boundary = [emulator.run(text, body) for text in ['null', '[]', '[""]', '["AA=="]']]
    native = module('list_native', 'build-native-entry-code.py')
    conversion = native.decode_ranges(emulator.image, {emulator.image.roots[emulator.image.containing(0x14451d5c0)]})
    report = dict(schema_version=1, source=emulator.base.bindings['source'], sha256=emulator.base.bindings['sha256'],
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=emulator.fragments,
                  conversion_fragments=conversion, crypto_version=cryptography.__version__,
                  cases=cases, boundary_cases=boundary, statistics=dict(native_assembly_cases=len(cases), boundary_cases=len(boundary)),
                  network_ready=False, limitations=['Native split/loop/append orchestration executed; FString helpers replaced by bounded shims.',
                      'RSA/UTF8 conversion shim uses verified common chunk backend, not client RSA/UTF8 implementation.',
                      'Stops before JSON parse or early failure/empty-container construction; no native JSON validation/cleanup.',
                      'Artificial ciphertext and plaintext only; private test key stays in memory; no game/network.'])
    path = emulator.base.bindings_path.parent/'headless-sdk-secret-list.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps(dict(output=str(path), **report['statistics'])))


if __name__ == '__main__':
    main()
