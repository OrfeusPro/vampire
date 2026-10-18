"""Execute client's OAEP checker with bounded hash/allocation shims, offline."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
START, MD = 0x148405020, 0x14a722610
SHIMS = {0x148795fe0: 'stack_probe', 0x148405fc0: 'digest_size', 0x148411200: 'allocate',
         0x1484049f0: 'mgf1_sha256', 0x14840c5a0: 'digest_sha256', 0x140c17060: 'memcmp',
         0x148403190: 'error_push', 0x148403730: 'error_clear', 0x140c17000: 'cleanse',
         0x148411360: 'clear_free', 0x148796040: 'stack_cookie'}


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE/file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def mgf1(seed, length):
    return b''.join(hashlib.sha256(seed+struct.pack('>I', counter)).digest()
                    for counter in range((length+31)//32))[:length]


class OAEPEmulator:
    def __init__(self):
        ping = module('oaep_ping', 'build-headless-ping-codec.py')
        self.base = ping.PingEmulator()
        self.uc, self.image, self.raw, self.x = self.base.uc, self.base.image, self.base.raw, ping.x
        self.fragments = ping.native.decode_ranges(self.image, {self.image.roots[self.image.containing(START)]})
        self.base.ranges += [(self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva']) for f in self.fragments]
        self.base.ranges += [(address, address+1) for address in SHIMS]
        rows = {i['address']: i for f in self.fragments for i in f['instructions']}
        self.cookie_address = rows[0x14840503d]['rip_references'][0]
        pages = {address & ~4095 for begin, end in self.base.ranges for address in range(begin, end+4095, 4096)}
        pages.add(self.cookie_address & ~4095)
        regions = list(self.uc.mem_regions())
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            offset = self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page, self.raw[offset:offset+4096])
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)

    def read(self, address, length):
        if not 0 <= length <= 2048 or not self.base.scratch <= address <= self.base.scratch+0x40000-length:
            if address == 0 and length == 0:
                return b''
            raise ValueError('OAEP shim read outside bounded scratch')
        return bytes(self.uc.mem_read(address, length)) if length else b''

    def write(self, address, data):
        self.read(address, len(data))
        if data:
            self.uc.mem_write(address, data)

    def hook(self, uc, address, size, user):
        kind = SHIMS.get(address)
        if kind is None:
            return
        x, b = self.x, self.base.scratch
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        args = [uc.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9]]
        a, c, d, e = args
        stack_args = struct.unpack('<2Q', self.read(stack+0x28, 16))
        result = 0
        if kind == 'allocate':
            if not 0 < a <= 512 or self.alloc_count >= 2:
                raise ValueError('OAEP allocation outside evidence bounds')
            result = b+0x10000+self.alloc_count*0x1000
            self.allocations[result] = a
            self.alloc_count += 1
            self.write(result, b'\0'*a)
        elif kind == 'clear_free':
            if a:
                if self.allocations.pop(a, None) != c:
                    raise ValueError('Unbalanced OAEP free')
                self.write(a, bytes(c))
        elif kind == 'digest_size':
            if a != MD:
                raise ValueError('Unexpected digest descriptor')
            result = 32
        elif kind == 'mgf1_sha256':
            if stack_args[0] != MD or c > 512 or e > 512:
                raise ValueError('Unexpected MGF1 parameters')
            self.write(a, mgf1(self.read(d, e), c))
        elif kind == 'digest_sha256':
            if stack_args != (MD, 0) or e != 0 or c > 512:
                raise ValueError('Unexpected digest parameters')
            self.write(d, hashlib.sha256(self.read(a, c)).digest())
            result = 1
        elif kind == 'memcmp':
            result = int(self.read(a, d) != self.read(c, d))
        elif kind == 'cleanse':
            self.write(a, bytes(c))
        elif kind in ('error_push', 'error_clear'):
            self.error_calls.append(kind)
        elif kind in ('stack_probe', 'stack_cookie'):
            # Both MSVC helpers preserve RAX: stack size or function result.
            result = uc.reg_read(x.UC_X86_REG_RAX)
        self.calls.append(kind)
        target = struct.unpack('<Q', self.read(stack, 8))[0]
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RSP, stack+8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def run(self, encoded, num, capacity=512, label=b''):
        if len(encoded) > 512 or not 0 < num <= 512 or not 0 < capacity <= 512 or len(label) > 512:
            raise ValueError('OAEP synthetic scenario exceeds bounds')
        b, x = self.base.scratch, self.x
        self.allocations, self.alloc_count, self.calls, self.error_calls = {}, 0, [], []
        self.uc.mem_write(b+0x4000, encoded or b'\0')
        self.uc.mem_write(b+0x6000, label or b'\0')
        self.uc.mem_write(b+0x8000, b'\xa5'*512)
        stack, stop = b+0x30000, b+0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        self.uc.mem_write(stack+0x28, struct.pack('<5Q', num, b+0x6000 if label else 0, len(label), MD, MD))
        for reg, value in [(x.UC_X86_REG_RCX, b+0x8000), (x.UC_X86_REG_RDX, capacity),
                           (x.UC_X86_REG_R8, b+0x4000), (x.UC_X86_REG_R9, len(encoded)), (x.UC_X86_REG_RSP, stack)]:
            self.uc.reg_write(reg, value)
        self.uc.emu_start(START, stop, count=300000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop or self.allocations:
            raise ValueError('OAEP did not finish within bounds or leaked synthetic allocations')
        result = self.uc.reg_read(x.UC_X86_REG_RAX)&0xffffffff
        result = result-(1 << 32) if result & 0x80000000 else result
        output = self.read(b+0x8000, 512)
        if result < 0 and output != b'\xa5'*512:
            raise ValueError('OAEP error changed output buffer')
        if result >= 0 and output[result:] != b'\xa5'*(512-result):
            raise ValueError('OAEP wrote past result')
        return dict(encoded_hex=encoded.hex(), num=num, capacity=capacity, label_hex=label.hex(),
                    result=result, output_hex=output[:max(result, 0)].hex(), shims=self.calls.copy())


def main():
    import cryptography
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.backends.openssl.backend import backend
    if cryptography.__version__ != '48.0.0':
        raise ValueError('Use pinned analysis cryptography 48.0.0')
    emulator = OAEPEmulator()
    valid, invalid, public_keys = [], [], []
    for bits in (2048, 3072, 4096):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        # Test key format through an independent backend; private PEM stays in memory.
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
        restored = serialization.load_pem_private_key(pem, password=None)
        numbers = key.private_numbers()
        public_keys.append(dict(bits=bits, n=str(numbers.public_numbers.n), e=numbers.public_numbers.e))
        width = bits//8
        for size in (0, 1, 32, width-66):
            plain = bytes((i*37+19)&255 for i in range(size))
            pad = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            encrypted = key.public_key().encrypt(plain, pad)
            if restored.decrypt(encrypted, pad) != plain:
                raise ValueError('Independent RSA/OAEP roundtrip differs')
            encoded = pow(int.from_bytes(encrypted, 'big'), numbers.d, numbers.public_numbers.n).to_bytes(width, 'big')
            for stripped in (False, True):
                case = emulator.run(encoded.lstrip(b'\0') if stripped else encoded, width, capacity=width)
                if case['result'] != size or bytes.fromhex(case['output_hex']) != plain:
                    raise ValueError('Client OAEP checker differs from RSA backend')
                valid.append(dict(**case, ciphertext_hex=encrypted.hex(), key_index=len(public_keys)-1))
            for bad_index, (bad, num, capacity, label) in enumerate([(bytes([1])+encoded[1:], width, width, b''),
                                             (encoded, width, width, b'wrong-label'),
                                             (bytes(width), width, width, b''),
                                             (b'', width, width, b''),
                                             (encoded, width-1, width, b'')]):
                case = emulator.run(bad, num, capacity, label)
                if case['result'] != -1:
                    raise ValueError(f'Invalid OAEP fixture accepted: bits={bits}, size={size}, kind={bad_index}, result={case["result"]}')
                invalid.append(case)
            if size:
                case = emulator.run(encoded, width, size-1) if size > 1 else emulator.run(encoded, width, 1, b'wrong')
                if case['result'] != -1:
                    raise ValueError('Invalid output capacity/label accepted')
                invalid.append(case)
    # Preserve the multiline native PEM format, omitted by printable-only literal scans.
    format_address = 0x1494e2540
    format_offset = emulator.image.offset(format_address-emulator.image.pe.base)
    format_bytes = emulator.raw[format_offset:emulator.raw.index(b'\0', format_offset)+1]
    if format_bytes != b'-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\0':
        raise ValueError('Native RSA key wrapper changed')
    native = module('oaep_native', 'build-native-entry-code.py')
    caller_fragments = native.decode_ranges(emulator.image, {emulator.image.roots[emulator.image.containing(0x14451d5c0)]})
    report = dict(schema_version=1, source=emulator.base.bindings['source'], sha256=emulator.base.bindings['sha256'],
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=emulator.fragments,
                  caller_fragments=caller_fragments,
                  shims={str(a): name for a, name in SHIMS.items()}, public_keys=public_keys,
                  key_format=dict(address=format_address, file_offset=format_offset, bytes=format_bytes.hex(),
                                  sha256=hashlib.sha256(format_bytes).hexdigest()),
                  crypto_version=cryptography.__version__, crypto_backend=backend.openssl_version_text(),
                  valid_cases=valid, invalid_cases=invalid, statistics=dict(valid_cases=len(valid), invalid_cases=len(invalid)),
                  network_ready=False, limitations=['Actual OAEP validation/copy loop executed; hash/MGF1/memory/error/stack helpers shimmed.',
                      'Client RSA, PEM reader and complete secret-constant pipeline not executed.',
                      'Independent backend generated test keys/RSA ciphertext; raw RSA pow is analysis only.',
                      'Only public test keys and artificial data persisted; no private keys, credentials or network.'])
    path = emulator.base.bindings_path.parent/'headless-sdk-oaep.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps(dict(output=str(path), **report['statistics'])))


if __name__ == '__main__':
    main()
