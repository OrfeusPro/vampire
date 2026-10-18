"""GMC2 secret ciphertext Base64 and native OAEP argument preparation, offline."""
import base64
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE/filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


B64, DIGEST = 0x14150cd70, 0x148404110
PREPARE, CAPTURE, END = 0x14451d946, 0x148405020, 0x14451d9a1


class SDKSecretEmulator:
    def __init__(self):
        ping = module('secret_ping', 'build-headless-ping-codec.py')
        self.config = module('secret_config', 'build-headless-sdk-config.py')
        self.native = self.config.native
        self.base = ping.PingEmulator()
        self.uc, self.image, self.raw, self.x = self.base.uc, self.base.image, self.base.raw, ping.x
        addresses = [B64, 0x141523200, 0x14451d5c0, 0x148404190, CAPTURE,
                     0x148405720, 0x148433880, 0x1484057e0, 0x1483f9780]
        self.fragments = self.native.decode_ranges(self.image, {self.image.roots[self.image.containing(a)] for a in addresses})
        rows = {i['address']: i for f in self.fragments for i in f['instructions']}
        self.data = []
        for address, length in [(rows[0x14150cdb5]['rip_references'][0], 128),
                                (rows[0x14150cdae]['rip_references'][0], 128), (0x14a722610, 64), (DIGEST, 8)]:
            offset = self.image.offset(address-self.image.pe.base)
            raw = self.raw[offset:offset+length]
            self.data.append(dict(address=address, file_offset=offset, bytes=raw.hex(), sha256=hashlib.sha256(raw).hexdigest()))
        self.base.ranges += [(self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva']) for f in self.fragments
                             if f['root_begin_rva'] == B64-self.image.pe.base]
        self.base.ranges += [(PREPARE, END), (DIGEST, DIGEST+8), (CAPTURE, CAPTURE+1)]
        pages = {a & ~4095 for pair in self.base.ranges for a in range(pair[0], pair[1]+4095, 4096)}
        pages.update(row['address'] & ~4095 for row in self.data)
        regions = list(self.uc.mem_regions())
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            offset = self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page, self.raw[offset:offset+4096])
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)

    def hook(self, uc, address, size, user):
        if address != CAPTURE:
            return
        x = self.x
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        args = [uc.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9]]
        args += list(struct.unpack('<5Q', bytes(uc.mem_read(stack+0x28, 40))))
        self.captured = args
        target = struct.unpack('<Q', bytes(uc.mem_read(stack, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX, 2)  # Synthetic result; OAEP itself is not executed.
        uc.reg_write(x.UC_X86_REG_RSP, stack+8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def decode(self, text):
        units = text.encode('utf-16le', 'surrogatepass')
        if len(units) > 4096:
            raise ValueError('Synthetic Base64 input exceeds bound')
        b, x = self.base.scratch, self.x
        self.uc.mem_write(b+0x4000, units+b'\0\0')
        self.uc.mem_write(b+0x8000, b'\xcc'*2048)
        stack, stop = b+0x30000, b+0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in [(x.UC_X86_REG_RCX, b+0x4000), (x.UC_X86_REG_RDX, len(units)//2),
                           (x.UC_X86_REG_R8, b+0x8000), (x.UC_X86_REG_R9, 0), (x.UC_X86_REG_RSP, stack)]:
            self.uc.reg_write(reg, value)
        self.uc.emu_start(B64, stop, count=100000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Base64 instruction budget exceeded')
        size = len(text.rstrip('='))*6//8
        return dict(input=text, success=bool(self.uc.reg_read(x.UC_X86_REG_RAX)&255),
                    output_hex=bytes(self.uc.mem_read(b+0x8000, size)).hex())

    def prepare(self, size, zero_prefix):
        if not 0 <= zero_prefix <= size <= 512 or size < 1:
            raise ValueError('Synthetic RSA result bound exceeded')
        b, x = self.base.scratch, self.x
        self.captured = None
        data = bytes(zero_prefix)+b'\x41'*(size-zero_prefix)
        self.uc.mem_write(b+0x8000, data)
        stack = b+0x30000
        self.uc.mem_write(stack+0x50, struct.pack('<Q', b+0xa000))
        for reg, value in [(x.UC_X86_REG_R14, b+0x8000), (x.UC_X86_REG_R15, size),
                           (x.UC_X86_REG_RDI, 0), (x.UC_X86_REG_RSP, stack)]:
            self.uc.reg_write(reg, value)
        self.uc.emu_start(PREPARE, END, count=10000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != END or self.captured is None:
            raise ValueError('OAEP call preparation did not complete')
        expected = [b+0xa000, size, b+0x8000+zero_prefix, size-zero_prefix, size, 0, 0, 0x14a722610, 0x14a722610]
        if self.captured != expected:
            raise ValueError('OAEP arguments differ')
        return dict(rsa_result_size=size, zero_prefix=zero_prefix, output_capacity=size,
                    input_offset=zero_prefix, input_size=size-zero_prefix, num=size,
                    label_pointer=0, label_size=0, digest=0x14a722610, mgf1_digest=0x14a722610)


def main():
    emulator = SDKSecretEmulator()
    valid = []
    for size in [0, 1, 2, 3, 4, 7, 16, 64, 128, 256, 512, 1024, 1536]:
        data = bytes((i*73+19)&255 for i in range(size))
        for text in [base64.b64encode(data).decode('ascii'), base64.b64encode(data).decode('ascii').rstrip('=')]:
            case = emulator.decode(text)
            if not case['success'] or case['output_hex'] != data.hex():
                raise ValueError('Native Base64 valid vector differs')
            valid.append(case)
    boundary = [emulator.decode(text) for text in ['A', 'AA$A', 'AA A', 'AAAA\n', 'АА==', '====', 'AB==', 'AA====']]
    preparation = [emulator.prepare(size, prefix) for size in [64, 128, 256, 512] for prefix in [0, 1, 2, size]]
    constants = []
    for f in emulator.fragments:
        for row in f['instructions']:
            for a in row['rip_references']:
                literal = emulator.config.read_literal(emulator.raw, emulator.image, a)
                if literal:
                    constants.append(dict(**literal, instruction=row))
    version = b'OpenSSL 1.1.1t  7 Feb 2023\0'
    offset = emulator.raw.index(version)
    report = dict(schema_version=1, source=emulator.base.bindings['source'], sha256=emulator.base.bindings['sha256'],
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=emulator.fragments,
                  data=emulator.data, constants=constants, openssl_version=dict(file_offset=offset, bytes=version.hex()),
                  valid_cases=valid, boundary_cases=boundary, oaep_preparation=preparation,
                  statistics=dict(base64_valid=len(valid), base64_boundary=len(boundary), oaep_preparation=len(preparation)),
                  network_ready=False, limitations=['Base64 loop executed, output preallocated; allocator/wrapper not executed.',
                      'OAEP call preparation and digest getter executed; OAEP call captured with synthetic return.',
                      'No RSA decryption, private keys, live DECKEY, server response or network execution.'])
    path = emulator.native.ROOT/'code-clues/headless-sdk-secret.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps(dict(output=str(path), **report['statistics'])))


if __name__ == '__main__':
    main()
