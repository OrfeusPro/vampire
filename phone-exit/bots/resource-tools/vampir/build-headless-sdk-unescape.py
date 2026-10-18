"""Execute GMC2 string unescape with bounded allocation/powf shims, offline."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE/file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


START, END = 0x1444f2670, 0x1444f2932
GROW, POW = 0x141431e70, 0x1487a2ed3


class SDKUnescapeEmulator:
    def __init__(self):
        self.ping = module('unescape_ping', 'build-headless-ping-codec.py')
        self.config = module('unescape_config', 'build-headless-sdk-config.py')
        self.base = self.ping.PingEmulator()
        self.uc, self.image, self.raw = self.base.uc, self.base.image, self.base.raw
        from unicorn import x86_const as x
        self.x = x
        native = self.config.native
        original = self.image.containing(START)
        # The unwind range includes switch-table data. Decode only through RET;
        # preserve the excluded data and original bounds separately, without skipdata.
        reviewed = (original[0], END-self.image.pe.base, original[2])
        self.image.roots[reviewed] = self.image.roots[original]
        self.fragments = native.decode_ranges(self.image, {self.image.roots[original]}, functions=[reviewed])
        self.unwind_bounds = list(original)
        self.data = []
        for address, length in [(END, original[1]-(END-self.image.pe.base)), (0x1489cd028, 4)]:
            offset = self.image.offset(address-self.image.pe.base)
            raw = self.raw[offset:offset+length]
            self.data.append(dict(address=address, file_offset=offset, bytes=raw.hex(),
                                  sha256=hashlib.sha256(raw).hexdigest()))
        rows = {i['address']: i for f in self.fragments for i in f['instructions']}
        float_address = rows[0x1444f2694]['rip_references'][0]
        if float_address != 0x1489cd028 or struct.unpack('<f', bytes.fromhex(self.data[1]['bytes']))[0] != 16:
            raise ValueError('Unescape power constant changed')
        imports = module('unescape_imports', 'build-object-zero-init-code.py')
        offset = self.image.offset(POW-self.image.pe.base)
        if self.raw[offset:offset+2] != b'\xff\x25':
            raise ValueError('Power import thunk changed')
        iat = POW+6+struct.unpack_from('<i', self.raw, offset+2)[0]
        self.pow_import = imports.import_at(self.raw, self.image, iat)
        if self.pow_import['name'] != 'powf':
            raise ValueError('Unverified power import')
        self.base.ranges += [(START, END), (GROW, GROW+1), (POW, POW+1)]
        addresses = [START, END, GROW, POW, float_address]
        pages = {a & ~4095 for a in addresses}
        regions = list(self.uc.mem_regions())
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            offset = self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page, self.raw[offset:offset+4096])
        self.uc.hook_add(self.ping.unicorn.UC_HOOK_CODE, self.hook)

    def hook(self, uc, address, size, user):
        if address not in (GROW, POW):
            return
        x, b = self.x, self.base.scratch
        if address == GROW:
            out = uc.reg_read(x.UC_X86_REG_RCX)
            count = struct.unpack('<i', bytes(uc.mem_read(out+8, 4)))[0]
            if out != b+0x1000 or count != 1 or self.allocations:
                raise ValueError('Unexpected synthetic array growth')
            uc.mem_write(out, struct.pack('<Q', b+0x8000))
            uc.mem_write(out+12, struct.pack('<i', 2048))
            self.allocations += 1
        else:
            def float_low(reg):
                return struct.unpack('<f', struct.pack('<I', uc.reg_read(reg)&0xffffffff))[0]
            value, exponent = float_low(x.UC_X86_REG_XMM0), float_low(x.UC_X86_REG_XMM1)
            if value != 16 or exponent not in (0, 1, 2, 3):
                raise ValueError('Power shim outside reviewed domain')
            result = struct.unpack('<I', struct.pack('<f', value**exponent))[0]
            uc.reg_write(x.UC_X86_REG_XMM0, result)
            self.pow_calls += 1
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(stack, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, stack+8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def run(self, units):
        if len(units) > 2048:
            raise ValueError('Native evidence input bound exceeded')
        self.allocations, self.pow_calls = 0, 0
        b, x = self.base.scratch, self.x
        self.base.copy_sizes, self.base.io_entries = [], []
        raw = struct.pack('<'+'H'*len(units), *units)+b'\0\0'
        self.uc.mem_write(b+0x4000, raw)
        self.uc.mem_write(b+0x2000, struct.pack('<QII', b+0x4000, len(units)+1, len(units)+1))
        stack, stop = b+0x30000, b+0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in [(x.UC_X86_REG_RCX, 0), (x.UC_X86_REG_RDX, b+0x1000),
                           (x.UC_X86_REG_R8, b+0x2000), (x.UC_X86_REG_RSP, stack)]:
            self.uc.reg_write(reg, value)
        self.uc.emu_start(START, stop, count=200000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Native unescape instruction budget exceeded')
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(b+0x1000, 16)))
        if count > 2048 or (count and (pointer != b+0x8000 or capacity != 2048)):
            raise ValueError('Output outside synthetic array bounds')
        result = list(struct.unpack('<'+'H'*count, bytes(self.uc.mem_read(pointer, count*2)))) if count else []
        return dict(input_units=list(units), output_units=result, pow_calls=self.pow_calls)


def units(text):
    data = text.encode('utf-16le', 'surrogatepass')
    return list(struct.unpack('<'+'H'*(len(data)//2), data))


def main():
    emulator = SDKUnescapeEmulator()
    valid = []
    for text in ['', 'ordinary', '\\"\\\\\\/\\b\\f\\n\\r\\t', '\\u0000', '\\uFFFF',
                 '\\uD83D\\uDE00', '\\ud800', 'a'*2048, '\\u1234'*300]:
        valid.append(emulator.run(units(text)))
    for value in [0, 1, 8, 9, 10, 12, 13, 34, 47, 92, 127, 255, 256, 0x432, 0xd800, 0xdc00, 65535]:
        for fmt in ['04x', '04X']:
            valid.append(emulator.run(units('\\u'+format(value, fmt))))
    for case in valid:
        text = struct.pack('<'+'H'*len(case['input_units']), *case['input_units']).decode('utf-16le', 'surrogatepass')
        expected = units(json.loads('"'+text+'"'))
        if expected != case['output_units']:
            raise ValueError('Valid JSON unescape differs from native result')
    invalid = [emulator.run(units(text)) for text in ['abc"tail', 'abc\\', 'abc\\q',
               'abc\\u12', 'abc\\u12G4', 'abc\nraw', 'abc\\U0041']]
    native = emulator.config.native
    addresses = [0x1444e3bc0, 0x1444f0e80, 0x1444ddc10, 0x1444ed7d0, 0x1444bd970, 0x1444c8c60]
    fragments = native.decode_ranges(emulator.image, {emulator.image.roots[emulator.image.containing(a)] for a in addresses})
    constants = []
    for f in fragments:
        for row in f['instructions']:
            for address in row['rip_references']:
                literal = emulator.config.read_literal(emulator.raw, emulator.image, address)
                if literal:
                    constants.append(dict(**literal, instruction=row))
    xor = module('unescape_xor', 'build-headless-sdk-values.py').SDKValuesEmulator()
    pipeline = []
    for clear_text, key_text in [('{"clientId":"synthetic"}', 'synthetic-key'),
                                  ('{"label":"Карта 😀"}', 'ключ'), ('{}', 'x')]:
        clear, key = units(clear_text), units(key_text)
        encrypted = [u ^ key[i % len(key)] for i, u in enumerate(clear)]
        encrypted_text = struct.pack('<'+'H'*len(encrypted), *encrypted).decode('utf-16le', 'surrogatepass')
        escaped = units(json.dumps(encrypted_text, ensure_ascii=True)[1:-1])
        stage = emulator.run(escaped)
        decoded = xor.decrypt(stage['output_units'], key)
        if decoded['output_units'] != clear:
            raise ValueError('Synthetic native unescape/XOR pipeline differs')
        pipeline.append(dict(unescape=stage, xor=decoded))
    report = dict(schema_version=1, source=emulator.base.bindings['source'], sha256=emulator.base.bindings['sha256'],
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  unescape_fragments=emulator.fragments, unwind_bounds=emulator.unwind_bounds,
                  data=emulator.data, pow_import=emulator.pow_import, fragments=fragments, constants=constants,
                  valid_cases=valid, permissive_cases=invalid, pipeline_cases=pipeline, network_ready=False,
                  statistics=dict(valid_cases=len(valid), permissive_cases=len(invalid), pipeline_cases=len(pipeline)),
                  limitations=['Only unescape executed; extraction/parser/secret decryption are static evidence.',
                      'Array growth replaced by one bounded allocation; powf shim restricted to 16**{0,1,2,3}.',
                      'Invalid input may return a prefix without an error; portable decoder must reject invalid JSON.',
                      'No live response, DECKEY acquisition, HTTP, credentials or game session.'])
    path = native.ROOT/'code-clues/headless-sdk-unescape.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps(dict(output=str(path), **report['statistics'], pow_import=emulator.pow_import['name'])))


if __name__ == '__main__':
    main()
