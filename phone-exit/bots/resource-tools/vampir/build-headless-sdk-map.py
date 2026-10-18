"""Native SDK string-map URL lookup and existing-key replacement slices."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('map_list', HERE/'build-headless-sdk-secret-list.py')
listing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(listing)
GET, HASH, MOVE = 0x144553700, 0x141420380, 0x1487a2e1f


class SDKMapEmulator(listing.SecretListEmulator):
    def __init__(self):
        super().__init__()
        native = self.config.native
        addresses = [GET, HASH, 0x144502730, 0x144584280, 0x141437e50,
                     0x141432f20, 0x1414599a0, 0x141420cc0, 0x14150df70,
                     0x1444f0e80, 0x1450e2640]
        self.fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(a)] for a in addresses})
        rows = {i['address']: i for f in self.fragments for i in f['instructions']}
        self.base.ranges += [(self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva']) for f in self.fragments]
        self.base.ranges += [(a, a+1) for a in (0x141420f70, 0x1414313d0, 0x141424870, MOVE)]
        self.data = []
        for ins, length in [(0x141420391, 1024), (0x1414599c0, 128), (0x141437ea2, 128)]:
            address = rows[ins]['rip_references'][0]
            off = self.image.offset(address-self.image.pe.base)
            content = self.raw[off:off+length]
            self.data.append(dict(address=address, file_offset=off, bytes=content.hex(), sha256=hashlib.sha256(content).hexdigest()))
        pages = {a & ~4095 for begin, end in self.base.ranges for a in range(begin, end+4095, 4096)}
        pages.update(a & ~4095 for row in rows.values() for a in row['rip_references'])
        pages.update(a & ~4095 for d in self.data for a in range(d['address'], d['address']+len(bytes.fromhex(d['bytes']))+4095, 4096))
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
        imports = listing.module('map_imports', 'build-object-zero-init-code.py')
        off = self.image.offset(MOVE-self.image.pe.base)
        if self.raw[off:off+2] != b'\xff\x25':
            raise ValueError('Move thunk changed')
        target = MOVE+6+struct.unpack_from('<i', self.raw, off+2)[0]
        self.move_import = imports.import_at(self.raw, self.image, target)
        if (self.move_import['dll'].lower(), self.move_import['name']) != ('vcruntime140.dll', 'memmove'):
            raise ValueError('Unexpected move import')

    def hook(self, uc, address, size, user):
        if address not in (0x141420f70, 0x1414313d0, 0x141424870, MOVE):
            return super().hook(uc, address, size, user)
        x = self.x
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == 0x141420f70:
            data = bytearray()
            for index in range(64):
                byte = bytes(uc.mem_read(b+index, 1))
                if byte == b'\0':
                    break
                data.extend(byte)
            else:
                raise ValueError('Unbounded ASCII prefix literal')
            self.put(a, data.decode('ascii'))
        elif address == 0x1414313d0:
            if not 0 < b <= 128:
                raise ValueError('Synthetic string allocation bound exceeded')
            pointer = self.allocate(b*2)
            uc.mem_write(a, struct.pack('<Q', pointer))
            uc.mem_write(a+12, struct.pack('<I', b))
        elif address == 0x141424870:
            if c > 127:
                raise ValueError('Synthetic assign bound exceeded')
            self.put(a, bytes(uc.mem_read(b, c*2)).decode('utf-16le', 'surrogatepass'))
        else:
            if c != 32 or not all(self.base.scratch <= p < self.base.scratch+0x28000-32 for p in (a, b)):
                raise ValueError('Move outside reviewed replacement')
            uc.mem_write(a, bytes(uc.mem_read(b, c)))
        self.calls.append(hex(address))
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(uc.mem_read(stack, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX, a)
        uc.reg_write(x.UC_X86_REG_RSP, stack+8)
        uc.reg_write(x.UC_X86_REG_RIP, ret)

    def reset(self):
        self.heap, self.allocations, self.calls = self.base.scratch+0x10000, set(), []
        self.base.copy_sizes, self.base.io_entries = [], []

    def lookup(self, pairs, key):
        if len(pairs) > 8 or any(len(k) > 32 or len(v) > 120 for k, v in pairs) or len(key) > 32:
            raise ValueError('Map fixture exceeds bound')
        self.reset()
        b = self.base.scratch
        manager, entries = b+0x8000, b+0x4000
        table = manager+0x310
        self.uc.mem_write(table, bytes(0x50))
        self.uc.mem_write(table, struct.pack('<QI', entries, len(pairs)))
        self.uc.mem_write(table+0x38, struct.pack('<i', 0 if pairs else -1))
        self.uc.mem_write(table+0x48, struct.pack('<I', 1))
        for index, (name, value) in enumerate(pairs):
            entry = entries+index*40
            self.put(entry, name)
            self.put(entry+16, value)
            self.uc.mem_write(entry+32, struct.pack('<iI', index+1 if index+1 < len(pairs) else -1, 0))
        self.put(b+0x1000, key)
        self.put(b+0x2000, 'unchanged')
        success = self.base.call(GET, manager, b+0x1000, b+0x2000)
        return dict(pairs=[list(pair) for pair in pairs], key=key, success=success, output=self.text(b+0x2000))

    def replace(self, old_key, new_key, old_value, new_value):
        self.reset()
        b, x = self.base.scratch, self.x
        table, entry, candidate = b+0x8000, b+0x4000, b+0x5000
        self.uc.mem_write(table, struct.pack('<Q', entry))
        self.put(entry, old_key)
        self.put(entry+16, old_value)
        self.put(candidate, new_key)
        self.put(candidate+16, new_value)
        self.uc.reg_write(x.UC_X86_REG_RDI, table)
        self.uc.reg_write(x.UC_X86_REG_R15, 0)
        self.uc.reg_write(x.UC_X86_REG_RSI, candidate)
        self.uc.reg_write(x.UC_X86_REG_RSP, b+0x30000)
        self.uc.emu_start(0x14150e037, 0x14150e070, count=200)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != 0x14150e070:
            raise ValueError('Replacement slice did not complete')
        return dict(old_key=old_key, new_key=new_key, old_value=old_value, new_value=new_value,
                    result_key=self.text(entry), result_value=self.text(entry+16))

    def key_hash(self, key):
        self.reset()
        b, x = self.base.scratch, self.x
        data = key.encode('utf-16le')
        self.uc.mem_write(b+0x4000, data+b'\0\0')
        self.base.call(HASH, len(data)//2, b+0x4000)
        return self.uc.reg_read(x.UC_X86_REG_RAX)&0xffffffff


def main():
    emulator = SDKMapEmulator()
    values = ['', 'https://auth.invalid/', 'HTTP://auth.invalid/', 'HtTpS://auth.invalid/',
              'https://', 'http://', 'ftp://auth.invalid/', 'prefixhttps://auth.invalid/',
              ' https://auth.invalid/', 'https://auth.invalid/Карта', 'HTTPS://AUTH.INVALID/path']
    cases = []
    for value in values:
        for key in ['authTokenUrl', 'AUTHTOKENURL']:
            case = emulator.lookup([('other', 'https://other.invalid/'), ('authTokenUrl', value)], key)
            expected = value.upper().startswith(('HTTP://', 'HTTPS://'))
            if case['success'] != expected or case['output'] != (value if expected else 'unchanged'):
                raise ValueError('Native URL-map lookup differs')
            cases.append(case)
    for pairs, key in [([], 'authTokenUrl'), ([('other', 'https://other.invalid/')], 'authTokenUrl')]:
        case = emulator.lookup(pairs, key)
        if case['success'] or case['output'] != 'unchanged':
            raise ValueError('Missing native URL key succeeded')
        cases.append(case)
    replacements = []
    for old_key, new_key in [('authTokenUrl', 'authTokenUrl'), ('authTokenUrl', 'AUTHTOKENURL'), ('clientId', 'CLIENTID')]:
        case = emulator.replace(old_key, new_key, 'ordinary', 'secret')
        if (case['result_key'], case['result_value']) != (new_key, 'secret'):
            raise ValueError('Native replacement differs')
        replacements.append(case)
    hashes = [dict(key=k, value=emulator.key_hash(k)) for k in ['authTokenUrl', 'AUTHTOKENURL', 'authtokenurl', 'clientId', 'CLIENTID']]
    if len({h['value'] for h in hashes[:3]}) != 1 or hashes[3]['value'] != hashes[4]['value']:
        raise ValueError('Native key hash is not ASCII case insensitive')
    constants = []
    for f in emulator.fragments:
        for row in f['instructions']:
            for target in row['rip_references']:
                literal = emulator.config.read_literal(emulator.raw, emulator.image, target)
                if literal:
                    constants.append(dict(**literal, instruction=row))
    report = dict(schema_version=1, source=emulator.base.bindings['source'], sha256=emulator.base.bindings['sha256'],
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=emulator.fragments,
                  data=emulator.data, constants=constants, move_import=emulator.move_import,
                  cases=cases, replacements=replacements, hash_cases=hashes,
                  statistics=dict(lookup_cases=len(cases), replacement_cases=len(replacements), hash_cases=len(hashes)), network_ready=False,
                  limitations=['Real getter/hash/map comparison/prefix checker executed; one-bucket synthetic map, at most eight entries.',
                      'String allocation/assign/free and memmove shimmed; existing-key replacement is a separate slice.',
                      'Full insertion/growth/lifetime and GMC2 parser not executed; parser call order is static evidence.',
                      'URL check only examines HTTP(S) prefix; no host validity, endpoint acquisition, HTTP or credentials.'])
    path = emulator.base.bindings_path.parent/'headless-sdk-map.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps(dict(output=str(path), **report['statistics'])))


if __name__ == '__main__':
    main()
