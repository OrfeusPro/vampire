"""Native BeginGame selection -> patch text slice -> actual CRT -> Login global.

Patch text is explicit fixture state. No manifest fetching or game execution.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load('revision_begin_game', 'replay-begin-game-server-target.py')
imports = load('revision_imports', 'build-object-zero-init-code.py')
native, x = base.native, base.x
STOP, GLOBAL, CRT = 0x146425adb, 0x14b520cb8, 0x30000100


class Replay(base.Replay):
    def __init__(self, raw, image, prior, text, expected, imported):
        record = dict(id=251, text='server-fixture.invalid', word_30=10001, word_32=20002)
        fixture = dict(last_id=251, invalid_id=0xffffffff, fallback_id=251, busy=False, records=[record])
        super().__init__(raw, image, prior['fragments'], prior['spans'], fixture)
        self.patch_text, self.expected = text, expected
        self.patch = self.allocate(0x300)
        self.uc.mem_write(self.title + 0xb78, struct.pack('<Q', self.patch))
        self.string(self.patch + 0x1b0, text)
        self.uc.mem_write(GLOBAL, bytes.fromhex('78563412'))
        self.uc.mem_write(imported['iat_address'], struct.pack('<Q', CRT))
        self.crt = ctypes.CDLL('ucrtbase.dll')
        self.crt._wtoi.argtypes = [ctypes.c_wchar_p]
        self.crt._wtoi.restype = ctypes.c_int
        for address in (0x141421150, 0x141432680):
            page = address & ~4095
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
        self.converted = []

    def wide(self, pointer):
        units = bytearray()
        for i in range(256):
            value = bytes(self.uc.mem_read(pointer + 2 * i, 2))
            if value == b'\0\0': return units.decode('utf-16le')
            units.extend(value)
        raise ValueError('Revision text bound')

    def hook(self, uc, address, size, user):
        if address == 0x146425a7d: return  # Continue beyond the earlier target-only replay.
        if address == STOP: uc.emu_stop(); return
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == 0x141421150:
            self.string(a, self.wide(b)); result = a
        elif address == 0x141432680:
            if a != self.patch + 0x1b0 or c != 8: raise ValueError('Patch text source or prefix length changed')
            self.string(b, self.text(a)[c:]); result = b
        elif address == CRT:
            value = self.wide(a)
            result = self.crt._wtoi(value) & 0xffffffff
            self.converted.append(dict(text=value, uint32=result))
        else: return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def capture(self):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.title)
        self.uc.emu_start(base.BEGIN, self.stop, count=8192)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != STOP: raise ValueError('Revision replay stopped before the store')
        value = int.from_bytes(self.uc.mem_read(GLOBAL, 4), 'little')
        server_id = int.from_bytes(self.uc.mem_read(self.transport + 0x270, 4), 'little')
        if value != self.expected or server_id != 251 or len(self.converted) != 1:
            raise ValueError('Revision input or independent server ID differs')
        return dict(patch_text_fixture=self.patch_text, extra_number=value, selected_server_id=server_id,
                    conversion=self.converted[0], stop=hex(STOP))


def build():
    prior_path = native.ROOT / 'code-clues/begin-game-server-target-replay.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    rows = {r['address']: r for f in prior['fragments'] for r in f['instructions']}
    slot = rows[0x146425ac1]['rip_references'][0]
    imported = imports.import_at(raw, image, slot)
    if imported['name'] != '_wtoi': raise ValueError('Revision conversion import changed')
    imported['iat_address'] = slot
    literal_address = 0x14960a8c0
    offset = image.offset(literal_address - image.pe.base)
    literal = ('Revision' + '\0').encode('utf-16le')
    if raw[offset:offset + len(literal)] != literal: raise ValueError('Revision prefix changed')
    cases = [(text, value) for text, value in (('', 0), ('Revision', 0), ('Revision0', 0),
             ('Revision258269', 258269), ('Revision258392', 258392), ('Revision00042', 42),
             ('Revision-1', 0xffffffff), ('Revision42junk', 42), ('Revisionjunk', 0), ('short', 0))]
    crt_path = Path(os.environ['SystemRoot']) / 'System32/ucrtbase.dll'
    return dict(source=prior['source'], source_sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-begin-game-server-target.py').read_bytes()).hexdigest(),
                upstream_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                crt=dict(path=str(crt_path), sha256=hashlib.sha256(crt_path.read_bytes()).hexdigest(), imported=imported),
                prefix=dict(address=hex(literal_address), file_offset=offset, bytes=literal.hex(),
                            sha256=hashlib.sha256(literal).hexdigest()),
                fragments=[f for f in prior['fragments'] if f['root_begin_rva'] == base.BEGIN - image.pe.base],
                cases=[Replay(raw, image, prior, text, value, imported).capture() for text, value in cases],
                limitations=['Native BeginGame from entry through target setters and global store; actual system CRT conversion.',
                             'FString construction and Mid helper are bounded fixtures; patch text is supplied, not loaded.',
                             'Source of patch object +1b0 and active revision remain unresolved; no default numeric value inferred.',
                             'Stops before lobby clock/send; no account, game launch, process memory or socket IO.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/login-revision-input-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
