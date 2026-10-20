"""Whole native GameInstance factory with bounded, explicit engine captures.

Only the valid default-class path with empty URL strings/options is supported.
Class metadata, WorldSettings lookup, string helpers and actor spawn
are fixtures; no active level or real engine object is inferred from this test.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('provider_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
import unicorn
from unicorn import x86_const as x

CTOR, FACTORY = 0x1468e30f0, 0x143c05a10
TABLE = 0x149e0d4d8


class Emulator:
    def __init__(self):
        if (native.capstone.__version__, unicorn.__version__) != ('5.0.6', '2.1.4'):
            raise ValueError('Use pinned native analysis libraries')
        manifest_raw = (native.ROOT / 'ghidra/entry-manifest.json').read_bytes()
        self.manifest = json.loads(manifest_raw)
        self.manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
        self.raw = Path(self.manifest['source']).read_bytes()
        if hashlib.sha256(self.raw).hexdigest() != self.manifest['source_sha256']:
            raise ValueError('Provider source changed')
        self.image = native.Image(self.raw)
        names = {'OwnerProvider_ConstructGame', 'OwnerProvider_CreateMode', 'OwnerProvider_CopyClass'}
        functions = [f for f in self.manifest['functions'] if f['name'] in names]
        if len(functions) != len(names):
            raise ValueError('Provider Ghidra source missing')
        self.source_ranges = [r for f in functions for r in f['ranges']]
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        for r in self.source_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            if hashlib.sha256(self.raw[r['file_offset']:r['file_offset'] + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Provider function bytes changed')
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_page(page)
        self.hooks = {0x1454d2b00, 0x144319a30, 0x143bf3d80, 0x141421150,
                      0x141577ac0, 0x144306070, 0x143daecc0,
                      0x14376ed60, 0x148796040}
        for a in (*self.hooks, TABLE, TABLE + 0x3e0, 0x14b35a640, 0x14b4e7d88, 0x14b2004c0):
            self.map_page(a & ~4095)
        off = self.image.offset(TABLE - self.image.pe.base)
        self.table = self.raw[off:off + 0x3e8]
        if tuple(struct.unpack_from('<Q', self.table, n)[0] for n in (0x3d0, 0x3e0)) != (FACTORY, 0x14178c590):
            raise ValueError('Provider virtual methods changed')
        self.ctx, self.stack, self.stop = 0x23000000, 0x22008008, 0x2200f000
        self.uc.mem_map(self.ctx, 0x10000)
        self.uc.mem_map(0x22000000, 0x10000)
        self.decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        self.decoder.detail = True
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)
        self.events = []

    def map_page(self, page):
        if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
            return
        self.uc.mem_map(page, 4096)
        try:
            offset = self.image.offset(page - self.image.pe.base)
        except ValueError:
            # Reviewed globals can occupy zero-initialized PE virtual tails.
            if not any(s['rva'] <= page - self.image.pe.base < s['rva'] + s['size']
                       for s in self.image.pe.sections):
                raise
            return
        self.uc.mem_write(page, self.raw[offset:offset + 4096])

    def finish(self, result):
        sp = self.uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', self.uc.mem_read(sp, 8))[0]
        self.uc.reg_write(x.UC_X86_REG_RAX, result)
        self.uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
        self.uc.reg_write(x.UC_X86_REG_RIP, target)

    def hook(self, uc, address, size, user):
        if address in self.hooks:
            a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX,
                                                  x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
            result = 0
            if address == 0x1454d2b00:
                if a != self.ctx:
                    raise ValueError('Provider base constructor receiver')
                self.events.append(dict(action='base_constructor_capture'))
            elif address == 0x144319a30:
                if (a, b & 255, c & 255) != (self.ctx + 0x1000, 0, 1):
                    raise ValueError('WorldSettings lookup arguments')
                result = self.ctx + 0x2000
                self.events.append(dict(action='world_settings_capture', world=a))
            elif address == 0x143bf3d80:
                result = self.ctx + 0x3000
            elif address in (0x141421150, 0x141577ac0):
                # All FString inputs in these scenarios are empty. Do not
                # silently claim support for arbitrary native string copies.
                if address == 0x141577ac0:
                    if struct.unpack('<i', uc.mem_read(b + 8, 4))[0] != 0:
                        raise ValueError('Only empty map name supported')
                elif bytes(uc.mem_read(b, 2)) != b'\0\0':
                    raise ValueError('Only empty portal supported')
                uc.mem_write(a, bytes(16))
                result = a
                self.events.append(dict(action='empty_string_capture', address=address))
            elif address == 0x144306070:
                uc.mem_write(a, bytes(48))
                result = a
                self.events.append(dict(action='spawn_parameters_capture'))
            elif address == 0x143daecc0:
                if (a, b, c, d) != (self.ctx + 0x1000, self.selected_class, 0, 0):
                    raise ValueError('Spawn world/class arguments')
                result = self.spawn_result
                self.events.append(dict(action='spawn_capture', world=a, selected_class=b, result=result))
            elif address == 0x14376ed60:
                if a != self.ctx + 0x6000:
                    raise ValueError('URL cleanup receiver')
                self.events.append(dict(action='url_cleanup_capture'))
            elif address == 0x148796040:
                result = uc.reg_read(x.UC_X86_REG_RAX)
            self.finish(result)
            return
        if not any(int(r['start'], 16) <= address < int(r['end_exclusive'], 16) for r in self.source_ranges):
            raise ValueError('Unexpected native target ' + hex(address))
        for ins in self.decoder.disasm(bytes(uc.mem_read(address, size)), address):
            for op in ins.operands:
                if op.type == native.capstone.x86_const.X86_OP_MEM and op.mem.base == native.capstone.x86_const.X86_REG_RIP:
                    self.map_page((address + size + op.mem.disp) & ~4095)
        if address == FACTORY:
            self.events.append(dict(action='native_factory'))
        if address == 0x14178c590:
            a, c = uc.reg_read(x.UC_X86_REG_RCX), uc.reg_read(x.UC_X86_REG_R8)
            incoming = struct.unpack('<Q', uc.mem_read(c, 8))[0]
            if a != self.ctx or incoming != self.selected_class:
                raise ValueError('Native class copy arguments')
            self.events.append(dict(action='native_class_copy', incoming=incoming))

    def call(self, address, args):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        for register, value in zip((x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8), args):
            self.uc.reg_write(register, value)
        self.uc.emu_start(address, self.stop, count=20000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('Provider instruction budget')
        return self.uc.reg_read(x.UC_X86_REG_RAX)

    def execute(self, implicit_world=False, alternate_default=False, spawn_null=False):
        self.uc.mem_write(self.ctx, bytes(0x10000))
        self.uc.mem_write(0x22000000, bytes(0x10000))
        self.uc.mem_write(0x14b35a640, b'\0')
        self.uc.mem_write(0x14b4e7d88, bytes(8))
        self.uc.mem_write(self.ctx + 0x7000, struct.pack('<Q', self.ctx))
        self.events = []
        self.call(CTOR, (self.ctx + 0x7000,))
        observed_table = struct.unpack('<Q', self.uc.mem_read(self.ctx, 8))[0]
        if observed_table != TABLE:
            raise ValueError('Native constructor did not install provider table')
        self.uc.mem_write(self.ctx + 0x30, struct.pack('<Q', self.ctx + 0x8000))
        self.uc.mem_write(self.ctx + 0x82c0, struct.pack('<Q', self.ctx + 0x1000))
        self.selected_class = self.ctx + (0x5000 if alternate_default else 0x4000)
        self.uc.mem_write(self.ctx + 0x2348, struct.pack('<Q', self.selected_class))
        # Explicit synthetic UClass inheritance metadata for valid classes.
        for relative in (0x4000, 0x5000):
            self.uc.mem_write(self.ctx + relative + 0x30, struct.pack('<Q', self.ctx + relative + 0x80))
            self.uc.mem_write(self.ctx + relative + 0x80, struct.pack('<Q', self.ctx + 0x3030))
        self.spawn_result = 0 if spawn_null else self.ctx + 0x9000
        target = struct.unpack('<Q', self.uc.mem_read(observed_table + 0x3d0, 8))[0]
        result = self.call(target, (self.ctx, self.ctx + 0x6000, 0 if implicit_world else self.ctx + 0x1000))
        if result != self.spawn_result:
            raise ValueError('Native factory did not preserve spawn result across cleanup')
        return dict(implicit_world=implicit_world, alternate_default=alternate_default, spawn_null=spawn_null,
                    table=observed_table, result=result, events=self.events)


def build():
    em = Emulator()
    cases = [em.execute(implicit, alternate, null) for implicit in (False, True)
             for alternate in (False, True) for null in (False, True)]
    names = {'OwnerProvider_RegisterEngine', 'OwnerProvider_RegisterGame', 'OwnerProvider_ConstructEngine',
             'OwnerProvider_ConstructBase', 'OwnerProvider_ConstructGame', 'OwnerProvider_CreateMode',
             'OwnerProvider_ModeClass', 'OwnerProvider_GetWorldSettings', 'OwnerProvider_CopyClass'}
    functions = [f for f in em.manifest['functions'] if f['name'] in names]
    if len(functions) != len(names):
        raise ValueError('Missing provider source evidence')
    roots = {em.image.roots[em.image.containing(int(f['address'], 16))] for f in functions}
    fragments = native.decode_ranges(em.image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for site, target in ((0x143bf3bf0, 0x143bf62e0), (0x1468e1147, CTOR)):
        if rows[site]['rip_references'] != [target]:
            raise ValueError('Provider registration constructor reference changed')
    stub_offset = em.image.offset(0x143bf62e0 - em.image.pe.base)
    stub = em.raw[stub_offset:stub_offset + 20]
    stub_rows = list(em.decoder.disasm(stub, 0x143bf62e0))
    if (sum(i.size for i in stub_rows) != 20 or stub_rows[-1].mnemonic != 'ret' or
            [(i.mnemonic, i.op_str) for i in stub_rows if i.mnemonic == 'jmp'] != [('jmp', '0x143bf9f20')]):
        raise ValueError('Engine constructor forwarding stub changed')
    literals = []
    for address, text in ((0x143bf3bcf, 'GameInstance'), (0x143bf3bde, '/Script/Engine'),
                          (0x1468e1126, 'RdGameInstance'), (0x1468e1135, '/Script/ProjectRED')):
        row = rows[address]
        if row['mnemonic'] != 'lea' or len(row['rip_references']) != 1:
            raise ValueError('Provider registration literal reference changed')
        offset = em.image.offset(row['rip_references'][0] - em.image.pe.base)
        raw = (text + '\0').encode('utf-16le')
        if em.raw[offset:offset + len(raw)] != raw:
            raise ValueError('Provider registration name changed')
        literals.append(dict(text=text, file_offset=offset, instruction=row))
    tables = []
    for address in (0x14929a098, 0x149866e58, TABLE):
        slots = []
        for slot, expected in ((0x3d0, FACTORY), (0x3e0, 0x14178c590)):
            offset = em.image.offset(address + slot - em.image.pe.base)
            raw = em.raw[offset:offset + 8]
            if struct.unpack('<Q', raw)[0] != expected:
                raise ValueError('Inherited provider slot changed')
            slots.append(dict(slot=slot, target=expected, file_offset=offset, bytes=raw.hex()))
        tables.append(dict(address=address, slots=slots))
    descriptor = 0x14915bda0
    offset = em.image.offset(descriptor - em.image.pe.base)
    raw = em.raw[offset:offset + 64]
    name_offset = em.image.offset(struct.unpack_from('<Q', raw)[0] - em.image.pe.base)
    if (em.raw[name_offset:name_offset + 16] != b'DefaultGameMode\0' or
            struct.unpack_from('<I', raw, 50)[0] != 0x348):
        raise ValueError('DefaultGameMode descriptor changed')
    return dict(source=em.manifest['source'], source_sha256=em.manifest['source_sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                manifest_sha256=em.manifest_sha256, ranges=em.source_ranges,
                table_address=TABLE, table_bytes=em.table.hex(), cases=cases,
                registration_literals=literals, provider_tables=tables, fragments=fragments,
                engine_constructor_stub=dict(address=0x143bf62e0, file_offset=stub_offset, bytes=stub.hex()),
                default_class_descriptor=dict(address=descriptor, file_offset=offset, bytes=raw.hex(),
                                              name='DefaultGameMode', object_offset=0x348),
                network_ready=False, active_world_class_verified=False,
                limitations=['Only valid default classes and empty URL options/map/portal are exercised.',
                             'Base constructor, WorldSettings, type metadata, string operations and spawn are explicit fixtures.',
                             'GAME override, invalid/missing class fallback and GC-enabled paths are not executed.',
                             'Factory result is not installed into an actual world and no server session is established.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/world-owner-provider-replay.json'
    output.write_text(json.dumps(report, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), cases=len(report['cases']),
                          sha256=hashlib.sha256(output.read_bytes()).hexdigest())))
