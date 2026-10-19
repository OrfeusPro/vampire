"""Native NID integer/channel helpers and OnResult integration; real local CRT calls."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation = load('nid_primitive_validation', 'replay-nid-result-validation.py')
imports = load('nid_primitive_imports', 'build-object-zero-init-code.py')
config = validation.bootstrap.settings.config
INTEGER, CHANNEL, COMPARE = 0x1415dea40, 0x14452b060, 0x1414596e0


def sources(raw, image):
    helpers = config.native.decode_ranges(image, {image.roots[image.containing(a)] for a in (INTEGER, CHANNEL)})
    targets = {a for f in helpers for r in f['instructions'] if r['mnemonic'] == 'mov'
               and r['operands'].startswith('rdx, qword ptr [rip') for a in r['rip_references']}
    candidates = config.native.rip_candidates(image, targets)
    init = config.native.decode_ranges(image, {image.roots[image.containing(a)] for a, _ in candidates if image.containing(a)})
    bindings = []
    for f in init:
        rows = f['instructions']
        for n, r in enumerate(rows):
            if r['mnemonic'] != 'lea' or not r['operands'].startswith('rcx,') or not set(r['rip_references']) & targets:
                continue
            previous, following = rows[n - 1], rows[n + 1]
            if previous['mnemonic'] != 'lea' or not previous['operands'].startswith('rdx,') or following['direct_target'] != 0x141421150:
                raise ValueError('Channel initializer constructor chain changed')
            literal = config.read_literal(raw, image, previous['rip_references'][0])
            bindings.append(dict(global_address=r['rip_references'][0], root=f['root_begin_rva'] + image.pe.base,
                source_instruction=previous['address'], destination_instruction=r['address'], source=literal))
    if len(bindings) != 13 or {b['global_address'] for b in bindings} != targets:
        raise ValueError('Channel initializer coverage changed')
    cs = config.native.capstone.Cs(config.native.capstone.CS_ARCH_X86, config.native.capstone.CS_MODE_64)
    cs.detail = True
    offset = image.offset(COMPARE - image.pe.base)
    leaf = raw[offset:offset + 0x47]
    instructions = list(cs.disasm(leaf, COMPARE))
    if sum(i.size for i in instructions) != len(leaf) or instructions[-1].mnemonic != 'ret':
        raise ValueError('Channel compare leaf boundary changed')
    table = instructions[1].address + instructions[1].size + instructions[1].operands[1].mem.disp
    table_offset = image.offset(table - image.pe.base)
    imports_bound = []
    for f in helpers:
        if f['root_begin_rva'] != INTEGER - image.pe.base:
            continue
        for r in f['instructions']:
            if r['call']:
                imports_bound.append(dict(instruction=r['address'], **imports.import_at(raw, image, r['rip_references'][0])))
    if [i['name'] for i in imports_bound] != ['_wtoi', '_finite', 'iswspace', 'iswspace']:
        raise ValueError('Numeric parser imports changed')
    return dict(helpers=helpers, initializers=init, bindings=bindings, imports=imports_bound,
        compare_leaf=dict(address=COMPARE, file_offset=offset, bytes=leaf.hex(), sha256=hashlib.sha256(leaf).hexdigest()),
        compare_table=dict(address=table, file_offset=table_offset, bytes=raw[table_offset:table_offset + 128].hex(),
                           sha256=hashlib.sha256(raw[table_offset:table_offset + 128]).hexdigest()))


class Replay(validation.Replay):
    def __init__(self, raw, image, fragments, bindings, evidence, crt):
        super().__init__(raw, image, fragments, bindings)
        self.crt = crt
        self.extra = evidence['helpers'] + evidence['initializers']
        extra_addresses = {r['address'] for f in self.extra for r in f['instructions']}
        leaf = evidence['compare_leaf']
        cs = config.native.capstone.Cs(config.native.capstone.CS_ARCH_X86, config.native.capstone.CS_MODE_64)
        extra_addresses.update(i.address for i in cs.disasm(bytes.fromhex(leaf['bytes']), COMPARE))
        pages = {a & ~4095 for a in extra_addresses | {0x141421150, 0x1487964ac, 0x14147d580}}
        pages.update(a & ~4095 for f in self.extra for r in f['instructions'] for a in r['rip_references'])
        pages.add(evidence['compare_table']['address'] & ~4095)
        regions = list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.allowed.update(extra_addresses)
        self.crt_hooks = {}
        for n, row in enumerate(evidence['imports']):
            address = self.base + 0x7f000 + n * 16
            self.uc.mem_write(row['iat_address'], struct.pack('<Q', address))
            self.crt_hooks[address] = row['name']
        for binding in evidence['bindings']:
            self.function(binding['root'])

    def wtext(self, address):
        values = []
        for n in range(2048):
            unit = bytes(self.uc.mem_read(address + n * 2, 2))
            if unit == b'\0\0':
                return b''.join(values).decode('utf-16le')
            values.append(unit)
        raise ValueError('CRT text exceeds fixture limit')

    def hook(self, uc, address, size, user):
        if address in self.allowed:
            return super().hook(uc, address, size, user)
        x = self.x
        a, b = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        if address in self.crt_hooks:
            name = self.crt_hooks[address]
            if name == '_wtoi':
                result = self.crt._wtoi(self.wtext(a))
            elif name == '_finite':
                value = struct.unpack('<d', struct.pack('<Q', uc.reg_read(x.UC_X86_REG_XMM0) & ((1 << 64) - 1)))[0]
                result = self.crt._finite(value)
            else:
                result = self.crt.iswspace(a & 65535)
            self.events.append(dict(kind='local_CRT_call', name=name, result=result))
        elif address == 0x141421150:
            self.string(a, self.wtext(b))
            result = a
        elif address in (0x1487964ac, 0x14147d580):
            result = 0  # atexit/free captures only; fixture arena lives until Replay disposal.
        else:
            return super().hook(uc, address, size, user)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX, result & ((1 << 64) - 1))
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, ret)

    def function(self, address, **registers):
        stop = self.base + 0x7fe00
        top = self.base + 0x7e000
        self.uc.mem_write(top, struct.pack('<Q', stop))
        self.uc.reg_write(self.x.UC_X86_REG_RSP, top)
        for name, value in registers.items():
            self.uc.reg_write(getattr(self.x, 'UC_X86_REG_' + name.upper()), value)
        self.uc.emu_start(address, stop, count=16384)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP) != stop:
            raise ValueError('Primitive replay instruction budget exceeded')

    def integer(self, text):
        desc, output = self.base + 0x8000, self.base + 0x8100
        self.string(desc, text)
        pointer = struct.unpack('<Q', bytes(self.uc.mem_read(desc, 8)))[0]
        self.uc.mem_write(output - 8, b'\xaa' * 20)
        self.events = []
        self.function(INTEGER, rcx=output, rdx=pointer)
        if bytes(self.uc.mem_read(output - 8, 8)) != b'\xaa' * 8 or bytes(self.uc.mem_read(output + 4, 8)) != b'\xaa' * 8:
            raise ValueError('Numeric parser output guard changed')
        return dict(text=text, ok=bool(self.uc.reg_read(self.x.UC_X86_REG_RAX) & 255),
            value=struct.unpack('<i', bytes(self.uc.mem_read(output, 4)))[0], calls=list(self.events), guards_unchanged=True)

    def channel(self, text):
        desc, output = self.base + 0x8000, self.base + 0x8100
        self.string(desc, text)
        self.uc.mem_write(output - 8, b'\xaa' * 17)
        self.function(CHANNEL, rcx=output, rdx=desc)
        if bytes(self.uc.mem_read(output - 8, 8)) != b'\xaa' * 8 or bytes(self.uc.mem_read(output + 1, 8)) != b'\xaa' * 8:
            raise ValueError('Channel mapper output guard changed')
        return dict(text=text, channel=bytes(self.uc.mem_read(output, 1))[0], guards_unchanged=True)


def build():
    prior = json.loads((config.native.ROOT / 'code-clues/headless-nid-result.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('NID primitive EXE changed')
    image = config.native.Image(raw)
    evidence = sources(raw, image)
    fragments = config.native.decode_ranges(image, {image.roots[image.containing(a)] for a in (validation.START, 0x141420cc0)})
    crt = ctypes.CDLL('ucrtbase.dll')
    crt._wtoi.argtypes, crt._wtoi.restype = [ctypes.c_wchar_p], ctypes.c_int
    crt._finite.argtypes, crt._finite.restype = [ctypes.c_double], ctypes.c_int
    crt.iswspace.argtypes, crt.iswspace.restype = [ctypes.c_ushort], ctypes.c_int
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
    buffer = ctypes.create_unicode_buffer(32768)
    if not kernel.GetModuleFileNameW(crt._handle, buffer, len(buffer)):
        raise ValueError('Unable to record loaded CRT source')
    crt_path = Path(buffer.value)
    make = lambda: Replay(raw, image, fragments, prior['bindings'], evidence, crt)
    vm = make()
    numeric = [vm.integer(t) for t in ('', '0', '00', '+0', '-0', ' 0', '0 ', '0.0', '0abc', '00abc',
        'abc', 'abc0', '+', '-', '1', '-1', '200', '1abc', '0x10', '0e9', '0\tbad', '0,1', '0.1',
        '2147483647', '2147483648', '-2147483649', '\u00a00', '\u20030')]
    names = [b['source']['text'] for b in evidence['bindings']]
    channel_inputs = [text for name in names for text in (name, name.upper(), name.swapcase())]
    channel_inputs += ['', 'unknown', 'email', 'mailUserKey ', ' mailUserKey', 'mailUserKeя']
    channels = [vm.channel(text) for text in channel_inputs]
    fields = dict(resultCode='0', accessToken='access-fixture', refreshToken='', channelKey='mailUserKey',
                  netmarbleId='user-fixture', joinedCountryCode='UA')
    integration = []
    for status, channel in [('0','mailUserKey'), ('200','mailUserKey'), ('abc','mailUserKey'),
                            ('0abc','MAILUSERKEY'), ('0','unknown'), ('0','mailUserKey ')]:
        sample = {**fields, 'resultCode': status, 'channelKey': channel}
        outcome = make().run(sample)
        # Parent fixture parameters are unused here: genuine helper code supplies them.
        for name in ('parse_ok', 'parsed_value', 'channel'):
            outcome.pop(name)
        outcome['integer_and_channel_helpers_executed'] = True
        integration.append(outcome)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), evidence=evidence,
        crt=dict(path=str(crt_path), sha256=hashlib.sha256(crt_path.read_bytes()).hexdigest(), locale='As loaded; locale not changed'),
        numeric=numeric, channels=channels, integration=integration, network_ready=False,
        limitations=['Native integer/channel/ASCII compare helpers and channel initializers executed.',
            'Named CRT imports dispatch to actual local ucrtbase; other machines/locales/Android not verified.',
            'FString initializer allocation/atexit/free and caller map/hash/settings remain explicit shims/captures.',
            'Integration reuses prior caller slice with actual integer/channel helpers; callbacks/session not executed.'])


if __name__ == '__main__':
    report = build()
    path = config.native.ROOT / 'code-clues/nid-result-primitives.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         numeric=len(report['numeric']), channels=len(report['channels']), integration=len(report['integration'])), indent=2))
