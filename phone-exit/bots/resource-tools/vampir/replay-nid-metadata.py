"""Whole NID metadata collector/selector with explicit UserInfo map fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_metadata_platform', HERE / 'replay-version-platform-context.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
COLLECT, SELECT = 0x145604bf0, 0x1455fb550


class Replay(base.Replay):
    def __init__(self, raw, image, source, platform, fragments, values, available):
        super().__init__(raw, image, source, fragments, platform['members'], False)
        self.allowed = {r['address'] for f in fragments for r in f['instructions']}
        self.values, self.available = values, available
        self.output, self.service = self.allocate(16), self.allocate(0x100)
        self.string(self.output, '')
        self.entries = self.allocate(max(40, 40 * len(values)))
        self.keys = list(values)
        self.lookups = []
        self.uc.mem_write(0x14b574aa8, bytes(8))  # Explicit absent optional DeviceKey backend.
        hooks = (0x1445c6e90, 0x14450e830, 0x145604090, 0x144551060,
                 0x141421150, 0x141424430, 0x141420380, 0x141467510,
                 0x144476940, 0x14142d840, 0x144512d90, 0x141573640)
        for page in {a & ~4095 for a in hooks}:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            offset = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[offset:offset + 4096])

    def hook(self, uc, address, size, user):
        if address in self.allowed: return
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x1445c6e90: pass  # Explicit absent marketing attribution.
        elif address == 0x14450e830:
            uc.mem_write(a, bytes(0x250)); result = a
        elif address == 0x145604090:
            if a != self.service: raise ValueError('NID service owner changed')
            result = int(self.available)
        elif address == 0x144551060:
            if c != 1: raise ValueError('UserInfo map mode changed')
            self.uc.mem_write(b, struct.pack('<Q', self.entries))
        elif address == 0x141421150:
            self.string(a, self.literal(b, 2)); result = a
        elif address == 0x141424430:
            if not 0 <= c <= 8192: raise ValueError('Metadata append bound')
            value = bytes(uc.mem_read(b, c * 2)).decode('utf-16le')
            self.string(a, self.text(a) + value); result = a
        elif address == 0x141420380: result = 0  # Hash backend fixture, lookup below checks the exact key.
        elif address == 0x141467510:
            key = self.text(c)
            self.lookups.append(key)
            result = self.keys.index(key) if key in self.values else 0xffffffff
        elif address == 0x144476940:
            index, remainder = divmod(a - self.entries - 16, 40)
            if remainder or not 0 <= index < len(self.keys): raise ValueError('Metadata map value address changed')
            self.string(b, self.values[self.keys[index]]); result = b
        elif address == 0x14142d840:
            fmt = self.literal(b, 2)
            if fmt != '"%s":"%s"': raise ValueError('Unreviewed metadata format')
            self.string(a, '"' + self.literal(c, 2) + '":"' + self.literal(d, 2) + '"'); result = a
        elif address in (0x144512d90, 0x141573640): pass
        else: return super().hook(uc, address, size, user)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(stack, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)

    def capture(self, order):
        self.call(COLLECT, self.service, self.output)
        text = self.text(self.output)
        expected = ('{' + ','.join('"' + k + '":"' + self.values[k] + '"' for k in order if k in self.values) + '}') if self.available else ''
        if text != expected or self.lookups != (order if self.available else []):
            raise ValueError('Native collector output or selector order changed')
        return dict(user_info_available=self.available, map_fixture=self.values, selected_keys=self.lookups, output=text)


def build():
    root = native.ROOT / 'code-clues'
    source = json.loads((root / 'headless-device-identity.json').read_text('utf-8'))
    platform = json.loads((root / 'version-platform-context-replay.json').read_text('utf-8'))
    index_path = root / 'lobby-nid-input-index.json'
    index = json.loads(index_path.read_text('utf-8'))
    raw = Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != source['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in (COLLECT, SELECT)})
    order = [r['key'] for r in index['collector_keys']]
    values = {key: 'fixture-' + str(n) for n, key in enumerate(dict.fromkeys(order))}
    fixtures = [(values, True), ({}, True), ({'I_World': '251'}, True),
                ({'I_PID': 'Ж界', 'I_Unselected': 'ignored'}, True),
                ({'I_PID': 'quote"slash\\'}, True), (values, False)]
    return dict(source=source['source'], source_sha256=source['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-version-platform-context.py').read_bytes()).hexdigest(),
                key_index_sha256=hashlib.sha256(index_path.read_bytes()).hexdigest(), fragments=fragments,
                cases=[Replay(raw, image, source, platform, fragments, values, available).capture(order)
                       for values, available in fixtures],
                limitations=['Whole collector/selector entries and returns execute for explicit UserInfo availability/map fixtures.',
                             'SDK UserInfo load/map/hash/lookup/value conversion, FString formatting/append and cleanup are fixtures.',
                             'Optional DeviceKey and marketing branches disabled; no sources of actual metadata values proven.',
                             'Format string and call order execute; formatting fixture does literal substitution, no escaping.',
                             'No game launch, account, device values, active SDK context or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/nid-metadata-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
