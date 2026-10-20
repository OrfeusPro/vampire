"""Whole native ID104 reader with bounded array/map storage fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_list_reader_base', HERE / 'replay-lobby-handshake-codecs.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
READER = 0x14574ae20


def text(value):
    data = value.encode('utf-8')
    return struct.pack('<H', len(data)) + data


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        addresses = (READER, 0x144aa5c50, 0x14574c790, 0x14574c630, 0x14574cec0,
            0x1456c35c0, 0x14574ab50, 0x14574ad20, 0x1456b0ca0, 0x1456b3640, 0x14570b2c0, 0x145712790, 0x1456b9440)
        self.list_fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(a)] for a in addresses})
        for f in self.list_fragments:
            self.ranges.append((self.image.pe.base + f['begin_rva'], self.image.pe.base + f['end_rva']))
        self.reserves = {0x145756110:0x28, 0x1457560d0:0x70, 0x1456b6000:4, 0x14571c150:16}
        self.cleanup = {0x1457443f0, 0x145744350, 0x1414349e0, 0x141496490, 0x1456c3ca0,
            0x1413ff0e0, 0x141453b80, 0x1415340d0, 0x141432280, 0x141417310}
        self.list_hooks = {*self.reserves, *self.cleanup, 0x145756320, 0x1456cf5c0,
            0x1417a3210, 0x1456b9440, 0x1457450c0, 0x1414313d0}
        self.map_pages()

    def map_pages(self):
        pages = {p for lo, hi in self.ranges for p in range(lo & ~4095, (hi + 4095) & ~4095, 4096)}
        pages.update(a & ~4095 for a in self.list_hooks)
        pages.update(a & ~4095 for f in self.list_fragments for r in f['instructions'] for a in r['rip_references'])
        pages.update(a & ~4095 for a in (0x1498f0f00, 0x1498f0ec0, 0x1498f0f48, 0x1498d4e88, 0x1498cf2c8))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: off = self.image.offset(page - self.image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, self.raw[off:off + 4096])

    def finish_fixture(self, value):
        self.uc.reg_write(x.UC_X86_REG_RAX, value)
        stack = self.uc.reg_read(x.UC_X86_REG_RSP)
        target = int.from_bytes(self.uc.mem_read(stack, 8), 'little')
        self.uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
        self.uc.reg_write(x.UC_X86_REG_RIP, target)

    def reserve(self, address, count, stride):
        if not 0 <= count <= 16: raise ValueError('Lobby array fixture count budget')
        pointer = self.alloc(max(count, 1) * stride)
        self.uc.mem_write(address, struct.pack('<QII', pointer, 0, count))

    def hook(self, uc, address, size, user):
        if address not in self.list_hooks: return super().hook(uc, address, size, user)
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address in self.reserves:
            self.reserve(b, c & 65535, self.reserves[address])
        elif address in (0x145756320, 0x1456cf5c0):
            stride = 0x10 if address == 0x145756320 else 0x20
            count = c & 65535
            if count > 16: raise ValueError('Lobby map fixture count budget')
            pointer = self.alloc(max(count, 1) * stride)
            uc.mem_write(b, bytes(0x50))
            uc.mem_write(b, struct.pack('<Q', pointer))
            uc.mem_write(b + 0x38, struct.pack('<I', 0xffffffff))
            uc.mem_write(b + 0x48, struct.pack('<I', 1))
            self.maps[b] = dict(pointer=pointer, stride=stride, count=0, capacity=count)
        elif address in (0x1417a3210, 0x1456b9440):
            state = self.maps[a]
            n = state['count']
            if n >= state['capacity']: raise ValueError('Lobby map insert fixture bound')
            node = state['pointer'] + n * state['stride']
            uc.mem_write(node, struct.pack('<I', c & 0xffffffff))
            link_offset = 8 if state['stride'] == 0x10 else 24
            previous = int.from_bytes(uc.mem_read(a + 0x38, 4), 'little')
            uc.mem_write(node + link_offset, struct.pack('<I', previous))
            if state['stride'] == 0x20: uc.mem_write(node + 8, struct.pack('<Q', 0x1498cf2c8))
            state['count'] += 1
            uc.mem_write(a + 8, struct.pack('<I', state['count']))
            uc.mem_write(a + 0x38, struct.pack('<I', n))
            uc.mem_write(b, struct.pack('<I', n))
            result = b
        elif address == 0x1457450c0:
            uc.mem_write(a, bytes(uc.mem_read(b, 0x70)))
            result = a
        elif address == 0x1414313d0:
            if not 0 <= b <= 1024: raise ValueError('Lobby FString allocation bound')
            count = int.from_bytes(uc.mem_read(a + 8, 4), 'little')
            uc.mem_write(a, struct.pack('<QII', self.alloc(max(2, b * 2)), count, b))
        elif address in self.cleanup: pass
        else: raise ValueError('Unknown lobby list fixture')
        self.finish_fixture(result)

    def fread(self, address):
        pointer, n, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(address, 16)))
        if not 0 <= n <= capacity <= 1024: raise ValueError('Lobby string snapshot bound')
        return bytes(self.uc.mem_read(pointer, (n - 1) * 2)).decode('utf-16le') if n else ''

    def read_list(self, data):
        self.writing = False
        obj, archive, buffer = self.start()
        self.maps = {}
        self.uc.mem_write(obj, bytes(0x118))
        self.uc.mem_write(obj, struct.pack('<Q', 0x1498f0f48))
        if len(data) > 8192: raise ValueError('Lobby list fixture byte budget')
        self.uc.mem_write(buffer, data)
        self.call(0x144aa6260, archive, buffer, len(data), 1, 0)
        returned = self.invoke(READER, obj, archive)
        arrays = {}
        for offset, stride in ((0x18, 0x28), (0x28, 0x70), (0x38, 4)):
            pointer, count = struct.unpack('<QI', bytes(self.uc.mem_read(obj + offset, 12)))
            if count > 16: raise ValueError('Lobby array snapshot bound')
            items = []
            for index in range(count):
                p = pointer + index * stride
                if offset == 0x38: items.append(int.from_bytes(self.uc.mem_read(p, 4), 'little'))
                elif offset == 0x18:
                    items.append([int.from_bytes(self.uc.mem_read(p + 8, 4), 'little'), self.fread(p + 0x10),
                        int.from_bytes(self.uc.mem_read(p + 0x20, 4), 'little')])
                else:
                    nested, n = struct.unpack('<QI', bytes(self.uc.mem_read(p + 0x50, 12)))
                    if n > 16: raise ValueError('Lobby nested string count bound')
                    items.append(dict(strings=[self.fread(p + o) for o in (0x10, 0x20, 0x38)],
                        u32=[int.from_bytes(self.uc.mem_read(p + o, 4), 'little') for o in (8, 12, 0x4c, 0x64)],
                        u16=[int.from_bytes(self.uc.mem_read(p + o, 2), 'little') for o in (0x30, 0x32)],
                        enums=[int.from_bytes(self.uc.mem_read(p + o, 1), 'little') for o in (0x34, 0x35, 0x60)],
                        flags=[int.from_bytes(self.uc.mem_read(p + o, 1), 'little') for o in (0x48, 0x49, 0x4a, 0x4b, 0x68)],
                        array50=[self.fread(nested + i * 16) for i in range(n)]))
            arrays[hex(offset)] = items
        maps = {}
        for offset in (0x48, 0x98):
            state = self.maps.get(obj + offset)
            items = []
            if state:
                for index in range(state['count']):
                    node = state['pointer'] + index * state['stride']
                    key = int.from_bytes(self.uc.mem_read(node, 4), 'little')
                    start, width = (4, 4) if offset == 0x48 else (16, 8)
                    items.append([key, int.from_bytes(self.uc.mem_read(node + start, width), 'little')])
            maps[hex(offset)] = sorted(items)
        return dict(payload_hex=data.hex(), returned=returned,
            consumed=int.from_bytes(self.uc.mem_read(archive + 0x30, 8), 'little') - buffer,
            result_code=int.from_bytes(self.uc.mem_read(obj + 0x10, 4), 'little'), arrays=arrays, maps=maps,
            flags=[int.from_bytes(self.uc.mem_read(obj + o, 1), 'little') for o in (0xe8, 0x110)],
            enum_e9=int.from_bytes(self.uc.mem_read(obj + 0xe9, 1), 'little'),
            strings=[self.fread(obj + o) for o in (0xf0, 0x100)])


def server_bytes(s):
    return (struct.pack('<II', *s['u32'][:2]) + text(s['strings'][0]) + text(s['strings'][1]) +
        struct.pack('<HHBB', *s['u16'], *s['enums'][:2]) + text(s['strings'][2]) +
        bytes(s['flags'][:4]) + struct.pack('<IH', s['u32'][2], len(s['array50'])) +
        b''.join(text(t) for t in s['array50']) + struct.pack('<BIB', s['enums'][2], s['u32'][3], s['flags'][4]))


def body(groups=(), servers=(), values=(), map48=(), map98=(), flags=(0, 0), enum=0, strings=('', ''), code=0):
    return (struct.pack('<IH', code, len(groups)) + b''.join(struct.pack('<I', g[0]) + text(g[1]) + struct.pack('<I', g[2]) for g in groups) +
        struct.pack('<H', len(servers)) + b''.join(server_bytes(s) for s in servers) +
        struct.pack('<H', len(values)) + b''.join(struct.pack('<I', v) for v in values) +
        struct.pack('<H', len(map48)) + b''.join(struct.pack('<II', *p) for p in map48) +
        struct.pack('<H', len(map98)) + b''.join(struct.pack('<IQ', *p) for p in map98) +
        bytes([flags[0], enum]) + text(strings[0]) + text(strings[1]) + bytes([flags[1]]))


def build():
    em = Emulator()
    minimal = body()
    fixtures = [dict()]
    for t in ('ASCII', 'Ж界🙂', 'x' * 128):
        fixtures.append(dict(groups=[(0xffffffff, t, 0x80000000)]))
    for enum in (0, 5, 6, 22, 255):
        s = dict(strings=['Ж界🙂', 'game.invalid', 'source-fixture'], u32=[42, 7, 0xffffffff, 0x80000000],
            u16=[12001, 65535], enums=[enum] * 3, flags=[0, 1, 2, 255, 1], array50=['HK', 'JP'])
        fixtures.append(dict(servers=[s], flags=(2, 255), enum=enum, strings=('outer-fixture', '🙂')))
    fixtures.append(dict(groups=[(1, 'g1', 2), (2, 'g2', 3)], servers=[s, s], values=[0, 42, 0xffffffff],
        map48=[(7, 9), (3, 11), (7, 13)], map98=[(42, 0xffffffffffffffff), (8, 7), (42, 9)], code=207))
    cases = []
    fixtures = json.loads(json.dumps(fixtures))
    for fixture in fixtures:
        data = body(**fixture)
        case = em.read_list(data)
        if (case['returned'], case['consumed']) != (1, len(data)): raise ValueError('Lobby body layout mismatch')
        cases.append(dict(fixture=fixture, **case))
    truncated = [em.read_list(minimal[:n]) for n in range(len(minimal))]
    if any(c['returned'] for c in truncated): raise ValueError('Short lobby list accepted')
    if len(minimal) != 21: raise ValueError('Lobby minimum changed')
    anchors = []
    for address, size in ((0x1498f3028, 24), (0x1498f3040, 24), (0x1498f3058, 24),
            (0x1498d4e88, 24), (0x1498d0200, 24), (0x1498e69f0, 24),
            (0x1498cf2c8, 40), (0x1498f0f00, 40), (0x1498f0ec0, 40), (0x1498f0f48, 40)):
        offset = em.image.offset(address - em.image.pe.base)
        data = em.raw[offset:offset + size]
        anchors.append(dict(address=address, file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    return dict(schema_version=1, source=em.bindings['source'], source_sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256={name:hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in
            ('replay-lobby-handshake-codecs.py', 'replay-login-result-reader.py')},
        fragments=em.list_fragments, data_anchors=anchors, cases=cases, truncated=truncated,
        limitations=['Whole ID104/record readers, generic array loop, item append and map lookup/duplicate replacement execute.',
            'Zeroed packet fixture; array/map reserves, map insertion/storage, server record copy, cleanup and string allocation use bounded fixtures.',
            'Map98 insertion body is preserved as source evidence but intercepted; its TimeBase value uses the source vtable.',
            'Synthetic one-bucket maps and at most 16 fixture entries; no actual allocator/hash topology/ownership proof.',
            'No packet constructor, handler, network or live response in this replay.'])


if __name__ == '__main__':
    report = build()
    out = native.ROOT / 'code-clues/lobby-server-list-reader-replay.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(out), sha256=hashlib.sha256(out.read_bytes()).hexdigest(), cases=len(report['cases']))))
