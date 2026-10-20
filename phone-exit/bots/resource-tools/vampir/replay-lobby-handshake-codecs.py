"""Execute lobby Version/list writers and VersionResult reader, without IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_codec_reader', HERE / 'replay-login-result-reader.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
VERSION_WRITER, LIST_WRITER, RESULT_READER = 0x145757490, 0x145757260, 0x14574b170


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.extra = native.decode_ranges(self.image, {self.image.roots[self.image.containing(a)]
            for a in (VERSION_WRITER, LIST_WRITER, RESULT_READER, 0x144aa6030, 0x144aa6210)})
        for f in self.extra:
            begin, end = self.image.pe.base + f['begin_rva'], self.image.pe.base + f['end_rva']
            self.ranges.append((begin, end))
            for page in range(begin & ~4095, (end + 4095) & ~4095, 4096):
                if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
                self.uc.mem_map(page, 4096)
                off = self.image.offset(page - self.image.pe.base)
                self.uc.mem_write(page, self.raw[off:off + 4096])

    def start(self):
        self.heap = self.scratch + 0x10000
        self.copy_sizes, self.io_entries = [], []
        obj, archive, buffer = self.scratch + 0x1000, self.scratch + 0x2000, self.scratch + 0x8000
        self.uc.mem_write(obj, bytes(0x100))
        self.uc.mem_write(archive, bytes(128))
        self.uc.mem_write(buffer, bytes(8192))
        return obj, archive, buffer

    def hook(self, uc, address, size, user):
        if getattr(self, 'writing', False):
            return base.base.Emulator.hook(self, uc, address, size, user)
        return super().hook(uc, address, size, user)

    def invoke(self, address, obj, archive):
        stack, stop = self.scratch + 0x30000, self.scratch + 0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, obj), (x.UC_X86_REG_RDX, archive)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(address, stop, count=200000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop: raise ValueError('Lobby codec instruction budget')
        return self.uc.reg_read(x.UC_X86_REG_AL)

    def write(self, kind, strings, raw_bytes, integer):
        self.writing = True
        obj, archive, buffer = self.start()
        offsets = (0x18, 0x28, 0x40, 0x50, 0x60) if kind == 'version' else (0x10, 0x20)
        if len(strings) != len(offsets) or len(raw_bytes) != 2: raise ValueError('Lobby fixture arity')
        for offset, text in zip(offsets, strings):
            data = text.encode('utf-16le') + b'\0\0'
            pointer = self.alloc(len(data))
            self.uc.mem_write(pointer, data)
            self.uc.mem_write(obj + offset, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))
        for offset, value in zip((0x10, 0x38) if kind == 'version' else (0x34, 0x35), raw_bytes):
            self.uc.mem_write(obj + offset, bytes([value]))
        self.uc.mem_write(obj + (0x70 if kind == 'version' else 0x30), struct.pack('<I', integer))
        self.call(0x144aa62f0, archive, 1)
        self.uc.mem_write(archive + 0x18, struct.pack('<QQQ', buffer, buffer, buffer + 8192))
        self.uc.mem_write(archive + 0x30, struct.pack('<III', 8192, 0, 0))
        returned = self.invoke(VERSION_WRITER if kind == 'version' else LIST_WRITER, obj, archive)
        size = int.from_bytes(self.uc.mem_read(archive + 0x34, 4), 'little')
        if size > 8192: raise ValueError('Lobby writer budget')
        return dict(kind=kind, strings=strings, raw_bytes=raw_bytes, integer=integer,
            returned=returned, payload_hex=bytes(self.uc.mem_read(buffer, size)).hex())

    def read_result(self, data):
        self.writing = False
        obj, archive, buffer = self.start()
        if len(data) > 8192: raise ValueError('Lobby reader budget')
        # Initialized nested TimeBase fixtures; constructors are not executed.
        for offset in (0x18, 0x28):
            self.uc.mem_write(obj + offset, struct.pack('<Q', 0x1498cf2c8))
        self.uc.mem_write(buffer, data)
        self.call(0x144aa6260, archive, buffer, len(data), 1, 0)
        returned = self.invoke(RESULT_READER, obj, archive)
        return dict(payload_hex=data.hex(), returned=returned,
            consumed=int.from_bytes(self.uc.mem_read(archive + 0x30, 8), 'little') - buffer,
            result_code=int.from_bytes(self.uc.mem_read(obj + 0x10, 4), 'little'),
            flag=int.from_bytes(self.uc.mem_read(obj + 0x14, 1), 'little'),
            time_bits=[int.from_bytes(self.uc.mem_read(obj + o, 8), 'little') for o in (0x20, 0x30)],
            raw_38=int.from_bytes(self.uc.mem_read(obj + 0x38, 2), 'little'))


def expected(case):
    text = [struct.pack('<H', len(t.encode('utf-8'))) + t.encode('utf-8') for t in case['strings']]
    a, b = case['raw_bytes']
    n = struct.pack('<I', case['integer'])
    return (bytes([a]) + b''.join(text[:2]) + bytes([b]) + b''.join(text[2:]) + n
        if case['kind'] == 'version' else b''.join(text) + n + bytes([a, b]))


def build():
    em = Emulator()
    cases = []
    for kind, count in (('version', 5), ('list', 2)):
        for text in ('', 'ASCII', 'x' * 128, 'Ж界', '🙂'):
            for raw_bytes in ([0, 3], [2, 255]):
                case = em.write(kind, [text + str(i) if text else '' for i in range(count)], raw_bytes, 0xfedcba98)
                if case['returned'] != 1 or bytes.fromhex(case['payload_hex']) != expected(case):
                    raise ValueError('Lobby writer layout mismatch')
                cases.append(case)
    results = []
    for code, flag in ((0, 0), (1, 1), (0xffffffff, 2), (207, 255)):
        values = (code, flag, 0xfedcba9876543210, 0x8000000000000001, 65535)
        data = struct.pack('<IBQQH', *values)
        case = em.read_result(data)
        if (case['returned'], case['consumed'], case['result_code'], case['flag'],
                case['time_bits'], case['raw_38']) != (1, 23, code, int(bool(flag)), list(values[2:4]), 65535):
            raise ValueError('Lobby VersionResult layout mismatch')
        results.append(case)
    truncated = [em.read_result(bytes(23)[:n]) for n in range(23)]
    if any(c['returned'] for c in truncated): raise ValueError('Short VersionResult accepted')
    return dict(schema_version=1, source=em.bindings['source'], source_sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_reader_tool_sha256=hashlib.sha256((HERE / 'replay-login-result-reader.py').read_bytes()).hexdigest(),
        fragments=em.extra, cases=cases, results=results, truncated=truncated,
        trailing=em.read_result(bytes(23) + b'extra'),
        limitations=['Actual independent lobby writers/reader and inherited archive/UTF-8 routines execute.',
            'Zeroed packet/nested TimeBase vtables and preallocated archive buffers are explicit fixtures.',
            'Inherited allocation/string assignment/free/cookie fixtures; valid terminated text only.',
            'No native preparation, framing, lobby lifecycle, field semantics or live network response.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/lobby-handshake-codecs.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        writers=len(report['cases']), results=len(report['results']), truncated=len(report['truncated']))))
