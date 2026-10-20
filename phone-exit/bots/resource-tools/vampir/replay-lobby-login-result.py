"""Execute the separate lobby response reader with bounded synthetic inputs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_reader_base', HERE / 'replay-login-result-reader.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
READER, TABLE = 0x14574aa80, 0x1498f02b8
STRINGS = (0x20, 0x30, 0x40, 0x50, 0x60)


def payload(strings, integers, tail):
    return (struct.pack('<III', *integers) + b''.join(
        struct.pack('<H', len(t.encode('utf-8'))) + t.encode('utf-8') for t in strings)
        + struct.pack('<I', tail))


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.lobby_fragments = native.decode_ranges(self.image,
            {self.image.roots[self.image.containing(READER)]})
        self.ranges.extend((self.image.pe.base + f['begin_rva'], self.image.pe.base + f['end_rva'])
            for f in self.lobby_fragments)
        pages = {p for f in self.lobby_fragments for p in range(
            (self.image.pe.base + f['begin_rva']) & ~4095,
            (self.image.pe.base + f['end_rva'] + 4095) & ~4095, 4096)}
        pages.add(TABLE & ~4095)
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            offset = self.image.offset(page - self.image.pe.base)
            self.uc.mem_write(page, self.raw[offset:offset + 4096])

    def read_lobby(self, data):
        if len(data) > 4096: raise ValueError('Lobby fixture budget')
        self.heap = self.scratch + 0x10000
        self.copy_sizes, self.io_entries = [], []
        packet, archive, buffer = self.scratch + 0x1000, self.scratch + 0x2000, self.scratch + 0x8000
        # Explicit initialized-object fixture; the lobby constructor is not executed.
        self.uc.mem_write(packet, struct.pack('<Q', TABLE) + bytes(0x78 - 8))
        self.uc.mem_write(buffer, bytes(4096))
        self.uc.mem_write(buffer, data)
        self.call(0x144aa6260, archive, buffer, len(data), 1, 0)
        stack, stop = self.scratch + 0x30000, self.scratch + 0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, packet), (x.UC_X86_REG_RDX, archive)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(READER, stop, count=200000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop: raise ValueError('Lobby reader instruction budget')
        returned = self.uc.reg_read(x.UC_X86_REG_AL)
        strings = []
        for offset in STRINGS:
            pointer, n, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(packet + offset, 16)))
            if not 0 <= n <= capacity <= 1024: raise ValueError('Lobby FString bound')
            strings.append(bytes(self.uc.mem_read(pointer, (n - 1) * 2)).decode('utf-16le') if n else '')
        return dict(payload_hex=data.hex(), returned=returned,
            consumed=int.from_bytes(self.uc.mem_read(archive + 0x30, 8), 'little') - buffer,
            strings=strings, integers=list(struct.unpack('<III', bytes(self.uc.mem_read(packet + 0x10, 12)))),
            tail=int.from_bytes(self.uc.mem_read(packet + 0x70, 4), 'little'))


def build():
    em = Emulator()
    binding = next(p for p in em.bindings['packets'] if p['name'] == 'PktLobbyLoginResult')
    if (binding['reader'], binding['vtable'], binding['packet_id']) != (READER, TABLE, 4):
        raise ValueError('Lobby binding changed')
    cases = []
    for text in ('', 'ASCII-15-values', 'x' * 16, 'x' * 128, 'Ж界', '🙂', 'é' * 80):
        strings = [text + str(i) if text else '' for i in range(5)]
        integers, tail = [0, 207, 0xffffffff], 0xfedcba98
        data = payload(strings, integers, tail)
        case = em.read_lobby(data)
        if (case['returned'], case['consumed'], case['strings'], case['integers'], case['tail']) != (
                1, len(data), strings, integers, tail):
            raise ValueError('Lobby native response layout mismatch')
        cases.append(case)
    minimal = payload([''] * 5, [0] * 3, 0)
    text_body = payload(['🙂'] * 5, [0] * 3, 0)
    truncated = [em.read_lobby(data[:n]) for data in (minimal, text_body) for n in range(len(data))]
    if any(c['returned'] != 0 for c in truncated): raise ValueError('Short lobby response accepted')
    trailing = em.read_lobby(minimal + b'extra')
    if trailing['returned'] != 1 or trailing['consumed'] != len(minimal):
        raise ValueError('Native lobby trailing policy changed')
    return dict(schema_version=1, source=em.bindings['source'], source_sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), packet_binding=binding,
        fragments=em.lobby_fragments, cases=cases, truncated=truncated, trailing=trailing,
        inherited_reader_tool_sha256=hashlib.sha256((HERE / 'replay-login-result-reader.py').read_bytes()).hexdigest(),
        limitations=['Actual lobby reader, archive primitives and UTF-8 readers execute with synthetic bodies.',
            'Packet initial state is an explicit zeroed fixture, not a native constructor execution.',
            'Inherited allocator/string assignment/growth/free/cookie fixtures and valid-text boundaries apply.',
            'No listener, dispatch, handler, field-name semantics, network or live account response.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/lobby-login-result-replay.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        cases=len(report['cases']), truncated=len(report['truncated']))))
