"""Whole native lobby Login writer with explicit synthetic fields."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_login_writer_base', HERE / 'replay-lobby-handshake-codecs.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native = base.native
WRITER = 0x145756e80
STRINGS = (0x18, 0x28, 0x38, 0x48, 0x58, 0x70)


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.login_fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(WRITER)]})
        for f in self.login_fragments:
            begin, end = self.image.pe.base + f['begin_rva'], self.image.pe.base + f['end_rva']
            self.ranges.append((begin, end))
            for page in range(begin & ~4095, (end + 4095) & ~4095, 4096):
                if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
                self.uc.mem_map(page, 4096)
                off = self.image.offset(page - self.image.pe.base)
                self.uc.mem_write(page, self.raw[off:off + 4096])

    def write_login(self, strings, integers, raw_80):
        self.writing = True
        obj, archive, buffer = self.start()
        for offset, text in zip(STRINGS, strings):
            data = text.encode('utf-16le') + b'\0\0'
            pointer = self.alloc(len(data))
            self.uc.mem_write(pointer, data)
            self.uc.mem_write(obj + offset, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))
        for offset, value in zip((0x10, 0x14, 0x68, 0x6c), integers):
            self.uc.mem_write(obj + offset, struct.pack('<I', value))
        self.uc.mem_write(obj + 0x80, bytes([raw_80]))
        self.call(0x144aa62f0, archive, 1)
        self.uc.mem_write(archive + 0x18, struct.pack('<QQQ', buffer, buffer, buffer + 8192))
        self.uc.mem_write(archive + 0x30, struct.pack('<III', 8192, 0, 0))
        returned = self.invoke(WRITER, obj, archive)
        size = int.from_bytes(self.uc.mem_read(archive + 0x34, 4), 'little')
        if size > 8192: raise ValueError('Lobby Login writer budget')
        return dict(strings=strings, integers=integers, raw_80=raw_80, returned=returned,
            payload_hex=bytes(self.uc.mem_read(buffer, size)).hex())


def expected(case):
    parts = [struct.pack('<H', len(t.encode('utf-8'))) + t.encode('utf-8') for t in case['strings']]
    return (struct.pack('<II', *case['integers'][:2]) + b''.join(parts[:5]) +
        struct.pack('<II', *case['integers'][2:]) + parts[5] + bytes([case['raw_80']]))


def build():
    em = Emulator()
    cases = []
    for text in ('', 'ASCII-15-values', 'x' * 16, 'x' * 128, 'Ж界', '🙂'):
        for flag in (0, 1, 2, 255):
            strings = [text + str(i) if text else '' for i in range(6)]
            case = em.write_login(strings, [0, 207, 0xffffffff, 0x80000000], flag)
            if case['returned'] != 1 or bytes.fromhex(case['payload_hex']) != expected(case):
                raise ValueError('Lobby Login writer mismatch')
            cases.append(case)
    return dict(schema_version=1, source=em.bindings['source'], source_sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_codec_tool_sha256=hashlib.sha256((HERE / 'replay-lobby-handshake-codecs.py').read_bytes()).hexdigest(),
        fragments=em.login_fragments, cases=cases,
        limitations=['Whole native lobby Login writer and inherited archive/UTF-8 routines execute.',
            'Explicit packet fields/preallocated archives; inherited allocation/string/CRT fixtures.',
            'No native preparation, field-name semantics, frame, auth, socket or live Login.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/lobby-login-writer-replay.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(), cases=len(report['cases']))))
