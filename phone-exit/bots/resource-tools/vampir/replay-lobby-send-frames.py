"""Actual send-A assembly with lobby packet tables and whole native writers."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import zlib

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


codec = module('lobby_frame_codec', 'replay-lobby-handshake-codecs.py')
frame = module('lobby_frame_base', 'build-headless-send-frame.py')
native, x = codec.native, codec.x


class Emulator(codec.Emulator):
    def __init__(self):
        super().__init__()
        assembly = frame.SendFrameEmulator()
        if assembly.bindings['sha256'] != self.bindings['sha256']: raise ValueError('Lobby source mismatch')
        self.ranges.extend(assembly.ranges)
        bindings = json.loads((native.ROOT / 'code-clues/lobby-server-bindings.json').read_text('utf-8'))
        self.packets = {p['name']: p for p in bindings['packets']}
        self.frame_fragments, self.frame_bodies = assembly.extra_fragments, assembly.extra_bodies
        for name in ('PktLobbyVersion', 'PktLobbyServerListRead'):
            p = self.packets[name]
            self.ranges.append((p['id_getter'], p['id_getter'] + 6))
        pages = {p for lo, hi in self.ranges for p in range(lo & ~4095, (hi + 4095) & ~4095, 4096)}
        pages.update(p['vtable'] & ~4095 for p in self.packets.values())
        pages.add(0x149504000)  # Actual CRC lookup table used by the inherited frame slice.
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            offset = self.image.offset(page - self.image.pe.base)
            self.uc.mem_write(page, self.raw[offset:offset + 4096])

    def execute(self, kind, strings, raw_bytes, integer, sequence):
        body = self.write(kind, strings, raw_bytes, integer)
        obj, connection = self.scratch + 0x1000, self.scratch + 0x4000
        packet = self.packets['PktLobbyVersion' if kind == 'version' else 'PktLobbyServerListRead']
        self.uc.mem_write(obj, struct.pack('<Q', packet['vtable']))
        self.uc.mem_write(connection + 0x228, struct.pack('<H', sequence))
        rbp = self.scratch + 0x18079
        inner, outer = rbp + 7, rbp - 0x39
        for archive, buffer in ((inner, self.scratch + 0x8000), (outer, self.scratch + 0xa000)):
            self.uc.mem_write(archive, bytes(64))
            self.call(0x144aa62f0, archive, 1)
            self.uc.mem_write(archive + 0x18, struct.pack('<QQQ', buffer, buffer, buffer + 8192))
            self.uc.mem_write(archive + 0x30, struct.pack('<III', 8192, 0, 0))
        for reg, value in ((x.UC_X86_REG_RBP, rbp), (x.UC_X86_REG_RSP, self.scratch + 0x18000),
                (x.UC_X86_REG_RDI, obj), (x.UC_X86_REG_R14, connection)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(frame.START, frame.END, count=200000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != frame.END: raise ValueError('Lobby frame instruction budget')
        size = int.from_bytes(self.uc.mem_read(outer + 0x34, 4), 'little')
        if size > 8192: raise ValueError('Lobby frame fixture budget')
        return dict(body, sequence=sequence, packet_id=packet['packet_id'],
            frame_hex=bytes(self.uc.mem_read(self.scratch + 0xa000, size)).hex(),
            sequence_after=int.from_bytes(self.uc.mem_read(connection + 0x228, 2), 'little'))


def build():
    em = Emulator()
    cases = []
    for kind, count in (('version', 5), ('list', 2)):
        for text in ('', 'Ж界🙂'):
            for sequence in (0, 255, 65535):
                case = em.execute(kind, [text] * count, [0, 3], 1, sequence)
                plain = struct.pack('<HH', case['packet_id'], sequence) + bytes.fromhex(case['payload_hex'])
                encrypted = struct.pack('<I', zlib.crc32(plain)) + plain
                key = struct.pack('<Q', 0x9ab378c9d02084a7)
                wanted = (len(encrypted) + 3).to_bytes(3, 'little') + bytes(b ^ key[i % 8] for i, b in enumerate(encrypted))
                if bytes.fromhex(case['frame_hex']) != wanted or case['sequence_after'] != (sequence + 1) & 65535:
                    raise ValueError('Native lobby frame mismatch')
                cases.append(case)
    upstreams = [native.ROOT / 'code-clues/lobby-server-bindings.json',
        HERE / 'replay-lobby-handshake-codecs.py', HERE / 'build-headless-send-frame.py']
    return dict(schema_version=1, source=em.bindings['source'], source_sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstreams=[dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in upstreams],
        frame_fragments=em.frame_fragments, frame_bodies=em.frame_bodies, cases=cases,
        limitations=['Actual send-A assembly slice with lobby vtables, ID getters and full writers.',
            'Explicit packet fields, connection sequence and preallocated archives; inherited allocation/string/CRT fixtures.',
            'No full sender, readiness, connect, queued flush, syscall or server response.'])


if __name__ == '__main__':
    result = build()
    output = native.ROOT / 'code-clues/lobby-send-frames.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(), cases=len(result['cases']))))
