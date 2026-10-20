"""Native LobbyLogin preparation/constructor to sender, Version flag +14 off."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_preparation_base', HERE / 'replay-lobby-login-writer.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.base.x
PREPARE, CTOR, SENDER = 0x1467a9360, 0x145744fa0, 0x144aa89b0


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.preparation_fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(PREPARE)]})
        self.extra_leaves = []
        cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        for address in (CTOR, 0x144aaaa10):
            off = self.image.offset(address - self.image.pe.base)
            rows = []
            for row in cs.disasm(self.raw[off:off + 256], address):
                rows.append(row)
                if row.mnemonic == 'ret': break
                if row.mnemonic not in ('lea', 'mov', 'xor'): raise ValueError('Unreviewed lobby constructor/getter leaf')
            if not rows or rows[-1].mnemonic != 'ret': raise ValueError('Unbounded lobby constructor/getter')
            size = rows[-1].address + rows[-1].size - address
            data = self.raw[off:off + size]
            self.extra_leaves.append(dict(address=address, file_offset=off, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
            self.ranges.append((address, address + size))
        self.preparation_hooks = {0x141424870, 0x14142d840, 0x141424430, 0x14143c260,
            0x141420cc0, 0x1414313d0, 0x1445c63a0, 0x144aaa9d0, 0x1445c77a0,
            0x1456048a0, 0x145606660, 0x1456039c0, 0x145604b90, 0x145604960, 0x145604bf0, SENDER}
        for f in self.preparation_fragments:
            self.ranges.append((self.image.pe.base + f['begin_rva'], self.image.pe.base + f['end_rva']))
        pages = {p for lo, hi in self.ranges for p in range(lo & ~4095, (hi + 4095) & ~4095, 4096)}
        pages.update(a & ~4095 for a in self.preparation_hooks)
        pages.update(a & ~4095 for f in self.preparation_fragments for r in f['instructions'] for a in r['rip_references'])
        pages.update(a & ~4095 for a in (0x14b520d40, 0x14b520cc3, 0x14b520cc9))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: off = self.image.offset(page - self.image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, self.raw[off:off + 4096])
        self.preparing = False

    def fwrite(self, address, text):
        data = text.encode('utf-16le') + b'\0\0' if text else b''
        pointer = self.alloc(len(data)) if data else 0
        if data: self.uc.mem_write(pointer, data)
        self.uc.mem_write(address, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))

    def fread(self, address):
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 1024: raise ValueError('Preparation FString bound')
        return bytes(self.uc.mem_read(pointer, (count - 1) * 2)).decode('utf-16le') if count else ''

    def hook(self, uc, address, size, user):
        if not self.preparing or address not in self.preparation_hooks:
            return super().hook(uc, address, size, user)
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == SENDER:
            if a != self.wrapper: raise ValueError('Lobby sender owner changed')
            if int.from_bytes(uc.mem_read(b, 8), 'little') != 0x1498f0258: raise ValueError('Lobby packet table changed')
            self.packet = dict(strings=[self.fread(b + o) for o in base.STRINGS],
                integers=[int.from_bytes(uc.mem_read(b + o, 4), 'little') for o in (0x10, 0x14, 0x68, 0x6c)],
                raw_80=int.from_bytes(uc.mem_read(b + 0x80, 1), 'little'))
            uc.emu_stop()
            return
        if address == 0x141424870:
            if c > 512: raise ValueError('Preparation copy bound')
            self.fwrite(a, bytes(uc.mem_read(b, c * 2)).decode('utf-16le') if c else '')
            result = a
        elif address == 0x14142d840: self.fwrite(a, '')
        elif address == 0x141424430: pass  # Diagnostic append only in the tested flag-off branch.
        elif address in (0x14143c260, 0x141420cc0): self.fwrite(a, self.fread(b)); result = a
        elif address == 0x1414313d0:
            if not 0 <= b <= 1024: raise ValueError('Preparation FString resize bound')
            count = int.from_bytes(uc.mem_read(a + 8, 4), 'little')
            uc.mem_write(a, struct.pack('<QII', self.alloc(max(2, b * 2)), count, b))
        elif address == 0x1445c63a0: self.fwrite(a, 'nm-fixture'); result = a
        elif address == 0x144aaa9d0: result = self.game_wrapper
        elif address == 0x1445c77a0: result = self.fixture['selector']
        elif address == 0x1456048a0: result = self.manager if self.fixture['manager'] else 0
        elif address == 0x145606660: result = self.player
        elif address == 0x1456039c0: result = self.token
        elif address == 0x145604b90: self.fwrite(b, 'nid-fixture'); result = b
        elif address == 0x145604960: self.fwrite(b, 'HK'); result = b
        elif address == 0x145604bf0: self.fwrite(b, 'explicit-collected-fixture')
        else: raise ValueError('Unknown preparation fixture')
        uc.reg_write(x.UC_X86_REG_RAX, result)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        target = int.from_bytes(uc.mem_read(stack, 8), 'little')
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def prepare(self, fixture):
        self.preparing = True
        self.fixture, self.packet = fixture, None
        self.heap = self.scratch + 0x10000
        self.copy_sizes, self.io_entries = [], []
        self.wrapper, self.manager = self.scratch + 0x4000, self.scratch + 0x5000
        self.game_wrapper, self.game_peer = self.scratch + 0x7000, self.scratch + 0x7500
        self.player, self.token = self.scratch + 0x9000, self.scratch + 0x9100
        for p, n in ((self.wrapper, 0x90), (self.manager, 0x100), (self.game_wrapper, 0x190), (self.game_peer, 0x320)):
            self.uc.mem_write(p, bytes(n))
        self.fwrite(self.player, 'player-fixture'); self.fwrite(self.token, 'sdk-token-fixture')
        self.fwrite(self.wrapper + 0x40, 'previous-player-fixture')
        self.fwrite(self.wrapper + 0x50, 'previous-token-fixture')
        self.fwrite(0x14b520d40, 'global-player-fixture')
        self.uc.mem_write(0x14b520cc3, bytes([fixture['sdk_enabled']]))
        self.uc.mem_write(0x14b520cc9, b'\0')
        self.uc.mem_write(self.wrapper + 0x64, struct.pack('<I', fixture['kind']))
        self.uc.mem_write(self.game_wrapper + 0x10, struct.pack('<Q', self.game_peer))
        self.uc.mem_write(self.game_peer + 0x270, struct.pack('<I', fixture['server_id']))
        self.uc.mem_write(self.manager + 0x38, struct.pack('<Q', self.scratch + 0x6000 if fixture['sdk_auth'] else 0))
        self.uc.mem_write(self.manager + 0x48, struct.pack('<Q', self.scratch + 0x6800 if fixture['nid_info'] else 0))
        stack, stop = self.scratch + 0x30000, self.scratch + 0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.wrapper)
        self.uc.emu_start(PREPARE, stop, count=200000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != SENDER or self.packet is None:
            raise ValueError('Lobby preparation did not reach sender boundary')
        return dict(fixture=fixture, packet=self.packet, stop='sender_boundary')


def build():
    em = Emulator()
    normal = dict(selector=3, kind=0, server_id=0, sdk_enabled=True, manager=True, sdk_auth=True, nid_info=True)
    fixtures = [normal]
    fixtures += [dict(normal, selector=n) for n in (0, 1, 2, 4, 255)]
    fixtures += [dict(normal, kind=n) for n in (1, 2, 3, 0xffffffff)]
    fixtures += [dict(normal, server_id=n) for n in (42, 0xffffffff)]
    fixtures += [dict(normal, **{key:False}) for key in ('sdk_enabled', 'manager', 'sdk_auth', 'nid_info')]
    cases = [em.prepare(f) for f in fixtures]
    for case in cases:
        f, p = case['fixture'], case['packet']
        expected = [2 if f['selector'] == 3 else 1, 2 if f['kind'] == 2 else 0, f['server_id'], 0]
        if p['integers'] != expected or p['raw_80'] != 7:
            raise ValueError('Native LobbyLogin numeric fields differ')
    return dict(schema_version=1, source=em.bindings['source'], source_sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_writer_tool_sha256=hashlib.sha256((HERE / 'replay-lobby-login-writer.py').read_bytes()).hexdigest(),
        fragments=em.preparation_fragments, leaves=em.extra_leaves, cases=cases,
        limitations=['Actual native preparation prefix/constructor/field assignments and selected-server getter execute to sender entry.',
            'SDK/NID getters, platform selector, collector, strings, allocation and diagnostics are explicit fixtures.',
            'Version flag is fixed false; additional numeric-text branch, sender, destructor and full metadata collection do not execute.',
            'Kind/server state are explicit fixtures, not observed live initial values; no account/session/network proof.'])


if __name__ == '__main__':
    result = build()
    output = native.ROOT / 'code-clues/lobby-login-preparation-replay.json'
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest(), cases=len(result['cases']))))
