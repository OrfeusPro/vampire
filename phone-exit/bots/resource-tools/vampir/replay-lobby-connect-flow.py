"""Execute lobby send wrapper and connected flush with bounded backend fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_flow_base', HERE / 'replay-lobby-handshake-codecs.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
native, x = base.native, base.x
WRAPPER, CONNECTED = 0x144aa89b0, 0x144aa96b0
PREPARE = 0x1467aae20


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.flow_fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(a)]
            for a in (WRAPPER, CONNECTED, 0x144aa8ac0, 0x144aa90c0)})
        self.flow_hooks = {PREPARE, 0x14420a250, 0x144aa9da0, 0x14142d840, 0x141424430,
            0x141435320, 0x1443fca20, 0x143231f80, 0x1445ead40, 0x144aa7510,
            0x1414400e0, 0x1445e7590, 0x1445e6f60, 0x1445eac20, 0x1445ea830}
        for f in self.flow_fragments:
            self.ranges.append((self.image.pe.base + f['begin_rva'], self.image.pe.base + f['end_rva']))
        pages = {p for lo, hi in self.ranges for p in range(lo & ~4095, (hi + 4095) & ~4095, 4096)}
        pages.update(a & ~4095 for a in self.flow_hooks)
        pages.update(a & ~4095 for f in self.flow_fragments for r in f['instructions'] for a in r['rip_references'])
        pages.add(0x149d84d78 & ~4095)
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: off = self.image.offset(page - self.image.pe.base)
            except ValueError: continue
            self.uc.mem_write(page, self.raw[off:off + 4096])
        self.active_flow = False

    def hook(self, uc, address, size, user):
        if not self.active_flow or address not in self.flow_hooks:
            return super().hook(uc, address, size, user)
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x14420a250:
            if a != self.peer: raise ValueError('Lobby wrapper peer changed')
            result = self.state
        elif address == PREPARE:
            if a != self.wrapper: raise ValueError('Lobby Version owner changed')
            uc.mem_write(b, struct.pack('<QQ', self.version if self.prepare_present else 0, 0))
            self.events.append(dict(action='prepare_version_fixture', present=self.prepare_present))
            result = b
        elif address == 0x144aa9da0:
            if a != self.peer or b not in (self.version, self.request): raise ValueError('Lobby lower sender changed')
            self.events.append(dict(action='lower_send_capture', packet='version' if b == self.version else 'request'))
            result = 1
        elif address == 0x14142d840: uc.mem_write(a, bytes(16))
        elif address == 0x141435320: uc.mem_write(a, bytes(0x90))
        elif address in (0x141424430, 0x1443fca20): pass
        elif address == 0x143231f80:
            if a != self.peer: raise ValueError('Lobby socket owner changed')
            result = self.peer + 0x110
        elif address == 0x1445ead40:
            if (a, b, c, d & 255) != (self.peer + 0x110, 2, 16, 1): raise ValueError('Socket configuration changed')
            self.events.append(dict(action='socket_option_capture'))
        elif address == 0x144aa7510: result = self.scratch + 0xb000
        elif address == 0x1414400e0: self.events.append(dict(action='special_helper_capture'))
        elif address in (0x1445e7590, 0x1445e6f60, 0x1445ea830):
            if a != self.peer + 0x230: raise ValueError('Lobby pending buffer offset changed')
            if address == 0x1445e7590: result = len(self.pending)
            elif address == 0x1445e6f60: result = self.pending_pointer
            else:
                self.events.append(dict(action='clear_pending_capture'))
                self.pending = b''
        elif address == 0x1445eac20:
            if (a, b, c) != (self.peer, self.pending_pointer, len(self.pending)):
                raise ValueError('Lobby flush arguments changed')
            actual = bytes(uc.mem_read(b, c))
            if actual != self.pending: raise ValueError('Lobby pending bytes changed')
            self.events.append(dict(action='transport_queue_capture', bytes_hex=actual.hex()))
            result = 1
        else: raise ValueError('Unknown lobby fixture')
        uc.reg_write(x.UC_X86_REG_RAX, result)
        stack = uc.reg_read(x.UC_X86_REG_RSP)
        target = int.from_bytes(uc.mem_read(stack, 8), 'little')
        uc.reg_write(x.UC_X86_REG_RSP, stack + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def fixture(self):
        self.peer, self.wrapper = self.scratch + 0x4000, self.scratch + 0x6000
        self.version, self.request, self.pending_pointer = self.scratch + 0x7000, self.scratch + 0x7100, self.scratch + 0x9000
        self.uc.mem_write(self.peer, bytes(0x2c0))
        self.uc.mem_write(self.wrapper, struct.pack('<Q', 0x149d84d78) + bytes(0x60))
        self.uc.mem_write(self.wrapper + 0x30, struct.pack('<Q', self.peer))
        self.events = []
        self.active_flow = True

    def run_wrapper(self, state, present):
        self.fixture()
        self.state, self.prepare_present = state, present
        returned = self.call(WRAPPER, self.wrapper, self.request)
        return dict(state_fixture=state, prepare_present_fixture=present, events=self.events, returned=returned)

    def run_connected(self, pending, special):
        self.fixture()
        self.pending = pending
        self.uc.mem_write(self.pending_pointer, pending)
        self.uc.mem_write(self.peer + 0x228, struct.pack('<H', 97))
        self.uc.mem_write(self.peer + 0x262, struct.pack('<HI', special, 123))
        self.call(CONNECTED, self.peer + 0x200)
        return dict(pending_hex=pending.hex(), special_fixture=special, events=self.events,
            pending_remaining=len(self.pending), sequence_after=int.from_bytes(self.uc.mem_read(self.peer + 0x228, 2), 'little'),
            special_bytes_after=bytes(self.uc.mem_read(self.peer + 0x262, 6)).hex())


def build():
    em = Emulator()
    wrappers = [em.run_wrapper(state, present) for state in (0, 1, 2, 3) for present in (False, True)]
    for c in wrappers:
        expected = ['version', 'request'] if c['state_fixture'] == 2 and c['prepare_present_fixture'] else ['request']
        if [e['packet'] for e in c['events'] if e['action'] == 'lower_send_capture'] != expected:
            raise ValueError('Lobby Version/request ordering changed')
    upstream = native.ROOT / 'code-clues/lobby-send-frames.json'
    frames = json.loads(upstream.read_text('utf-8'))
    pending = b''.join(bytes.fromhex(next(c['frame_hex'] for c in frames['cases']
        if c['kind'] == kind and c['sequence'] == 0)) for kind in ('version', 'list'))
    # Concatenated native frames are a pending-buffer fixture, not a sequence-valid session replay.
    connected = [em.run_connected(data, special) for data in (b'', pending) for special in (0, 1)]
    for c in connected:
        queue = [e for e in c['events'] if e['action'] == 'transport_queue_capture']
        if len(queue) != bool(c['pending_hex']) or c['pending_remaining'] or c['sequence_after'] != 97:
            raise ValueError('Lobby connected flush/sequence behavior changed')
    return dict(schema_version=1, source=em.bindings['source'], source_sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        inherited_codec_tool_sha256=hashlib.sha256((HERE / 'replay-lobby-handshake-codecs.py').read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(upstream.read_bytes()).hexdigest(),
        fragments=em.flow_fragments, wrappers=wrappers, connected=connected,
        limitations=['Actual wrapper body and connected callback execute separately.',
            'State getter, Version preparation/shared owner, lower sender, pending buffer, queue, socket option and diagnostics are fixtures/captures.',
            'Version shared control block is null; reference-count cleanup branches are not exercised.',
            'Pending bytes are synthetic concatenation of native frame vectors, not a sequence-valid or source-created pending queue.',
            'No native connect, socket readiness dispatcher, queue backend/drain, network or live lobby session.'])


if __name__ == '__main__':
    report = build()
    out = native.ROOT / 'code-clues/lobby-connect-flow.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(out), sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
        wrappers=len(report['wrappers']), connected=len(report['connected']))))
