"""Execute Login writer with actual FString UTF-8 conversion and archive IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('login_writer_base', HERE / 'replay-version-packet-writer.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
spec = importlib.util.spec_from_file_location('login_prepare_base', HERE / 'replay-login-packet-fields.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
native, x = base.native, base.x
WRITER = 0x1456e57c0
STRINGS = (0x10, 0x20, 0x30, 0x40, 0x58, 0x68, 0x78, 0x88, 0xa0, 0xb8, 0xc8, 0xd8, 0xe8, 0x100, 0x110)
INTEGERS = (0x50, 0xb0, 0xf8, 0x120)
BYTES = (0x98, 0x99, 0x124, 0x130, 0x131)
# From the Ghidra writer, then checked against native execution.
ORDER = tuple([('s', o) for o in STRINGS[:4]] + [('i', 0x50)] +
    [('s', o) for o in STRINGS[4:8]] + [('b', 0x98), ('b', 0x99), ('s', 0xa0), ('i', 0xb0)] +
    [('s', o) for o in STRINGS[9:13]] + [('i', 0xf8), ('s', 0x100), ('s', 0x110),
    ('i', 0x120), ('b', 0x124), ('q', 0x128), ('b', 0x130), ('b', 0x131)])


def expected(packet):
    parts = []
    for kind, offset in ORDER:
        if kind == 's':
            data = packet['strings'][hex(offset)].encode('utf-8')
            parts.extend((struct.pack('<H', len(data)), data))
        else:
            value = packet[{'i': 'integers', 'b': 'bytes', 'q': 'qwords'}[kind]][hex(offset)]
            parts.append(struct.pack({'i': '<I', 'b': '<B', 'q': '<Q'}[kind], value))
    return b''.join(parts)


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.login_fragments = native.decode_ranges(self.image, {
            self.image.roots[self.image.containing(a)] for a in (WRITER, 0x144aa6030, 0x144aa6210)})
        for fragment in self.login_fragments:
            begin, end = (self.image.pe.base + fragment[k] for k in ('begin_rva', 'end_rva'))
            self.ranges.append((begin, end))
            for page in range(begin & ~4095, (end + 4095) & ~4095, 4096):
                if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                    continue
                self.uc.mem_map(page, 4096)
                off = self.image.offset(page - self.image.pe.base)
                self.uc.mem_write(page, self.raw[off:off+4096])
        self.raw_calls = 0
        self.fail_at = None

    def hook(self, uc, address, size, user):
        if address == 0x144aa6120:
            self.raw_calls += 1
            if self.raw_calls == self.fail_at:
                # Failure fixture tests propagation; not real allocator failure.
                archive = uc.reg_read(x.UC_X86_REG_RCX)
                self.failure = dict(offset=int.from_bytes(uc.mem_read(archive+0x34, 4), 'little'),
                                    length=uc.reg_read(x.UC_X86_REG_R8))
                uc.reg_write(x.UC_X86_REG_RAX, 0)
                sp = uc.reg_read(x.UC_X86_REG_RSP)
                ret = int.from_bytes(uc.mem_read(sp, 8), 'little')
                uc.reg_write(x.UC_X86_REG_RSP, sp+8)
                uc.reg_write(x.UC_X86_REG_RIP, ret)
                return
        super().hook(uc, address, size, user)

    def execute_login(self, packet, fail_at=None):
        self.heap = self.scratch + 0x10000
        self.copy_sizes, self.io_entries = [], []
        self.raw_calls, self.fail_at = 0, fail_at
        self.failure = None
        obj, archive, buffer = self.scratch+0x1000, self.scratch+0x2000, self.scratch+0x8000
        self.uc.mem_write(obj, bytes(0x140))
        self.uc.mem_write(archive, bytes(128))
        self.uc.mem_write(buffer, b'\xcc'*8192)
        for offset in STRINGS:
            text = packet['strings'][hex(offset)]
            data = text.encode('utf-16le')+b'\0\0'
            pointer = self.alloc(len(data))
            self.uc.mem_write(pointer, data)
            self.uc.mem_write(obj+offset, struct.pack('<QII', pointer, len(data)//2, len(data)//2))
        for offsets, key, fmt in ((INTEGERS, 'integers', '<I'), (BYTES, 'bytes', '<B'), ((0x128,), 'qwords', '<Q')):
            for offset in offsets:
                self.uc.mem_write(obj+offset, struct.pack(fmt, packet[key][hex(offset)]))
        self.call(0x144aa62f0, archive, 1)
        self.uc.mem_write(archive+0x18, struct.pack('<QQQ', buffer, buffer, buffer+8192))
        self.uc.mem_write(archive+0x30, struct.pack('<III', 8192, 0, 0))
        stack, stop = self.scratch+0x30000, self.scratch+0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, obj), (x.UC_X86_REG_RDX, archive)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(WRITER, stop, count=200000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Login writer instruction budget')
        size = int.from_bytes(self.uc.mem_read(archive+0x34, 4), 'little')
        if not 0 <= size <= 8192:
            raise ValueError('Login writer output bound')
        return dict(packet=packet, returned=self.uc.reg_read(x.UC_X86_REG_AL), size=size,
            payload_hex=bytes(self.uc.mem_read(buffer, size)).hex(), raw_calls=self.raw_calls,
            fail_at=fail_at, failure=self.failure)


def build():
    path = native.ROOT / 'code-clues/login-packet-fields-replay.json'
    prior = json.loads(path.read_text('utf-8'))
    emulator = Emulator()
    if prior['sha256'] != emulator.bindings['sha256']:
        raise ValueError('Login writer source mismatch')
    class Capture(prepare.Replay):
        def hook(self, uc, address, size, user):
            if address == 0x144aa8020:
                packet = uc.reg_read(x.UC_X86_REG_RDX)
                value = int.from_bytes(uc.mem_read(packet+0x128, 8), 'little')
                super().hook(uc, address, size, user)
                self.packet['qwords'] = {'0x128': value}
            else:
                super().hook(uc, address, size, user)
    fixtures = []
    for case in prior['cases']:
        run = Capture(emulator.raw, emulator.image, prior['fragments'], prior['leaves'], case['fixture'], prior['globals']).capture()
        packet = run['packet']
        if {k: v for k, v in packet.items() if k != 'qwords'} != case['packet']:
            raise ValueError('Login preparation snapshot changed')
        fixtures.append((case['fixture']['name'], packet))
    distinct = dict(strings={hex(o): 'field-'+hex(o) for o in STRINGS},
        integers={hex(o): v for o, v in zip(INTEGERS, (0x01020304, 0xffffffff, 207, 0))},
        bytes={hex(o): v for o, v in zip(BYTES, (255, 128, 7, 2, 255))},
        qwords={'0x128': 0xfedcba9876543210})
    fixtures.append(('distinct-fields-and-raw-bool-bytes', distinct))
    for index, text in enumerate(('', 'a'*15, 'a'*16, 'a'*127, 'a'*128, 'Ж界', '🙂', 'é'*80)):
        packet = dict(distinct, strings={hex(o): text if o == STRINGS[index % 15] else '' for o in STRINGS})
        fixtures.append(('boundary-'+str(index), packet))
    cases = []
    for name, packet in fixtures:
        case = emulator.execute_login(packet)
        if case['returned'] != 1 or bytes.fromhex(case['payload_hex']) != expected(packet):
            raise ValueError('Login writer layout mismatch: '+name)
        cases.append(dict(name=name, **case))
    # Every raw IO failure point on a packet with all strings nonempty.
    success = emulator.execute_login(distinct)
    failures = []
    full = bytes.fromhex(success['payload_hex'])
    io_order = [kind for kind, _ in ORDER for _ in range(2 if kind == 's' else 1)]
    if success['raw_calls'] != len(io_order):
        raise ValueError('Login raw IO call count changed')
    for call, kind in enumerate(io_order, 1):
        case = emulator.execute_login(distinct, fail_at=call)
        failed = case['failure']
        ignored = kind == 's'
        wanted = full[:failed['offset']] + (full[failed['offset']+failed['length']:] if ignored else b'')
        if case['returned'] != int(ignored) or case['raw_calls'] != (len(io_order) if ignored else call) or bytes.fromhex(case['payload_hex']) != wanted:
            raise ValueError('Login writer failure propagation changed')
        failures.append(dict(ignored_by_string_helper=ignored, **case))
    table_off = emulator.image.offset(base.ping.WRITE_TABLE-emulator.image.pe.base)
    table = emulator.raw[table_off:table_off+0xf8]
    for slot, target in ((0xb8, 0x144aa61e0), (0xc8, 0x144aa6090), (0xe0, 0x144aa6030), (0xf0, 0x144aa6210)):
        if struct.unpack_from('<Q', table, slot)[0] != target:
            raise ValueError('Login archive dispatch changed')
    binding = next(p for p in emulator.bindings['packets'] if p['name'] == 'PktLogin')
    slot = binding['vtable'] + binding['writer_slot']
    offset = emulator.image.offset(slot-emulator.image.pe.base)
    anchor = emulator.raw[offset:offset+8]
    if binding['writer'] != WRITER or struct.unpack('<Q', anchor)[0] != WRITER:
        raise ValueError('Login writer packet binding changed')
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        base_tool_sha256=hashlib.sha256((HERE/'replay-version-packet-writer.py').read_bytes()).hexdigest(),
        preparation_tool_sha256=hashlib.sha256((HERE/'replay-login-packet-fields.py').read_bytes()).hexdigest(),
        packet_binding=binding,
        packet_writer_anchor=dict(address=slot, file_offset=offset, bytes=anchor.hex()),
        fragments=emulator.login_fragments, string_fragments=emulator.writer_fragments,
        encoder_leaf=emulator.encoder_leaf, archive_fragments=emulator.fragments,
        archive_leaves=emulator.leaves,
        archive_table=dict(address=base.ping.WRITE_TABLE, file_offset=table_off, bytes=table.hex(),
                           sha256=hashlib.sha256(table).hexdigest()),
        field_order=[dict(kind=k, offset=o) for k, o in ORDER], cases=cases, failures=failures,
        native_execution=True, network_ready=False,
        limitations=['Actual Login writer/UTF-8 conversion/archive primitives execute; allocator/free/cookie/memcpy fixtures.',
            'Prior preparation snapshots feed separate serialization runs; no full constructor-to-frame path.',
            'Extended native preparation captures qword128 at handoff (zero in covered fixtures); field semantics unknown.',
            'Raw bool slot writes byte unchanged; portable codec rejects out-of-range values but does not normalize.',
            'Failures injected at raw IO entry only: FString ignores this return, scalar writer propagates; real capacity/growth unverified.',
            'Terminated valid text only; invalid UTF-16/embedded NUL/uint16 overflow not native-tested.',
            'No game launch/profile/process memory/credentials/network/auth/session/server response/Android.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/login-packet-writer-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         cases=len(report['cases']), failures=len(report['failures']))))
