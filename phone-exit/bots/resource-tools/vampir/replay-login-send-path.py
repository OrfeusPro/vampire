"""Native request dedup/timeout, virtual wrapper, Login writer, frame and queue."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE/filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = module('login_send_base', 'replay-version-send-path.py')
writer = module('login_send_writer', 'replay-login-packet-writer.py')
native, x = base.native, base.x
HANDOFF, GETTER, GLOBAL, HANDLE_TABLE = 0x144aa8020, 0x144aaa9d0, 0x14b520d90, 0x149d84e50
INSERT, NOTIFY = 0x144aa7640, 0x144aa7870


class Emulator(base.Emulator):
    def __init__(self):
        super().__init__()
        self.packet_binding = next(p for p in self.bindings['packets'] if p['name'] == 'PktLogin')
        addresses = (HANDOFF, writer.WRITER, self.packet_binding['name_getter'], 0x144aa6030, 0x144aa6210)
        self.login_fragments = native.decode_ranges(self.image, {
            self.image.roots[self.image.containing(a)] for a in addresses})
        self.ranges.extend((self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva']) for f in self.login_fragments)
        self.login_leaves = []
        for address, length in ((GETTER, 8), (self.packet_binding['id_getter'], 6)):
            offset = self.image.offset(address-self.image.pe.base)
            data = self.raw[offset:offset+length]
            self.login_leaves.append(dict(address=address, file_offset=offset, bytes=data.hex(),
                sha256=hashlib.sha256(data).hexdigest()))
            self.ranges.append((address, address+length))
        getter = bytes.fromhex(self.login_leaves[0]['bytes'])
        if getter[:3] != b'\x48\x8b\x05' or GETTER+7+struct.unpack_from('<i', getter, 3)[0] != GLOBAL or getter[-1] != 0xc3:
            raise ValueError('Singleton getter binding changed')
        self.anchors = []
        for address, size in ((HANDLE_TABLE, 0x48), (self.packet_binding['vtable'], 0x40)):
            offset = self.image.offset(address-self.image.pe.base)
            self.anchors.append(dict(address=address, file_offset=offset, bytes=self.raw[offset:offset+size].hex()))
        if struct.unpack_from('<Q', bytes.fromhex(self.anchors[0]['bytes']), 0x38)[0] != base.WRAPPER:
            raise ValueError('Derived handle send slot changed')
        rows = [r for f in self.login_fragments for r in f['instructions']]
        pages = {p for begin, end in self.ranges for p in range(begin & ~4095, (end+4095) & ~4095, 4096)}
        pages.update(a & ~4095 for a in (GLOBAL, HANDLE_TABLE, INSERT, NOTIFY))
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = self.image.offset(page-self.image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, self.raw[offset:offset+4096])

    def finish_fixture(self, result=0):
        self.uc.reg_write(x.UC_X86_REG_RAX, result)
        sp = self.uc.reg_read(x.UC_X86_REG_RSP)
        ret = int.from_bytes(self.uc.mem_read(sp, 8), 'little')
        self.uc.reg_write(x.UC_X86_REG_RSP, sp+8)
        self.uc.reg_write(x.UC_X86_REG_RIP, ret)

    def hook(self, uc, address, size, user):
        if address in (HANDOFF, GETTER, writer.WRITER):
            self.events.append(dict(action='native_entry', address=address))
        if address in (INSERT, NOTIFY):
            a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
            if address == INSERT:
                kind_pointer, timeout_pointer = struct.unpack('<QQ', bytes(uc.mem_read(c, 16)))
                sp = uc.reg_read(x.UC_X86_REG_RSP)
                if a != self.manager+0x38 or d:
                    raise ValueError('Request insertion arguments changed')
                self.events.append(dict(action='request_insert_capture',
                    kind=int.from_bytes(uc.mem_read(kind_pointer, 2), 'little'),
                    timeout=struct.unpack('<f', bytes(uc.mem_read(timeout_pointer, 4)))[0],
                    opaque_argument=int.from_bytes(uc.mem_read(sp+0x30, 8), 'little')))
                uc.mem_write(b, bytes(8))
            else:
                if a != self.manager+8:
                    raise ValueError('Request notify arguments changed')
                self.events.append(dict(action='request_notify_capture',
                    callback=int.from_bytes(uc.mem_read(b, 8), 'little')))
            self.finish_fixture()
            return
        if address == 0x141420f70:
            a, b = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
            name = bytes(uc.mem_read(b, 9))
            if name != b'PktLogin\0':
                raise ValueError('Login packet name changed')
            data = 'PktLogin\0'.encode('utf-16le')
            pointer = self.alloc(len(data))
            uc.mem_write(pointer, data)
            uc.mem_write(a, struct.pack('<QII', pointer, 9, 9))
            self.events.append(dict(action='packet_name_constructor_fixture', name='PktLogin'))
            self.finish_fixture(a)
            return
        super().hook(uc, address, size, user)

    def execute_login(self, packet_fields, fixture):
        self.fixture, self.events = fixture, []
        self.heap = self.scratch+0x10000
        self.copy_sizes, self.io_entries = [], []
        self.queue_calls = self.wake_calls = 0
        b = self.scratch
        packet, wrapper, peer, queue = b+0x1000, b+0x3000, b+0x4000, b+0xa000
        self.manager = b+0xb000
        self.uc.mem_write(packet, bytes(0x140))
        self.uc.mem_write(packet, struct.pack('<Q', self.packet_binding['vtable']))
        for offset in writer.STRINGS:
            text = packet_fields['strings'][hex(offset)]
            data = text.encode('utf-16le')+b'\0\0'
            pointer = self.alloc(len(data))
            self.uc.mem_write(pointer, data)
            self.uc.mem_write(packet+offset, struct.pack('<QII', pointer, len(data)//2, len(data)//2))
        for offsets, key, fmt in ((writer.INTEGERS, 'integers', '<I'), (writer.BYTES, 'bytes', '<B'), ((0x128,), 'qwords', '<Q')):
            for offset in offsets:
                self.uc.mem_write(packet+offset, struct.pack(fmt, packet_fields[key][hex(offset)]))
        self.uc.mem_write(wrapper, struct.pack('<Q', HANDLE_TABLE))
        self.uc.mem_write(wrapper+0x10, struct.pack('<Q', peer))
        self.uc.mem_write(GLOBAL, struct.pack('<Q', wrapper))
        self.uc.mem_write(peer, bytes(0x400))
        self.uc.mem_write(peer+0x108, struct.pack('<I', 1))
        self.uc.mem_write(peer+0xc0, struct.pack('<I', int(not fixture['wake'])))
        self.uc.mem_write(peer+0x50, struct.pack('<Q', b+0x6000))
        self.uc.mem_write(b+0x6020, struct.pack('<Q', self.wake_address))
        self.uc.mem_write(peer+0x240, struct.pack('<H', fixture['sequence']))
        self.uc.mem_write(peer+0x248, struct.pack('<Q', fixture['key']))
        self.uc.mem_write(peer+0x2a5, bytes([fixture['special']]))
        self.uc.mem_write(peer+0x300, bytes([fixture['already_flag']]))
        self.uc.mem_write(base.DISABLE, bytes([fixture['disabled']]))
        self.uc.mem_write(base.FILTER, struct.pack('<Q', b+0xe000))
        self.uc.mem_write(b+0xe000, bytes(8))
        self.metadata = b+0xf000
        self.uc.mem_write(self.metadata+0x18, bytes([fixture['metadata_byte']]))
        self.uc.mem_write(peer+0x178, struct.pack('<QQQ', queue, queue+1, queue+4096))
        self.uc.mem_write(queue, b'\0')
        self.uc.mem_write(self.manager, bytes(0x100))
        self.uc.mem_write(self.manager+0x30, struct.pack('<f', fixture['default_timeout']))
        nodes, buckets = b+0xc000, b+0xd000
        self.uc.mem_write(nodes, bytes(0x100))
        count = len(fixture['pending_kinds'])
        self.uc.mem_write(self.manager+0x38, struct.pack('<Q', nodes))
        self.uc.mem_write(self.manager+0x40, struct.pack('<I', count))
        self.uc.mem_write(self.manager+0x80, struct.pack('<I', fixture['bucket_count']))
        self.uc.mem_write(buckets, b'\xff'*64)
        self.uc.mem_write(self.manager+0x70, b'\xff'*8)
        bucket_pointer = buckets if fixture['external_buckets'] else self.manager+0x70
        self.uc.mem_write(self.manager+0x78, struct.pack('<Q', buckets if fixture['external_buckets'] else 0))
        if count:
            bucket = (fixture['bucket_count']-1) & fixture['request_kind']
            self.uc.mem_write(bucket_pointer+4*bucket, struct.pack('<i', 0))
        for index, kind in enumerate(fixture['pending_kinds']):
            self.uc.mem_write(nodes+index*0x20, struct.pack('<H', kind))
            self.uc.mem_write(nodes+index*0x20+0x18, struct.pack('<i', index+1 if index+1<count else -1))
        stack, stop = b+0x30000, b+0x3f000
        self.uc.mem_write(stack, struct.pack('<Q', stop))
        self.uc.mem_write(stack+0x28, struct.pack('<f', fixture['timeout']))
        for reg, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, self.manager),
            (x.UC_X86_REG_RDX, packet), (x.UC_X86_REG_R8, fixture['request_kind']), (x.UC_X86_REG_R9, 0x12345678)):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(HANDOFF, stop, count=250000)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != stop:
            raise ValueError('Login handoff/send instruction budget')
        end = int.from_bytes(self.uc.mem_read(peer+0x180, 8), 'little')
        if not queue+1 <= end <= queue+4096:
            raise ValueError('Login queue bounds')
        frame = bytes(self.uc.mem_read(queue, end-queue-1))
        self.uc.mem_write(b+0x9000, b'\xcc'*4096)
        if frame != bytes(self.uc.mem_read(queue, len(frame))):
            raise ValueError('Login queue borrowed temporary archive')
        return dict(packet_fields=packet_fields, fixture=fixture, frame_hex=frame.hex(), events=self.events,
            sequence_after=int.from_bytes(self.uc.mem_read(peer+0x240, 2), 'little'),
            packet_byte_a=int.from_bytes(self.uc.mem_read(packet+0xa, 1), 'little'),
            queue_calls=self.queue_calls, wake_calls=self.wake_calls, queue_owns_bytes=True)


def build():
    path = native.ROOT/'code-clues/login-packet-writer-replay.json'
    prior = json.loads(path.read_text('utf-8'))
    emulator = Emulator()
    if prior['sha256'] != emulator.bindings['sha256']:
        raise ValueError('Login send source mismatch')
    default = dict(sequence=0, key=0, wake=False, metadata_present=False, metadata_byte=7,
        disabled=False, raw_mode=0, special=False, already_flag=False, timeout=0,
        default_timeout=12.5, request_kind=4, bucket_count=1, external_buckets=False, pending_kinds=[])
    cases = []
    for index, case in enumerate(prior['cases']):
        fixture = dict(default, name=case['name'], sequence=65535 if index % 2 else 0,
            key=0x1020304050607080 if index % 3 else 0, wake=bool(index % 2), metadata_present=bool(index % 2))
        cases.append(emulator.execute_login(case['packet'], fixture))
    packet = prior['cases'][0]['packet']
    extra = [dict(name='duplicate-inline', pending_kinds=[4]),
        dict(name='duplicate-chain-external', pending_kinds=[8, 12, 4], bucket_count=4, external_buckets=True),
        dict(name='collision-no-duplicate', pending_kinds=[8, 12], bucket_count=4, external_buckets=True),
        dict(name='explicit-timeout', timeout=3.25), dict(name='negative-zero-timeout', timeout=-0.0),
        dict(name='negative-timeout', timeout=-2.0), dict(name='disabled', disabled=True),
        dict(name='mode-two', raw_mode=2), dict(name='special', special=True)]
    for update in extra:
        cases.append(emulator.execute_login(packet, dict(default, **update)))
    return dict(schema_version=1, source=emulator.bindings['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        base_tool_sha256=hashlib.sha256((HERE/'replay-version-send-path.py').read_bytes()).hexdigest(),
        fragments=emulator.login_fragments+emulator.extra+emulator.send_fragments,
        writer_fragments=emulator.writer_fragments, frame_leaves=emulator.send_leaves,
        leaves=emulator.login_leaves+emulator.leaves_extra, anchors=emulator.anchors,
        encoder_leaf=emulator.encoder_leaf, cases=cases, native_execution=True, network_ready=False,
        limitations=['Actual handoff/dedup/timeout/getter/derived virtual send/wrapper/ID3/Login writer/UTF-8/frame/queue execute together.',
            'Request insert and notify are captures: no actual container mutation, callback execution, clocks or timeout expiry.',
            'Container/bucket/pending entries and handle/peer objects synthetic; real table bytes, no live singleton.',
            'Metadata/predicates/name constructor/allocator/free/memcpy/cookie/cleanup fixtures, filter empty.',
            'Archives/queue capacity4096, no growth or failure; queue wake captured, no drain/socket.',
            'Preparation supplied as earlier snapshots; no complete SDK response-to-Login path.',
            'No game launch/profile/process memory/real credentials/network/server response/session/Android.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT/'code-clues/login-send-path-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
