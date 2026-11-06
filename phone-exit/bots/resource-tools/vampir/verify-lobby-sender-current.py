"""Bounded current lobby wrapper, packet writers and full send-A assembly."""
import argparse
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import struct
import sys
import zlib

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/lobby-sender-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'lobby-sender-current-v1'
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))

from vampir_core.lobby_packets import LobbyLoginPayload, LobbyServerListPayload, LobbyVersionPayload
from vampir_core.send_frame import encode_lobby_login_frame, encode_lobby_server_list_frame, encode_lobby_version_frame

def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(ok, message):
    if not ok:
        raise ValueError('Current lobby sender ' + message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def retain(inputs, path, expected=None):
    path = Path(path).resolve()
    sha = digest(path)
    require(expected is None or sha == expected, 'input SHA differs: ' + str(path))
    inputs[str(path)] = sha
    return path


def pointer(inputs, root, item):
    return json.loads(retain(inputs, root / item['path'], item['sha256']).read_bytes())


def definition(context_path, root):
    inputs = {}
    context_path = retain(inputs, context_path)
    c = json.loads(context_path.read_bytes())
    require(c.get('schema') == 1 and c.get('recipe') == RECIPE and c.get('source_sha256') == SOURCE
            and set(c['functions']) == {'wrapper', 'sender', 'version', 'login', 'list'}
            and set(c['tables']) == set(REQUESTS) and set(c['queue']) == {'notify', 'append'},
            'recipe scope differs')
    for name in ('verify-lobby-sender-current', 'update-native-harness', 'build-native-entry-code',
                 'build-object-zero-init-code', 'audit-launcher-shape-11318', 'audit-client-release',
                 'research-workflow'):
        retain(inputs, HERE / (name + '.py'))
    core = HERE.parents[1] / 'vampir-shared/vampir_core'
    for name in ('lobby_packets', 'send_frame', 'frame_primitives', 'login_packet'):
        retain(inputs, core / (name + '.py'))
    parent = pointer(inputs, root, c['reuse']['integrity'])
    result = pointer(inputs, root, c['reuse']['integrity_result'])
    p = parent['target']
    require(p['source_sha256'] == result['source_sha256'] == SOURCE
            and result['proof']['sha256'] == c['reuse']['integrity']['sha256']
            and result['native_checksum_used'] is True and result['native_transform_used'] is True
            and result['native_wire_used'] is True and result['network_used'] is False,
            'reused OUTPUT/integrity proof differs')
    wire = pointer(inputs, root, p['wire_context'])
    require(wire['source_sha256'] == SOURCE, 'reused OUTPUT source differs')
    reference = json.loads(retain(inputs, HERE / 'knowledge/native-contexts/frame-integrity-11322.json',
                                  c['reuse']['reference_context_sha256']).read_bytes())
    require(all(reference[name] == p[name] for name in ('functions', 'leaves', 'tails', 'source_inputs')),
            'reused reference/native context differ')
    source = retain(inputs, root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe', SOURCE)
    c.update(source=str(source), function_budget=19, verify_whole_exports=True, helpers=p['helpers'],
             backend=p['backend'], archive=wire['archive'], fixtures=wire['fixtures'],
             cookie=wire['writer_metadata']['cookie'], integrity=p['integrity'], source_inputs=p['source_inputs'])
    shared = {role: at for role, at in p['functions'].items() if role.startswith('wire.')
              and role not in {'wire.login-writer', 'wire.archive.u64'}}
    wanted = set(shared.values())
    for run, sha in reference['exports'].items():
        path = root / 'ghidra/request-exports' / SOURCE / run / 'details.json'
        # Only the four exports contributing an executed archive/UTF8 root
        # enter this composition. The parent backend matrix is not executed.
        if run == 'run-fd7ea2d83bfc':
            continue
        report = json.loads(retain(inputs, path, sha).read_bytes())
        found = wanted & {row['address'] for row in report['functions']}
        require(found and report['new_source_sha256'] == SOURCE, 'reused export contributes no closure')
        wanted -= found
        c['exports'][run] = sha
    require(not wanted and len(shared) == 13, 'reused OUTPUT/UTF8 closure differs')
    c['functions'].update(shared)
    require(len(set(c['functions'].values())) == 18, 'executed root count differs')
    c['leaves'] = {**p['leaves'], **p['tails'], **c['leaves']}
    for run, sha in c['exports'].items():
        path = root / 'ghidra/request-exports' / SOURCE / run / 'details.json'
        if str(path.resolve()) not in inputs:
            retain(inputs, path, sha)
    return c, dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, inputs=inputs,
                   runtime=load('update-native-harness').runtime_inputs())


REQUESTS = {
    'version': (1, (0x18, 0x28, 0x40, 0x50, 0x60), ((0x10, 1), (0x38, 1), (0x70, 4)),
                LobbyVersionPayload, encode_lobby_version_frame),
    'login': (3, (0x18, 0x28, 0x38, 0x48, 0x58, 0x70),
              ((0x10, 4), (0x14, 4), (0x68, 4), (0x6c, 4), (0x80, 1)),
              LobbyLoginPayload, encode_lobby_login_frame),
    'list': (103, (0x10, 0x20), ((0x30, 4), (0x34, 1), (0x35, 1)),
             LobbyServerListPayload, encode_lobby_server_list_frame),
}


def inputs_for(kind, populated):
    _, text_offsets, number_fields, payload_type, encode_frame = REQUESTS[kind]
    strings = ('Ж界🙂', 'B', '', 'W' * 130, 'E', 'F')[:len(text_offsets)] if populated else ('',) * len(text_offsets)
    values = {'version': (255, 7, 0x81234567), 'login': (2, 2, 387, 0xf2345678, 7),
              'list': (0xfedcba98, 254, 199)}[kind] if populated else (0,) * len(number_fields)
    if kind == 'version':
        args = (values[:2], values[2])
    elif kind == 'login':
        args = (values[:4], values[4])
    else:
        args = (values[0], values[1:])
    return strings, values, payload_type(strings, *args), encode_frame


def cases():
    for kind in REQUESTS:
        yield kind, False, 1, 0, False, 1
        yield kind, True, 2, 65535, False, 1
    yield 'login', True, 1, 255, False, 0
    yield 'login', True, 2, 23, True, 1


def expected_case(kind, populated, peer_state, seq, gate, direct_ret, payload_override=None):
    packet_id = REQUESTS[kind][0]
    _, _, payload, encode_frame = inputs_for(kind, populated)
    if payload_override is not None:
        require(kind == 'login' and isinstance(payload_override, LobbyLoginPayload), 'prepared payload type differs')
        payload = payload_override
    expected_frame = encode_frame(payload, seq, max_payload_size=1000)
    return dict(kind=kind, populated=populated, peer_state=peer_state, sequence_before=seq,
                suppressed=gate, return_byte=1 if gate or peer_state == 2 else direct_ret,
                path='suppressed' if gate else 'queued' if peer_state == 2 else 'direct',
                sequence_after=seq if gate else (seq + 1) & 65535,
                frame_sha256=None if gate else hashlib.sha256(expected_frame).hexdigest(),
                frame_size=0 if gate else len(expected_frame), request_id=None if gate else packet_id)


class Replay:
    def __init__(self, c, root):
        self.c = c
        self.f = f = {role: int(at, 16) for role, at in c['functions'].items()}
        self.h = h = load('update-native-harness').make_harness(
            c, c['exports'], set(f.values()), {int(at, 16): data for at, data in c['leaves'].items()}, root=root)
        self.uc, self.x = h.uc, h.x
        self.packet, self.wrapper, self.peer, self.table = (h.scratch + i for i in (0x1000, 0x3000, 0x4000, 0x5000))
        self.heap_start = h.scratch + 0x9000
        self.pending_fixture = h.scratch + 0x6000
        self.gate = int(c['backend']['globals']['gate'], 16)
        self.archive_table = int(c['archive']['table'], 16)
        self.cleanup_at = int(c['backend']['cleanup_wrapper'], 16)
        self.crc_at = int(c['integrity']['update'], 16)
        self.xor_at = int(c['integrity']['transform'], 16)
        self.notify_at, self.queue_at = (int(c['queue'][name], 16) for name in ('notify', 'append'))
        self.direct_at = int(c['backend']['transport'], 16)
        for item in (*c['source_inputs'].values(), c['integrity']['table']):
            if 'bytes' in item:
                address, data = int(item['address'], 16), bytes.fromhex(item['bytes'])
                require(self.source(address, len(data)) == data, 'reused source data differ')
                self.map_source(address, len(data))
        for kind, row in c['tables'].items():
            address = int(row['address'], 16)
            self.map_source(address, 0x30)
            require(self.num(address + 0x10) == f[kind] and self.num(address + 0x28) == int(row['id_getter'], 16),
                    'packet writer/ID table linkage differs')
        for slot, helper in ((0x28, 'string'), (0x88, 'raw'), (0xc0, 'u32'), (0xc8, 'u32'),
                             (0xd0, 'u16'), (0xd8, 'u16'), (0xe0, 'u8'), (0xf0, 'bool')):
            require(self.num(self.archive_table + slot) == int(c['archive'][helper], 16),
                    'archive OUTPUT table linkage differs')
        # Source wrapper dispatches through +0x40. The ambient pending provider
        # is supplied as an empty shared pointer in this composition.
        self.put(self.table + 0x40, self.pending_fixture)
        h.add_fixture(self.pending_fixture, self.no_pending)
        for at, fn in ((self.notify_at, self.queue_notify), (self.queue_at, self.deliver),
                       (self.direct_at, self.deliver), (int(c['archive']['growth'], 16), self.grow)):
            h.add_fixture(at, fn)
        fixtures = dict(cpp_allocate=self.cpp_allocate, cpp_free=self.free,
                        utf8_allocate=self.utf8_allocate, utf8_free=self.free, security_check=self.cookie)
        for role, fn in fixtures.items():
            h.add_fixture(int(c['fixtures'][role], 16), fn)
        import unicorn
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.observe)

    def reg(self, name):
        return self.uc.reg_read(getattr(self.x, 'UC_X86_REG_' + name))

    def set_reg(self, name, value):
        self.uc.reg_write(getattr(self.x, 'UC_X86_REG_' + name), value)

    def num(self, at, width=8):
        return int.from_bytes(self.uc.mem_read(at, width), 'little')

    def put(self, at, value, width=8):
        self.uc.mem_write(at, value.to_bytes(width, 'little'))

    def source(self, at, size):
        offset = self.h.image.offset(at - self.h.image.pe.base)
        return self.h.raw[offset:offset + size]

    def map_source(self, at, size):
        for page in range(at & ~4095, ((at + size - 1) & ~4095) + 4096, 4096):
            if not any(left <= page <= right for left, right, _ in self.uc.mem_regions()):
                self.uc.mem_map(page, 4096)
                self.uc.mem_write(page, self.source(page, 4096))

    def allocate(self, size, kind):
        require(0 < size <= 2048 and self.heap + size < self.h.scratch + 0x20000, 'fixture allocation extent differs')
        pointer = self.heap + 16
        self.heap += (size + 63) & ~15
        self.allocations[pointer] = (size, kind)
        self.uc.mem_write(pointer - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        return pointer

    def cpp_allocate(self, machine):
        self.h.finish(self.allocate(self.reg('RCX'), 'cpp'))

    def utf8_allocate(self, machine):
        target, size = self.reg('RCX'), self.reg('R8')
        require(self.num(target) == 0 and self.reg('RDX') == 0 and self.reg('R9') == 1 and size >= 129,
                'UTF8 allocation arguments differ')
        self.put(target, self.allocate(size, 'utf8'))
        self.h.finish(0)

    def free(self, machine):
        pointer = self.reg('RCX')
        size, kind = self.allocations[pointer]
        require(pointer not in self.released and kind != 'input', 'allocation freed twice or input freed')
        if kind == 'archive':
            require(pointer == self.num(self.archives[self.cleanups[-1]] + 0x18), 'archive freed out of order')
        self.released.add(pointer)
        self.h.finish(0)

    def cookie(self, machine):
        require(self.reg('RCX') == int.from_bytes(self.source(int(self.c['cookie'], 16), 8), 'little'),
                'source stack cookie differs')
        self.h.finish(self.reg('RAX'))

    def grow(self, machine):
        archive, size = self.reg('RCX') - 0x18, self.reg('RDX')
        require(archive in self.archives and size == 1024 and self.num(archive + 0x30, 4) == size
                and bytes(self.uc.mem_read(archive + 0x18, 24)) == bytes(24),
                'archive initial growth arguments differ')
        ptr = self.allocate(size, 'archive')
        self.uc.mem_write(archive + 0x18, struct.pack('<QQQ', ptr, ptr + size, ptr + size))
        self.h.finish(0)

    def contents(self, archive):
        ptr, end, limit = struct.unpack('<QQQ', self.uc.mem_read(archive + 0x18, 24))
        capacity, size, count = struct.unpack('<III', self.uc.mem_read(archive + 0x30, 12))
        require(size == count and 0 <= count <= capacity == 1024 and end == limit == ptr + capacity
                and ptr not in self.released and self.allocations.get(ptr) == (capacity, 'archive'),
                'archive bytes/cursor differ')
        return ptr, bytes(self.uc.mem_read(ptr, size))

    def no_pending(self, machine):
        target = self.reg('RDX')
        require(self.reg('RCX') == self.wrapper and self.peer_state == 2
                and bytes(self.uc.mem_read(target, 16)) == bytes(16), 'pending provider input differs')
        self.pending_calls += 1
        self.h.finish(target)

    def queue_notify(self, machine):
        require(self.reg('RCX') == self.peer and self.peer_state == 2 and self.cleanups == [1],
                'queued notification boundary differs')
        self.notified += 1
        self.h.finish(0)

    def deliver(self, machine):
        queued = self.reg('RIP') == self.queue_at
        require(queued == (self.peer_state == 2) and self.notified == int(queued)
                and self.reg('RCX') == self.peer + (0x230 if queued else 0)
                and self.cleanups == [1] and self.frame is None, 'transport call order/receiver differs')
        ptr, frame = self.contents(self.archives[0])
        require((ptr, len(frame)) == (self.reg('RDX'), self.reg('R8')), 'transport extent differs')
        self.frame = frame
        self.h.finish(0xa5a5a5a500000000 | self.direct_ret)

    def observe(self, machine, at, size, unused):
        if at == self.f['sender']:
            require(self.reg('RCX') == self.peer and self.reg('RDX') == self.packet, 'wrapper handoff differs')
            self.sender_calls += 1
        elif at == self.f['wire.archive.constructor']:
            self.archives.append(self.reg('RCX'))
        elif at == self.f[self.kind]:
            require(len(self.archives) == 2 and self.reg('RCX') == self.packet
                    and self.reg('RDX') == self.archives[1], 'writer native dispatch differs')
            self.writers += 1
        elif at == self.id_getter:
            require(self.reg('RCX') == self.packet, 'packet ID receiver differs')
            self.ids += 1
        elif at == self.crc_at:
            ptr, body = self.contents(self.archives[1])
            require(self.reg('RDX') == ptr and self.reg('R8') == len(body)
                    and self.num(self.reg('RCX'), 4) == 0xffffffff and body == self.inner,
                    'native packet bytes / CRC arguments differ')
            self.crcs += 1
        elif at == self.xor_at:
            ptr, frame = self.contents(self.archives[0])
            require(self.reg('RCX') == self.reg('R8') == ptr + 3 and self.reg('RDX') == len(frame) - 3
                    and self.reg('R9') == 0 and frame == self.plain_frame, 'native CRC / transform arguments differ')
            self.transforms += 1
        elif at == self.cleanup_at:
            self.cleanups.append(self.archives.index(self.reg('RCX')))

    def run(self, kind, populated, peer_state, seq, gate, direct_ret, payload_override=None):
        self.kind, self.peer_state, self.direct_ret = kind, peer_state, direct_ret
        self.id_getter = int(self.c['tables'][kind]['id_getter'], 16)
        self.archives, self.cleanups, self.allocations, self.released = [], [], {}, set()
        self.writers = self.ids = self.crcs = self.transforms = self.pending_calls = self.notified = self.sender_calls = 0
        self.heap, self.frame = self.heap_start, None
        packet_id, text_offsets, number_fields, _, _ = REQUESTS[kind]
        strings, values, payload, encode_frame = inputs_for(kind, populated)
        if payload_override is not None:
            require(kind == 'login' and isinstance(payload_override, LobbyLoginPayload), 'prepared payload type differs')
            payload = payload_override
            strings = payload.strings
            values = payload.integers + (payload.raw_80,)
        self.inner = struct.pack('<HH', packet_id, seq) + payload.encode(max_payload_size=1000)
        self.plain_frame = (len(self.inner) + 7).to_bytes(3, 'little') + struct.pack('<I', zlib.crc32(self.inner)) + self.inner
        self.uc.mem_write(self.peer - 16, b'\xa5' * 16 + bytes(0x300) + b'\xa6' * 16)
        self.put(self.peer + 0x108, peer_state, 4)
        self.put(self.peer + 0x228, seq, 2)
        self.put(self.gate, int(gate), 1)
        self.uc.mem_write(self.wrapper - 16, b'\xa5' * 16 + bytes(0x38) + b'\xa6' * 16)
        self.put(self.wrapper, self.table)
        self.put(self.wrapper + 0x30, self.peer)
        self.uc.mem_write(self.packet - 16, b'\xa5' * 16 + bytes(0x88) + b'\xa6' * 16)
        self.put(self.packet, int(self.c['tables'][kind]['address'], 16))
        for offset, text in zip(text_offsets, strings):
            if text:
                encoded = text.encode('utf-16-le') + b'\0\0'
                ptr = self.allocate(len(encoded), 'input')
                self.uc.mem_write(ptr, encoded)
                self.uc.mem_write(self.packet + offset, struct.pack('<QII', ptr, len(encoded) // 2, len(encoded) // 2))
        for (offset, width), value in zip(number_fields, values):
            self.put(self.packet + offset, value, width)
        bounds = [(self.packet - 16, 0xa8), (self.wrapper - 16, 0x58), (self.peer - 16, 0x238),
                  (self.peer + 0x22a, 0xe6)]
        bounds.extend((at - 16, size + 32) for at, (size, _) in self.allocations.items())
        snapshots = [(at, bytes(self.uc.mem_read(at, size))) for at, size in bounds]
        stack, stop = self.h.scratch + 0x38008, self.h.scratch + 0x3f000
        self.uc.mem_write(stack - 0x2000, bytes(0x2100))
        self.put(stack, stop)
        preserved = {name: 0x534b000100000000 + i
                     for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in preserved.items():
            self.set_reg(name, value)
        self.set_reg('RSP', stack)
        self.set_reg('RCX', self.wrapper)
        self.set_reg('RDX', self.packet)
        self.uc.emu_start(self.f['wrapper'], 0, count=300000)
        require(self.reg('RIP') == stop and self.reg('RSP') == stack + 8
                and all(self.reg(name) == value for name, value in preserved.items()), 'wrapper Win64 ABI differs')
        require(all(bytes(self.uc.mem_read(at, len(data))) == data for at, data in snapshots), 'packet/peer/string changed')
        for at, (size, alloc_kind) in self.allocations.items():
            require(bytes(self.uc.mem_read(at - 16, 16)) == b'\xa5' * 16
                    and bytes(self.uc.mem_read(at + size, 16)) == b'\xa6' * 16
                    and (at in self.released) == (alloc_kind != 'input'), 'allocation guard or ownership differs')
        active = int(not gate)
        require(self.sender_calls == 1 and self.writers == self.ids == self.crcs == self.transforms == active
                and len(self.archives) == 2 * active and self.cleanups == ([1, 0] if active else [])
                and self.pending_calls == int(peer_state == 2), 'native composition counts differ')
        require(self.frame == (encode_frame(payload, seq, max_payload_size=1000) if active else None),
                'native transport frame differs from portable codec')
        row = expected_case(kind, populated, peer_state, seq, gate, direct_ret, payload_override)
        require(self.reg('RAX') & 255 == row['return_byte'] and self.num(self.peer + 0x228, 2) == row['sequence_after'],
                'native sender sequence/return differs')
        return row


def validate(report, selected):
    require(report.get('definition') == selected and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('native_execution') is True
            and report.get('network_used') is False and report.get('runtime_admitted') is False
            and report.get('limits')
            and report.get('cases') == [expected_case(*case) for case in cases()], 'report differs')


def verify_report(path, *, context_path=CONTEXT, root=ROOT):
    _, selected = definition(context_path, Path(root).resolve())
    report = json.loads(Path(path).read_bytes())
    validate(report, selected)
    return report


def verify(context_path=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    c, selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge/lobby-sender-current-cache' / (key + '.json')
    if cache.is_file():
        item = json.loads(cache.read_bytes())
        path = root / 'code-clues' / RECIPE / item['sha256'] / 'manifest.json'
        require(Path(item['path']).resolve() == path and digest(path) == item['sha256'], 'cache pointer differs')
        validate(json.loads(path.read_bytes()), selected)
        return dict(report=str(path), sha256=item['sha256'], reused=True)
    replay = Replay(c, root)
    result = [replay.run(*case) for case in cases()]
    require(all(digest(path) == sha for path, sha in selected['inputs'].items()), 'post-execution SHA barrier differs')
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, cases=result,
                  native_execution=True, network_used=False, runtime_admitted=False,
                  limits=['Current wrapper, sender, three packet writers, OUTPUT/UTF8, CRC and fallback XOR execute.',
                          'Peer readiness, queue notification, transport capture, allocation, growth and CRT remain fixtures.',
                          'No native socket drain, live server acceptance or runtime admission.'])
    validate(report, selected)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    item = dict(path=str(path), sha256=digest(path))
    workflow.atomic(cache, workflow.canonical(item))
    return dict(report=item['path'], sha256=item['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
