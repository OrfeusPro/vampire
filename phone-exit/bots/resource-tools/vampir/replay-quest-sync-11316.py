"""Whole current ID1854 input, including typed copies. Bounded fresh storage only."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run():
    context_path = HERE / 'knowledge/native-contexts/quest-sync-11316.json'
    context = json.loads(context_path.read_text('utf-8'))
    functions = {k: int(v, 16) for k, v in context['functions'].items()}
    h = load('native-request-harness-11316').make_harness(context['exports'], set(functions.values()),
        leaves={int(k, 16): v for k, v in context['leaves'].items()})
    if h.sha != context['source_sha256']:
        raise ValueError('Quest sync context source differs')
    for table, slot, target in context['bindings']:
        offset = h.image.offset(int(table, 16) + int(slot, 16) - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, offset)[0] != int(target, 16):
            raise ValueError('Quest sync virtual/descriptor binding differs')
    uc, x = h.uc, h.x
    packet, archive, buffer = [h.scratch + n for n in (0x2000, 0x4000, 0x5000)]
    allocations = {}
    heap = [h.scratch + 0x10000]

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def number(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def allocate(machine):
        container, n = reg('RCX'), reg('RDX') & 0xffffffff
        stride = 32 if reg('RIP') == 0x141437f60 else 72
        pointer, count, capacity = struct.unpack('<QII', uc.mem_read(container, 16))
        if pointer or capacity or count not in (0, n) or n > 8:
            raise ValueError('Only fresh bounded quest allocation is fixture')
        size = n * stride
        pointer = heap[0] + 16 if n else 0
        if n:
            heap[0] += (size + 47) & ~15
            if heap[0] > h.scratch + 0x30000:
                raise ValueError('Quest heap budget exceeded')
            uc.mem_write(pointer - 16, b'\xb1' * 16 + bytes(size) + b'\xb2' * 16)
            allocations[pointer] = dict(size=size, stride=stride, capacity=n, freed=False)
        uc.mem_write(container, struct.pack('<QII', pointer, count, n))
        h.finish()

    def empty_groups(machine):
        if reg('RCX') or (reg('RDX') & 0xffffffff):
            raise ValueError('Only empty previous group cleanup is fixture')
        h.finish()

    def cleanup_quests(machine):
        pointer, n = reg('RCX'), reg('RDX') & 0xffffffff
        if pointer:
            allocation = allocations.get(pointer)
            if not allocation or allocation['freed'] or allocation['stride'] != 72 or n > allocation['capacity']:
                raise ValueError('Quest temporary cleanup is outside tracked storage')
        elif n:
            raise ValueError('Nonempty null quest cleanup')
        h.finish()

    def free(machine):
        pointer = reg('RCX')
        allocation = allocations.get(pointer)
        if not allocation or allocation['freed']:
            raise ValueError('Untracked or repeated quest free')
        allocation['freed'] = True
        uc.mem_write(pointer, b'\xdd' * allocation['size'])
        h.finish()

    def no_growth(machine):
        raise ValueError('Fresh reserved quest storage grew')

    for address in (0x141437f60, 0x141865280, 0x141864f90):
        h.add_fixture(address, allocate)
    h.add_fixture(0x145782280, empty_groups)
    h.add_fixture(0x145782250, cleanup_quests)
    h.add_fixture(0x141483080, free)
    for address in (0x141437520, 0x1414d7f70):
        h.add_fixture(address, no_growth)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.quest_sync import decode_quest_sync

    def read(body):
        allocations.clear()
        heap[0] = h.scratch + 0x10000
        uc.mem_write(packet - 16, b'\xa1' * 16 + bytes(64) + b'\xa2' * 16)
        uc.mem_write(buffer - 16, b'\xa3' * 16 + body + b'\xa4' * 16)
        uc.mem_write(archive, bytes(64))
        if h.call(functions['packet_constructor'], packet) != packet:
            raise ValueError('Quest sync constructor return differs')
        if (number(packet), number(packet + 16), h.call(0x145834440, packet)) != (0x1499654c0, 0x149948c10, 1854):
            raise ValueError('Actual quest sync packet/nested type or ID differs')
        uc.reg_write(x.UC_X86_REG_RDX, buffer)
        uc.reg_write(x.UC_X86_REG_R8, len(body))
        uc.reg_write(x.UC_X86_REG_R9, 1)
        uc.mem_write(h.scratch + 0x38028, bytes(8))
        h.call(functions['input_constructor'], archive)
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        accepted = bool(h.call(functions['reader'], packet, budget=1000000) & 255)
        consumed = number(archive + 0x30) - buffer
        if not 0 <= consumed <= len(body):
            raise ValueError('Quest input cursor exceeded body')
        for at, guard in ((packet - 16, b'\xa1' * 16), (packet + 64, b'\xa2' * 16),
                          (buffer - 16, b'\xa3' * 16), (buffer + len(body), b'\xa4' * 16)):
            if bytes(uc.mem_read(at, 16)) != guard:
                raise ValueError('Quest input/object guard changed')
        for pointer, allocation in allocations.items():
            if bytes(uc.mem_read(pointer - 16, 16)) != b'\xb1' * 16 or bytes(uc.mem_read(pointer + allocation['size'], 16)) != b'\xb2' * 16:
                raise ValueError('Quest allocation guard changed')
        return accepted, consumed

    def live_storage(pointer, n, stride):
        if n:
            allocation = allocations.get(pointer)
            if not allocation or allocation['freed'] or (allocation['capacity'], allocation['stride']) != (n, stride):
                raise ValueError('Final quest data references invalid storage')
        elif pointer:
            raise ValueError('Unexpected empty quest pointer')

    def compare(expected):
        pointer, n, capacity = struct.unpack('<QII', uc.mem_read(packet + 24, 16))
        if (n, capacity) != (len(expected.groups), len(expected.groups)) or number(packet + 40) != expected.raw18:
            raise ValueError('Quest sync group count or suffix differs')
        live_storage(pointer, n, 32)
        for index, group in enumerate(expected.groups):
            at = pointer + index * 32
            if number(at) != 0x149948bc8 or number(at + 8, 1) != group.raw08:
                raise ValueError('Quest group type differs')
            quests, count, cap = struct.unpack('<QII', uc.mem_read(at + 16, 16))
            if (count, cap) != (len(group.quests), len(group.quests)):
                raise ValueError('Quest group size differs')
            live_storage(quests, count, 72)
            for j, record in enumerate(group.quests):
                address = quests + j * 72
                if number(address) != 0x149948b88 or number(address + 24) != 0x149948b40:
                    raise ValueError('Final typed quest copy differs')
                actual = (number(address + 8), number(address + 16, 1), number(address + 32, 1),
                    number(address + 40), number(address + 48), number(address + 56, 1),
                    *struct.unpack('<III', uc.mem_read(address + 60, 12)))
                want = (record.raw08, record.raw10, record.progress.raw08, record.progress.raw10,
                    record.progress.raw18, int(record.raw38), record.raw3c, record.raw40, record.raw44)
                if actual != want:
                    raise ValueError('Native/portable quest fields differ after temporary cleanup')

    def make_body(groups, quests, raw):
        parts = [struct.pack('<H', groups)]
        for i in range(groups):
            parts.append(struct.pack('<BH', raw, quests))
            for j in range(quests):
                parts.append(struct.pack('<QBBQQBIII', 0xffffffffffffffff - i * 8 - j,
                    raw, 255 - j, 0x8000000000000000 + i, j, raw, j, i, 0xffffffff))
        parts.append(struct.pack('<Q', 0xffffffffffffffff if raw else 0))
        return b''.join(parts)

    cases = []
    for groups in (0, 1, 2, 8):
        for quests in (0, 1, 2, 8):
            for raw in (0, 1, 6, 7, 12, 255):
                body = make_body(groups, quests, raw)
                expected = decode_quest_sync(body, source_sha256=h.sha,
                    max_collection_items=8, max_total_items=72, max_payload_size=8192)
                if read(body) != (True, len(body)):
                    raise ValueError('Whole quest sync reader rejected body')
                compare(expected)
                cases.append(dict(groups=groups, quests=quests, raw=raw, size=len(body)))
    short = []
    body = make_body(2, 2, 255)
    for size in range(len(body)):
        accepted, consumed = read(body[:size])
        if accepted:
            raise ValueError('Truncated quest sync accepted')
        short.append(dict(size=size, consumed=consumed))
    audit = load('audit-client-release')
    report = dict(source_sha256=h.sha, tool_sha256=audit.sha256(Path(__file__)),
        context_sha256=audit.sha256(context_path), native_execution=True, network_used=False,
        cases=cases, short=short, exports=h.evidence, bindings=context['bindings'],
        limits=['Whole actual packet/nested constructors, readers, input array loop, callbacks, reserve wrappers and typed Quest copy execute.',
            'Fresh allocation, cleanup/free and raw archive memcpy are bounded fixtures; temporary buffers are poisoned before final comparison.',
            'No reuse/growth/real allocator/destructor, handler semantics, active quest or outgoing action is established.',
            'Native storage fixtures accept at most eight records per collection; portable limits remain explicit.'])
    return audit.save_snapshot(h.root / 'code-clues/quest-sync-11316', report), report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), short=len(report['short']))))
