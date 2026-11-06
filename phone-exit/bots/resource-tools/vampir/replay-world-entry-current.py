"""Current bounded writers/readers and Ping receiver; explicit IO boundaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SHA = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
SELECT_WRITE, START_WRITE = (5459838000, 5459651344)
RESERVE, NESTED, START, PING = (5461309392, 5461124016, 5461309680, 5459784800)
RECEIVER, HANDLER, GET = (5477574688, 5477366016, 5441901856)

def load(name):
    s = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m

def replay(context, root=None):
    root = Path(root) if root else ROOT
    guard = load('verify-ping-world-source-current').verify(context, root)
    exports = context['exports']
    h = load('native-request-harness-11316').make_harness(exports, {SELECT_WRITE, START_WRITE, RESERVE, NESTED, START, PING, RECEIVER}, leaves={GET: context['leaves'][hex(GET)]}, root=root, source_sha256=SHA, copy_thunk=int(context['copy_thunk'], 16))
    uc, x = (h.uc, h.x)
    packet, archive, table, nested_table, opaque_table = [h.scratch + n for n in (65536, 73728, 77824, 81920, 86016)]
    state = {}
    events = []
    cases = []

    def take(count):
        at = state['cursor']
        if at + count > len(state['body']):
            return None
        state['cursor'] += count
        return state['body'][at:at + count]

    def io(machine, size, boolean=False):
        destination = machine.reg_read(x.UC_X86_REG_RDX)
        if not h.scratch <= destination <= h.scratch + 262144 - size:
            raise ValueError('Read fixture bounds')
        data = take(size)
        if data is not None:
            machine.mem_write(destination, bytes((bool(data[0]),)) if boolean else data)
        h.finish(int(data is not None))
    slots = {64: (4, False), 80: (8, False), 88: (4, False), 96: (4, False), 120: (1, False), 136: (1, True)}
    for slot, (size, boolean) in slots.items():
        at = h.scratch + 131072 + slot
        h.add_fixture(at, lambda machine, size=size, boolean=boolean: io(machine, size, boolean))
        uc.mem_write(table + slot, struct.pack('<Q', at))

    def raw64(machine):
        io(machine, 8)
    h.add_fixture(5447009632, raw64)

    def nested(machine):
        archive_arg = machine.reg_read(x.UC_X86_REG_RCX)
        target = machine.reg_read(x.UC_X86_REG_RDX)
        vptr = int.from_bytes(machine.mem_read(target, 8), 'little')
        method = int.from_bytes(machine.mem_read(vptr + 32, 8), 'little')
        machine.reg_write(x.UC_X86_REG_RCX, target)
        machine.reg_write(x.UC_X86_REG_RDX, archive_arg)
        machine.reg_write(x.UC_X86_REG_RIP, method)
    h.add_fixture(5447012992, nested)

    def opaque(machine):
        if machine.reg_read(x.UC_X86_REG_RCX) != packet + 48:
            raise ValueError('Wrong reserve boundary')
        events.append('opaque-reserve-suffix')
        h.finish(0)
    h.add_fixture(h.scratch + 135168, opaque)
    uc.mem_write(nested_table + 32, struct.pack('<Q', NESTED))
    uc.mem_write(opaque_table + 32, struct.pack('<Q', h.scratch + 135168))

    def vector(machine):
        destination = machine.reg_read(x.UC_X86_REG_RDX)
        data = take(12)
        if data is not None:
            machine.mem_write(destination, struct.pack('<ddd', *struct.unpack('<fff', data)))
        h.finish(int(data is not None))
    h.add_fixture(5447012400, vector)

    def read(at, body):
        state.update(body=body, cursor=0)
        events.clear()
        uc.mem_write(packet, b'\x00' * 1024)
        uc.mem_write(packet + 24, struct.pack('<Q', nested_table))
        uc.mem_write(packet + 48, struct.pack('<Q', opaque_table))
        uc.mem_write(archive, struct.pack('<Q', table))
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        return h.call(at, packet) & 255
    for values in ((0, 0, 0, 0, 0, 0), (16, 255, 2 ** 64 - 1, 2 ** 32 - 1, 255, 255), (0, 1, 12345, 456, 1, 22)):
        body = struct.pack('<IBQIBB', *values)
        for size in range(20):
            read(RESERVE, body[:size])
            if bool(events) != (size == 19):
                raise ValueError('Reserve prefix boundary differs')
            if size == 19:
                actual = (struct.unpack('<I', bytes(uc.mem_read(packet + 16, 4)))[0], uc.mem_read(packet + 20, 1)[0], struct.unpack('<Q', bytes(uc.mem_read(packet + 32, 8)))[0], struct.unpack('<I', bytes(uc.mem_read(packet + 40, 4)))[0], uc.mem_read(packet + 44, 1)[0], uc.mem_read(packet + 45, 1)[0])
                expected = (values[0], min(values[1], 32), values[2], values[3], bool(values[4]), min(values[5], 22))
                if actual != expected:
                    raise ValueError('Reserve fields differ')
            cases.append(dict(kind='reserve-prefix', size=size, reached_boundary=bool(events)))
    for code, kind, flag in ((0, 0, 0), (16, 255, 255), (0, 22, 1)):
        body = struct.pack('<IIfffBBQ', code, 10010, 1.25, -2.5, 3.75, kind, flag, 1234)
        for size in range(31):
            accepted = read(START, body[:size])
            if accepted != int(size == 30):
                raise ValueError('Start reader length gate differs')
            if accepted:
                if struct.unpack('<ddd', bytes(uc.mem_read(packet + 24, 24))) != (1.25, -2.5, 3.75):
                    raise ValueError('Start vector differs')
                if (uc.mem_read(packet + 48, 1)[0], uc.mem_read(packet + 49, 1)[0]) != (min(kind, 22), bool(flag)):
                    raise ValueError('Start enum/bool differs')
            cases.append(dict(kind='start-result', size=size, accepted=bool(accepted)))
    for code, value in ((0, 0), (16, 2 ** 64 - 1), (2 ** 32 - 1, 12345)):
        body = struct.pack('<IQ', code, value)
        for size in range(13):
            accepted = read(PING, body[:size])
            if accepted != int(size == 12):
                raise ValueError('Ping reader length differs')
            cases.append(dict(kind='ping-result', size=size, accepted=bool(accepted)))
    output = []

    def write(machine, fmt):
        value = machine.reg_read(x.UC_X86_REG_RDX) & (1 << struct.calcsize(fmt) * 8) - 1
        output.append(struct.pack(fmt, value))
        h.finish(1)
    for slot, fmt in ((184, '<Q'), (200, '<I')):
        at = h.scratch + 139264 + slot
        h.add_fixture(at, lambda machine, fmt=fmt: write(machine, fmt))
        uc.mem_write(table + slot, struct.pack('<Q', at))
    for a, b, c in ((0, 0, 0), (12345, 0, 67890), (2 ** 64 - 1, 2 ** 32 - 1, 2 ** 64 - 1)):
        uc.mem_write(packet + 16, struct.pack('<Q8xQ', a, c))
        uc.mem_write(packet + 24, struct.pack('<I', b))
        for at, expected in ((SELECT_WRITE, struct.pack('<QIQ', a, b, c)), (START_WRITE, struct.pack('<Q', a))):
            output.clear()
            uc.reg_write(x.UC_X86_REG_RDX, archive)
            if h.call(at, packet) & 255 != 1 or b''.join(output) != expected:
                raise ValueError('World request writer differs')
            cases.append(dict(kind='writer', address=hex(at), bytes=len(expected)))
    clock = h.scratch + 94208
    uc.mem_write(5558925504, struct.pack('<Q', clock))
    for sent, now in ((1000, 2000), (5000, 5000), (2000, 1000)):
        uc.mem_write(packet, b'\x00' * 1024)
        uc.mem_write(packet + 376, struct.pack('<q', sent))
        uc.mem_write(packet + 360, struct.pack('<ii', 0, 6))
        uc.mem_write(clock + 16, struct.pack('<q', now * 10000))
        h.call(RECEIVER, packet)
        if struct.unpack('<ii', bytes(uc.mem_read(packet + 360, 8))) != (0, 0):
            raise ValueError('Ping receiver tracking reset differs')
        if struct.unpack('<q', bytes(uc.mem_read(packet + 376, 8)))[0] != now - sent:
            raise ValueError('Ping elapsed differs')
        cases.append(dict(kind='ping-receiver', sent=sent, now=now))
    report = dict(source_sha256=SHA, exports=h.evidence, cases=cases, network_used=False, profile_activated=False, source_guard=guard, context_sha256=hashlib.sha256((HERE / 'knowledge/native-contexts/clock-world-current.json').read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), limits=['Actual ID109/203 writers, ID202 prefix/nested, ID204 and ID17 readers and Ping receiver.', 'Archive scalar/nested thunk/vector, output IO are bounded fixtures. Reserve stops before opaque suffix.', 'ID110/206 nested decoders are historical bounded parsers; full current nested compatibility is not established.', 'No world engine streaming, active state or server session established by this replay.'])
    report['evidence'] = guard['evidence']
    report['dependencies'] = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in ('replay-world-entry-current.py', 'verify-ping-world-source-current.py', 'native-request-harness-11316.py', 'build-native-entry-code.py', 'build-object-zero-init-code.py', 'extract-native-enums.py', 'audit-launcher-shape-11318.py', 'knowledge-index.py', 'knowledge/native-contexts/clock-world-current.json')}
    return report

def verify(exports):
    context = json.loads((HERE / 'knowledge/native-contexts/clock-world-current.json').read_bytes())
    if exports != context['exports']:
        raise ValueError('World replay supplied exports differ')
    report = replay(context)
    path = load('audit-client-release').save_snapshot(ROOT / 'code-clues/world-entry-current', report)
    return dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))
if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--context', type=Path, default=HERE / 'knowledge/native-contexts/clock-world-current.json')
    a = p.parse_args()
    print(json.dumps(verify(json.loads(a.context.read_bytes())['exports'])))
