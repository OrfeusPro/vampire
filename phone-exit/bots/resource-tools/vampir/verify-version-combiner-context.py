"""Whole current combiners/copy/append/grow with explicit allocation/copy boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify(context, root):
    functions = {int(at, 16) for at in context['functions'].values()}
    h = load('update-native-harness').make_harness(context, context['exports'], functions, root=root)
    output, left, right = [h.scratch + n for n in (0x1000, 0x2000, 0x3000)]
    state = {}
    def reg(name): return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))
    def allocate(size):
        if not 1 <= size <= 2048 or state['heap'] + size + 48 > h.scratch + 0x30000:
            raise ValueError('Combiner heap bound')
        pointer = state['heap'] + 16; state['heap'] += (size + 63) & ~15
        h.uc.mem_write(pointer - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        state['allocations'][pointer] = size
        return pointer
    def release(pointer):
        if pointer not in state['allocations'] or pointer in state['freed']:
            raise ValueError('Combiner free ownership differs')
        state['freed'].add(pointer)
    def write(at, value, spare=0, allocated_empty=False):
        raw = (value + '\0').encode('utf-16le') if value or allocated_empty else b''
        count = len(raw) // 2; capacity = count + spare if raw else 0
        pointer = allocate(capacity * 2) if capacity else 0
        if raw: h.uc.mem_write(pointer, raw)
        h.uc.mem_write(at, struct.pack('<QII', pointer, count, capacity))
    def text(at):
        pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(at, 16))
        if not 0 <= count <= capacity <= 1024: raise ValueError('Combiner descriptor bound')
        data = bytes(h.uc.mem_read(pointer, count * 2)) if count else b''
        if count and not data.endswith(b'\0\0'): raise ValueError('Combiner NUL differs')
        return data[:-2].decode('utf-16le') if data else ''
    load('version-combiner-fixtures').install(load, h, context, state, allocate, release, reg)
    abi = {key: 0xfedcba9876543200 + index for index, key in enumerate(('RBX','RSI','RDI','RBP','R12','R13','R14','R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    cases = []
    pairs = [('', ''), ('', '_'), ('Windows', ''), ('Windows', '_'), ('Windows_', '10.0.26100.1.256.64bit'),
             ('контекст🙂', '_界'), ('a\0b', 'c\0d'), ('x' * 127, 'y' * 128)]
    for poison in (0, 0x55, 0xaa, 0xff):
        for name in ('first', 'second'):
            for first, second in pairs:
                for spare in (0, 300):
                    for allocated_empty in (False, True):
                        state.update(heap=h.scratch + 0x10000, allocations={}, freed=set(), combiner_events=[])
                        write(left, first, spare, allocated_empty); write(right, second, 0, allocated_empty)
                        before = {at: bytes(h.uc.mem_read(at, 16)) for at in (left, right)}
                        h.uc.mem_write(output - 16, b'\xa5' * 16 + bytes((poison,)) * 16 + b'\xa6' * 16)
                        for key, value in abi.items(): h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + key), value)
                        h.uc.reg_write(h.x.UC_X86_REG_RDX, left); h.uc.reg_write(h.x.UC_X86_REG_R8, right)
                        if h.call(int(context['functions'][name], 16), output) != output or text(output) != first + second:
                            raise ValueError('Combiner result differs')
                        left_consumed = name == 'second' and bool(first)
                        right_consumed = name == 'first' and not first
                        for at, consumed in ((left, left_consumed), (right, right_consumed)):
                            expected = bytes(16) if consumed else before[at]
                            if bytes(h.uc.mem_read(at, 16)) != expected: raise ValueError('Combiner ownership transfer differs')
                        live = {int.from_bytes(h.uc.mem_read(at, 8), 'little') for at in (left,right,output)} - {0}
                        if live != set(state['allocations']) - state['freed']: raise ValueError('Combiner temporary leak')
                        for pointer, size in state['allocations'].items():
                            if bytes(h.uc.mem_read(pointer - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(pointer + size, 16)) != b'\xa6' * 16:
                                raise ValueError('Combiner allocation canary differs')
                        if (bytes(h.uc.mem_read(output - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(output + 16, 16)) != b'\xa6' * 16
                                or any(reg(key) != value for key, value in abi.items()) or reg('RSP') != h.scratch + 0x38008):
                            raise ValueError('Combiner ABI/guards differ')
                        cases.append(dict(function=name, poison=poison, left=first, right=second, spare=spare,
                            allocated_empty=allocated_empty, result=text(output), left_consumed=left_consumed,
                            right_consumed=right_consumed, events=list(state['combiner_events'])))
    for name in ('first', 'second'):
        state.update(heap=h.scratch + 0x10000, allocations={}, freed=set(), combiner_events=[])
        h.uc.mem_write(left, struct.pack('<QII', 0, 0x7fffffff, 0x7fffffff))
        h.uc.mem_write(right, struct.pack('<QII', 0, 2, 2))
        h.uc.reg_write(h.x.UC_X86_REG_RDX, left); h.uc.reg_write(h.x.UC_X86_REG_R8, right)
        try: h.call(int(context['functions'][name], 16), output)
        except ValueError as error:
            if str(error) != 'Native combiner length overflow': raise
        else: raise ValueError('Native length overflow not rejected')
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
        overflow_cases=2,evidence=h.evidence,network_used=False,profile_activated=False,
        runtime=load('update-native-harness').runtime_inputs(), limits=[
            'Whole two combiners, copy constructor, append and capacity grow; no final text fixture.',
            'Allocation/resize/append-grow/size quantization/internal copy/overflow are explicit bounded fixtures.',
            'Internal copy returns destination; alternate short-copy behavior and real allocation failure not established.',
            'Valid independent descriptors; aliasing and whole Version/Login prepare not covered here.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args(); report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['fixture_sha256'] = hashlib.sha256((HERE/'version-combiner-fixtures.py').read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-version-combiner-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']), overflow_cases=report['overflow_cases'])))
