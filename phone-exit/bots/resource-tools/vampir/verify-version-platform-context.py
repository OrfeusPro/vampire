"""Whole Version platform selector/context accessors; explicit synthetic callees."""
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
    functions = {int(context[key], 16) for key in ('selector', 'store', 'lookup')}
    h = load('update-native-harness').make_harness(context, context['exports'], functions, root=root)
    rows = load('update-bindings').rows; native = load('build-native-entry-code')
    calls = {hex(row['address']): hex(row['direct_target']) for at in functions
             for row in rows(native, h.image, at) if row['call']}
    if calls != context['call_sites']:
        raise ValueError('Platform/context call sites differ')
    fixtures = {key: int(value, 16) for key, value in context['fixtures'].items()}
    cache = int(context['cache'], 16)
    receiver, output, array, text = [h.scratch + n for n in (0x1000, 0x2000, 0x3000, 0x4000)]
    state = {}

    def reg(name): return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))
    def write_reg(name, value): h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
    def wide(at):
        value = bytearray()
        for index in range(128):
            pair = bytes(h.uc.mem_read(at + index * 2, 2))
            if pair == b'\0\0': return value.decode('utf-16le')
            value.extend(pair)
        raise ValueError('Platform fixture string exceeds budget')

    def handler(name):
        def execute(machine):
            a, b, c = [reg(r) for r in ('RCX', 'RDX', 'R8')]
            state['events'].append(name)
            result = 0
            if name == 'platform_text':
                payload = (state['platform'] + '\0').encode('utf-16le')
                h.uc.mem_write(text, payload)
                pointer = text if state['allocated'] else 0
                count = len(payload) // 2 if state['platform'] else 0
                h.uc.mem_write(a, struct.pack('<QII', pointer, count, count))
                result = a
            elif name == 'name_ctor':
                if c != 1 or wide(b) != state['platform']:
                    raise ValueError('Platform name input differs')
                h.uc.mem_write(a, struct.pack('<Q', 0x12345678))
            elif name == 'free':
                if a != text: raise ValueError('Platform free ownership differs')
            elif name == 'equals':
                if a != 0x12345678: raise ValueError('Platform name token differs')
                literal = wide(b)
                if literal not in ('Android', 'IOS', 'Windows'):
                    raise ValueError('Platform literal differs')
                state['comparisons'].append(literal)
                result = state['truth'] if literal == state['platform'] else 0
            elif name == 'store_type':
                result = 0x1234
            elif name == 'store_resolve':
                if (a, b, c) != (int(context['factory'], 16), 0x1234, int(context['descriptor'], 16)):
                    raise ValueError('Context store resolver arguments differ')
                result = state['resolved']
            elif name == 'value_at':
                if a != receiver or b != output or c != state['expected_index']:
                    raise ValueError('Context lookup projection differs')
                h.uc.mem_write(output, struct.pack('<Q', c))
            else:
                raise ValueError('Unknown platform fixture')
            h.finish(result)
        return execute
    for key, address in fixtures.items(): h.add_fixture(address, handler(key))
    cases = []
    abi = {key: 0x123456789abcdef0 + index for index, key in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})

    def call(at, argument=0):
        for key, value in abi.items(): write_reg(key, value)
        result = h.call(int(context[at], 16), argument)
        if any(reg(key) != value for key, value in abi.items()) or reg('RSP') != h.scratch + 0x38008:
            raise ValueError('Platform/context ABI differs')
        return result

    for poison in (0, 0x55, 0xaa, 0xff):
        for platform in ('Android', 'IOS', 'Windows', 'Linux', '', 'windows'):
            for truth in (1, 128, 255):
                state.update(platform=platform, allocated=True, truth=truth, events=[], comparisons=[])
                h.uc.mem_write(h.scratch + 0x37000, bytes((poison,)) * 0x1000)
                result = call('selector') & 255
                expected = {'Android': 1, 'IOS': 2, 'Windows': 3}.get(platform, 0)
                comparisons = ['Android', 'IOS', 'Windows'][:expected] if expected in (1, 2) else ['Android', 'IOS', 'Windows']
                if result != expected or state['comparisons'] != comparisons:
                    raise ValueError('Platform selector result differs')
                if state['events'] != ['platform_text', 'name_ctor', 'free'] + ['equals'] * len(comparisons):
                    raise ValueError('Platform selector cleanup/order differs')
                cases.append(dict(kind='selector', poison=poison, platform=platform, truth=truth, result=result))
        state.update(platform='', allocated=False, truth=1, events=[], comparisons=[])
        if call('selector') & 255 or 'free' in state['events']:
            raise ValueError('Empty unallocated platform differs')
        cases.append(dict(kind='empty_platform', poison=poison))
        for initial, resolved in ((receiver, receiver), (0, receiver), (0, 0)):
            state.update(events=[], resolved=resolved)
            h.uc.mem_write(cache, struct.pack('<Q', initial))
            for repeat in range(2):
                if call('store') != (initial or resolved): raise ValueError('Context store cache differs')
            expected_events = [] if initial else ['store_type', 'store_resolve'] * (1 if resolved else 2)
            if state['events'] != expected_events or int.from_bytes(h.uc.mem_read(cache, 8), 'little') != (initial or resolved):
                raise ValueError('Context store lifecycle differs')
            cases.append(dict(kind='store', poison=poison, initial=bool(initial), resolved=bool(resolved)))
        for values, count, target, expected in (([], 0, 3, 0xffffffff), ([], -1, 3, 0xffffffff),
                ([1, 2, 3], 3, 1, 0), ([1, 2, 3], 3, 3, 2), ([1, 2, 3], 3, 4, 0xffffffff),
                ([3, 3], 2, 3, 0), ([0xffffffffffffffff, 0], 2, 0xffffffffffffffff, 0)):
            state.update(events=[], expected_index=expected)
            body = bytes((poison,)) * 0x40 + struct.pack('<Qi', array, count) + bytes((poison,)) * 20
            h.uc.mem_write(receiver, body)
            h.uc.mem_write(array, b''.join(struct.pack('<QQ', 0x100 + i, value) for i, value in enumerate(values)))
            h.uc.mem_write(output - 16, b'\xa5' * 16 + bytes((poison,)) * 16 + b'\xa6' * 16)
            before = bytes(h.uc.mem_read(array, 64))
            write_reg('RDX', output); write_reg('R8', target)
            if call('lookup', receiver) != output or int.from_bytes(h.uc.mem_read(output, 8), 'little') != expected:
                raise ValueError('Context lookup result differs')
            if (bytes(h.uc.mem_read(receiver, len(body))) != body or bytes(h.uc.mem_read(array, 64)) != before
                    or bytes(h.uc.mem_read(output - 16, 16)) != b'\xa5' * 16
                    or bytes(h.uc.mem_read(output + 16, 16)) != b'\xa6' * 16
                    or state['events'] != ['value_at']):
                raise ValueError('Context lookup guards differ')
            cases.append(dict(kind='lookup', poison=poison, count=count, target=target, index=expected))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
        evidence=h.evidence, network_used=False, profile_activated=False,
        runtime=load('update-native-harness').runtime_inputs(),
        limits=['Whole selector/store/lookup functions from current exports; initialized synthetic memory.',
                'Platform text, FName constructor/equality/free, store type/resolution and value-at are fixtures.',
                'Equality fixture is exact text comparison; actual FName normalization is not established.',
                'No Windows/CPU helpers, real enum text mapping, full Version/Login integration, auth or sockets.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args(); report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-version-platform-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
