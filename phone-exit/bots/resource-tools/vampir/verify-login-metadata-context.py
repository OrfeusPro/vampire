"""Current whole metadata collector, selector, loader, UserInfo copy/move/writer.

SDK stores, map/variant and string primitives are explicit bounded fixtures.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
FIELD_MAP = {
    'I_OS': 0, 'I_DeviceOSVersion': 0x10, 'I_DeviceModel': 0x20,
    'I_NMManufacturer': 0x30, 'I_NMModel': 0x40, 'I_UDID': 0x60,
    'I_GameVersion': 0x80, 'I_SDKVersion': 0x90, 'I_GameCode': 0xa0,
    'I_NMBuildCode': 0xb0, 'I_NMMarket': 0xc0, 'I_TID': 0xd0,
    'I_ConnectIP': 0xe0, 'I_NMMobileIP': 0xf0, 'I_CountryCD': 0x100,
    'I_City': 0x110, 'I_ChannelType': 0x120, 'I_NMChannelCode': 0x130,
    'I_NMChannelUserID': 0x140, 'I_PID': 0x150, 'I_Region': 0x160,
    'I_JoinedCountryCode': 0x170, 'I_LanguageCD': 0x180, 'I_World': 0x190,
    'I_NMCharacterID': 0x1a0, 'I_NMSessionID': 0x1b0, 'I_TimeZone': 0x1c0,
    'I_NMCPU': 0x1f0, 'I_NMRAM': 0x200, 'I_NMVGA': 0x210,
    'I_NMResolution': 0x220, 'I_NMNID': 0x230, 'I_NMNIDChannelType': 0x240,
}
PATTERNS = ('full', 'empty', 'omit-gates', 'omit-nid', 'omit-channel', 'unicode-quote')
BACKENDS = ('none', 'invalid', 'ready', 'shared', 'weak-shared', 'unmanaged')


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def session(context, h, bridge=None):
    functions = {key: int(at, 16) for key, at in context['functions'].items()}
    native = load('build-native-entry-code')
    rows = load('update-bindings').rows
    calls = {hex(r['address']): {'target': hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
             for at in functions.values() for r in rows(native, h.image, at) if r['call']}
    if calls != context['call_sites']:
        raise ValueError('Metadata call sites differ')
    fixture = {key: int(at, 16) for key, at in context['fixtures'].items()}
    # The memset thunk is an explicit import, not arbitrary host execution.
    off = h.image.offset(fixture['memset'] - h.image.pe.base)
    if h.raw[off:off + 2] != b'\xff\x25':
        raise ValueError('Metadata memset import thunk differs')
    slot = fixture['memset'] + 6 + struct.unpack_from('<i', h.raw, off + 2)[0]
    identity = load('build-object-zero-init-code').import_at(h.raw, h.image, slot)
    if (identity['dll'].lower(), identity['name']) != ('vcruntime140.dll', 'memset'):
        raise ValueError('Metadata memset import identity differs')
    globals_ = {key: int(at, 16) for key, at in context['globals'].items()}
    source, output, service, control, control_table, backend, settings, optional_store, entries = [
        h.scratch + n for n in (0x1000, 0x2000, 0x2800, 0x3000, 0x3100, 0x3200, 0x3300, 0x3400, 0x5000)]
    state = {}
    if bridge:
        source, output, service, control, control_table, backend, settings, optional_store = [
            h.scratch + n for n in (0xa000, 0xa400, 0xa500, 0xb000, 0xb100, 0xb200, 0xb300, 0xb400)]

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def allocate(size):
        require(0 < size <= 8192 and state['heap'] + size + 64 < h.scratch + 0x30000, 'Metadata allocation bound')
        at = state['heap'] + 16
        state['heap'] += (size + 63) & ~15
        h.uc.mem_write(at - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        state['allocations'][at] = size
        return at

    def release(at):
        require(at in state['allocations'] and at not in state['freed'],
                'Metadata unowned or repeated free ' + hex(at) + ' return ' + hex(int.from_bytes(h.uc.mem_read(reg('RSP'), 8), 'little')))
        size = state['allocations'][at]
        require(bytes(h.uc.mem_read(at - 16, 16)) == b'\xa5' * 16
                and bytes(h.uc.mem_read(at + size, 16)) == b'\xa6' * 16, 'Metadata allocation canary changed')
        state['freed'].add(at)

    def text(at):
        pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(at, 16))
        require(0 <= count <= capacity <= 4096 and (not count or pointer), 'Metadata descriptor bound')
        if not count:
            return ''
        require(pointer not in state['freed'], 'Metadata reads freed text')
        raw = bytes(h.uc.mem_read(pointer, count * 2))
        require(raw.endswith(b'\0\0'), 'Metadata terminator differs')
        return raw[:-2].decode('utf-16le')

    def put(at, value):
        raw = value.encode('utf-16le') + b'\0\0' if value else b''
        pointer = allocate(len(raw)) if raw else 0
        if pointer:
            h.uc.mem_write(pointer, raw)
        h.uc.mem_write(at, struct.pack('<QII', pointer, len(raw) // 2, len(raw) // 2))
        return at

    def replace(at, value):
        old = int.from_bytes(h.uc.mem_read(at, 8), 'little')
        if old:
            release(old)
        return put(at, value)

    def literal(at, wide=True):
        raw = bytearray()
        width = 2 if wide else 1
        for i in range(2048):
            chunk = bytes(h.uc.mem_read(at + i * width, width))
            if chunk == bytes(width):
                return raw.decode('utf-16le' if wide else 'ascii')
            raw.extend(chunk)
        raise ValueError('Metadata literal bound')

    if bridge:
        allocate, release = bridge['allocate'], bridge['release']

    def handler(name):
        def execute(machine):
            a, b, c, d = [reg(k) for k in ('RCX', 'RDX', 'R8', 'R9')]
            result = 0
            state['events'].append(name)
            if name == 'marketing':
                require(a != b, 'Metadata marketing arguments differ')
                put(a, 'click-fixture' if state['marketing'] else '')
                h.uc.mem_write(b, struct.pack('<I', 202))
                result = int(state['marketing'])
            elif name == 'construct_info':
                h.uc.mem_write(a, bytes(0x250))
                result = a
            elif name == 'destroy_info':
                for field in range(0, 0x250, 16):
                    pointer = int.from_bytes(h.uc.mem_read(a + field, 8), 'little')
                    if pointer:
                        release(pointer)
                h.uc.mem_write(a, bytes(0x250))
            elif name == 'backend':
                result = 0 if state['backend'] == 'none' else backend
            elif name == 'unwrap_backend':
                require(b == backend, 'Metadata backend unwrap receiver differs')
                h.uc.mem_write(a, struct.pack('<Q', backend + 0x10))
                result = a
            elif name == 'shared_info':
                require(b == backend + 0x10, 'Metadata shared factory input differs')
                h.uc.mem_write(a, struct.pack('<QQ', 0 if state['backend'] == 'invalid' else backend + 0x20,
                                             0 if state['backend'] == 'unmanaged' else control))
                result = a
            elif name == 'settings':
                result = settings
            elif name == 'source_info':
                require(a == settings, 'Metadata source settings receiver differs')
                result = source
            elif name == 'memset':
                require(b == 0 and c == 0x250, 'Metadata memset arguments differ')
                h.uc.mem_write(a, bytes(c))
                result = a
            elif name == 'copy_string':
                if source <= b < source + 0x250:
                    state['copy_offsets'].append(b - source)
                result = replace(a, text(b))
            elif name == 'free':
                release(a)
            elif name in ('wide_string', 'ascii_string'):
                result = put(a, literal(b, name == 'wide_string'))
            elif name == 'append':
                require(c <= 4096, 'Metadata append bound')
                value = bytes(h.uc.mem_read(b, c * 2)).decode('utf-16le') if c else ''
                result = replace(a, text(a) + value)
            elif name == 'format':
                fmt = literal(b)
                if fmt == '"%s":"%s"':
                    value = '"' + literal(c) + '":"' + literal(d) + '"'
                elif fmt in (',"I_DeviceKey":"%s"', '"MktClickId":"%s",'):
                    value = fmt.replace('%s', literal(c))
                elif fmt == '"MktChannel":%d':
                    value = fmt.replace('%d', str(c & 0xffffffff))
                else:
                    raise ValueError('Metadata unreviewed format')
                result = put(a, value)
            elif name in ('idfv', 'nm_key', 'adid'):
                result = put(a, {'idfv': 'idfv-fixture', 'nm_key': 'nm-key-fixture', 'adid': 'adid-fixture'}[name])
            elif name == 'variant_text':
                state['variants'][a] = text(b)
                state['variant_sources'][a] = b - state['info'] if state['info'] <= b < state['info'] + 0x250 else None
                h.uc.mem_write(a, bytes(16))
                result = a
            elif name == 'variant_number':
                state['variants'][a] = dict(opaque_number=b)
                state['variant_sources'][a] = None
                h.uc.mem_write(a, bytes(16))
                result = a
            elif name == 'variant_destroy':
                require(a in state['variants'], 'Metadata unknown variant destruction')
            elif name == 'insert':
                require(d == 0, 'Metadata map insert mode differs')
                key_desc, variant = struct.unpack('<QQ', h.uc.mem_read(c, 16))
                key = text(key_desc)
                require(key not in state['mapping'] and variant in state['variants'], 'Metadata duplicate/unknown map entry')
                require(len(state['keys']) < 64, 'Metadata map entry bound')
                if not state['keys']:
                    state['entries'] = allocate(64 * 40)
                state['keys'].append(key)
                state['mapping'][key] = state['variants'][variant]
                state['field_map'][key] = state['variant_sources'][variant]
                h.uc.mem_write(a, struct.pack('<Q', state['entries']))
                h.uc.mem_write(b, bytes(4))
                state['map'] = a
                result = b
            elif name == 'hash':
                require(a <= 4096, 'Metadata hash length bound')
                require(len(literal(b).encode('utf-16le')) // 2 == a, 'Metadata hash source length differs')
                result = 0x17
            elif name == 'lookup':
                key = text(c)
                require(a == state['map'] and b == 0x17, 'Metadata lookup context differs')
                state['lookups'].append(key)
                result = state['keys'].index(key) if key in state['mapping'] else 0xffffffff
            elif name == 'value_text':
                index, remainder = divmod(a - state['entries'] - 16, 40)
                require(remainder == 0 and 0 <= index < len(state['keys']), 'Metadata selected entry address differs')
                value = state['mapping'][state['keys'][index]]
                require(isinstance(value, str), 'Metadata opaque variant conversion not supported')
                result = put(b, value)
            elif name == 'map_destroy':
                require(b == 0, 'Metadata map destruction argument differs')
            elif name == 'optional_store':
                result = optional_store
            elif name == 'optional_resolve':
                require(a == optional_store, 'Metadata optional resolver receiver differs')
                h.uc.mem_write(optional_store + 0x110, struct.pack('<Q', settings))
            elif name == 'device_key':
                require(a == settings and c == 1, 'Metadata optional DeviceKey arguments differ')
                result = put(b, 'device-fixture')
            elif name == 'security':
                require(a == int.from_bytes(h.uc.mem_read(globals_['cookie'], 8), 'little'), 'Metadata stack cookie differs')
            elif name in ('strong_destroy', 'weak_destroy'):
                require(a == control and (name != 'weak_destroy' or b == 1), 'Metadata control block destructor differs')
            elif name in ('diagnostic_text', 'diagnostic_log'):
                raise ValueError('Metadata diagnostic branch is outside reviewed fixture')
            else:
                raise ValueError('Unknown metadata fixture ' + name)
            h.finish(result)
        return execute

    for key, at in fixture.items():
        callback = handler(key)
        previous = h.fixtures.get(at)
        if bridge and previous:
            def dispatch(machine, callback=callback, previous=previous):
                (callback if state.get('active') else previous)(machine)
            h.add_fixture(at, dispatch)
        else:
            h.add_fixture(at, callback)
    h.uc.mem_write(control_table, struct.pack('<QQ', fixture['strong_destroy'], fixture['weak_destroy']))
    import unicorn
    targets = {at: key for key, at in functions.items()}

    def entered(machine, at, size, unused):
        if bridge and state.get('active') and at == state['return_address']:
            state['captured_output'] = text(state['output'])
            state['active'] = False
        if at == functions['collector'] and bridge:
            state['active'] = True
            state['output'] = reg('RDX')
            state['return_address'] = int.from_bytes(h.uc.mem_read(reg('RSP'), 8), 'little')
            bridge['entered']()
        if at in targets:
            key = targets[at]
            state['native_calls'][key] = state['native_calls'].get(key, 0) + 1
            if key == 'writer':
                state['info'] = reg('RCX')
    h.uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    order = context['collector_order']
    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    def seed(backend_case, pattern, optional, marketing, poison):
        state.clear()
        state.update(heap=h.scratch + 0x10000, allocations={}, freed=set(), events=[], variants={}, variant_sources={},
                     mapping={}, keys=[], field_map={}, lookups=[], copy_offsets=[], native_calls={},
                     backend=backend_case, marketing=marketing, info=0)
        if bridge:
            state['allocations'] = bridge['outer']['allocations']
            state['freed'] = bridge['outer']['freed']
        else:
            h.uc.mem_write(h.scratch + 0x30000, bytes([poison]) * 0x8000)
        h.uc.mem_write(source - 16, b'\xa5' * 16 + bytes(0x250) + b'\xa6' * 16)
        values = {off: '' if pattern == 'empty' else 'f' + format(off, '03x') for off in range(0, 0x250, 16)}
        if pattern == 'omit-gates':
            for off in (0xa0, 0xb0, 0x230, 0x240):
                values[off] = ''
        if pattern == 'omit-nid':
            values[0x230] = ''
        if pattern == 'omit-channel':
            values[0x240] = ''
        if pattern == 'unicode-quote':
            values[0x170] = 'Ж🙂'
            values[0x150] = 'q"\\'
        for off, value in values.items():
            put(source + off, value)
        h.uc.mem_write(output - 16, b'\xa5' * 16 + bytes(16) + b'\xa6' * 16)
        h.uc.mem_write(service - 16, b'\xa5' * 16 + bytes([0x66]) * 0x80 + b'\xa6' * 16)
        strong, weak = (2 if backend_case == 'shared' else 1), (2 if backend_case == 'weak-shared' else 1)
        h.uc.mem_write(control - 16, b'\xa5' * 16 + struct.pack('<QII', control_table, strong, weak) + b'\xa6' * 16)
        h.uc.mem_write(optional_store, bytes(0x120))
        # Optional DeviceKey backend is separate from the SDK UserInfo backend.
        if not bridge:
            h.uc.mem_write(globals_['optional_manager'], struct.pack('<Q', service if optional else 0))
            h.uc.mem_write(service + 0x38, struct.pack('<Q', backend if optional else 0))
        h.uc.mem_write(globals_['log_level'], b'\0')
        h.uc.mem_write(globals_['log_enabled'], b'\0')
        input_pointers = set(state['allocations'])
        guards = {at: bytes(h.uc.mem_read(at, size)) for at, size in ((source - 16, 0x270), (service - 16, 0xa0))}
        input_data = {at: bytes(h.uc.mem_read(at - 16, size + 32)) for at, size in state['allocations'].items()}
        state['seed'] = dict(backend_case=backend_case, pattern=pattern, optional=optional, marketing=marketing, poison=poison, values=values, strong=strong, weak=weak, input_pointers=input_pointers, guards=guards, input_data=input_data)

    def check():
        backend_case, pattern, optional, marketing, poison, values, strong, weak, input_pointers, guards, input_data = [state['seed'][key] for key in ('backend_case', 'pattern', 'optional', 'marketing', 'poison', 'values', 'strong', 'weak', 'input_pointers', 'guards', 'input_data')]
        active = backend_case not in ('none', 'invalid')
        expected_map = {key: values[off] for key, off in FIELD_MAP.items()}
        if not values[0xa0]:
            expected_map.pop('I_GameCode')
        if not values[0xb0]:
            expected_map.pop('I_NMBuildCode')
        if not values[0x1a0]:
            expected_map.pop('I_NMCharacterID')
        if not values[0x230]:
            expected_map.pop('I_NMNID')
            expected_map.pop('I_NMNIDChannelType')
        expected_map.update(I_NMDeviceKey='nm-key-fixture', I_PlatformADID='adid-fixture', I_NMIDFV='idfv-fixture',
                            I_NMAppSetID='', I_NMInstallPackageName='', I_NMAppSetIDScope=dict(opaque_number=0))
        expected = ''
        if active:
            require(state['mapping'] == expected_map, 'Metadata UserInfo fields/gates differ ' + pattern + ' '
                    + repr({key: (state['mapping'].get(key), expected_map.get(key))
                            for key in set(state['mapping']) | set(expected_map)
                            if state['mapping'].get(key) != expected_map.get(key)}))
            require(state['field_map'] == {key: off for key, off in FIELD_MAP.items() if key in expected_map}
                    | {key: {'I_NMDeviceKey': 0x50, 'I_PlatformADID': 0x70}.get(key)
                       for key in expected_map if key not in FIELD_MAP}, 'Metadata map field provenance differs')
            expected = '{' + ','.join('"' + key + '":"' + expected_map[key] + '"' for key in order if key in expected_map)
            if optional:
                expected += ',"I_DeviceKey":"device-fixture"'
            if marketing:
                expected += ',"I_LogDes":{"MktClickId":"click-fixture","MktChannel":202}'
            expected += '}'
        actual = state.get('captured_output', '') if bridge else text(output)
        require(actual == expected, 'Metadata collector projection differs: ' + backend_case + '/' + pattern + ' ' + repr(actual))
        require(state['lookups'] == (order if active else []), 'Metadata selector order differs')
        require(state['copy_offsets'] == (list(range(0, 0x250, 16)) if active else []), 'Metadata UserInfo copy fields differ')
        require(state['native_calls'].get('writer', 0) == int(active)
                and state['native_calls'].get('selector', 0) == 27 * int(active)
                and state['native_calls'].get('copy', 0) == int(active)
                and state['native_calls'].get('move', 0) == int(not active), 'Metadata native lifecycle differs')
        touched_control = backend_case not in ('none', 'unmanaged')
        expected_strong = strong - int(touched_control)
        expected_weak = weak - int(touched_control and strong == 1)
        require(bytes(h.uc.mem_read(control - 16, 48)) == b'\xa5' * 16
                + struct.pack('<QII', control_table, expected_strong, expected_weak) + b'\xa6' * 16,
                'Metadata shared refcounts/guards differ')
        require(state['events'].count('strong_destroy') == int(touched_control and strong == 1)
                and state['events'].count('weak_destroy') == int(touched_control and strong == weak == 1),
                'Metadata shared destructors differ')
        if not bridge:
            result_pointer = int.from_bytes(h.uc.mem_read(output, 8), 'little')
            if result_pointer:
                release(result_pointer)
            require(set(state['allocations']) - input_pointers == state['freed'], 'Metadata temporary leak or input free')
        require(all(bytes(h.uc.mem_read(at, len(data))) == data for at, data in guards.items())
                and all(bytes(h.uc.mem_read(at - 16, len(data))) == data for at, data in input_data.items()), 'Metadata input changed')
        require(bytes(h.uc.mem_read(output - 16, 16)) == b'\xa5' * 16
                and bytes(h.uc.mem_read(output + 16, 16)) == b'\xa6' * 16, 'Metadata output guard changed')
        if not bridge:
            require(all(reg(key) == value for key, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                    'Metadata ABI differs')
        return actual

    return seed, check, state


def verify(context, root):
    functions = {key: int(at, 16) for key, at in context['functions'].items()}
    h = load('update-native-harness').make_harness(context, context['exports'], set(functions.values()), root=root)
    seed, check, state = session(context, h)
    cases = []
    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i):0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    for backend_case, pattern, optional, marketing, poison in itertools.product(BACKENDS, PATTERNS, (False, True), (False, True), (0x55, 0xaa)):
        seed(backend_case, pattern, optional, marketing, poison)
        for register, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + register), value)
        h.uc.reg_write(h.x.UC_X86_REG_RDX, h.scratch + 0x2000)
        h.call(functions['collector'], h.scratch + 0x2800, budget=100000)
        actual = check()
        cases.append(dict(backend=backend_case, pattern=pattern, optional_device=optional, marketing=marketing,
                          poison=poison, output=actual, mapping=state['mapping'], field_map=state['field_map'],
                          native_calls=state['native_calls'], guards=True))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
                evidence=h.evidence, runtime=load('update-native-harness').runtime_inputs(), network_used=False,
                profile_activated=False, field_map=FIELD_MAP,
                limits=['Whole six explicit roots execute: collector, selector, loader, UserInfo copy/move/writer.',
                        'SDK backend/shared factory/settings/UserInfo, getters, map/hash/lookup/variant/string primitives and cleanup are fixtures.',
                        'Strings are bounded literal substitutions; escaping and real SDK values are not proved. Diagnostic branch disabled.',
                        'Loader control refcount branches execute on synthetic control blocks; virtual destructor bodies are fixtures.',
                        'No whole Login integration, auth/network, game actions or runtime activation.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-login-metadata-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
