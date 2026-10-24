"""Whole Login caller/constructor; explicit SDK, string and post-send fixtures."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
STRINGS = (0x10, 0x20, 0x30, 0x40, 0x58, 0x68, 0x78, 0x88,
           0xa0, 0xb8, 0xc8, 0xd8, 0xe8, 0x100, 0x110)
SCENARIOS = (
    ('windows-all', 'Windows', True, True, 7, 1),
    ('windows-mode-zero', 'Windows', True, True, 7, 0),
    ('windows-mode-two', 'Windows', True, True, 7, 2),
    ('windows-mode-negative', 'Windows', True, True, 7, 0xffffffff),
    ('sdk-disabled', 'Windows', False, True, 7, 1),
    ('sdk-absent', 'Windows', True, False, 7, 1),
    ('handles-absent', 'Windows', True, True, 0, 1),
    ('main-absent', 'Windows', True, True, 6, 1),
    ('aux-absent', 'Windows', True, True, 5, 1),
    ('extra-absent', 'Windows', True, True, 3, 1),
    ('android', 'Android', True, True, 7, 1),
    ('ios', 'IOS', True, True, 7, 1),
    ('unknown-platform', 'Linux', True, True, 7, 1),
    ('empty-platform', '', True, True, 7, 1),
)


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    prepare, constructor, table = [int(context[k], 16) for k in ('prepare', 'constructor', 'packet_table')]
    sdk = context.get('native_sdk')
    functions = {prepare, constructor}
    exports = dict(context['exports'])
    leaves = {}
    if sdk:
        functions.update(int(v, 16) for v in sdk['functions'].values())
        exports.update(sdk['exports'])
        leaves = {int(at, 16): spec['bytes'] for at, spec in sdk['leaves'].items()}
    h = load('update-native-harness').make_harness(context, exports, functions, leaves=leaves, root=root)
    rows = load('update-bindings').rows
    native = load('build-native-entry-code')
    calls = {hex(r['address']): {'target': hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
             for at in (prepare, constructor) for r in rows(native, h.image, at) if r['call']}
    if calls != context['call_sites']:
        raise ValueError('Login prepare call sites differ')
    if not any(r['mnemonic'] == 'lea' and r['rip_references'] == [table] for r in rows(native, h.image, constructor)):
        raise ValueError('Login constructor table link differs')
    fixture = {k: int(v, 16) for k, v in context['fixtures'].items()}
    if set(fixture.values()) | {constructor, int(context['helpers']['memcpy'], 16)} != {
            int(c['target'], 16) for c in calls.values()}:
        raise ValueError('Login fixture coverage differs')
    globals_ = {k: int(v, 16) for k, v in context['globals'].items()}
    owner, manager, language, session, receiver, flags, sdk_value = [h.scratch + n for n in
        (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000)]
    handles = (h.scratch + 0x8000, h.scratch + 0x8100, h.scratch + 0x8200)
    state = {}

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def allocate(size):
        if not 1 <= size <= 2048 or state['heap'] + size + 64 > h.scratch + 0x30000:
            raise ValueError('Login allocation bound')
        at = state['heap'] + 16
        state['heap'] += (size + 63) & ~15
        h.uc.mem_write(at - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        state['allocations'][at] = size
        return at

    def release(at):
        if at not in state['allocations'] or at in state['freed']:
            raise ValueError('Login unowned or repeated free')
        size = state['allocations'][at]
        if bytes(h.uc.mem_read(at - 16, 16)) != b'\xa5' * 16 or bytes(h.uc.mem_read(at + size, 16)) != b'\xa6' * 16:
            raise ValueError('Login allocation canary changed')
        state['freed'].add(at)

    def write_text(at, text):
        raw = text.encode('utf-16le') + b'\0\0' if text else b''
        pointer = allocate(len(raw)) if raw else 0
        if raw:
            h.uc.mem_write(pointer, raw)
        h.uc.mem_write(at, struct.pack('<QII', pointer, len(raw) // 2, len(raw) // 2))
        return at

    def read_text(at):
        pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(at, 16))
        if not 0 <= count <= capacity <= 1024 or (count and not pointer):
            raise ValueError('Login string descriptor bound')
        if not count:
            return ''
        if pointer in state['freed']:
            raise ValueError('Login reads freed string')
        raw = bytes(h.uc.mem_read(pointer, count * 2))
        if not raw.endswith(b'\0\0'):
            raise ValueError('Login string terminator differs')
        return raw[:-2].decode('utf-16le')

    def literal(at, wide=False):
        data = bytearray()
        width = 2 if wide else 1
        for i in range(256):
            chunk = bytes(h.uc.mem_read(at + i * width, width))
            if chunk == bytes(width):
                return data.decode('utf-16le' if wide else 'ascii')
            data.extend(chunk)
        raise ValueError('Login literal bound')

    def require(value, message):
        if not value:
            raise ValueError(message)

    def handler(name):
        def execute(machine):
            a, b, c, d = [reg(k) for k in ('RCX', 'RDX', 'R8', 'R9')]
            state['events'].append(name)
            result = 0
            if name == 'platform_text':
                result = write_text(a, state['platform'])
            elif name in ('ascii_string', 'wide_string'):
                result = write_text(a, literal(b, name == 'wide_string'))
            elif name == 'wide_compare':
                result = int(literal(a, True) != literal(b, True))
            elif name == 'copy_string':
                old = int.from_bytes(h.uc.mem_read(a, 8), 'little')
                if old:
                    release(old)
                result = write_text(a, read_text(b))
            elif name == 'resize':
                require(0 <= b <= 1024, 'Login resize bound')
                old, count, capacity = struct.unpack('<QII', h.uc.mem_read(a, 16))
                previous = bytes(h.uc.mem_read(old, min(capacity, b) * 2)) if old else b''
                if old:
                    release(old)
                pointer = allocate(b * 2) if b else 0
                if previous:
                    h.uc.mem_write(pointer, previous)
                h.uc.mem_write(a, struct.pack('<QII', pointer, count, b))
            elif name == 'free':
                release(a)
            elif name == 'nm_provider':
                result = write_text(a, state['nm'])
            elif name == 'selector':
                result = state['selector']
            elif name == 'owner_number':
                require(a == owner, 'Login owner number receiver differs')
                result = state['number']
            elif name == 'language':
                result = language
            elif name == 'sdk_manager':
                result = manager if state['manager_present'] else 0
            elif name == 'sdk_mode':
                require(a == handles[0], 'Login SDK mode handle differs')
                result = state['mode']
            elif name in ('sdk_aux_text', 'sdk_main_text'):
                require(a == handles[1 if name == 'sdk_aux_text' else 0], 'Login SDK text handle differs')
                result = write_text(b, state['aux' if name == 'sdk_aux_text' else 'main'])
            elif name == 'sdk_value':
                require(a == handles[0], 'Login SDK value handle differs')
                result = sdk_value
            elif name == 'flags_manager':
                result = flags
            elif name == 'sdk_flag':
                require(a == flags, 'Login SDK flag receiver differs')
                result = state['flag']
            elif name == 'sdk_extra_flag':
                require(a == handles[2], 'Login SDK extra handle differs')
                result = state['extra_flag']
            elif name == 'session':
                result = session
            elif name == 'send':
                require(a == session and c == 4 and not state.get('sent'), 'Login send arguments differ')
                require(int.from_bytes(h.uc.mem_read(b, 8), 'little') == table, 'Login send packet table differs')
                require(d == int.from_bytes(h.uc.mem_read(int(context['send_argument_global'], 16), 8), 'little'),
                        'Login send fourth argument differs')
                state['strings'] = {hex(off): read_text(b + off) for off in STRINGS}
                state['integers'] = {hex(off): int.from_bytes(h.uc.mem_read(b + off, size), 'little')
                    for off, size in ((0x50, 4), (0x98, 1), (0x99, 1), (0xb0, 4),
                                      (0xf8, 4), (0x120, 4), (0x124, 1), (0x128, 8), (0x130, 1), (0x131, 1))}
                state.update(sent=True, packet=b)
                result = state['send_return']
            elif name == 'log':
                require(state.get('sent'), 'Login log before send')
            elif name == 'post_receiver':
                result = receiver
            elif name == 'format_number':
                require(c == state['number'], 'Login formatted number differs')
                require(literal(b, True) == state['format_literal'], 'Login number format differs')
                result = write_text(a, 'number-fixture')
            elif name == 'post_notify':
                require(a == receiver and read_text(b) == 'number-fixture', 'Login post-send notification differs')
            elif name == 'variant_number':
                require(b == state['number'], 'Login variant number differs')
                h.uc.mem_write(a, struct.pack('<QQQ', b, 0, 0))
            elif name == 'variant_reserve':
                require(b == 1, 'Login variant count differs')
                h.uc.mem_write(a, struct.pack('<QII', allocate(24), 1, 1))
            elif name == 'variant_copy':
                require(c == 1 and int.from_bytes(h.uc.mem_read(b, 8), 'little') == state['number'],
                        'Login variant copy differs')
                h.uc.mem_write(a, bytes(h.uc.mem_read(b, 24)))
            elif name == 'event_object':
                require(literal(b, True) == state['event_literal'], 'Login SDK event name differs')
                pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(c, 16))
                require(count == capacity == 1 and int.from_bytes(h.uc.mem_read(pointer, 8), 'little') == state['number'],
                        'Login SDK event value differs')
                h.uc.mem_write(a, struct.pack('<QQ', allocate(16), 1))
                result = a
            elif name == 'sdk_event':
                require(a == handles[0] and state.get('sent'), 'Login SDK event receiver/lifecycle differs')
                require(int.from_bytes(h.uc.mem_read(b, 8), 'little') in state['allocations'], 'Login SDK event object differs')
            elif name == 'variant_destroy':
                require(a in state['allocations'] and b == 1, 'Login variant cleanup differs')
            elif name == 'destructor':
                require(a == state['packet'], 'Login destructor receiver differs')
                for off in STRINGS:
                    pointer = int.from_bytes(h.uc.mem_read(a + off, 8), 'little')
                    if pointer:
                        release(pointer)
                state['destroyed'] = True
            else:
                raise ValueError('Unknown Login fixture ' + name)
            h.finish(result)
        return execute

    for name, address in fixture.items():
        if sdk and name in sdk['native_names']:
            continue
        h.add_fixture(address, handler(name))
    if sdk:
        seed_sdk, check_sdk, metadata_fields = load('login-sdk-fixtures').install(
            load, h, sdk, fixture, state, owner, manager, language, flags, handles,
            allocate, release, write_text, read_text, literal, reg)
    tag_pointer = int.from_bytes(h.uc.mem_read(globals_['tag_pointer'], 8), 'little')
    require(tag_pointer == int(context['tag_literal'], 16), 'Login tag source pointer differs')
    page = tag_pointer & ~4095
    if not any(lo <= page <= hi for lo, hi, _ in h.uc.mem_regions()):
        h.uc.mem_map(page, 4096)
        off = h.image.offset(page - h.image.pe.base)
        h.uc.mem_write(page, h.raw[off:off + 4096])
    compiled_tag = literal(tag_pointer)
    require(compiled_tag == '32283C4C6485307BCF524765A84409C3', 'Login compiled tag differs')
    format_literal = literal(int(context['format_literal'], 16), True)
    event_literal = literal(int(context['event_literal'], 16), True)
    cases = []
    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}
    cache_cases = ('warm', 'resolve', 'absent') if sdk else ('fixture',)
    for scenario, selector, empty, send_return, poison, cache_case in itertools.product(
            SCENARIOS, (0, 1, 2, 3, 4, 255), (False, True), (0, 1), (0x55, 0xaa), cache_cases):
        name, platform, enabled, present, mask, mode = scenario
        state.clear()
        state.update(heap=h.scratch + 0x10000, allocations={}, freed=set(), events=[], sent=False,
            platform=platform, manager_present=present, mode=mode, selector=selector,
            nm='' if empty else 'nm-Ж🙂', main='' if empty else 'main-界', aux='' if empty else 'aux-🙂',
            number=0 if empty else 0xfedcba98, flag=0 if empty else 0x80, extra_flag=0 if empty else 0xff,
            send_return=send_return, format_literal=format_literal, event_literal=event_literal)
        h.uc.mem_write(h.scratch + 0x30000, bytes([poison]) * 0x8000)
        h.uc.mem_write(manager, b'\x77' * 0x80)
        for bit, offset, handle in zip((1, 2, 4), (0x38, 0x48, 0x68), handles):
            h.uc.mem_write(manager + offset, struct.pack('<Q', handle if mask & bit else 0))
        h.uc.mem_write(language, b'\x66' * 0x20)
        h.uc.mem_write(language + 0x18, bytes([0 if empty else 0xf3]))
        owner_bytes = bytearray([poison] * 0x180)
        h.uc.mem_write(owner - 16, b'\xa5' * 16 + owner_bytes + b'\xa6' * 16)
        for off, text in ((0xe0, 'owner-e0'), (0xf0, 'owner-f0'), (0x100, 'owner-100')):
            write_text(owner + off, '' if empty else text + '-🙂')
        write_text(globals_['text'], '' if empty else 'global-Ж')
        write_text(sdk_value, '' if empty else 'sdk-value-界')
        h.uc.mem_write(globals_['enabled'], bytes([int(enabled)]))
        h.uc.mem_write(globals_['enum'], struct.pack('<I', 0 if empty else 0xffffffff))
        h.uc.mem_write(globals_['number'], struct.pack('<I', 0 if empty else 0x89abcdef))
        if sdk:
            seed_sdk(cache_case, empty)
        input_pointers = set(state['allocations'])
        inputs = {at: bytes(h.uc.mem_read(at, size)) for at, size in
                  ((owner - 16, 0x1a0), (manager, 0x80), (language, 0x20), (sdk_value, 16), (globals_['text'], 16))}
        input_buffers = {at: bytes(h.uc.mem_read(at - 16, size + 32)) for at, size in state['allocations'].items()}
        for register, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + register), value)
        h.call(prepare, owner, budget=20000)
        if sdk:
            check_sdk()
        main = enabled and present and bool(mask & 1)
        aux = enabled and present and bool(mask & 2)
        extra = enabled and present and bool(mask & 4)
        expected = {hex(off): '' for off in STRINGS}
        expected.update({'0x10': '' if empty else 'owner-f0-🙂', '0x20': '' if empty else 'owner-e0-🙂',
            '0x30': state['main'] if main else '', '0x40': '' if empty else 'global-Ж', '0x78': state['nm'],
            '0x88': '' if empty else 'owner-100-🙂',
            '0xa0': (state['sdk_value_expected'] if sdk else read_text(sdk_value)) if main else '',
            '0xd8': state['aux'] if aux else '', '0x110': compiled_tag})
        os_code = 0 if platform == 'Android' else 1 if platform == 'IOS' else 6 if platform == 'Windows' and main and mode == 1 else 3
        integers = {'0x50': 0 if empty else 0x89abcdef, '0x98': {1: 1, 2: 2, 3: 3, 4: 5}.get(selector, 0),
            '0x99': os_code, '0xb0': state['number'], '0xf8': 207, '0x120': 0 if empty else 0xffffffff,
            '0x124': 0 if empty else 0xf3, '0x128': 0, '0x130': state['flag'] if enabled else 0,
            '0x131': state['extra_flag'] if extra else 0}
        require(state['sent'] and state['strings'] == expected and state['integers'] == integers,
                'Login prepared fields differ: ' + name + ' ' + repr(state.get('integers')))
        events = state['events']
        require(state.get('destroyed') and events.count('send') == 1 and events.count('post_notify') == 1
                and events.count('sdk_event') == int(main) and events.count('owner_number') == 2 + int(main),
                'Login post-send lifecycle differs')
        require(events.index('send') < events.index('post_notify') < events.index('destructor'), 'Login cleanup order differs')
        if main:
            require(events.index('post_notify') < events.index('sdk_event') < events.index('destructor'), 'Login SDK event order differs')
        require(events.count('sdk_mode') == int(platform == 'Windows' and main), 'Login SDK mode branch differs')
        require(events.count('sdk_aux_text') == int(aux) and events.count('sdk_main_text') == int(main)
                and events.count('sdk_value') == int(main) and events.count('sdk_flag') == int(enabled)
                and events.count('sdk_extra_flag') == int(extra), 'Login SDK projection branches differ')
        require(set(state['allocations']) - input_pointers - state.get('sdk_retained', set()) == state['freed'],
                'Login preparation leak or input free')
        require(all(bytes(h.uc.mem_read(at, len(data))) == data for at, data in inputs.items())
                and all(bytes(h.uc.mem_read(at - 16, len(data))) == data for at, data in input_buffers.items()), 'Login input changed')
        require(all(reg(k) == v for k, v in abi.items()) and reg('RSP') == h.scratch + 0x38008, 'Login prepare ABI differs')
        cases.append(dict(scenario=name, selector=selector, empty=empty, send_return=send_return, poison=poison,
                          strings=state['strings'], integers=state['integers'], guards=True,
                          sdk_event=main, lifecycle=['send', 'post_notify'] + (['sdk_event'] if main else []) + ['destructor']))
        if sdk:
            cases[-1].update(cache_case=cache_case, native_calls=dict(state['sdk_native_calls']))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
        evidence=h.evidence, runtime=load('update-native-harness').runtime_inputs(), network_used=False, profile_activated=False,
        native_sdk_used=bool(sdk), metadata_fields=metadata_fields if sdk else None,
        sdk_fixture_sha256=hashlib.sha256((HERE / 'login-sdk-fixtures.py').read_bytes()).hexdigest() if sdk else None,
        limits=['Whole Login prepare/constructor plus declared SDK functions/leaves execute native source instructions.' if sdk
                else 'Only whole Login prepare and constructor execute native source instructions.',
                'Aux metadata collector, platform text/selector, inner SDK cache/string boundaries, allocator/destructor, send and post-send notifications remain fixtures.' if sdk
                else 'SDK getters/objects, platform text, selector, language/number, strings/allocator/destructor, send and post-send notifications are explicit fixtures.',
                'Stable synthetic SDK manager/handles; no concurrent mutation, real SDK values, wire integration or result readers proved.',
                'When native_sdk_used, declared leaves and mode/main/value getters are native; inner platform text/cache resolver/string boundaries remain fixtures.',
                'Metadata key/consumer projection is static; auxiliary metadata collector is not executed and field values/encoding are not proven.',
                'Windows source platform branches are fixtures, not Android/IOS runtime compatibility. No authorization or profile activation.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-login-prepare-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
