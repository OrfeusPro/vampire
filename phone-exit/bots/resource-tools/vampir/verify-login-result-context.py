"""Current whole LoginResult/nested reader projection with explicit archive fixtures."""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
STRINGS = (0x18, 0x28, 0x38, 0x70, 0x90, 0xb8, 0xc8)
U32 = (0x10, 0x130, 0x134)
U16 = (0x48, 0x60)
U64 = (0x58, 0x68, 0x80, 0xb0, 0xf0, 0x100, 0x110, 0x120)
FLAGS = (0x88, 0xa0, 0xe0, 0x128, 0x138)
ORDER = (('u32', 0x10), ('string', 0x18), ('string', 0x28), ('string', 0x38),
         ('u16', 0x48), ('time', 0x58), ('u16', 0x60), ('u64', 0x68),
         ('string', 0x70), ('u64', 0x80), ('bool', 0x88), ('string', 0x90),
         ('bool', 0xa0), ('time', 0xb0), ('string', 0xb8), ('string', 0xc8),
         ('bool', 0xe0), ('time', 0xf0), ('time', 0x100), ('time', 0x110),
         ('time', 0x120), ('bool', 0x128), ('raw32', 0x130), ('raw32', 0x134), ('bool', 0x138))
WIDTH = dict(u32=4, raw32=4, u16=2, time=8, u64=8, bool=1)


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    functions = {key: int(at, 16) for key, at in context['functions'].items()}
    leaves = {int(at, 16): spec['bytes'] for at, spec in context['leaves'].items()}
    input_ = context.get('native_input')
    exports = dict(context['exports'])
    roots = set(functions.values())
    if input_:
        if input_['source_sha256'] != context['source_sha256']:
            raise ValueError('LoginResult input source differs')
        roots.update(int(at, 16) for at in input_['functions'].values())
        exports.update(input_['exports'])
        leaves.update({int(at, 16): spec['bytes'] for at, spec in input_['leaves'].items()})
    handler = context.get('native_handler')
    if handler:
        if handler['source_sha256'] != context['source_sha256']:
            raise ValueError('LoginResult handler source differs')
        roots.update(int(at, 16) for at in handler['functions'].values())
        exports.update(handler['exports'])
        leaves.update({int(at, 16): code for at, code in handler['leaves'].items()})
    h = load('update-native-harness').make_harness(context, exports, roots, leaves=leaves, root=root)
    native, rows = load('build-native-entry-code'), load('update-bindings').rows
    calls = {hex(r['address']): {'target': hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
             for at in functions.values() for r in rows(native, h.image, at) if r['call']}
    if calls != context['call_sites']:
        raise ValueError('LoginResult call sites differ')
    for spec in context['tables']:
        at = int(spec['address'], 16)
        data = bytes.fromhex(spec['bytes'])
        off = h.image.offset(at - h.image.pe.base)
        if h.raw[off:off + len(data)] != data or hashlib.sha256(data).hexdigest() != spec['sha256']:
            raise ValueError('LoginResult table bytes differ')
    packet_table, time_table, period_table = [int(context[key], 16) for key in ('packet_table', 'time_table', 'period_table')]
    for table, reader in ((packet_table, functions['reader']), (time_table, functions['time_reader']),
                          (period_table, functions['period_reader'])):
        if struct.unpack_from('<Q', h.raw, h.image.offset(table - h.image.pe.base) + 0x20)[0] != reader:
            raise ValueError('LoginResult reader table link differs')
    id_getter = int(context['id_getter'], 16)
    if struct.unpack_from('<Q', h.raw, h.image.offset(packet_table - h.image.pe.base) + 0x28)[0] != id_getter:
        raise ValueError('LoginResult ID table link differs')
    if h.call(id_getter) != 4:
        raise ValueError('LoginResult ID differs')
    packet, archive, archive_table = [h.scratch + n for n in (0x1000, 0x2000, 0x3000)]
    state = {}

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def archive_fixture(kind):
        def execute(machine):
            a, b = reg('RCX'), reg('RDX')
            require(a == archive and len(state['operations']) < len(ORDER), 'LoginResult archive receiver/budget differs')
            expected_kind, offset = ORDER[len(state['operations'])]
            require((kind, b) == (expected_kind, packet + offset), 'LoginResult field order or destination differs')
            state['operations'].append([kind, hex(offset)])
            if state['fail_at'] == len(state['operations']) - 1:
                h.finish(0)
                return
            position = state['position']
            if input_:
                position = input_position()
                state['position'] = position
            if kind == 'string':
                if position + 2 > len(state['body']):
                    h.finish(0)
                    return
                size = int.from_bytes(state['body'][position:position + 2], 'little')
                state['position'] += 2
                position += 2
                if input_:
                    set_input_position(state['position'])
            else:
                size = WIDTH[kind]
            if position + size > len(state['body']):
                h.finish(0)
                return
            raw = state['body'][position:position + size]
            state['position'] += size
            if input_:
                set_input_position(state['position'])
            if kind == 'string':
                text = raw.decode('utf-8')
                require('\0' not in text, 'LoginResult fixture NUL unsupported')
                data = text.encode('utf-16le') + b'\0\0' if text else b''
                pointer = state['heap'] + 16 if data else 0
                require(len(data) <= 2048 and state['heap'] + len(data) + 64 < h.scratch + 0x30000,
                        'LoginResult string allocation bound')
                if data:
                    h.uc.mem_write(pointer - 16, b'\xa5' * 16 + data + b'\xa6' * 16)
                    state['heap'] += (len(data) + 63) & ~15
                    state['allocations'][pointer] = len(data)
                count = len(data) // 2
                h.uc.mem_write(b, struct.pack('<QII', pointer, count, count))
            else:
                if kind == 'bool':
                    # Explicit primitive policy; normalization inside the real archive is not proved here.
                    raw = bytes([int(raw[0] != 0)])
                h.uc.mem_write(b, raw)
            state['written'].append(offset)
            h.finish(state['primitive_true'])
        return execute

    fixture = {key: int(at, 16) for key, at in context['fixtures'].items()}
    for kind, at in fixture.items():
        if input_ and input_.get('string_fixtures'):
            continue
        if input_ and kind != 'string':
            continue
        h.add_fixture(at, archive_fixture(kind))
    for slot, kind in ((0x28, 'time'), (0x50, 'u64'), (0x58, 'u32'), (0x60, 'raw32'), (0x70, 'u16'), (0x88, 'bool')):
        h.uc.mem_write(archive_table + slot, struct.pack('<Q', fixture[kind]))
    h.uc.mem_write(archive - 16, b'\xa5' * 16 + struct.pack('<Q', archive_table) + b'\xa6' * 16)
    archive_guard = bytes(h.uc.mem_read(archive - 16, 40))
    if input_:
        seed_input, input_position, set_input_position, check_input, construction_cases = load('login-result-input-fixtures').install(
            load, h, input_, state, packet, archive, ORDER)
        if input_.get('string_fixtures'):
            load('login-result-string-fixtures').install(load, h, input_, state, packet, STRINGS)
    all_tables = ((0, packet_table), (0x50, time_table), (0xa8, time_table), (0xd8, period_table)) + tuple(
        (off, time_table) for off in (0xe8, 0xf8, 0x108, 0x118))
    abi = {name: 0xfedcba9876543210 + i for i, name in enumerate(('RBX', 'RSI', 'RDI', 'RBP', 'R12', 'R13', 'R14', 'R15'))}

    def capture():
        values = dict(strings=[], u32=[], u16=[], u64=[], flags=[])
        for off in STRINGS:
            pointer, count, capacity = struct.unpack('<QII', h.uc.mem_read(packet + off, 16))
            require(count == capacity and 0 <= count <= 1024, 'LoginResult descriptor differs')
            values['strings'].append(bytes(h.uc.mem_read(pointer, count * 2))[:-2].decode('utf-16le') if count else '')
        for key, offsets, size in (('u32', U32, 4), ('u16', U16, 2), ('u64', U64, 8), ('flags', FLAGS, 1)):
            values[key] = [int.from_bytes(h.uc.mem_read(packet + off, size), 'little') for off in offsets]
        return values

    def read(body, poison=0x55, fail_at=None, primitive_true=1):
        state.clear()
        state.update(body=body, position=0, operations=[], written=[], heap=h.scratch + 0x10000,
                     allocations={}, fail_at=fail_at, primitive_true=primitive_true)
        if input_ and input_.get('string_fixtures'):
            # Explicit initial stack contents; malformed conversion may consume its NUL.
            h.uc.mem_write(h.scratch + 0x30000, bytes(0x8000))
        h.uc.mem_write(packet - 16, b'\xa5' * 16 + bytes([poison]) * 0x140 + b'\xa6' * 16)
        h.call(functions['constructor'], packet)
        if input_:
            seed_input(body, poison)
        before = bytes(h.uc.mem_read(packet, 0x140))
        for name, value in abi.items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
        h.uc.reg_write(h.x.UC_X86_REG_RDX, archive)
        returned = h.call(functions['reader'], packet, budget=1000000 if input_ and input_.get('string_fixtures') else 30000) & 255
        if input_:
            state['position'] = input_position()
            check_input()
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'LoginResult ABI differs')
        require(bytes(h.uc.mem_read(packet - 16, 16)) == b'\xa5' * 16
                and bytes(h.uc.mem_read(packet + 0x140, 16)) == b'\xa6' * 16, 'LoginResult object guards changed')
        if not input_:
            require(bytes(h.uc.mem_read(archive - 16, 40)) == archive_guard, 'LoginResult archive input changed')
        for off, table in all_tables:
            require(int.from_bytes(h.uc.mem_read(packet + off, 8), 'little') == table, 'LoginResult nested vptr differs')
        allowed = set()
        for off in ([int(at, 16) for _, at in state['operations']] if input_ else state['written']):
            kind = next(kind for kind, field in ORDER if field == off)
            allowed.update(range(off, off + (16 if kind == 'string' else WIDTH[kind])))
        after = bytes(h.uc.mem_read(packet, 0x140))
        require(all(a == b for i, (a, b) in enumerate(zip(before, after)) if i not in allowed),
                'LoginResult write outside decoded field')
        for pointer, size in state['allocations'].items():
            require(bytes(h.uc.mem_read(pointer - 16, 16)) == b'\xa5' * 16
                    and bytes(h.uc.mem_read(pointer + size, 16)) == b'\xa6' * 16, 'LoginResult string guard changed')
        if input_ and input_.get('string_fixtures'):
            final_pointers = {int.from_bytes(h.uc.mem_read(packet + off, 8), 'little') for off in STRINGS} - {0}
            require(set(state['allocations']) - final_pointers == state.get('string_freed', set()),
                    'LoginResult temporary leak or final string freed')
        require(state['position'] <= len(body), 'LoginResult reads past available body')
        result = dict(returned=returned, consumed=state['position'], operations=list(state['operations']),
                      fields=capture(), guards=True, body_hex=body.hex(), fail_at=fail_at)
        if input_:
            result.update(input_entries=dict(state['input_entries']),
                          last_count=int.from_bytes(h.uc.mem_read(archive + 0x10, 4), 'little'))
        return result

    def payload(text, code, raw_flag):
        parts = []
        expected = dict(strings=[text] * 7, u32=[code, 0xfedcba98, 0x89abcdef], u16=[0x8000, 0xffff],
                        u64=[0x8000000000000000 + i for i in range(8)], flags=[int(raw_flag != 0)] * 5)
        for kind, off in ORDER:
            if kind == 'string':
                data = text.encode('utf-8')
                parts.extend((len(data).to_bytes(2, 'little'), data))
            else:
                value = expected['u32'][U32.index(off)] if off in U32 else expected['u16'][U16.index(off)] if off in U16 else (
                    expected['u64'][U64.index(off)] if off in U64 else raw_flag)
                parts.append(value.to_bytes(WIDTH[kind], 'little'))
        return b''.join(parts), expected

    cases = []
    # Once all primitives are native, the fixture return-value dimension has no effect.
    true_values = (1,) if input_ and input_.get('string_fixtures') else (1, 128)
    for text, code, flag, poison, true_value in itertools.product(
            ('', 'ASCII', 'x' * 128, 'Ж界🙂'), (0, 1, 16, 58, 0xffffffff), (0, 1, 2, 255), (0x55, 0xaa), true_values):
        body, expected = payload(text, code, flag)
        case = read(body, poison, primitive_true=true_value)
        require(case['returned'] == 1 and case['consumed'] == len(body) and case['fields'] == expected,
                'LoginResult full field projection differs ' + repr((text, code, flag, case['returned'], case['consumed'], len(body), case['fields'])))
        cases.append(case)
    truncated = []
    for text in ('', 'x', '🙂'):
        body, _ = payload(text, 0, 255)
        for size in range(len(body)):
            case = read(body[:size])
            require(case['returned'] == 0, 'LoginResult accepted short body')
            truncated.append(case)
    body, _ = payload('Ж🙂', 0, 255)
    failures = []
    for at in range(len(ORDER)):
        case = read(body, fail_at=at)
        require(case['returned'] == 0 and len(case['operations']) == at + 1, 'LoginResult read continued after failure')
        failures.append(case)
    trailing_body, _ = payload('', 0, 0)
    trailing = read(trailing_body + b'extra')
    require(trailing['returned'] == 1 and trailing['consumed'] == len(trailing_body), 'LoginResult trailing behavior differs')
    special, boundaries = [], []
    if input_ and input_.get('string_fixtures'):
        for size in (15, 16, 127, 128):
            body, expected = payload('x' * size, 0, 255)
            case = read(body)
            require(case['returned'] == 1 and case['fields'] == expected, 'Native string boundary differs')
            boundaries.append(case)
        minimal, _ = payload('', 0, 0)
        for data in (b'\xff', b'\xc0\xaf', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'a\0b', b'\xef\xbf\xbe'):
            body = minimal[:4] + len(data).to_bytes(2, 'little') + data + minimal[6:]
            special.append(read(body))
    handler_report = None
    if handler:
        def body_for_handler(code, field48, raw16, settings):
            values = dict(strings=[settings.get('reader_text', 'fixture'), '', settings['message'], '', '', '', ''],
                          u32=[code, 0xfedcba98, 0x89abcdef], u16=[field48, raw16],
                          u64=[0x8000000000000000 + i for i in range(8)],
                          flags=[1, 1, 1, 1, settings['flag138']])
            parts = []
            for kind, off in ORDER:
                if kind == 'string':
                    data = values['strings'][STRINGS.index(off)].encode('utf-8')
                    parts.extend((len(data).to_bytes(2, 'little'), data))
                else:
                    key, offsets = ('u32', U32) if off in U32 else ('u16', U16) if off in U16 else (
                        ('u64', U64) if off in U64 else ('flags', FLAGS))
                    parts.append(values[key][offsets.index(off)].to_bytes(WIDTH[kind], 'little'))
            return b''.join(parts), values

        def read_packet(code, field48, raw16, settings):
            body, expected = body_for_handler(code, field48, raw16, settings)
            if 'reader_cut' in settings:
                body = body[:settings['reader_cut']]
            result = read(body, fail_at=settings.get('reader_fail'))
            if result['returned'] == 1:
                require(result['fields'] == expected and result['consumed'] == len(body), 'Handler input projection differs')
            require(state['heap'] < h.scratch + 0x28000, 'Reader heap overlaps handler storage')
            return result

        def check_after_handler():
            check_input()
            for pointer, size in state['allocations'].items():
                require(bytes(h.uc.mem_read(pointer - 16, 16)) == b'\xa5' * 16
                        and bytes(h.uc.mem_read(pointer + size, 16)) == b'\xa6' * 16,
                        'Handler changed reader allocation guards')

        normal, _ = body_for_handler(0, 0, 0x8000, dict(message='', flag138=1))
        handler_report = load('verify-login-result-handler-context').verify(handler, root, shared=dict(
            h=h, read_packet=read_packet, check_after=check_after_handler,
            additional_settings=[dict(reader_text=value) for value in ('', 'Ж界🙂', 'x' * 15, 'x' * 16, 'x' * 127, 'x' * 128)],
            rejected_settings=[dict(reader_cut=i) for i in range(len(normal))] + [dict(reader_fail=i) for i in range(len(ORDER))]))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
                truncated=truncated, failures=failures, trailing=trailing, evidence=h.evidence,
                runtime=load('update-native-harness').runtime_inputs(), network_used=False, profile_activated=False,
                native_input_used=bool(input_),
                handler=handler_report,
                construction_cases=construction_cases if input_ else [],
                native_string_used=bool(input_ and input_.get('string_fixtures')), special=special, boundaries=boundaries,
                string_fixture_sha256=hashlib.sha256((HERE / 'login-result-string-fixtures.py').read_bytes()).hexdigest() if input_ and input_.get('string_fixtures') else None,
                input_fixture_sha256=hashlib.sha256((HERE / 'login-result-input-fixtures.py').read_bytes()).hexdigest() if input_ else None,
                limits=['Whole current packet/nested constructors and readers plus two leaves and virtual read thunk execute.',
                        'Input constructor/scalars/raw IO/bookkeeping execute when native_input_used; UTF-8/FString readers execute only when native_string_used.',
                        'Buffer binding is native only with explicit buffer_construction; memcpy and bounded string storage remain fixtures. Whole reading is little endian only.',
                        'Native string runs use a zero-filled initial stack; malformed outputs do not prove termination writes or general malformed behavior.',
                        'Handler/gate only execute when handler report is present; no real dispatch, network, login success or runtime activation proved.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-login-result-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']), truncated=len(report['truncated']), failures=len(report['failures']))))
