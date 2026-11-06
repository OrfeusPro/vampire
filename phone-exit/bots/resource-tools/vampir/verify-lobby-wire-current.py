"""Current whole lobby reader with real INPUT/string/TimeBase providers.

Only storage/allocation/string assignment remain fixtures. The previous large
CharacterList and metadata matrices are retained as evidence, never replayed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/lobby-wire-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'lobby-wire-current-v1'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def definition(context_path, root):
    context_path, root = Path(context_path).resolve(), Path(root).resolve()
    context = json.loads(context_path.read_bytes())
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE or context.get('source_sha256') != SOURCE
            or context.get('function_budget') != 19 or context.get('verify_whole_exports') is not True
            or context['functions'].get('reader') != '0x14574f5d0'
            or context['functions'].get('constructor') != '0x145749a50'
            or context.get('string_constructor') != '0x1414269b0'
            or set(context['functions']) != {'constructor', 'reader', 'time_constructor', 'time_reader',
                'input_constructor', 'buffer_constructor', 'raw', 'std_string', 'string', 'time', 'u16', 'u32', 'u64', 'bool',
                'utf8_convert', 'utf8_core', 'utf8_length', 'utf8_scalar'}):
        raise ValueError('Current lobby wire context differs')
    pointer = context['reuse']['character_list']
    if digest(pointer['path']) != pointer['sha256']:
        raise ValueError('Current lobby wire shared CharacterList pointer changed')
    reused = load('verify-character-list-current').verify_report(pointer['path'], root=root)
    inputs = dict(reused['definition']['inputs'])
    inputs.update(reused['definition']['files'])
    inputs[pointer['path']] = pointer['sha256']
    pointer = context['reuse']['record_context']
    if digest(pointer['path']) != pointer['sha256']:
        raise ValueError('Current lobby wire retained INPUT context changed')
    record = json.loads(Path(pointer['path']).read_bytes())
    if record['source_sha256'] != SOURCE:
        raise ValueError('Current lobby wire INPUT source differs')
    for key, at in record['native_input']['functions'].items():
        if context['functions']['input_constructor' if key == 'constructor' else key] != at:
            raise ValueError('Current lobby wire INPUT root role differs')
    for key in ('time_constructor', 'time_reader'):
        if context['functions'][key] != record['functions'][key]:
            raise ValueError('Current lobby wire TimeBase root differs')
    expected_leaves = {at: spec['bytes'] for at, spec in record['native_input']['leaves'].items()}
    expected_leaves.update({at: record['leaves'][at] for at in ('0x144aad280', '0x1457fdef0')})
    if context['leaves'] != expected_leaves:
        raise ValueError('Current lobby wire INPUT/TimeBase leaf closure differs')
    inputs[str(context_path)] = digest(context_path)
    for name in ('verify-lobby-wire-current.py', 'login-result-string-fixtures.py',
                 'update-native-harness.py', 'build-object-zero-init-code.py'):
        path = HERE / name
        inputs[str(path)] = digest(path)
    for name in ('lobby_current.py', 'lobby_packets.py', 'login_packet.py'):
        path = HERE.parents[1] / 'vampir-shared/vampir_core' / name
        inputs[str(path)] = digest(path)
    for run, sha in context['exports'].items():
        path = root / 'ghidra/request-exports' / SOURCE / run / 'details.json'
        if digest(path) != sha: raise ValueError('Current lobby wire export changed')
        inputs[str(path)] = sha
    selected = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, context=str(context_path),
                    inputs=inputs, runtime=load('update-native-harness').runtime_inputs())
    barrier(selected)
    return context, selected


def barrier(selected):
    if any(digest(path) != sha for path, sha in selected['inputs'].items()):
        raise ValueError('Current lobby wire retained input changed')


def execute(context, root):
    f = {key: int(at, 16) for key, at in context['functions'].items()}
    h = load('update-native-harness').make_harness(context, context['exports'], set(f.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    uc, x = h.uc, h.x
    packet, archive, buffer = [h.scratch + n for n in (0x1000, 0x2000, 0x5000)]
    state, operations = {}, []
    def reg(name): return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))
    def number(at, size): return int.from_bytes(uc.mem_read(at, size), 'little')
    def require(ok, why):
        if not ok: raise ValueError(why)
    def source(at, size):
        offset = h.image.offset(at - h.image.pe.base)
        return h.raw[offset:offset + size]
    for block in context['blocks']:
        at, data = int(block['address'], 16), bytes.fromhex(block['bytes'])
        require(source(at, len(data)) == data and hashlib.sha256(data).hexdigest() == block['sha256'],
                'Current lobby wire table bytes differ')
    require(number(int(context['input_table'], 16) + 0x30, 8) == f['std_string']
        and number(int(context['time_table'], 16) + 0x20, 8) == f['time_reader'],
        'Current lobby wire string/time virtual linkage differs')
    load('login-result-string-fixtures').install(load, h, context, state, packet, (0x40,))
    def string_constructor(machine):
        a = reg('RCX')
        require(a == packet + 0x40, 'Current lobby string constructor receiver differs')
        uc.mem_write(a, bytes(16)); h.finish(a)
    h.add_fixture(int(context['string_constructor'], 16), string_constructor)
    import unicorn
    primitives = {f[name]: name for name in ('u16', 'u32', 'u64', 'bool', 'time')}
    primitives[f['string']] = 'string'
    def entered(machine, at, size, unused):
        if at in primitives and packet + 0x10 <= reg('RDX') <= packet + 0x54:
            name = primitives[at]
            require(reg('RCX') == archive, 'Current lobby provider archive receiver differs')
            operations.append(dict(kind=name, destination=reg('RDX') - packet))
            if len(operations) == state['fail_at']:
                h.finish(0)
    uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.lobby_packets import decode_current_lobby_version_result
    from vampir_core.lobby_current import make_current_windows_lobby_login
    expected_order = [('u32', 0x10), ('bool', 0x14), ('time', 0x20), ('time', 0x30),
                      ('u16', 0x38), ('string', 0x40), ('u32', 0x50), ('u32', 0x54)]

    def run(body, *, fail_at=None, tail=False):
        require(type(body) is bytes and len(body) <= 4096, 'Current lobby wire local payload budget')
        state.clear(); state.update(body=body, heap=h.scratch + 0x10000, allocations={}, fail_at=fail_at)
        operations.clear()
        uc.mem_write(h.scratch + 0x30000, bytes(0x8000))
        uc.mem_write(packet - 16, b'\xa5' * 16 + b'\x55' * 0x58 + b'\xa6' * 16)
        require(h.call(f['constructor'], packet) == packet, 'Current lobby constructor returned another packet')
        uc.mem_write(archive - 16, b'\xa7' * 16 + bytes(0x40) + b'\xa8' * 16)
        uc.mem_write(buffer - 16, b'\xa9' * 16 + body + b'\xaa' * 16)
        uc.reg_write(x.UC_X86_REG_RDX, buffer); uc.reg_write(x.UC_X86_REG_R8, len(body)); uc.reg_write(x.UC_X86_REG_R9, 1)
        uc.mem_write(h.scratch + 0x38028, bytes(8))
        # INPUT constructor creates the concrete bounded buffer through its native constructor.
        h.call(f['input_constructor'], archive)
        abi = {name: 0x1234567800000000 + index for index, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items(): uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        accepted = h.call(f['reader'], packet, budget=1000000) & 255
        consumed = number(archive + 0x30, 8) - buffer
        require(0 <= consumed <= len(body), 'Current lobby INPUT cursor escaped buffer')
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'Current lobby wire Win64 ABI differs')
        require(bytes(uc.mem_read(packet - 16, 16)) == b'\xa5' * 16 and bytes(uc.mem_read(packet + 0x58, 16)) == b'\xa6' * 16
                and bytes(uc.mem_read(buffer - 16, len(body) + 32)) == b'\xa9' * 16 + body + b'\xaa' * 16,
                'Current lobby wire packet/buffer guard changed')
        for at, size in state['allocations'].items():
            require(bytes(uc.mem_read(at - 16, 16)) == b'\xa5' * 16 and bytes(uc.mem_read(at + size, 16)) == b'\xa6' * 16,
                    'Current lobby wire storage guard changed')
        if accepted:
            wire = body[:consumed] if tail else body
            decoded = decode_current_lobby_version_result(wire, source_sha256=SOURCE)
            pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(packet + 0x40, 16)))
            require(count == capacity and 0 <= count <= 2048, 'Current lobby FString descriptor differs')
            text = bytes(uc.mem_read(pointer, (count - 1) * 2)).decode('utf-16-le') if count else ''
            actual = (number(packet + 0x10, 4), bool(number(packet + 0x14, 1)),
                (number(packet + 0x20, 8), number(packet + 0x30, 8)), number(packet + 0x38, 2),
                text, number(packet + 0x50, 4), number(packet + 0x54, 4))
            expected = (decoded.result_code, decoded.flag_14, decoded.time_bits, decoded.raw_38,
                        decoded.raw_40, decoded.raw_50, decoded.raw_54)
            require(actual == expected, 'Current lobby native wire/strict portable projection differs')
            require([(row['kind'], row['destination']) for row in operations] == expected_order,
                    'Current lobby native provider field order differs: ' + repr(operations))
            if decoded.result_code == 0 and not decoded.flag_14:
                binding = make_current_windows_lobby_login(version_result=decoded, kind=2, selected_server_id=0,
                    metadata='', source_sha256=SOURCE)
                require(binding.version_result is decoded and binding.metadata_applied is False,
                        'Current lobby binder discarded current result or claimed provider application')
        return dict(accepted=bool(accepted), consumed=consumed, operations=list(operations))

    def body(text, code=0, flag=0, first=0xffffffffffffffff, second=0x8000000000000000, offset=65535, left=0xffffffff, right=0x80000000):
        data = text.encode('utf-8')
        return struct.pack('<IBQQHH', code, flag, first, second, offset, len(data)) + data + struct.pack('<II', left, right)
    cases = [run(body(text, flag=flag)) for text in ('', 'Zone', 'Ж♥猫😀', 'X' * 130) for flag in (0, 255)]
    value = body('Ж♥猫😀')
    prefixes = [run(value[:size]) for size in range(len(value))]
    failures = [run(value, fail_at=stage) for stage in range(1, 9)]
    require(all(not item['accepted'] for item in prefixes + failures), 'Current lobby native input accepted a short/failed provider')
    require(all(len(item['operations']) == stage for stage, item in enumerate(failures, 1)), 'Current lobby provider failure did not stop reader')
    extra = run(value + b'extra', tail=True)
    require(extra['accepted'] and extra['consumed'] == len(value), 'Current lobby native reader tail policy differs')
    try: decode_current_lobby_version_result(value + b'extra', source_sha256=SOURCE)
    except ValueError: pass
    else: raise ValueError('Strict portable decoder accepted native-unconsumed tail')
    return dict(cases=cases, prefixes=prefixes, failures=failures, extra=extra)


def verify(context_path=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    context, selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge/lobby-wire-current-cache' / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes()); path = Path(pointer['path']).resolve()
        if (path != root / 'code-clues/lobby-wire-current-v1' / pointer['sha256'] / 'manifest.json'
                or digest(path) != pointer['sha256']): raise ValueError('Current lobby wire cache pointer differs')
        report = json.loads(path.read_bytes())
        if report['definition'] != selected: raise ValueError('Current lobby wire cached definition differs')
        validate(report); barrier(selected)
        return dict(report=str(path), sha256=digest(path), reused=True)
    result = execute(context, root)
    barrier(selected)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, **result,
        native_execution=True, network_used=False, runtime_admitted=False,
        limits=['Whole current constructor/reader, concrete INPUT/buffer/scalars, string/std-string/UTF8, TimeBase constructor/reader and dispatch leaf execute together.',
            'Only allocation/growth, FString assignment, free/cookie and initial empty FString constructor are bounded fixtures.',
            'Native reader permits an unconsumed tail; portable policy requires exact length and strict valid Unicode.',
            'No metadata consumer/provider, timezone database/OS state, native LoginPrepare, SDK/identity, transport, lobby session or world admission.'])
    validate(report)
    path = load('audit-client-release').save_snapshot(root / 'code-clues/lobby-wire-current-v1', report)
    workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=digest(path))))
    return dict(report=str(path), sha256=digest(path), reused=False)


def validate(report):
    if (report.get('source_sha256') != SOURCE or report.get('native_execution') is not True
            or report.get('network_used') is not False or report.get('runtime_admitted') is not False
            or not report.get('limits') or len(report.get('cases', [])) != 8
            or len(report.get('prefixes', [])) != 45 or len(report.get('failures', [])) != 8
            or any(row.get('accepted') is not True for row in report.get('cases', []))
            or any(row.get('accepted') is not False for row in report.get('prefixes', []) + report.get('failures', []))
            or report.get('extra', {}).get('accepted') is not True
            or report.get('extra', {}).get('consumed') != 45):
        raise ValueError('Current lobby wire report composition/boundary differs')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
