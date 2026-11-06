"""Current Create104 INPUT/record/handler with explicit engine boundaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/create-handler-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'create-handler-current-v1'
HANDLER = 0x1467984c0


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def barrier(inputs):
    if any(digest(path) != sha for path, sha in inputs.items()):
        raise ValueError('Current Create handler retained input changed')


def definition(context_path, root):
    context_path = Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    if (context.get('schema'), context.get('recipe'), context.get('source_sha256'), context.get('handler')) != (
            1, RECIPE, SOURCE, hex(HANDLER)):
        raise ValueError('Current Create handler context differs')
    parent = load('verify-create-result-current')
    pointer = context['create_result_proof']
    if digest(pointer['path']) != pointer['sha256']:
        raise ValueError('Current Create handler parent proof changed')
    proof = parent.verify_report(pointer['path'], root=root)
    record, packet, harness, parent_definition = parent.materials(root, parent.CONTEXT)
    inputs = dict(parent_definition['inputs'])
    for path in (context_path, Path(__file__).resolve(), Path(pointer['path']),
                 HERE / 'research-workflow.py', HERE / 'audit-client-release.py'):
        inputs[str(path.resolve())] = digest(path)
    for run, sha in context['exports'].items():
        inputs[str(root / 'ghidra/request-exports' / SOURCE / run / 'details.json')] = sha
    if proof['source_sha256'] != SOURCE:
        raise ValueError('Current Create handler parent source differs')
    barrier(inputs)
    return context, record, packet, harness, dict(schema=1, recipe=RECIPE, source_sha256=SOURCE,
        inputs=inputs, runtime=parent_definition['runtime'])


def execute(context, record_context, packet_context, harness, root):
    parent = load('verify-create-result-current')
    functions = {key: value for key, value in record_context['functions'].items() if not key.startswith('list_')}
    functions.update(result_constructor=hex(parent.CONSTRUCTOR), result_reader=hex(parent.READER), handler=hex(HANDLER))
    leaves = {at: code for at, code in record_context['leaves'].items()
              if at not in (record_context['bindings']['id_getter'], record_context['bindings']['packet_constructor'])}
    native_context = dict(record_context, functions=functions, leaves=leaves, verify_whole_exports=True)
    exports = record_context['exports'] | packet_context['exports'] | context['exports']
    roots = {int(at, 16) for at in functions.values()}
    if len(roots) != 34 or len(exports) != 9:
        raise ValueError('Current Create handler explicit root/export scope differs')
    h = load('create_handler_native', harness).make_harness(native_context, exports, roots,
        leaves={int(at, 16): data for at, data in leaves.items()}, root=root)
    load('verify-create-packets-current').static_contract(packet_context, h.image)
    uc, x, scratch = h.uc, h.x, h.scratch
    packet, archive, buffer = (scratch + off for off in (0x31000, 0x2000, 0x5000))
    record = packet + 0x18
    manager, selection, ui, ui_type, metadata, hierarchy, vtable, sdk_manager = (
        scratch + off for off in (0x8000, 0x9000, 0xa000, 0xc000, 0xb000, 0xd000, 0xe000, 0xf000))
    list_manager, ui_manager = scratch + 0x7400, scratch + 0x7800
    state, events = dict(packet=packet), []

    def require(ok, message):
        if not ok:
            raise ValueError('Current Create handler ' + message)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def number(at, width=8):
        return int.from_bytes(uc.mem_read(at, width), 'little')

    def put(at, value, width=8):
        uc.mem_write(at, value.to_bytes(width, 'little'))

    def allocate(size):
        require(0 < size <= 4096 and state['heap'] + size + 64 < scratch + 0x30000, 'allocation budget')
        at = state['heap'] + 16
        state['heap'] += (size + 63) & ~15
        uc.mem_write(at - 16, b'\xa5' * 16 + bytes(size) + b'\xa6' * 16)
        state['allocations'][at] = size
        return at

    def text(at):
        pointer, count, capacity = struct.unpack('<QII', uc.mem_read(at, 16))
        require(0 <= count <= capacity <= 128 and (not count or pointer in state['allocations']), 'FString bound')
        return bytes(uc.mem_read(pointer, count * 2))[:-2].decode('utf-16le') if count else ''

    def write_text(at, value):
        data = value.encode('utf-16le') + b'\0\0' if value else b''
        pointer = allocate(len(data)) if data else 0
        if data:
            uc.mem_write(pointer, data)
        uc.mem_write(at, struct.pack('<QII', pointer, len(data) // 2, len(data) // 2))

    record_tool = load('verify-character-record-context')
    load('login-result-string-fixtures').install(load, h, record_context['string_storage'], state, record, record_tool.STRINGS)
    load('character-list-storage-fixtures').install(h, record_context, state, allocate)
    if roots & set(h.fixtures):
        raise ValueError('Current Create handler fixture overlaps a composed native root')
    string_free = h.fixtures.get(0x1414830e0)
    called = set()
    ids = {
        0x145d507e0: 'manager', 0x145d603d0: 'name_match', 0x145c9df60: 'list_manager',
        0x145c9a470: 'insert_record', 0x14641ce50: 'selection', 0x144a27df0: 'ui_manager',
        0x146437a50: 'ui_metadata', 0x144a26d30: 'ui_lookup', 0x145d507a0: 'manager_finalize',
        0x145d568a0: 'finalize', 0x14560ad70: 'sdk_manager', 0x14563c4b0: 'sdk_feature',
        0x145fd70f0: 'error', 0x14641cdf0: 'player', 0x1445d3090: 'error_ui',
        0x145c90290: 'error_metadata', 0x141436f30: 'resize', 0x14145f240: 'compare',
        0x1414830e0: 'free', scratch + 0xf00: 'refresh',
    }

    def fixture(machine):
        name = ids[reg('RIP')]
        a, b, c = (reg(register) for register in ('RCX', 'RDX', 'R8'))
        result = 0
        called.add(name)
        if name in ('manager', 'manager_finalize'):
            result = manager
        elif name == 'list_manager':
            result = list_manager
        elif name == 'ui_manager':
            result = ui_manager
        elif name == 'name_match':
            require(a == manager, 'name callback receiver differs')
            events.append(name)
        elif name == 'insert_record':
            require((a, b) == (list_manager, record), 'decoded record handoff differs')
            require(number(record + 8) == state['key'] and text(record + 0x18) == state['name'], 'record fields changed before insertion')
            events.append(name)
        elif name == 'selection':
            result = selection if state['selected'] else 0
        elif name in ('ui_metadata', 'error_metadata'):
            result = metadata
        elif name == 'ui_lookup':
            require((a, b) == (ui_manager, metadata), 'UI lookup arguments differ')
            result = ui if state['ui'] != 'missing' else 0
        elif name == 'refresh':
            require((a, b, c) == (ui, 1, 1), 'UI refresh arguments differ')
            events.append(name)
        elif name == 'finalize':
            require(a == manager, 'finalizer receiver differs')
            events.append(name)
        elif name == 'sdk_manager':
            result = sdk_manager if state['sdk'] != 'missing' else 0
        elif name == 'sdk_feature':
            require(a == 0x12345678, 'SDK feature receiver differs')
            events.append(name)
        elif name == 'error':
            require((a & 0xffffffff, b) == (state['code'], 0), 'error arguments differ')
            events.append(name)
        elif name == 'player':
            result = manager if state['player'] else 0
        elif name == 'error_ui':
            require(a == 0, 'error UI lookup argument differs')
            result = ui if state['ui'] != 'missing' else 0
        elif name == 'resize':
            require(0 < b <= 128, 'temporary name allocation differs')
            pointer = allocate(b * 2)
            uc.mem_write(a, struct.pack('<QII', pointer, b, b))
            state['handler_allocations'].add(pointer)
        elif name == 'compare':
            def terminated(pointer):
                data = bytearray()
                for offset in range(128):
                    part = bytes(uc.mem_read(pointer + offset * 2, 2))
                    if part == b'\0\0':
                        return bytes(data)
                    data.extend(part)
                raise ValueError('Current Create handler comparator bound')
            result = int(terminated(a) != terminated(b))
        elif name == 'free':
            if a not in state['handler_allocations']:
                require(string_free is not None, 'unknown free')
                return string_free(machine)
            require(a not in state['freed'], 'temporary name freed twice')
            state['freed'].add(a)
        else:
            raise ValueError('Unhandled current Create handler fixture')
        h.finish(result)

    for at in ids:
        h.add_fixture(at, fixture)

    import unicorn
    scenarios = [
        dict(code=0, name='Тест日本', expected='Тест日本', selected=True, ui='valid', sdk='active', player=True),
        dict(code=0, name='Тест日本', expected='Other!', selected=False, ui='missing', sdk='off', player=True),
        dict(code=0, name='', expected='', selected=True, ui='mismatch', sdk='missing', player=True),
        dict(code=1, name='', expected='', selected=False, ui='valid', sdk='off', player=False),
        dict(code=58, name='', expected='', selected=False, ui='valid', sdk='off', player=True),
        dict(code=0xffffffff, name='', expected='', selected=False, ui='disabled', sdk='off', player=True),
    ]
    results = []
    for case in scenarios:
        body = struct.pack('<I', case['code']) + record_tool.body_for(case['name'], 1, 1, 1, 0x1234)
        state.clear()
        state.update(case, packet=packet, record=record, generation=1, body=body, heap=scratch + 0x10000,
                     allocations={}, map_storage={}, insertions=[], rehashes=[], handler_allocations=set(), freed=set(), key=0x1234)
        events.clear()
        called.clear()
        uc.mem_write(packet - 16, b'\xa7' * 16 + bytes(0x188) + b'\xa8' * 16)
        h.call(parent.CONSTRUCTOR, packet)
        uc.mem_write(archive, bytes(0x40))
        uc.mem_write(buffer, body)
        for name, value in (('RDX', buffer), ('R8', len(body)), ('R9', 1)):
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.mem_write(scratch + 0x38028, bytes(8))
        h.call(int(functions['input_constructor'], 16), archive)
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        require(h.call(parent.READER, packet, budget=1000000) & 255 == 1, 'current native body reader rejected input')
        require(number(archive + 0x30) - buffer == len(body) and number(packet + 0x10, 4) == case['code'], 'native INPUT boundary differs')
        for at, size in ((manager, 0x400), (selection, 0x410), (ui, 0x600), (ui_type, 0x80),
                         (metadata, 0x80), (hierarchy, 32), (vtable, 0x600), (sdk_manager, 0xb0)):
            uc.mem_write(at, bytes(size))
        write_text(manager + 0x350, case['expected'])
        put(ui, vtable)
        put(ui + 0x10, ui_type)
        put(vtable + 0x598, scratch + 0xf00)
        put(metadata + 0x38, 1, 4)
        put(ui_type + 0x30, hierarchy)
        put(ui_type + 0x38, 2, 4)
        put(hierarchy + 8, metadata + (0x20 if case['ui'] == 'mismatch' else 0x30))
        put(ui + 0x378, 1, 1)
        put(sdk_manager + 0xa0, 0x12345678 if case['sdk'] == 'active' else 0)
        put(0x14b594eb3, int(case['sdk'] != 'off'), 1)
        put(0x14b2f2fcb, int(case['ui'] == 'disabled'), 1)
        before = bytes(uc.mem_read(packet, 0x188))
        abi = {name: 0xabc0000000000000 + index for index, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, 0)
        uc.reg_write(x.UC_X86_REG_R8, packet)
        fault = None
        try:
            h.call(HANDLER, 0, budget=200000)
        except unicorn.UcError:
            fault = reg('RIP')
        expect_fault = case['code'] != 0 and case['player'] and case['ui'] == 'disabled'
        require(bool(fault) == expect_fault, 'null error UI fault boundary differs')
        if fault:
            require(fault == 0x146798527 and reg('RDI') == 0, 'unexpected native fault escaped handler model')
        require(bytes(uc.mem_read(packet, 0x188)) == before, 'handler changed result packet')
        require(bytes(uc.mem_read(packet - 16, 16)) == b'\xa7' * 16
                and bytes(uc.mem_read(packet + 0x188, 16)) == b'\xa8' * 16, 'packet guard changed')
        if not fault:
            require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == scratch + 0x38008,
                    'handler ABI differs')
        if case['code'] == 0:
            expected = (['name_match'] if case['name'] == case['expected'] else []) + ['insert_record']
            expected += ['refresh'] if case['ui'] == 'valid' else []
            expected += ['finalize'] + (['sdk_feature'] if case['sdk'] == 'active' else [])
            require(events == expected, 'success event sequence differs')
            require(number(selection + 0x400) == (state['key'] if case['selected'] else 0), 'selected character key differs')
        else:
            require(events == ['error'] and 'insert_record' not in called, 'error used success consumers')
            require(number(ui + 0x378, 1) == (0 if case['player'] and not fault else 1), 'error wait state differs')
        for at, size in state['allocations'].items():
            require(bytes(uc.mem_read(at - 16, 16)) == b'\xa5' * 16 and bytes(uc.mem_read(at + size, 16)) == b'\xa6' * 16,
                    'allocation guard changed')
        require(state['handler_allocations'] == state['freed'], 'temporary name not freed')
        results.append(dict(code=case['code'], name_match=case['name'] == case['expected'], selection_present=case['selected'],
            ui=case['ui'], sdk=case['sdk'], player_present=case['player'], events=list(events),
            selected_key=number(selection + 0x400), body_sha256=hashlib.sha256(body).hexdigest(),
            packet_unchanged=True, input_consumed=len(body), null_error_ui_fault=hex(fault) if fault else None))
    return results


def validate(report, selected):
    expected = [
        (['name_match', 'insert_record', 'refresh', 'finalize', 'sdk_feature'], 0x1234, None),
        (['insert_record', 'finalize'], 0, None),
        (['name_match', 'insert_record', 'finalize'], 0x1234, None),
        (['error'], 0, None), (['error'], 0, None), (['error'], 0, '0x146798527'),
    ]
    if (report.get('recipe') != RECIPE or report.get('source_sha256') != SOURCE or report.get('definition') != selected
            or report.get('native_execution') is not True or report.get('runtime_admitted') is not False
            or report.get('network_used') is not False or len(report.get('cases', [])) != 6
            or [row['code'] for row in report['cases']] != [0, 0, 0, 1, 58, 0xffffffff]
            or [(row['events'], row['selected_key'], row['null_error_ui_fault']) for row in report['cases']] != expected
            or any(row['packet_unchanged'] is not True or row['input_consumed'] <= 4 for row in report['cases'])
            or not report.get('limits')):
        raise ValueError('Current Create handler receipt boundary differs')


def verify(context_path=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    c, record, packet, harness, selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['path']).resolve()
        if path != root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json' or digest(path) != pointer['sha256']:
            raise ValueError('Current Create handler cache pointer differs')
        validate(json.loads(path.read_bytes()), selected)
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    cases = execute(c, record, packet, harness, root)
    barrier(selected['inputs'])
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, cases=cases,
        native_execution=True, network_used=False, runtime_admitted=False,
        limits=['Current complete INPUT/record reader and handler execute together on the same packet.',
                'String assignment/allocation, comparison, record insertion, selection/UI/SDK services and side effects are bounded fixtures.',
                'Null error UI write is an emulator boundary observation, not a claim of a live crash.',
                'No producer, persistent character default, server meaning of raw codes, live account or creation admission.'])
    validate(report, selected)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    sha = digest(path)
    workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=sha)))
    return dict(report=str(path), sha256=sha, reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context)))
