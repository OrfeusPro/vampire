"""Compose current Create 104 and the retained native CharacterRecord reader."""
import argparse
from dataclasses import asdict
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/create-result-current.json'
SHA = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'create-result-current-v1'
CONSTRUCTOR = 0x1456d6ea0
READER = 0x1456b7780
TABLE = 0x14992b068


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path or HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def materials(root, context_path):
    context_path = Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    if (context.get('schema'), context.get('recipe'), context.get('source_sha256'),
            context.get('runtime_admitted')) != (1, RECIPE, SHA, False):
        raise ValueError('Current Create Result context differs')
    packet_tool = load('verify-create-packets-current')
    pointer = context['packet_proof']
    if digest(pointer['path']) != pointer['sha256']:
        raise ValueError('Current Create packet proof changed')
    packet_proof = packet_tool.verify_report(pointer['path'], root=root)
    packet_context = json.loads(packet_tool.CONTEXT.read_bytes())
    list_pointer = packet_context['record_proof']
    list_proof = json.loads(Path(list_pointer['path']).read_bytes())
    generated = json.loads(Path(list_proof['definition']['generated']['path']).read_bytes())
    record_context_path = Path(generated['contexts']['character-list-records'])
    record_context = json.loads(record_context_path.read_bytes())
    harness = Path(record_context['current_character_harness']['path'])
    if (record_context['functions']['constructor'], record_context['functions']['reader'],
            record_context['functions']['input_constructor'], record_context['functions']['input_u32'],
            record_context['bindings']['record_table']) != (
                '0x145783c00', '0x1457888c0', '0x144aacc30', '0x144aac390', '0x14992b020'):
        raise ValueError('Current Create Result nested reader/INPUT bindings differ')
    if generated['files'].get(str(harness)) != digest(harness):
        raise ValueError('Current Create Result retained harness changed')
    files = dict(packet_proof['definition']['inputs'])
    for path in (context_path, Path(pointer['path']), Path(__file__),
                 HERE.parents[1] / 'vampir-shared/vampir_core/character_list.py'):
        files[str(path.resolve())] = digest(path)
    return record_context, packet_context, harness, dict(source_sha256=SHA, inputs=files,
                                                         runtime=packet_proof['definition']['runtime'])


def execute(record_context, packet_context, harness, root):
    context = dict(record_context)
    functions = {name: at for name, at in context['functions'].items() if not name.startswith('list_')}
    functions.update(result_constructor=hex(CONSTRUCTOR), result_reader=hex(READER))
    leaves = {at: code for at, code in context['leaves'].items()
              if at not in (context['bindings']['id_getter'], context['bindings']['packet_constructor'])}
    context.update(functions=functions, leaves=leaves, verify_whole_exports=True)
    exports = dict(context['exports'], **packet_context['exports'])
    roots = {int(at, 16) for at in functions.values()}
    if len(roots) != 33 or len(exports) != 8:
        raise ValueError('Current Create Result explicit composition budget differs')
    h = load('create_result_native', harness).make_harness(context, exports, roots,
        leaves={int(at, 16): code for at, code in leaves.items()}, root=root)
    load('verify-create-packets-current').static_contract(packet_context, h.image)
    uc, x = h.uc, h.x
    packet, archive, buffer = (h.scratch + off for off in (0x31000, 0x2000, 0x5000))
    record = packet + 0x18
    state, operations, boundaries = dict(packet=packet), [], []

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def number(at, width):
        return int.from_bytes(uc.mem_read(at, width), 'little')

    def allocate(size):
        require(0 < size <= 4096 and state['heap'] + size + 64 < h.scratch + 0x30000,
                'Create Result allocation budget')
        pointer = state['heap'] + 16
        state['heap'] += (size + 63) & ~15
        uc.mem_write(pointer - 16, b'\xa5' * 16 + b'\x5a' * size + b'\xa6' * 16)
        state['allocations'][pointer] = size
        return pointer

    def position():
        consumed = number(archive + 0x30, 8) - buffer
        require(0 <= consumed <= len(state['body']), 'Create Result cursor outside input')
        return consumed

    for block in context['blocks']:
        start, expected = int(block['address'], 16), bytes.fromhex(block['bytes'])
        off = h.image.offset(start - h.image.pe.base)
        require(h.raw[off:off + len(expected)] == expected, 'Create Result retained source table differs')
        for page in range(start & ~4095, (start + len(expected) + 4095) & ~4095, 4096):
            if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
                off = h.image.offset(page - h.image.pe.base)
                uc.mem_map(page, 4096)
                uc.mem_write(page, h.raw[off:off + 4096])
    record_tool = load('verify-character-record-context')
    load('login-result-string-fixtures').install(load, h, context['string_storage'], state,
                                               record, record_tool.STRINGS)
    load('character-list-storage-fixtures').install(h, context, state, allocate)
    if roots & set(h.fixtures):
        raise ValueError('Current Create Result fixture overlaps composed native code')

    import unicorn
    primitives = {int(functions['input_' + name], 16): name for name in ('u16', 'u32', 'u64', 'bool', 'raw')}
    nested_constructor, nested_reader = (int(functions[name], 16) for name in ('constructor', 'reader'))

    def entered(machine, at, size, unused):
        if at in (nested_constructor, nested_reader):
            require(reg('RCX') == record, 'Create Result nested receiver differs')
            if at == nested_reader:
                require(reg('RDX') == archive and position() == 4, 'Create Result nested input handoff differs')
                state['nested_start'] = len(operations)
            boundaries.append('constructor' if at == nested_constructor else 'reader')
        elif at in primitives:
            require(reg('RCX') == archive, 'Create Result primitive receiver differs')
            operations.append((primitives[at], position()))
            if len(operations) == state['fail_operation']:
                h.finish(0)

    uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.character_list import decode_character_list

    def portable(body):
        return decode_character_list(body[:4] + struct.pack('<IH', 0, 1) + body[4:] + bytes(28),
            max_payload_size=4130, max_characters=1, max_extension_items=16)

    def capture():
        strings = []
        for off in record_tool.STRINGS:
            pointer, count, capacity = struct.unpack('<QII', uc.mem_read(record + off, 16))
            require(count == capacity <= 2048 and (not count or pointer in state['allocations']),
                    'Create Result string descriptor differs')
            strings.append(bytes(uc.mem_read(pointer, count * 2))[:-2].decode('utf-16le') if count else '')
        projected = dict(strings=tuple(strings), enum60=number(record + 0x60, 1),
            appearance=tuple(uc.mem_read(record + 0xb8, 10)), appearance_flags=tuple(uc.mem_read(record + 0xd8, 2)),
            flag108=bool(number(record + 0x108, 1)))
        for field, offsets, width in (('u32', (0x10, 0x30), 4), ('u16', (0x70, 0x72, 0x74, 0x76), 2),
                                      ('u64', record_tool.U64, 8)):
            projected[field] = tuple(number(record + off, width) for off in offsets)

        def items(at, stride, layout):
            pointer, count, capacity = struct.unpack('<QII', uc.mem_read(at, 16))
            require(count <= capacity <= 8 and (not count or pointer in state['allocations']),
                    'Create Result extension descriptor differs')
            return tuple(tuple(number(pointer + index * stride + off, width) for off, width in layout)
                         for index in range(count))

        projected['appearance_items'] = items(record + 0xe0, 16, ((8, 4), (12, 1), (14, 2)))
        projected['optional_items'] = None
        if number(record + 0x118, 1):
            projected['optional_items'] = tuple(sorted(items(record + 0x120, 0x38,
                ((0, 1), (0x10, 1), (0x14, 4), (0x18, 4), (0x1c, 4), (0x28, 8)))))
        return projected

    def replay(body, fail_operation=None, extra=0, expect_nested=None):
        require(len(body) <= 4096, 'Create Result input budget')
        state.clear()
        state.update(packet=packet, record=record, generation=1, body=body, heap=h.scratch + 0x10000,
                     allocations={}, fail_operation=fail_operation, map_storage={}, insertions=[], rehashes=[])
        operations.clear()
        boundaries.clear()
        uc.mem_write(packet - 16, b'\xa7' * 16 + b'\x55' * 0x188 + b'\xa8' * 16)
        require(h.call(CONSTRUCTOR, packet) == packet and number(packet, 8) == TABLE
                and number(record, 8) == int(context['bindings']['record_table'], 16)
                and boundaries == ['constructor'], 'Create Result constructor composition differs')
        uc.mem_write(archive - 16, b'\xa9' * 16 + bytes(0x40) + b'\xaa' * 16)
        wire = b'\xab' * 16 + body + b'\xac' * 16
        uc.mem_write(buffer - 16, wire)
        for name, value in (('RDX', buffer), ('R8', len(body)), ('R9', 1)):
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.mem_write(h.scratch + 0x38028, bytes(8))
        h.call(int(functions['input_constructor'], 16), archive)
        abi = {name: 0x1234567800000000 + index
               for index, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, archive)
        accepted = bool(h.call(READER, packet, budget=1000000) & 255)
        consumed = position()
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'Create Result reader ABI differs')
        require(bytes(uc.mem_read(packet - 16, 16)) == b'\xa7' * 16
                and bytes(uc.mem_read(packet + 0x188, 16)) == b'\xa8' * 16
                and bytes(uc.mem_read(archive - 16, 16)) == b'\xa9' * 16
                and bytes(uc.mem_read(archive + 0x40, 16)) == b'\xaa' * 16
                and bytes(uc.mem_read(buffer - 16, len(wire))) == wire, 'Create Result reader guards differ')
        for pointer, size in state['allocations'].items():
            require(bytes(uc.mem_read(pointer - 16, 16)) == b'\xa5' * 16
                    and bytes(uc.mem_read(pointer + size, 16)) == b'\xa6' * 16, 'Create Result storage guards differ')
        require(operations[0] == ('u32', 0), 'Create Result code read order differs')
        has_record = len(body) >= 4 if expect_nested is None else expect_nested
        require(boundaries == ['constructor'] + (['reader'] if has_record else []),
                f'Create Result code/record dispatch differs ({len(body)=}, {fail_operation=}, {boundaries=}, {operations=})')
        if accepted:
            expected = portable(body[:consumed])
            require(consumed == len(body) - extra and number(packet + 0x10, 4) == expected.result_code
                    and capture() == asdict(expected.records[0]), 'Create Result decoded projection differs')
        return dict(accepted=accepted, consumed=consumed, available=len(body), nested_reader=has_record,
                    operations=len(operations), nested_start=state.get('nested_start'))

    plain = record_tool.body_for('Silverwolf', 1, 1, 1, 0x1234)
    base = record_tool.body_for('Тест日本😀', 255, 255, 2, 0xffffffffffffffff)
    appearance = struct.pack('<HIBH', 1, 0xffffffff, 255, 65535)
    entries = ((1, 255, 2, 3, 4, 5), (9, 2, 3, 4, 5, 6), (1, 1, 7, 8, 9, 10))
    optional = b'\xff' + struct.pack('<H', len(entries)) + b''.join(struct.pack('<BBIIIQ', *item) for item in entries)
    extended = base[:-28] + appearance + base[-26:-1] + optional
    cases = [dict(code=code, **replay(struct.pack('<I', code) + value))
             for code in (0, 58, 0xffffffff) for value in (plain, extended)]
    require(all(case['accepted'] for case in cases), 'Create Result full body rejected')
    body = struct.pack('<I', 58) + extended
    truncated = [replay(body[:size]) for size in (0, 1, 2, 3, 4, 5, len(body) - 1)]
    extended_complete = cases[3]
    failures = [dict(failed_operation=at, **replay(body, fail_operation=at, expect_nested=nested))
                for at, nested in ((1, False), (extended_complete['nested_start'] + 1, True),
                                   (extended_complete['operations'], True))]
    require(all(not case['accepted'] for case in truncated + failures)
            and all(row['operations'] == row['failed_operation'] for row in failures),
            'Create Result partial or failed read accepted/continued')
    extra = replay(body + b'\xfe', extra=1)
    require(extra['accepted'], 'Create Result native reader tail boundary differs')
    try:
        portable(body + b'\xfe')
    except ValueError:
        pass
    else:
        raise ValueError('Create Result portable projection accepted a tail')
    return dict(cases=cases, truncated=truncated, failures=failures, extra=extra, exports=h.evidence)


def verify_report(path, *, root=ROOT, context_path=CONTEXT):
    path, root = Path(path).resolve(), Path(root).resolve()
    if path.parent.parent != root / 'code-clues' / RECIPE or path.name != 'manifest.json' or path.parent.name != digest(path):
        raise ValueError('Current Create Result cached proof path/hash differs')
    report = json.loads(path.read_bytes())
    _, _, _, definition = materials(root, context_path)
    if (report.get('definition') != definition or report.get('method') != 'bounded_native'
            or report.get('source_sha256') != SHA or report.get('native_execution') is not True
            or any(report.get(flag) is not False for flag in ('network_used', 'runtime_admitted', 'profile_activated', 'live_verified'))
            or [len(report[key]) for key in ('cases', 'truncated', 'failures')] != [6, 7, 3]
            or not all(row['accepted'] for row in report['cases'])
            or any(row['accepted'] for row in report['truncated'] + report['failures'])):
        raise ValueError('Current Create Result cached proof scope differs')
    return report


def run(*, root=ROOT, context_path=CONTEXT):
    root = Path(root).resolve()
    record, packet, harness, definition = materials(root, context_path)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
    cache = root / 'knowledge/create-result-current-cache' / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        report = verify_report(pointer['path'], root=root, context_path=context_path)
        if digest(pointer['path']) != pointer['sha256'] or report['definition'] != definition:
            raise ValueError('Current Create Result cache pointer differs')
        return Path(pointer['path']), report, True
    executed = execute(record, packet, harness, root)
    if materials(root, context_path)[-1] != definition:
        raise ValueError('Current Create Result inputs changed during execution')
    report = dict(schema=1, recipe=RECIPE, source_sha256=SHA, definition=definition, method='bounded_native',
        native_execution=True, network_used=False, runtime_admitted=False, profile_activated=False, live_verified=False,
        limits=['Whole current ID 104 constructor/reader, INPUT and nested record/extension readers execute.',
                'Storage, allocation, copy, cleanup and map bookkeeping remain bounded fixtures.',
                'No result handler, producer, account mutation, game send or live creation established.'], **executed)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=digest(path))))
    return path, report, False


def verify(*, root=ROOT, context_path=CONTEXT):
    path, report, reused = run(root=root, context_path=context_path)
    return dict(report=str(path), sha256=digest(path), reused=reused, cases=len(report['cases']),
                truncated=len(report['truncated']), failures=len(report['failures']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    print(json.dumps(verify(context_path=args.context)))
