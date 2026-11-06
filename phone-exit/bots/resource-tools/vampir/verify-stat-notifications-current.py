"""Transfer current stat wire readers and their captured apply arguments."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/stat-notifications-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
BASELINE = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
RECIPE = 'stat-notifications-current-v1'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError('Current stat notifications ' + reason)


def barrier(inputs):
    require(all(digest(name) == expected for name, expected in inputs.items()), 'retained input changed')


def definition(root, context_path):
    root, context_path = Path(root).resolve(), Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    require((context.get('schema'), context.get('recipe'), context.get('source_sha256'), context.get('baseline_sha256'))
        == (1, RECIPE, SOURCE, BASELINE) and len(context.get('roots', {})) == 5
        and set(context.get('packet_bindings', {})) == {'321', '322'}, 'context scope differs')
    inputs = {}
    files = [context_path, Path(__file__).resolve()]
    files += [HERE / (name + '.py') for name in ('verify-initial-stats-current', 'verify-character-list-current',
        'build-native-entry-code', 'update-bindings', 'update-native-contexts', 'verify-world-results-current',
        'audit-client-release', 'research-workflow', 'native-publication-v2')]
    files += [HERE / 'entry-current-check-guard.py', HERE / 'knowledge/native-contexts/stat-notify-11318.json', HERE / 'replay-stat-notify-11318.py',
        HERE / 'stat-support-11318.py']
    core = HERE.parents[1] / 'vampir-shared/vampir_core'
    files += [core / name for name in ('stat_change.py', 'stat_change_11318.py')]
    inputs.update((str(path.resolve()), digest(path)) for path in files)
    parent = context['baseline']
    parent_path = Path(parent['path']).resolve()
    require(parent_path == root / 'code-clues/stat-notify-11318' / parent['sha256'] / 'manifest.json'
        and digest(parent_path) == parent['sha256'], 'baseline proof path or hash differs')
    inherited = json.loads(parent_path.read_bytes())
    require(inherited.get('source_sha256') == BASELINE and len(inherited.get('cases', [])) == 1119
        and inherited.get('network_used') is False and inherited.get('profile_activated') is False
        and inherited.get('runtime_decoder_admitted') is False and inherited.get('limits'), 'baseline proof scope differs')
    require(inherited['context_sha256'] == inputs[str((HERE / 'knowledge/native-contexts/stat-notify-11318.json').resolve())]
        and inherited['tool_sha256'] == inputs[str((HERE / 'replay-stat-notify-11318.py').resolve())]
        and inherited['fixture_tool_sha256'] == inputs[str((HERE / 'stat-support-11318.py').resolve())]
        and inherited['portable_decoder_sha256'] == inputs[str((core / 'stat_change_11318.py').resolve())],
        'inherited proof producer changed')
    inputs[str(parent_path)] = parent['sha256']
    for pointer in inherited['exports']:
        path = Path(pointer['path']).resolve()
        require(path.is_relative_to(root / 'ghidra/request-exports' / BASELINE)
            and path.name == 'details.json' and digest(path) == pointer['sha256'],
            'inherited native export changed')
        inputs[str(path)] = pointer['sha256']
    for name, expected in inherited['dependency_sha256'].items():
        path = (HERE / name).resolve()
        require(path.parent == HERE and digest(path) == expected, 'inherited dependency changed')
        inputs[str(path)] = expected
    pointer = context['current_input']
    input_path = Path(pointer['path']).resolve()
    require(input_path == root / 'knowledge/character-list-current-bounded' / pointer['sha256'] / 'manifest.json'
        and digest(input_path) == pointer['sha256'], 'current input proof path or hash differs')
    current_input = input_report(input_path, root)
    inputs.update(current_input['definition']['inputs'])
    inputs.update(current_input['definition']['files'])
    inputs[str(input_path)] = pointer['sha256']
    generated_path = Path(current_input['definition']['generated']['path'])
    inputs[str(generated_path)] = current_input['definition']['generated']['sha256']
    generated = json.loads(generated_path.read_bytes())
    current_context = json.loads(Path(generated['contexts']['character-list-records']).read_bytes())
    require(all(current_context['functions'].get(name) == at for name, at in context['input_functions'].items()),
        'current archive function selection differs')
    initial_pointer = load('verify-initial-stats-current').verify(root=root)
    initial_path = Path(initial_pointer['report']).resolve()
    require(initial_path == root / 'code-clues/initial-stats-current-v1' / initial_pointer['sha256'] / 'manifest.json'
        and digest(initial_path) == initial_pointer['sha256'], 'current EStat proof differs')
    initial = json.loads(initial_path.read_bytes())
    require(initial.get('initial_projection_verified') is True and initial.get('known_vital_ids_match') is True
        and initial.get('source_sha256') == SOURCE, 'current EStat proof scope differs')
    inputs.update(initial['definition']['inputs'])
    inputs[str(initial_path)] = initial_pointer['sha256']
    for sha in (SOURCE, BASELINE):
        inputs[str(root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe')] = sha
    for path in load('native-publication-v2').runtime_files():
        inputs[str(path.resolve())] = digest(path)
    barrier(inputs)
    return context, inherited, initial, dict(recipe=RECIPE, source_sha256=SOURCE, inputs=inputs)


def input_report(path, root):
    return load('entry-current-check-guard').character_report(load('verify-character-list-current'),path,root)


def transfer(context, root):
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    support = load('verify-world-results-current')
    signature = load('update-native-contexts').signature
    images = {sha: native.Image((root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').read_bytes())
        for sha in (BASELINE, SOURCE)}
    old, new = images[BASELINE], images[SOURCE]
    wanted = {int(a, 16): int(b, 16) for category in ('roots', 'leaves', 'tables', 'fixture_edges')
        for a, b in context[category].items()}
    found = {}
    def link(a, b):
        require(a not in found or found[a] == b, 'dependency relocation conflict')
        require(wanted.get(a) == b, 'unregistered dependency ' + hex(a))
        found[a] = b
    def compare(a, b, before, after):
        require(signature(native, before) == signature(native, after), 'whole source shape changed at ' + hex(a))
        link(a, b)
        local = {row['address'] for row in before}
        for left, right in zip(before, after):
            require(len(left['rip_references']) == len(right['rip_references']), 'data reference count differs')
            for x, y in zip(left['rip_references'], right['rip_references']):
                link(x, y)
            if (left['call'] or left['branch']) and left['direct_target'] is not None and left['direct_target'] not in local:
                link(left['direct_target'], right['direct_target'])
    pairs = []
    for a, b in context['roots'].items():
        left, right = int(a, 16), int(b, 16)
        before, after = bindings.rows(native, old, left), bindings.rows(native, new, right)
        compare(left, right, before, after)
        pairs.append(dict(baseline=a, current=b, instructions=len(before)))
    baseline_context = json.loads((HERE / 'knowledge/native-contexts/stat-notify-11318.json').read_bytes())
    for a, b in context['leaves'].items():
        left, right = int(a, 16), int(b, 16)
        raw = bytes.fromhex(baseline_context['leaves'][a])
        require(support.source(old, left, len(raw)) == raw, 'inherited leaf changed')
        compare(left, right, support.ranged(native, old, left, len(raw)), support.ranged(native, new, right, len(raw)))
    collection_old, collection_new = (int(value, 16) for value in next(iter(context['tables'].items())))
    record_old, record_new = (int(value, 16) for value in list(context['tables'].items())[1])
    require(int.from_bytes(support.source(old, collection_old + 16, 8), 'little') == 0x1456c6a70
        and int.from_bytes(support.source(new, collection_new + 16, 8), 'little') == 0x1456c66b0
        and int.from_bytes(support.source(old, record_old + 32, 8), 'little') == 0x1457a8410
        and int.from_bytes(support.source(new, record_new + 32, 8), 'little') == 0x1457a83f0,
        'callback or record table link differs')
    require(found == wanted, 'declared source closure is incomplete')
    apply = bindings.rows(native, new, 0x145d8ec00)
    require(any([row['bytes'] for row in apply[index:index + 4]] ==
        ['488b5318', '4c8bc2', '488bce', '418bd1']
        and apply[index + 4]['direct_target'] == 0x1455f10e0 for index in range(len(apply) - 4)),
        'apply second-value argument changed')
    packet_bindings = {}
    for packet, item in context['packet_bindings'].items():
        table, reader, constructor = (int(item[name], 16) for name in ('table', 'reader', 'constructor'))
        require(support.source(new, table + 0x50, len(item['name']) + 1) == item['name'].encode() + b'\0'
            and int.from_bytes(support.source(new, table + 32, 8), 'little') == reader,
            'packet name or reader table differs')
        getter = int.from_bytes(support.source(new, table + 40, 8), 'little')
        require(support.source(new, getter, 6) == b'\xb8' + struct.pack('<I', int(packet)) + b'\xc3',
            'packet ID getter differs')
        instructions = []
        decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        for instruction in decoder.disasm(support.source(new, constructor, 64), constructor):
            instructions.append(instruction)
            if instruction.mnemonic == 'ret':
                break
            require(instruction.mnemonic in ('lea', 'mov', 'xor'), 'packet constructor has an unreviewed operation')
        require(instructions and instructions[-1].mnemonic == 'ret'
            and instructions[0].mnemonic == 'lea' and instructions[0].bytes[:3] == b'\x48\x8d\x05'
            and constructor + instructions[0].size + struct.unpack_from('<i', instructions[0].bytes, 3)[0] == table
            and any(instruction.bytes == b'\x48\x89\x01' for instruction in instructions), 'packet constructor vptr differs')
        packet_bindings[packet] = dict(item, packet_id=int(packet), binding_verified=True,
            constructor_bytes=b''.join(instruction.bytes for instruction in instructions).hex(),
            table_bytes=support.source(new, table, 64).hex())
    return dict(pairs=pairs, roots=5, leaves=2, callback_tables=2, relocations=len(found),
        packet_bindings=packet_bindings, apply_uses_second_value=True)


def projection():
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core import stat_change, stat_change_11318
    samples = [[], [(4, 123, 0)], [(3, 1, 12), (4, -1, 1500), (5, 0, 2000), (9, 2**63 - 1, 25), (10, -2**63, 100)],
        [(4, index, index + 10) for index in range(8)], [(134, 123, -101)], [(index, 987, index * 123) for index in range(207)]]
    cases = []
    for packet, name, flags in ((321, 'decode_character_level_up', (None,)), (322, 'decode_stat_change', (0, 255))):
        for values in samples:
            for flag in flags:
                body = struct.pack('<QH', 2**64 - 1, len(values)) + b''.join(struct.pack('<iqq', *row) for row in values)
                if flag is not None:
                    body += struct.pack('<BH', flag, 0xffff)
                old = getattr(stat_change_11318, name)(body, source_sha256=BASELINE)
                current = getattr(stat_change, name)(body, source_sha256=stat_change.SOURCE_SHA256)
                require(old == current and [(row.stat_type, row.signed_second) for row in current.values]
                    == [(row[0], row[2]) for row in values], 'portable stat projection changed')
                cases.append(dict(packet_id=packet, records=len(values), flag=flag))
    return cases


def validate(report, selected):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE and report.get('source_sha256') == SOURCE
        and report.get('definition') == selected and report.get('native_execution') is False
        and report.get('native_proofs_reused') is True and report.get('network_used') is False
        and report.get('runtime_admitted') is False and report.get('notifications_projection_verified') is True
        and report.get('apply_uses_second_value') is True and report.get('roots') == 5
        and report.get('leaves') == 2 and report.get('inherited_native_cases') == 1119
        and len(report.get('projection_cases', [])) == 18 and report.get('limits'), 'cached proof boundary differs')
    require(set(report.get('packet_bindings', {})) == {'321', '322'}
        and all(row.get('binding_verified') is True and row.get('packet_id') == int(packet)
            for packet, row in report['packet_bindings'].items()), 'cached packet ID binding differs')


def verify(*, root=ROOT, context_path=CONTEXT):
    root = Path(root).resolve()
    context, inherited, initial, selected = definition(root, context_path)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['path']).resolve()
        require(path == root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
            and digest(path) == pointer['sha256'], 'cached proof path or hash differs')
        validate(json.loads(path.read_bytes()), selected)
        barrier(selected['inputs'])
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    result = transfer(context, root)
    cases = projection()
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, method='source_transfer',
        native_execution=False, native_proofs_reused=True, network_used=False, runtime_admitted=False,
        notifications_projection_verified=True, inherited_native_cases=len(inherited['cases']),
        projection_cases=cases, vital_ids=initial['vital_ids'], enums=initial['enums'], **result,
        limits=['Current packet ID/name/constructor/reader bindings and whole readers, callback, record and apply argument paths are checked.',
            'Native archive reads retain the separately verified current CharacterList input proof and existing bounded contracts.',
            '1119 prior native reader/apply scenarios are reused. Allocation/reset, cleanup, capacity growth and setter service remain fixtures.',
            'The apply caller reads the second record value. Native model service effects, entity lookup, UI units and live notification receipt are separate.'])
    validate(report, selected)
    barrier(selected['inputs'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(report=str(path), sha256=pointer['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
