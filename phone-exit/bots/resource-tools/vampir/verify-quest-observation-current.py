"""Reuse current native packet proofs for bounded quest/tutorial observation only."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/quest-observation-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'quest-observation-current-v1'
COUNTS = {'1854': 269, '9905': 909}
BOUNDS = {'1854': dict(max_groups=8, max_quests_per_group=8, max_total_items=72, max_payload_size=2530),
          '9905': dict(max_records=64, max_payload_size=835)}
FAMILIES = {'1854': 'quest-sync', '9905': 'tutorial-update'}
LIMITS = [
    'Only bounded complete QuestSync1854 and Tutorial9905 messages, tied to the observed character and world.',
    'Saved native reports retain accepted/consumed outcomes. Field expectations are inherited through the unchanged SHA-pinned native scenario producer, not fabricated saved decoded objects.',
    'Portable readers reject both trailing bodies that the native archive reader accepts with two bytes remaining.',
    'Fresh bounded storage and allocator/cleanup fixtures retain their original limits. No active quest model, task advance, outgoing action, NPC lookup, dialogue or online admission is granted.'
]


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
        raise ValueError('Current quest observation ' + reason)


def barrier(inputs):
    require(all(digest(name) == expected for name, expected in inputs.items()), 'retained input changed')


def definition(root, context_path):
    root, context_path = Path(root).resolve(), Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    require((context.get('schema'), context.get('recipe'), context.get('source_sha256')) == (1, RECIPE, SOURCE)
        and context.get('bounds') == BOUNDS and context.get('families') == FAMILIES
        and set(context.get('parents', {})) == set(COUNTS), 'context scope differs')
    files = [context_path, Path(__file__).resolve()]
    files += [HERE / (name + '.py') for name in ('quest-packet-native-v1', 'quest-packet-cases-v1',
        'build-native-entry-code', 'audit-client-release', 'research-workflow', 'native-publication-v2')]
    core = HERE.parents[1] / 'vampir-shared/vampir_core'
    files += [core / name for name in ('quest_sync.py', 'quest_record.py', 'tutorial_update.py',
        'world_move_start.py', 'bounded_world_admission.py')]
    inputs = {str(path.resolve()): digest(path) for path in files}
    parents = {}
    runtime_inputs = {}

    def retain(values):
        require(isinstance(values, dict) and values, 'empty inherited input set')
        for name, expected in values.items():
            path = Path(name).resolve()
            require(Path(name).is_absolute() and isinstance(expected, str) and len(expected) == 64
                and (str(path) not in inputs or inputs[str(path)] == expected), 'inherited input conflict')
            inputs[str(path)] = expected

    api = SimpleNamespace(extension=load)
    validator = load('quest-packet-native-v1')
    for packet, pointer in context['parents'].items():
        path = Path(pointer['path']).resolve()
        require(set(pointer) == {'path', 'sha256'} and path == root / 'knowledge/quest-packet-native-checks-v1'
            / pointer['sha256'] / 'manifest.json' and digest(path) == pointer['sha256'], 'native parent path or hash differs')
        report = json.loads(path.read_bytes())
        selected = report.get('inputs', {})
        native_context = selected.get('context', {})
        require(native_context.get('source_sha256') == SOURCE and native_context.get('family') == FAMILIES[packet]
            and Path(selected.get('root', '')).resolve() == root and len(report.get('cases', [])) == COUNTS[packet],
            'native parent identity differs')
        # This validates the entire saved matrix and native ABI/memory/export
        # coverage, but never enters the emulator or native update runner.
        validator.validate_report(api, report, native_context, selected)
        aliases = selected.get('aliases', {})
        require(isinstance(aliases, dict) and all(Path(old).resolve() == Path(new).resolve()
            for old, new in aliases.items()), 'inherited input alias differs')
        retain(selected['files'])
        retain(selected['tools'])
        retain(selected['runtime']['files'])
        runtime_inputs.update({str(Path(name).resolve()):expected for name,expected in selected['runtime']['files'].items()})
        inputs[str(path)] = pointer['sha256']
        for export in report['exports']:
            material = Path(export['path']).resolve()
            require(material.is_relative_to(root / 'ghidra/request-exports' / SOURCE)
                and material.name == 'details.json' and digest(material) == export['sha256'], 'current export differs')
            inputs[str(material)] = export['sha256']
        parents[packet] = report
    inputs[str(root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe')] = SOURCE
    runtime_inputs.update({str(path.resolve()): digest(path) for path in load('native-publication-v2').runtime_files()})
    runtime_inputs.update({name:expected for name,expected in inputs.items()
        if Path(name).resolve().is_relative_to(Path(sys.base_prefix).resolve())
        or Path(name).resolve()==Path('C:/Windows/System32/ucrtbase.dll').resolve()})
    retain(runtime_inputs)
    barrier(inputs)
    return context, parents, dict(recipe=RECIPE, source_sha256=SOURCE, inputs=inputs, runtime_inputs=runtime_inputs, parents=context['parents'])


def packet_bindings(parents, raw):
    native = load('build-native-entry-code')
    image = native.Image(raw)
    output = {}

    def data(at, count):
        offset = image.offset(at - image.pe.base)
        value = raw[offset:offset + count]
        require(len(value) == count, 'packet binding exceeds source')
        return value

    for packet, report in parents.items():
        context = report['inputs']['context']
        reader, constructor = (int(context['functions'][name], 16) for name in ('reader', 'packet_constructor'))
        tables = [int(table, 16) for table, slot, target in context['bindings']
                  if int(slot, 16) == 0x20 and int(target, 16) == reader]
        require(len(tables) == 1, 'reader table is ambiguous')
        table = tables[0]
        getters = [int(target, 16) for candidate, slot, target in context['bindings']
                   if int(candidate, 16) == table and int(slot, 16) == 0x28]
        require(len(getters) == 1 and int.from_bytes(data(table + 0x20, 8), 'little') == reader
            and int.from_bytes(data(table + 0x28, 8), 'little') == getters[0]
            and data(getters[0], 6) == b'\xb8' + struct.pack('<I', int(packet)) + b'\xc3', 'packet ID/table binding differs')
        part = image.containing(constructor)
        require(part is not None and image.pe.base + image.roots[part][0] == constructor,
            'packet constructor root differs')
        rows = [row for fragment in native.decode_ranges(image, {image.roots[part]}) for row in fragment['instructions']]
        require(any(row['rip_references'] == [table] for row in rows), 'packet constructor/table link differs')
        output[packet] = dict(packet_id=int(packet), table=hex(table), getter=hex(getters[0]),
            constructor=hex(constructor), reader=hex(reader), nested_reader=context['functions']['nested_reader'],
            binding_verified=True, table_bytes=data(table, 48).hex())
    return output


def projected(value, packet):
    if packet == '9905':
        return dict(flag=value.flag, records=[[r.raw08, r.raw0c, r.raw10, r.state] for r in value.records])
    return dict(groups=[dict(kind=g.raw08, quests=[[r.raw08, r.raw10, r.progress.raw08,
        r.progress.raw10, r.progress.raw18, r.raw38, r.raw3c, r.raw40, r.raw44] for r in g.quests])
        for g in value.groups], suffix=value.raw18)


def expected_projection(packet, spec):
    first, second, raw = spec
    if packet == '9905':
        return dict(flag=bool(first), records=[[2**32 - 1 - i, i, 1001002 + i, min(raw, 3)] for i in range(second)])
    return dict(groups=[dict(kind=min(raw, 12), quests=[[2**64 - 1 - g * 8 - i, min(raw, 6),
        255 - i, 2**63 + g, i, bool(raw), i, g, 2**32 - 1] for i in range(second)])
        for g in range(first)], suffix=2**64 - 1 if raw else 0)


def projection(parents):
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.quest_sync import decode_quest_sync, CURRENT_SOURCE_SHA256
    from vampir_core.tutorial_update import decode_tutorial_update, CURRENT_PROBE_SOURCE
    cases, workflow = load('quest-packet-cases-v1'), load('research-workflow')
    output = {}
    for packet, report in parents.items():
        rows = []
        for saved, (expected, body) in zip(report['cases'], cases.scenarios(FAMILIES[packet]), strict=True):
            require(workflow.canonical(saved) == workflow.canonical(expected), 'native scenario differs')
            try:
                if packet == '1854':
                    value = decode_quest_sync(body, source_sha256=CURRENT_SOURCE_SHA256,
                        max_collection_items=8, max_total_items=72, max_payload_size=2530)
                else:
                    value = decode_tutorial_update(body, source_sha256=CURRENT_PROBE_SOURCE,
                        max_records=64, max_payload_size=835)
            except (ValueError, BufferError):
                require(saved['kind'] in ('truncated', 'trailing'), 'portable decoder rejected a native valid body')
                rows.append(dict(kind=saved['kind'], native_accepted=saved['accepted'], portable_accepted=False,
                    native_consumed=saved['consumed'], size=len(body)))
                continue
            require(saved['kind'] == 'valid' and saved['accepted'] is True and saved['consumed'] == len(body),
                'portable decoder accepted an incomplete or trailing body')
            fields = projected(value, packet)
            require(fields == expected_projection(packet, saved['spec']), 'portable fields differ from native scenario expectations')
            rows.append(dict(kind='valid', native_accepted=True, portable_accepted=True,
                native_consumed=len(body), size=len(body), projection_sha256=hashlib.sha256(workflow.canonical(fields)).hexdigest()))
        output[packet] = rows
    return output


def validate(report, selected):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE and report.get('definition') == selected
        and report.get('source_sha256') == SOURCE and report.get('native_execution') is False
        and report.get('native_proofs_reused') is True and report.get('network_used') is False
        and report.get('runtime_admitted') is False and report.get('observation_projection_verified') is True
        and report.get('packet_compatibility') == {'1854': True, '9905': True} and report.get('bounds') == BOUNDS
        and report.get('scope') == 'last_received_message_only' and report.get('limits') == LIMITS
        and report.get('method') == 'retained_native_projection' and report.get('parents') == selected.get('parents')
        and report.get('inherited_native_cases') == sum(COUNTS.values()), 'cached proof boundary differs')
    require(set(report.get('packet_bindings', {})) == set(COUNTS)
        and all(row.get('binding_verified') is True and row.get('packet_id') == int(packet)
                for packet, row in report['packet_bindings'].items()), 'cached packet binding differs')
    expected = {'1854': {'valid': 96, 'truncated': 172, 'trailing': 1},
                '9905': {'valid': 73, 'truncated': 835, 'trailing': 1}}
    require(set(report.get('projection_cases', {})) == set(COUNTS), 'cached projection families differ')
    cases = load('quest-packet-cases-v1')
    workflow = load('research-workflow')
    for packet, row in report['packet_bindings'].items():
        parent=json.loads(Path(selected['parents'][packet]['path']).read_bytes())['inputs']['context']
        reader=parent['functions']['reader']
        tables=[table for table,slot,target in parent['bindings'] if int(slot,16)==0x20 and target==reader]
        require(len(tables)==1, 'cached binding parent differs')
        table=tables[0]
        getters=[target for candidate,slot,target in parent['bindings'] if candidate==table and int(slot,16)==0x28]
        require(len(getters)==1 and all(row.get(name)==expected for name,expected in dict(
            table=table,getter=getters[0],reader=reader,constructor=parent['functions']['packet_constructor'],
            nested_reader=parent['functions']['nested_reader']).items()), 'cached packet binding differs')
        try:table_bytes=bytes.fromhex(row['table_bytes'])
        except (ValueError,TypeError,KeyError):raise ValueError('Current quest observation cached table bytes differ') from None
        require(len(table_bytes)==48 and int.from_bytes(table_bytes[32:40],'little')==int(reader,16)
            and int.from_bytes(table_bytes[40:48],'little')==int(getters[0],16), 'cached table bytes differ')
    for packet, matrix in report['projection_cases'].items():
        require(len(matrix) == COUNTS[packet] and {kind: sum(row.get('kind') == kind for row in matrix)
            for kind in expected[packet]} == expected[packet]
            and all(row.get('portable_accepted') is (row.get('kind') == 'valid')
                    and row.get('native_accepted') is (row.get('kind') != 'truncated') for row in matrix),
            'cached portable/native matrix differs')
        for row, (native, body) in zip(matrix, cases.scenarios(FAMILIES[packet]), strict=True):
            require(row.get('kind') == native['kind'] and row.get('size') == len(body)
                and row.get('native_consumed') == native['consumed']
                and (native['kind'] != 'valid' or row.get('projection_sha256')==hashlib.sha256(
                    workflow.canonical(expected_projection(packet,native['spec']))).hexdigest()),
                'cached portable/native case differs')


def verify(*, root=ROOT, context_path=CONTEXT):
    root = Path(root).resolve()
    context, parents, selected = definition(root, context_path)
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
    raw = (root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCE, 'current source changed')
    bindings, cases = packet_bindings(parents, raw), projection(parents)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, method='retained_native_projection',
        native_execution=False, native_proofs_reused=True, network_used=False, runtime_admitted=False,
        observation_projection_verified=True, scope='last_received_message_only', bounds=BOUNDS,
        packet_compatibility={'1854': True, '9905': True}, packet_bindings=bindings, projection_cases=cases,
        parents=context['parents'], inherited_native_cases=sum(COUNTS.values()),
        limits=LIMITS)
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
