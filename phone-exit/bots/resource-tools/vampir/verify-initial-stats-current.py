"""Qualify initial stat pairs through the retained current Select110 closure."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/initial-stats-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'initial-stats-current-v1'
FIELDS = {'Level': 3, 'Hp': 4, 'MaxHp': 5, 'Mp': 9, 'MaxMp': 10}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError('Current initial stats ' + message)


def barrier(inputs):
    require(all(digest(path) == expected for path, expected in inputs.items()), 'retained input changed')


def definition(root, context_path):
    root, context_path = Path(root).resolve(), Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    require((context.get('schema'), context.get('recipe'), context.get('source_sha256')) ==
        (1, RECIPE, SOURCE) and context.get('vital_ids') == FIELDS
        and context.get('enum_members') == 208 and context.get('collection_field') == 0x1c8
        and context.get('world_results_recipe') == 'world-results-current-v1',
        'context or vital mapping differs')
    parent = load('verify-world-results-current').verify(root=root)
    path = Path(parent['report']).resolve()
    require(path == root / 'code-clues/world-results-current-v1' / parent['sha256'] / 'manifest.json'
        and digest(path) == parent['sha256'], 'Select110 proof path or hash differs')
    report = json.loads(path.read_bytes())
    require(report.get('schema') == 1 and report.get('recipe') == context['world_results_recipe']
        and report.get('source_sha256') == SOURCE and report.get('compatible_with_portable_codecs') is True
        and report.get('packet_compatibility', {}).get('110') is True
        and report.get('native_proofs_reused') is True and report.get('network_used') is False
        and report.get('runtime_admitted') is False, 'Select110 proof boundary differs')
    inputs = dict(report['definition']['inputs'])
    inputs[str(path)] = parent['sha256']
    core = HERE.parents[1] / 'vampir-shared/vampir_core'
    files = [context_path, Path(__file__).resolve(), core / 'stat_change.py', core / 'character_select_result.py']
    files += [HERE / (name + '.py') for name in ('verify-world-results-current', 'extract-native-enums',
        'build-native-entry-code', 'audit-client-release', 'research-workflow')]
    for item in files:
        inputs[str(item.resolve())] = digest(item)
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    inputs[str(source)] = SOURCE
    barrier(inputs)
    return context, report, dict(recipe=RECIPE, source_sha256=SOURCE, inputs=inputs)


def source_links(context, parent, raw):
    native = load('build-native-entry-code')
    image = native.Image(raw)
    roles = parent['roles']['110']
    closure = {row['current'] for row in roles['pairs'] if row['kind'] == 'whole_root'}
    require(all(context[name] in closure for name in ('player_reader', 'collection_reader', 'callback', 'record_reader')),
        'stat reader is outside the transferred closure')
    def data(at, count):
        offset = image.offset(at - image.pe.base)
        return raw[offset:offset + count]
    def rows(at):
        fragment = image.containing(at)
        require(fragment is not None and image.pe.base + image.roots[fragment][0] == at,
            'stat function is not an exact PE root')
        return [row for part in native.decode_ranges(image, {image.roots[fragment]}) for row in part['instructions']]
    player = rows(int(context['player_reader'], 16))
    reader = int(context['collection_reader'], 16)
    matches = [player[i:i + 3] for i in range(len(player) - 2)
        if player[i]['bytes'] == '488d97c8010000' and player[i + 1]['bytes'] == '488bcb'
        and player[i + 2]['direct_target'] == reader and player[i + 2]['call']]
    require(len(matches) == 1, 'PktCharacter +1c8 link differs')
    collection_table = int(context['collection_table'], 16)
    wrapper = rows(reader)
    require(any(row['rip_references'] == [collection_table] for row in wrapper)
        and int.from_bytes(data(collection_table + 16, 8), 'little') == int(context['callback'], 16),
        'stat collection callback binding differs')
    record_table = int(context['record_table'], 16)
    callback = rows(int(context['callback'], 16))
    require(any(row['rip_references'] == [record_table] for row in callback)
        and int.from_bytes(data(record_table + 0x20, 8), 'little') == int(context['record_reader'], 16),
        'stat record reader binding differs')
    return dict(player_field='0x1c8', player_reader=context['player_reader'],
        collection_reader=context['collection_reader'], callback=context['callback'], record_reader=context['record_reader'],
        type_offset=8, type_wire_bytes=4, value_offset=16, value_wire_bytes=8,
        callsite=matches[0], collection_table_bytes=data(collection_table, 24).hex(),
        record_table_bytes=data(record_table, 40).hex())


def enums(raw, count):
    extracted, rejected = load('extract-native-enums').extract(raw)
    rows = extracted.get('EStat')
    require(not any(row.get('enum') == 'EStat' for row in rejected)
        and isinstance(rows, list) and len(rows) == count, 'EStat descriptor array is missing or ambiguous')
    names = {row['name']: row['value'] for row in rows}
    require(len(names) == count and {row['value'] for row in rows} == set(range(count))
        and all(names.get('EStat::' + name) == value for name, value in FIELDS.items()),
        'EStat vital IDs differ')
    return rows


def portable_projection(parent):
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.character_select_result import decode_character_select_result
    from vampir_core.stat_change import SOURCE_SHA256, initial_stat_values
    selected = []
    for name, expected in parent['definition']['inputs'].items():
        path = Path(name)
        if path.name not in ('character-select-collections-replay.json', 'character-select-fields-replay.json'):
            continue
        require(digest(path) == expected, 'inherited Select fixture changed')
        report = json.loads(path.read_bytes())
        require(report.get('native_execution') is True, 'initial pair fixture was not natively checked')
        for index, row in enumerate(report['cases']):
            native_pairs = row['collections']['0x1c8']
            if not native_pairs:
                continue
            value = decode_character_select_result(bytes.fromhex(row['payload_hex']),
                max_payload_size=65536, max_collection_items=4096)
            pairs = initial_stat_values(value.player.at(0x1c8), source_sha256=SOURCE_SHA256)
            signed = lambda number, width: number if number < 2 ** (width - 1) else number - 2 ** width
            expected_pairs = tuple((signed(stat, 32), signed(bits, 64)) for stat, bits in native_pairs)
            require(pairs == expected_pairs, 'portable pair conversion differs from native fields')
            selected.append(dict(parent=path.name, case=index, records=len(pairs)))
    require(len(selected) == 4 and sum(row['records'] for row in selected) == 13,
        'inherited initial pair coverage differs')
    return selected


def validate(report, selected):
    require(report.get('schema') == 1 and report.get('recipe') == RECIPE and report.get('definition') == selected
        and report.get('source_sha256') == SOURCE and report.get('native_execution') is False
        and report.get('native_proofs_reused') is True and report.get('network_used') is False
        and report.get('runtime_admitted') is False and report.get('initial_projection_verified') is True
        and report.get('known_vital_ids_match') is True and report.get('vital_ids') == FIELDS
        and len(report.get('enums', {}).get('EStat', [])) == 208 and report.get('limits'),
        'cached proof boundary differs')
    names = {row['name']: row['value'] for row in report['enums']['EStat']}
    require(len(names) == 208 and set(names.values()) == set(range(208))
        and all(names.get('EStat::' + name) == value for name, value in FIELDS.items()),
        'cached EStat vital IDs differ')


def verify(*, root=ROOT, context_path=CONTEXT):
    root = Path(root).resolve()
    context, parent, selected = definition(root, context_path)
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
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCE, 'source changed before field verification')
    links = source_links(context, parent, raw)
    descriptors = enums(raw, context['enum_members'])
    cases = portable_projection(parent)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, method='source_transfer',
        native_execution=False, native_proofs_reused=True, network_used=False, runtime_admitted=False,
        initial_projection_verified=True, known_vital_ids_match=True, vital_ids=FIELDS,
        enums={'EStat': descriptors}, layout=links, inherited_pair_cases=cases,
        limits=['Initial Select110 PktCharacter +1c8 pairs only; the complete current reader closure is retained.',
            'Four retained native Select bodies contain 13 initial stat pairs; their matrices are not replayed.',
            'Current EStat name pointers and signed descriptor values are read from the exact source.',
            'This qualifies initial wire values. StatChange321/322, model apply, UI units and live observations require separate evidence.'])
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
