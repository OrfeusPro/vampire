"""Transfer exact lobby 4/104 reader layouts with explicit storage boundaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
BASELINE = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
RECIPE = 'lobby-results-current-v1'
CONTEXT = HERE / 'knowledge/native-contexts/lobby-results-current.json'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def barrier(inputs):
    if any(digest(path) != sha for path, sha in inputs.items()):
        raise ValueError('Lobby results retained input changed')


def definition(context_path, root):
    context_path = Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    if (context.get('recipe') != RECIPE or context.get('source_sha256') != SOURCE
            or context.get('baseline_sha256') != BASELINE or len(context.get('mapping', {})) != 71):
        raise ValueError('Lobby results transfer context differs')
    files = [context_path, Path(__file__).resolve()]
    files.extend(HERE / (name + '.py') for name in ('build-native-entry-code', 'update-bindings',
        'update-native-contexts', 'audit-launcher-shape-11318', 'audit-client-release', 'research-workflow'))
    files.extend(HERE.parents[1] / 'vampir-shared/vampir_core' / (name + '.py')
                 for name in ('lobby_login_result', 'lobby_server_list', 'lobby_packets', 'login_packet'))
    inputs = {str(path.resolve()): digest(path) for path in files}
    for pointer in context['parents'].values():
        inputs[pointer['path']] = pointer['sha256']
    for sha in (SOURCE, BASELINE):
        inputs[str(root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe')] = sha
    export = root / 'ghidra/request-exports' / SOURCE / context['export']['run'] / 'details.json'
    inputs[str(export)] = context['export']['sha256']
    wire = load('verify-lobby-wire-current')
    wire_context, wire_inputs = wire.definition(wire.CONTEXT, root)
    inputs.update(wire_inputs['inputs'])
    wire_result = wire.verify(root=root)
    wire_report = json.loads(Path(wire_result['report']).read_bytes())
    wire.validate(wire_report)
    if wire_report['definition'] != wire_inputs:
        raise ValueError('Lobby results retained current INPUT proof differs')
    inputs[wire_result['report']] = wire_result['sha256']
    barrier(inputs)
    return context, dict(recipe=RECIPE, source_sha256=SOURCE, inputs=inputs), wire_context


def transfer(context, root, wire_context):
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    signature = load('update-native-contexts').signature
    images = {sha: native.Image((root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').read_bytes())
              for sha in (BASELINE, SOURCE)}
    old, new = images[BASELINE], images[SOURCE]
    parent = json.loads(Path(context['parents']['server_list']['path']).read_bytes())
    login_parent = json.loads(Path(context['parents']['login']['path']).read_bytes())
    if (parent['source_sha256'] != BASELINE or login_parent['source_sha256'] != BASELINE
            or len(parent['cases']) != 10 or len(parent['truncated']) != 21
            or len(login_parent['cases']) != 7 or len(login_parent['truncated']) != 72):
        raise ValueError('Lobby result inherited coverage differs')
    roots = {old.pe.base + fragment['root_begin_rva'] for fragment in parent['fragments']} | {0x14574aa80}
    if len(roots) != 14:
        raise ValueError('Lobby result inherited root closure differs')
    wanted = {int(left, 16): int(right, 16) for left, right in context['mapping'].items()}
    mapping = {0x14574aa80: 0x14574eee0, 0x14574ae20: 0x14574f280,
               0x1498f0f48: 0x1499444a8, 0x1498cf2c8: int(wire_context['time_table'], 16),
               0x144aa5c50: 0x144aac620}
    anchors = {row['address']: bytes.fromhex(row['bytes']) for row in parent['data_anchors']}
    checked_roots, checked_tables, pairs, external = set(), set(), [], set()

    def link(left, right):
        if left in mapping and mapping[left] != right:
            raise ValueError('Lobby result relocation conflict')
        mapping[left] = right

    def source(image, address, size):
        offset = image.offset(address - image.pe.base)
        data = image.data[offset:offset + size]
        if len(data) != size:
            raise ValueError('Lobby result source data bounds differ')
        return data

    for _ in range(32):
        progress = False
        for address in sorted(roots & mapping.keys() - checked_roots):
            target = mapping[address]
            before, after = bindings.rows(native, old, address), bindings.rows(native, new, target)
            if signature(native, before) != signature(native, after):
                raise ValueError('Lobby result whole instruction/control flow changed at ' + hex(address))
            locations = {row['address'] for row in before}
            for left, right in zip(before, after):
                if len(left['rip_references']) != len(right['rip_references']):
                    raise ValueError('Lobby result RIP dependency count differs')
                for a, b in zip(left['rip_references'], right['rip_references']):
                    link(a, b)
                if (left['call'] or left['branch']) and left['direct_target'] and left['direct_target'] not in locations:
                    link(left['direct_target'], right['direct_target'])
                    if left['direct_target'] not in roots:
                        external.add(left['direct_target'])
            pairs.append(dict(baseline=hex(address), current=hex(target), instructions=len(before),
                              equal_instruction_shape=True, equal_local_edges=True))
            checked_roots.add(address)
            progress = True
        for address in sorted(anchors.keys() & mapping.keys() - checked_tables):
            data = anchors[address]
            if source(old, address, len(data)) != data:
                raise ValueError('Lobby inherited descriptor bytes differ')
            current = source(new, mapping[address], len(data))
            for offset in range(0, len(data), 8):
                link(int.from_bytes(data[offset:offset + 8], 'little'),
                     int.from_bytes(current[offset:offset + 8], 'little'))
            checked_tables.add(address)
            progress = True
        if not progress:
            break
    if checked_roots != roots or checked_tables != set(anchors) or mapping != wanted:
        raise ValueError('Lobby result code/table dependency closure differs')
    if int.from_bytes(source(new, int(wire_context['input_table'], 16) + 0x18, 8), 'little') != mapping[0x144aa5c50]:
        raise ValueError('Lobby result generic array INPUT slot differs')
    if mapping[0x144aa66f0] != int(wire_context['functions']['string'], 16):
        raise ValueError('Lobby result shared native string provider differs')
    for table, reader, getter, packet_id in ((0x149943818, 0x14574eee0, 0x141453ca0, 4),
                                              (0x1499444a8, 0x14574f280, 0x14487f000, 104)):
        if (int.from_bytes(source(new, table + 0x20, 8), 'little') != reader
                or int.from_bytes(source(new, table + 0x28, 8), 'little') != getter
                or source(new, getter, 6) != b'\xb8' + struct.pack('<I', packet_id) + b'\xc3'):
            raise ValueError('Lobby result current packet ID/table differs')
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.lobby_login_result import decode_lobby_login_result
    from vampir_core.lobby_server_list import decode_lobby_server_list
    for case in login_parent['cases']:
        value = decode_lobby_login_result(bytes.fromhex(case['payload_hex']), max_payload_size=8192)
        if value.strings != tuple(case['strings']) or value.integers != tuple(case['integers'] + [case['tail']]):
            raise ValueError('Lobby Login portable/native inherited projection differs')
    for case in parent['cases']:
        value = decode_lobby_server_list(bytes.fromhex(case['payload_hex']), max_payload_size=8192, max_collection_items=100)
        fields = dict(result_code=value.result_code, groups=[[g.raw_08, g.text_10, g.raw_20] for g in value.groups],
            values=list(value.values38), map48=[list(pair) for pair in value.map48],
            map98=[list(pair) for pair in value.map98], flags=list(value.flags),
            enum=value.enum_e9, strings=list(value.strings))
        expected = dict(result_code=case['result_code'], groups=case['arrays']['0x18'],
            values=case['arrays']['0x38'], map48=case['maps']['0x48'], map98=case['maps']['0x98'],
            flags=[bool(n) for n in case['flags']], enum=case['enum_e9'], strings=case['strings'])
        if fields != expected or len(value.servers) != len(case['arrays']['0x28']):
            raise ValueError('Lobby server list portable/native inherited projection differs')
        for actual, expected_record in zip(value.servers, case['arrays']['0x28']):
            if (any(list(getattr(actual, name)) != expected_record[name]
                    for name in ('strings', 'u32', 'u16', 'enums', 'array50'))
                    or list(actual.flags) != [bool(n) for n in expected_record['flags']]):
                raise ValueError('Lobby server record portable/native inherited projection differs')
    return dict(pairs=sorted(pairs, key=lambda row: row['baseline']), tables=len(checked_tables),
                relocations=len(mapping), storage_external_pairs={hex(a): hex(mapping[a]) for a in sorted(external)})


def validate(report, selected):
    if (report.get('definition') != selected or report.get('recipe') != RECIPE
            or report.get('source_sha256') != SOURCE or report.get('method') != 'source_transfer'
            or report.get('native_execution') is not False or report.get('native_proofs_reused') is not True
            or report.get('runtime_admitted') is not False or report.get('network_used') is not False
            or len(report.get('pairs', [])) != 14 or report.get('tables') != 10
            or report.get('relocations') != 71 or not report.get('limits')):
        raise ValueError('Lobby result transfer report boundary differs')


def verify(context_path=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    context, selected, wire_context = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['path']).resolve()
        if path != root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json' or digest(path) != pointer['sha256']:
            raise ValueError('Lobby results transfer cache changed')
        validate(json.loads(path.read_bytes()), selected)
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    result = transfer(context, root, wire_context)
    barrier(selected['inputs'])
    report = dict(recipe=RECIPE, source_sha256=SOURCE, baseline_sha256=BASELINE, definition=selected,
        method='source_transfer', native_execution=False, native_proofs_reused=True,
        runtime_admitted=False, network_used=False, **result,
        limits=['Exact whole reader/record/array/map instructions and local control flow transfer across the two sources.',
                'Ten descriptor/vtable blocks and all code/data relocations have one consistent explicit mapping.',
                'Current INPUT/string/TimeBase native proof and historical lobby 4/104 native scenarios are retained without replay.',
                'Storage/allocation/copy/cleanup, initialized packet and one-bucket maps keep historical fixture boundaries.',
                'No new current native execution, packet handlers, network or full Unreal ownership proof.'])
    validate(report, selected)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    sha = digest(path)
    workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=sha)))
    return dict(report=str(path), sha256=sha, reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
