"""Source-bound nested world-result transfer, with explicit per-role blockers."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/world-results-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
RECIPE = 'world-results-current-v1'


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
        raise ValueError('Current world result ' + message)


def barrier(inputs):
    require(all(digest(name) == expected for name, expected in inputs.items()), 'retained input changed')


def definition(context_path, root):
    context_path, root = Path(context_path).resolve(), Path(root).resolve()
    context = json.loads(context_path.read_bytes())
    require((context.get('schema'), context.get('recipe'), context.get('source_sha256')) ==
        (1, RECIPE, SOURCE) and set(context.get('roles', {})) == {'110', '206'}, 'context/source differs')
    paths = [context_path, Path(__file__).resolve()]
    paths += [HERE / (name + '.py') for name in ('build-native-entry-code', 'update-bindings',
        'update-native-contexts', 'build-object-zero-init-code', 'audit-client-release', 'research-workflow',
        'audit-launcher-shape-11318', 'extract-native-enums', 'native-publication-v2', 'run-clock-world-current', 'entry-current-check-guard')]
    paths += [HERE.parents[1] / 'vampir-shared/vampir_core' / (name + '.py') for name in
        ('character_select_result', 'world_move_finish_result', 'login_result', 'bounded_world_admission')]
    inputs = {str(path): digest(path) for path in paths}

    def retain(files):
        for name, expected in files.items():
            key = str(Path(name).resolve())
            require(key not in inputs or inputs[key] == expected, 'retained source hashes conflict')
            inputs[key] = expected

    parents = {}
    for identifier, role in context['roles'].items():
        require(role['source_sha256'] == SOURCE and role['packet_id'] == int(identifier), 'role source differs')
        baseline = role['baseline_sha256']
        source = root / 'client-code-snapshots' / baseline / 'ProjectRED-Win64-Shipping.exe'
        inputs[str(source)] = baseline
        parents[identifier] = {}
        for name, pointer in role['parents'].items():
            path = Path(pointer['path']).resolve()
            require(path.is_relative_to(root) and digest(path) == pointer['sha256'], 'parent proof changed')
            report = json.loads(path.read_bytes())
            require(report.get('source_sha256', report.get('sha256')) == baseline
                and report.get('native_execution') is True
                and (report.get('network_used') is False or report.get('network_ready') is False)
                and report.get('limits', report.get('limitations')), 'parent proof boundary differs')
            inputs[str(path)] = pointer['sha256']
            parents[identifier][name] = report
            if report.get('crt'):
                retain({report['crt']['path']: report['crt']['sha256']})
    inputs[str(root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe')] = SOURCE
    pointer = context['export']
    path = Path(pointer['path']).resolve()
    require(path.is_relative_to(root / 'ghidra/request-exports' / SOURCE)
        and digest(path) == pointer['sha256'], 'whole export changed')
    export = json.loads(path.read_bytes())
    require(export['new_source_sha256'] == SOURCE and {'0x1456f02c0', '0x14584f520'} <=
        {row['address'] for row in export['functions']}, 'current whole reader export differs')
    inputs[str(path)] = pointer['sha256']
    parents['current_export'] = export
    for identifier in ('world-player-constructor-current', 'world-select-clamps-current'):
        proof = load('verify-' + identifier).verify(root=root)
        path = Path(proof['report']).resolve()
        require(path == root / 'code-clues' / (identifier + '-v1') / proof['sha256'] / 'manifest.json'
            and digest(path) == proof['sha256'], 'current bridge proof changed')
        report = json.loads(path.read_bytes())
        require(report.get('recipe') == identifier + '-v1' and report.get('source_sha256') == SOURCE
            and report.get('native_execution') is True and report.get('network_used') is False
            and report.get('runtime_admitted') is False, 'current bridge proof scope differs')
        retain({str(path): proof['sha256']})
        retain(report['definition']['inputs'])
        parents[identifier] = report
    pointer = context['clock_proof']
    clock = load('run-clock-world-current')
    _, clock_definition = clock.inputs(root)
    retained = json.loads(Path(pointer['path']).read_bytes())['definition']
    clock_definition = clock_runtime_alias(clock_definition, retained)
    report = clock.verify_report(pointer['path'], pointer['sha256'], clock_definition, root)
    retain({pointer['path']: pointer['sha256']})
    retain(clock_definition['files'])
    retain(clock_definition['exports'])
    retain({item['path']: item['sha256'] for item in report['components'].values()})
    # Runtime identity participates in the cache although no native emulation is
    # executed. Source comparison uses the installed Capstone decoder.
    for path in load('native-publication-v2').runtime_files():
        inputs[str(path.resolve())] = digest(path)
    barrier(inputs)
    return context, parents, dict(recipe=RECIPE, source_sha256=SOURCE, inputs=inputs)


def clock_runtime_alias(current, retained):
    """Windows drive-letter spelling is not a different interpreter or proof."""
    return load('entry-current-check-guard').runtime_alias(current,retained)


def source(image, at, size):
    offset = image.offset(at - image.pe.base)
    raw = image.data[offset:offset + size]
    require(len(raw) == size, 'source data bounds differ')
    return raw


def ranged(native, image, at, size):
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    rows = []
    for ins in decoder.disasm(source(image, at, size), at):
        call, branch = ins.group(native.capstone.CS_GRP_CALL), ins.group(native.capstone.CS_GRP_JUMP)
        target = ins.operands[0].imm if (call or branch) and len(ins.operands) == 1 and ins.operands[0].type == native.X86_OP_IMM else None
        refs = [ins.address + ins.size + op.mem.disp for op in ins.operands
            if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP]
        rows.append(dict(address=ins.address, bytes=bytes(ins.bytes).hex(), call=call,
            branch=branch, direct_target=target, rip_references=refs))
    require(sum(len(bytes.fromhex(row['bytes'])) for row in rows) == size, 'range instruction coverage differs')
    return rows


def transfer(role, old, new, *, constructor=None, clamp=None):
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    signature = load('update-native-contexts').signature
    mapping = {int(a, 16): int(b, 16) for a, b in role['seeds'].items()}
    wanted = {int(a, 16): int(b, 16) for a, b in role['mapping'].items()}
    roots = {int(a, 16): int(b, 16) for a, b in role['roots'].items()}
    anchors = {int(a, 16): bytes.fromhex(raw) for a, raw in role['anchors'].items()}
    leaves = {int(a, 16): bytes.fromhex(raw) for a, raw in role['leaves'].items()}
    math_ranges = {int(row['baseline'], 16): row for row in role['math_ranges']}
    visited, tables, leaf_seen, math_seen, pairs = set(), set(), set(), set(), []
    changes = role.get('scalar_changes', {})
    applied_changes = []

    def link(a, b):
        require(a not in mapping or mapping[a] == b, 'relocation conflict at ' + hex(a))
        mapping[a] = b

    def compare(a, b, before, after, kind):
        normal_after = after
        if hex(a) in changes:
            delta = changes[hex(a)]
            require(clamp is not None and clamp['current_bounds'][delta['field']] == delta['after']
                and int(delta['current'], 16) == b, 'changed scalar lacks current native proof')
            normal_after = copy.deepcopy(after)
            decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
            decoder.detail = True
            sites = []
            for left, right in zip(before, normal_after):
                x = next(decoder.disasm(bytes.fromhex(left['bytes']), left['address']))
                y = next(decoder.disasm(bytes.fromhex(right['bytes']), right['address']))
                if (x.mnemonic == y.mnemonic == delta['mnemonic'] and len(x.operands) == len(y.operands) == 2
                        and x.reg_name(x.operands[0].reg) == y.reg_name(y.operands[0].reg) == delta['register']
                        and x.operands[1].type == y.operands[1].type == native.X86_OP_IMM
                        and x.operands[1].imm == delta['before'] and y.operands[1].imm == delta['after']):
                    raw = bytearray(y.bytes)
                    raw[y.imm_offset:y.imm_offset + y.imm_size] = delta['before'].to_bytes(y.imm_size, 'little')
                    right['bytes'] = raw.hex()
                    sites.append(hex(y.address))
            require(len(sites) == 1, 'Select changed enum immediate count differs')
            applied_changes.append(dict(delta, instruction=sites[0]))
        require(signature(native, before) == signature(native, normal_after),
            'whole instruction/control flow changed at ' + hex(a))
        locations = {row['address'] for row in before}
        for left, right in zip(before, after):
            require(len(left['rip_references']) == len(right['rip_references']), 'RIP dependency count differs')
            for x, y in zip(left['rip_references'], right['rip_references']):
                link(x, y)
            if (left['call'] or left['branch']) and left['direct_target'] and left['direct_target'] not in locations:
                link(left['direct_target'], right['direct_target'])
        pairs.append(dict(baseline=hex(a), current=hex(b), instructions=len(before), kind=kind))

    for _ in range(64):
        progress = False
        bridge = role.get('constructor_bridge')
        if bridge and int(bridge['baseline'], 16) in mapping and int(bridge['baseline'], 16) not in visited:
            a, b = int(bridge['baseline'], 16), int(bridge['current'], 16)
            require(constructor is not None and constructor['constructor_equivalent'] is True
                and len(constructor['cases']) == 8 and mapping[a] == b, 'Select constructor bridge differs')
            for field in ('0x0', '0x28', '0x48'):
                old_table, new_table = (int(value, 16) for value in constructor['pointer_relocations'][field])
                link(old_table, new_table)
            link(int(bridge['baseline_time'], 16), int(bridge['current_time'], 16))
            visited.add(a)
            progress = True
        for a in sorted(roots.keys() & mapping.keys() - visited):
            require(mapping[a] == roots[a], 'root binding differs')
            compare(a, mapping[a], bindings.rows(native, old, a), bindings.rows(native, new, mapping[a]), 'whole_root')
            visited.add(a); progress = True
        for a in sorted(math_ranges.keys() & mapping.keys() - math_seen):
            row = math_ranges[a]
            require(mapping[a] == int(row['current'], 16), 'math range binding differs')
            compare(a, mapping[a], ranged(native, old, a, row['size']),
                ranged(native, new, mapping[a], row['size']), 'retained_math_range')
            math_seen.add(a); progress = True
        for a in sorted(anchors.keys() & mapping.keys() - tables):
            raw = anchors[a]
            require(source(old, a, len(raw)) == raw, 'inherited descriptor bytes differ')
            current = source(new, mapping[a], len(raw))
            for offset in range(0, len(raw), 8):
                link(int.from_bytes(raw[offset:offset + 8], 'little'), int.from_bytes(current[offset:offset + 8], 'little'))
            tables.add(a); progress = True
        for a in sorted(leaves.keys() & mapping.keys() - leaf_seen):
            raw = leaves[a]
            require(source(old, a, len(raw)) == raw, 'inherited leaf changed')
            compare(a, mapping[a], ranged(native, old, a, len(raw)),
                ranged(native, new, mapping[a], len(raw)), 'whole_leaf')
            leaf_seen.add(a); progress = True
        if not progress:
            break
    expected_roots = set(roots)
    if role.get('constructor_bridge'):
        expected_roots.add(int(role['constructor_bridge']['baseline'], 16))
    require(visited == expected_roots and tables == anchors.keys() and leaf_seen == leaves.keys()
        and math_seen == math_ranges.keys() and mapping == wanted, 'reader dependency closure differs')
    for encoded, raw in role['read_data'].items():
        at, raw = int(encoded, 16), bytes.fromhex(raw)
        require(source(old, at, len(raw)) == raw and source(new, mapping[at], len(raw)) == raw, 'math/scalar constant changed')
    imported = []
    for encoded, width, opcode, _, _ in role['read_data_changed']:
        at = int(encoded, 16)
        require(width == 8 and opcode in ('jmp', 'call'), 'unreviewed mutable input')
        helper = load('build-object-zero-init-code')
        before, after = helper.import_at(old.data, old, at), helper.import_at(new.data, new, mapping[at])
        require((before['dll'].lower(), before['name']) == (after['dll'].lower(), after['name'])
            and before['name'] in ('_invalid_parameter_noinfo_noreturn', 'atan2', 'fmod'), 'native import identity changed')
        imported.append(dict(name=before['name'], dll=before['dll'], baseline=hex(at), current=hex(mapping[at])))
    return dict(state='passed', baseline_sha256=role['baseline_sha256'], roots=len(visited),
        leaves=len(leaf_seen), tables=len(tables), math_ranges=len(math_seen), relocations=len(mapping),
        constants=len(role['read_data']), imports=imported, pairs=pairs,
        scalar_changes=applied_changes)


def checked_bindings(context, parents, new):
    native = load('build-native-entry-code')
    normalize = load('audit-launcher-shape-11318').normalize_function
    for packet_id, binding in context['packet_bindings'].items():
        at, reader = int(binding['table'], 16), int(binding['reader'], 16)
        getter = int.from_bytes(source(new, at + 0x28, 8), 'little')
        require(int.from_bytes(source(new, at + 0x20, 8), 'little') == reader
            and source(new, getter, 6) == b'\xb8' + struct.pack('<I', int(packet_id)) + b'\xc3',
            'packet table/ID binding differs')
        if 'name' in binding:
            name = binding['name'].encode('ascii') + bytes(1)
            require(source(new, at + 0x50, len(name)) == name, 'packet table/name binding differs')
        rows = [row for row in parents['current_export']['functions'] if int(row['address'], 16) == reader]
        require(len(rows) == 1, 'current whole export identity differs')
        normalize(native, new, rows[0])
    archive = json.loads((HERE / 'knowledge/native-contexts/clock-world-native-input-current.json').read_bytes())['native_input']
    table = bytes.fromhex(archive['table_bytes'])
    require(source(new, int(archive['table'], 16), len(table)) == table, 'current INPUT table differs')
    for identifier in ('110', '206'):
        mapping = context['roles'][identifier]['mapping']
        require(archive['functions']['string'] in mapping.values(), 'shared FString INPUT role differs')


def portable_projections(parents):
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core import bounded_world_admission
    from vampir_core.character_select_result import decode_character_select_result, SelectionRecord
    from vampir_core.world_move_finish_result import decode_world_move_finish_result

    def select(body, current):
        return decode_character_select_result(body, max_payload_size=8192, max_collection_items=1024,
            source_sha256=SOURCE if current else None)

    select_count, select_short = 0, 0
    # Fixture limited to the pure decoder, which otherwise deliberately has no
    # world policy before publication. No world loader or network action runs.
    with patch.object(bounded_world_admission, 'permits',
            lambda sha, policy: sha == SOURCE and policy == 'world-selection-move-v1'):
        for report in parents['110'].values():
            for row in (*report['cases'], *report.get('vector_cases', [])):
                payload = bytes.fromhex(row['payload_hex'])
                before, after = select(payload, False), select(payload, True)
                require(before.result_code == after.result_code == row['result_code'], 'Select result code differs')
                require(row['returned'] == 1 and row['consumed'] == len(payload), 'Select parent consumption differs')
                # Normalize the two new scalar clamps to their old bounds and
                # compare every other portable field, including raw float bits.
                normalized = []
                for offset, value in after.player.fields:
                    if offset in (0x1d8, 0x250):
                        field, bound = (8, 91) if offset == 0x1d8 else (9, 7)
                        value = tuple(SelectionRecord(tuple((key, min(number, bound) if key == field else number)
                            for key, number in item.fields)) for item in value)
                    normalized.append((offset, value))
                require(SelectionRecord(tuple(normalized)) == before.player
                    and after.data.fields[1:] == before.data.fields[1:], 'unreviewed Select portable projection changed')
                select_count += 1
            select_short += len(report.get('truncated', []))

    finish_reader = parents['206']['reader']
    finish_collections = parents['206']['collections']
    require(len(finish_reader['cases']) == 18 and len(finish_reader['heading']) == 256
        and len(finish_collections['cases']) == 24 and len(finish_collections['short']) == 286,
        'inherited Finish coverage differs')
    for row in finish_reader['cases']:
        payload = bytes.fromhex(row['body_hex'])
        value = decode_world_move_finish_result(payload, max_payload_size=8192, max_collection_items=1024)
        require(all((value.result_code if key == '0x10' else value.data.at(int(key, 16))) == expected
            for key, expected in row['fields'].items()), 'Finish native/portable fields differ')
        require(struct.pack('<ddd', *value.data.at(0x30).finite_values()).hex() == row['vector_hex'],
            'Finish native/portable vector differs')
    for row in finish_collections['cases']:
        payload = bytes.fromhex(row['body_hex'])
        value = decode_world_move_finish_result(payload, max_payload_size=8192, max_collection_items=1024)
        require(row['fields_match'] is True and row['consumed'] == len(payload)
            and all(len(value.data.at(int(key, 16))) == count for key, count in row['counts'].items()),
            'Finish collection projection differs')
    require(select_count == 322 and select_short == 909, 'inherited Select coverage differs')
    return dict(select=select_count, select_short=select_short, finish=42,
        finish_heading=256, finish_short=len(finish_reader['short']) + len(finish_collections['short']))


def validate(report, selected):
    require(report.get('schema') == 1 and report.get('definition') == selected and report.get('recipe') == RECIPE
        and report.get('source_sha256') == SOURCE and report.get('native_execution') is False
        and report.get('native_proofs_reused') is True and report.get('runtime_admitted') is False
        and report.get('network_used') is False and report.get('packet_compatibility') == {'110': True, '206': True}
        and report.get('compatible_with_portable_codecs') is True and report.get('limits'), 'cached report boundary differs')


def verify(*, root=ROOT, context_path=CONTEXT):
    root = Path(root).resolve()
    context, parents, selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes()); path = Path(pointer['path']).resolve()
        require(path == root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
            and digest(path) == pointer['sha256'], 'cache path or hash differs')
        validate(json.loads(path.read_bytes()), selected)
        barrier(selected['inputs'])
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    native = load('build-native-entry-code')
    images = {sha: native.Image((root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').read_bytes())
        for sha in {SOURCE, *(role['baseline_sha256'] for role in context['roles'].values())}}
    checked_bindings(context, parents, images[SOURCE])
    finish_role = context['roles']['206']
    finish = transfer(finish_role, images[finish_role['baseline_sha256']], images[SOURCE])
    select_role = context['roles']['110']
    select = transfer(select_role, images[select_role['baseline_sha256']], images[SOURCE],
        constructor=parents['world-player-constructor-current'], clamp=parents['world-select-clamps-current'])
    finish_math = {row['current'] for row in finish['pairs'] if row['kind'] == 'retained_math_range'}
    require(all(select_role['mapping'].get(old) == current and current in finish_math
        for old, current in select_role['current_math_bridge'].items()), 'shared current math bridge differs')
    select['current_math_bridge'] = select_role['current_math_bridge']
    projections = portable_projections(parents)
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected, method='source_transfer',
        native_execution=False, native_proofs_reused=True, runtime_admitted=False, network_used=False,
        packet_compatibility={'110': True, '206': True}, compatible_with_portable_codecs=True,
        roles={'110': select, '206': finish}, inherited_cases=projections,
        limits=['Finish206 uses its last matching 98802d baseline. Select110 uses its separate c755 baseline.',
            'Whole reader/nested functions and descriptor blocks preserve inherited fresh storage, cleanup and archive fixtures.',
            'Two Select enum clamps and Block2B8 initialization use their separate current native receipts.',
            'Two common math boundaries use the newer current Finish206 closure. Portable heading remains the original wire byte.',
            'Historical native scenarios and current bridge receipts are reused without repeating their matrices.',
            'Byte compatibility remains separate from handler/engine ownership and real world entry.'])
    validate(report, selected); barrier(selected['inputs'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(report=str(path), sha256=pointer['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
