"""Transfer source-bound Tutorial application and queue-consumer contexts."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
RECIPE = 'quest-tutorial-state-transfer-v1'
POLICY = HERE / 'knowledge/quest-tutorial-state-transfer.json'
SHA = re.compile('[0-9a-f]{64}')
FAMILIES = ('tutorial-startup', 'tutorial-populated', 'tutorial-drain')
FLAGS = dict(native_consumer_verified=False, consumer_semantic_verified=False,
             target_exports_verified=False, profile_activated=False, runtime_activated=False)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tools():
    names = ('quest-action-transfer-rules-v1', 'quest-reader-transfer-rules-v1',
             'quest-input-seed-v2', 'update-native-version-result', 'update-native-contexts',
             'update-native-archive-wire', 'update-bindings', 'build-native-entry-code',
             'login-input-transfer-rules', 'extract-native-enums', 'portable-native-family')
    return {str(path): digest(path) for path in (Path(__file__).resolve(), POLICY,
            *(HERE / (name + '.py') for name in names))}


def policy():
    raw = POLICY.read_bytes()
    value = json.loads(raw)
    if (len(raw) > 64 * 1024 or set(value) != {'schema', 'recipe', 'baseline_source_sha256',
            'baselines', 'roots', 'fixtures', 'drain_indirect', 'packet_table', 'record_table'}
            or type(value['schema']) is not int or value['schema'] != 1 or value['recipe'] != RECIPE
            or not SHA.fullmatch(value['baseline_source_sha256']) or len(value['roots']) != 11
            or set(value['baselines']) != {'startup', 'populated', 'drain'}
            or set(value['fixtures']) != set(value['baselines'])
            or any(spec['tails'] for spec in value['roots'].values())):
        raise ValueError('Tutorial state transfer rule differs')
    return value


def baselines(index):
    rule = policy()
    result = {}
    for name, pointer in rule['baselines'].items():
        path = HERE / 'knowledge/native-contexts' / pointer['file']
        if (path.resolve().parent != (HERE / 'knowledge/native-contexts').resolve()
                or digest(path) != pointer['sha256']):
            raise ValueError('Tutorial state baseline context changed')
        context = index.read_json(path)
        if context['source_sha256'] != rule['baseline_source_sha256']:
            raise ValueError('Tutorial state baseline source differs')
        result[name] = context
    return result


def dependencies(index, args, action_pointer):
    rule = policy()
    paths = tools()
    for name, context in baselines(index).items():
        path = (HERE / 'knowledge/native-contexts' / rule['baselines'][name]['file']).resolve()
        paths[str(path)] = rule['baselines'][name]['sha256']
        for run, expected in context['exports'].items():
            export = Path(args.root) / 'ghidra/request-exports' / context['source_sha256'] / run / 'details.json'
            if index.digest(export) != expected:
                raise ValueError('Tutorial state baseline export changed')
            paths[str(export.resolve())] = expected
            receipt = index.receipt_for(export)
            if not receipt.is_file():
                raise ValueError('Tutorial state baseline export receipt missing')
            paths[str(receipt.resolve())] = index.digest(receipt)
    paths.update(index.extension('portable-native-family').lineage_inputs(args, Path(action_pointer['path'])))
    if paths.get(str(Path(action_pointer['path']).resolve())) != action_pointer['sha256']:
        raise ValueError('Tutorial state action proof SHA differs')
    args.source_store.source(rule['baseline_source_sha256'])
    return paths


def data_span(image, at, size):
    """Read initialized PE bytes, including the image's declared zero-fill tail."""
    if type(size) is not int or not 1 <= size <= 16:
        raise ValueError('Tutorial state data span budget differs')
    rva = at - image.pe.base
    sections = [s for s in image.pe.sections if s['rva'] <= rva and rva + size <= s['rva'] + s['size']]
    if len(sections) != 1:
        raise ValueError('Tutorial state data span outside one PE section')
    section = sections[0]
    raw_count = max(0, min(size, section['raw_size'] - (rva - section['rva'])))
    offset = section['raw'] + rva - section['rva']
    return section['name'], image.data[offset:offset + raw_count] + bytes(size - raw_count)


def transfer(index, args, action_pointer):
    rule = policy()
    context_api = index.extension('quest-action-transfer-rules-v1')
    reader = index.extension('quest-reader-transfer-rules-v1')
    native = index.extension('build-native-entry-code')
    bindings = index.extension('update-bindings')
    api = index.extension('update-native-version-result')
    common = index.extension('update-native-archive-wire')
    action = context_api.document(index, action_pointer, Path(args.root) / 'knowledge/quest-action-transfer-proofs-v1')
    index.extension('quest-action-transfer-rules-v1').validate_package(action['package'], action['inputs'])
    if (action.get('recipe') != 'quest-action-transfer-v1' or action.get('method') != 'static'
            or any(action.get(key) is not False for key in ('native_consumer_verified', 'runtime_activated', 'profile_activated'))):
        raise ValueError('Tutorial state requires an exact static action proof')
    oldsha, sha = rule['baseline_source_sha256'], action['inputs']['target_source_sha256']
    if action['inputs']['baseline_source_sha256'] != oldsha or sha == oldsha:
        raise ValueError('Tutorial state ordered source identities differ')
    before = args.source_store.image(native, oldsha)
    after = args.source_store.image(native, sha)
    contexts = baselines(index)
    roots = {int(value, 16) for c in contexts.values() for value in c['functions'].values()}
    if {hex(at) for at in roots} != set(rule['roots']):
        raise ValueError('Tutorial state reviewed root inventory differs')
    for context in contexts.values():
        reader.export_coverage(index, args, context, native, bindings, before)
    mapping = {int(a, 16): int(b, 16) for a, b in action['package']['relation']['mapping'].items()}
    checks = context_api.resolve(native, bindings, api, before, after, rule, mapping)
    old_rows = {at: bindings.rows(native, before, at) for at in roots}
    all_leaves = {int(at, 16): text for c in contexts.values() for at, text in c.get('leaves', {}).items()}
    leaf_api = index.extension('login-input-transfer-rules')
    leaf_checks = []
    for at, encoded in sorted(all_leaves.items()):
        if at not in mapping:
            raise ValueError('Tutorial state leaf lacks a reviewed native caller')
        raw = bytes.fromhex(encoded)
        rows = leaf_api.leaf_rows(native, before, at, raw)
        current = leaf_api.leaf_rows(native, after, mapping[at], raw)
        leaf_api.pair_leaf(native, rows, current, mapping)
        actual = api.image_bytes(after, mapping[at], len(raw))
        leaf_checks.append(dict(baseline=hex(at), target=hex(mapping[at]), baseline_bytes=encoded,
                                bytes=actual.hex(), sha256=hashlib.sha256(actual).hexdigest()))
    projected = {}
    data_proofs = {}
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    for name, baseline in contexts.items():
        family = 'tutorial-' + name
        local_roots = {int(at, 16) for at in baseline['functions'].values()}
        local_leaves = {int(at, 16) for at in baseline.get('leaves', {})}
        roles = dict(rule['fixtures'][name])
        fixtures = {role: hex(mapping[int(at, 16)]) for role, at in roles.items()}
        callers = {role: [] for role in fixtures}
        indirect = []
        readonly = {}
        excluded = []
        for at in sorted(local_roots):
            for row in old_rows[at]:
                target = row['direct_target']
                if row['call'] and target is not None and target not in local_roots | local_leaves:
                    matches = [role for role, value in roles.items() if int(value, 16) == target]
                    if not matches:
                        role = 'excluded_' + hex(target)[2:]
                        roles[role] = hex(target)
                        fixtures[role] = hex(mapping[target])
                        callers[role] = []
                    else:
                        role = matches[0]
                    callers[role].append(hex(mapping[row['address']]))
                    section, _ = data_span(after, mapping[target], 1)
                    if section != '.text':
                        raise ValueError('Tutorial state fixture entry is outside source code')
                for data_at in row['rip_references']:
                    instruction = next(decoder.disasm(bytes.fromhex(row['bytes']), row['address']))
                    operands = [op for op in instruction.operands if op.type == native.X86_OP_MEM
                                and op.mem.base == native.X86_REG_RIP]
                    if len(operands) != 1:
                        raise ValueError('Tutorial state RIP operand scope differs')
                    op = operands[0]
                    target_data = mapping[data_at]
                    if row['mnemonic'] == 'lea':
                        data_proofs[hex(data_at)] = dict(baseline=hex(data_at), target=hex(target_data),
                                                       kind='address-link-only', value_verified=False)
                    else:
                        size = op.size
                        section, current = data_span(after, target_data, size)
                        oldsection, prior = data_span(before, data_at, size)
                        if section != oldsection:
                            raise ValueError('Tutorial state data section role changed')
                        reading = bool(op.access & native.capstone.CS_AC_READ)
                        writing = bool(op.access & native.capstone.CS_AC_WRITE)
                        if section == '.rdata' and (writing or prior != current):
                            raise ValueError('Tutorial state immutable data changed')
                        if reading:
                            readonly[hex(target_data)] = current.hex()
                        data_proofs[hex(data_at)] = dict(baseline=hex(data_at), target=hex(target_data),
                            kind='mutable-data-storage' if section == '.data' else 'constant',
                            bytes=size, value_verified=section == '.rdata', native_write_allowed=False,
                            fixture_bytes=current.hex() if reading else None)
        packet_table = hex(mapping[int(rule['packet_table'], 16)])
        record_table = hex(mapping[int(rule['record_table'], 16)])
        selected_tables = []
        for at in (rule['packet_table'], rule['record_table']):
            rows = [r for r in action['package']['relation']['tables'] if r['baseline'] == at]
            if len(rows) != 1:
                raise ValueError('Tutorial state packet/record table missing from action proof')
            selected_tables.append(dict(target=rows[0]['target'], bytes=rows[0]['bytes']))
        if name == 'drain':
            spec = rule['drain_indirect']
            consumer = int(baseline['functions']['consumer'], 16)
            row = next(r for r in old_rows[consumer] if r['address'] == consumer + spec['destructor_offset'])
            if not row['call'] or row['operands'] != spec['destructor_operand'] or row['direct_target'] is not None:
                raise ValueError('Tutorial state deleting destructor virtual call changed')
            site = hex(mapping[row['address']])
            indirect = [[site, spec['destructor_operand'], fixtures['destructor']]]
            callers['destructor'] = [site]
        for role, value in roles.items():
            if not callers[role]:
                raise ValueError('Tutorial state fixture lacks a declared caller: ' + role)
            excluded.append(dict(role=role, baseline=value, target=fixtures[role], callers=callers[role],
                                 kind='excluded-direct-call-entry', body_verified=False))
        current = dict(family=family, source_sha256=sha,
            source=str(Path(args.root) / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'),
            functions={role: hex(mapping[int(at, 16)]) for role, at in baseline['functions'].items()},
            leaves={hex(mapping[int(at, 16)]): api.image_bytes(after, mapping[int(at, 16)], len(bytes.fromhex(text))).hex()
                    for at, text in baseline.get('leaves', {}).items()},
            fixtures=fixtures, fixture_calls=callers, fixture_boundaries=excluded, indirect_fixtures=indirect,
            handler_global=action['package']['target_contexts']['tutorial-dispatch']['handler_global'],
            readonly_globals=readonly, packet_table=packet_table, record_table=record_table, tables=selected_tables,
            **FLAGS)
        if name == 'drain':
            current.update(destructor=fixtures['destructor'], application=fixtures['application'],
                           id_getter=hex(mapping[0x145855ec0]))
        projected[family] = current
    result = dict(schema=1, recipe=RECIPE, method='static', baseline_source_sha256=oldsha,
        source_sha256=sha, action_proof=copy.deepcopy(action_pointer), contexts=projected,
        export_addresses=[hex(mapping[at]) for at in sorted(roots)],
        relation=dict(mapping={hex(a): hex(b) for a, b in sorted(mapping.items())},
                      rootchecks=checks, leaves=leaf_checks, data=list(data_proofs.values())),
        **FLAGS)
    validate_package(result, sha, action_pointer)
    return result


def validate_package(package, sha=None, action_pointer=None):
    rule = policy()
    expected_keys = {'schema', 'recipe', 'method', 'baseline_source_sha256', 'source_sha256',
                     'action_proof', 'contexts', 'export_addresses', 'relation', *FLAGS}
    if (not isinstance(package, dict) or set(package) != expected_keys
            or type(package.get('schema')) is not int or package['schema'] != 1
            or package.get('recipe') != RECIPE or package.get('method') != 'static'
            or package.get('baseline_source_sha256') != rule['baseline_source_sha256']
            or not SHA.fullmatch(package.get('source_sha256', '')) or package['source_sha256'] == rule['baseline_source_sha256']
            or (sha is not None and package['source_sha256'] != sha)
            or (action_pointer is not None and package.get('action_proof') != action_pointer)
            or any(package.get(key) is not False for key in FLAGS)
            or set(package.get('contexts', {})) != set(FAMILIES)):
        raise ValueError('Tutorial state static package scope differs')
    relation = package['relation']
    if set(relation) != {'mapping', 'rootchecks', 'leaves', 'data'}:
        raise ValueError('Tutorial state cached relation fields differ')
    mapping = relation['mapping']
    if (not 11 <= len(mapping) <= 8192 or any(not re.fullmatch('0x[0-9a-f]+', key)
            or not re.fullmatch('0x[0-9a-f]+', value) for key, value in mapping.items())):
        raise ValueError('Tutorial state static mapping budget differs')
    pointer = package['action_proof']
    if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
            or not SHA.fullmatch(str(pointer['sha256'])) or digest(pointer['path']) != pointer['sha256']):
        raise ValueError('Tutorial state cached action pointer changed')
    action = json.loads(Path(pointer['path']).read_bytes())
    if (action['inputs']['target_source_sha256'] != package['source_sha256']
            or action['inputs']['baseline_source_sha256'] != package['baseline_source_sha256']
            or any(mapping.get(at) != target for at, target in action['package']['relation']['mapping'].items())):
        raise ValueError('Tutorial state cached action mapping differs')
    checks = {r['baseline']: r for r in package['relation']['rootchecks']}
    if set(checks) != set(rule['roots']) or len(checks) != len(package['relation']['rootchecks']):
        raise ValueError('Tutorial state whole root coverage differs')
    for at, expected in rule['roots'].items():
        row = checks[at]
        if (set(row) != {'baseline', 'target', 'candidates', 'whole_instruction_shape_verified', 'calls', 'data', 'tails'}
                or row['target'] != mapping[at] or row['whole_instruction_shape_verified'] is not True
                or type(row['candidates']) is not int or not 1 <= row['candidates'] <= 32
                or any(row[key] != expected[key] for key in ('calls', 'data', 'tails'))):
            raise ValueError('Tutorial state cached root policy differs')
    if package['export_addresses'] != [mapping[at] for at in sorted(rule['roots'], key=lambda text: int(text, 16))]:
        raise ValueError('Tutorial state export root projection differs')
    baselines = baselines_for_validation(rule)
    old_leaves = {at: text for c in baselines.values() for at, text in c.get('leaves', {}).items()}
    leaf_rows = relation['leaves']
    if len(leaf_rows) != len(old_leaves) or {r['baseline'] for r in leaf_rows} != set(old_leaves):
        raise ValueError('Tutorial state cached leaf inventory differs')
    for row in leaf_rows:
        text = old_leaves[row['baseline']]
        raw = bytes.fromhex(row['bytes'])
        # Only the packet-base LEA contains an address-bearing displacement.
        relocations = set(range(3, 7)) if bytes.fromhex(text).startswith(b'\x48\x8d\x05') else set()
        if (set(row) != {'baseline', 'target', 'baseline_bytes', 'bytes', 'sha256'}
                or row['baseline_bytes'] != text or row['target'] != mapping[row['baseline']]
                or len(raw) != len(bytes.fromhex(text)) or hashlib.sha256(raw).hexdigest() != row['sha256']
                or any(value != raw[pos] for pos, value in enumerate(bytes.fromhex(text)) if pos not in relocations)):
            raise ValueError('Tutorial state cached leaf bytes differ')
        if relocations:
            old_ref = int(row['baseline'], 16) + 7 + struct.unpack_from('<i', bytes.fromhex(text), 3)[0]
            new_ref = int(row['target'], 16) + 7 + struct.unpack_from('<i', raw, 3)[0]
            if mapping[hex(old_ref)] != hex(new_ref):
                raise ValueError('Tutorial state cached leaf data relocation differs')
    data = {r['baseline']: r for r in relation['data']}
    expected_data = {at for spec in rule['roots'].values() for values in spec['data'].values() for at in values}
    if len(data) != len(relation['data']) or set(data) != expected_data:
        raise ValueError('Tutorial state cached RIP data coverage differs')
    for at, row in data.items():
        if row['target'] != mapping[at]:
            raise ValueError('Tutorial state cached data edge differs')
        if row['kind'] == 'address-link-only':
            if set(row) != {'baseline', 'target', 'kind', 'value_verified'} or row['value_verified'] is not False:
                raise ValueError('Tutorial state address-only scope differs')
        elif (set(row) != {'baseline', 'target', 'kind', 'bytes', 'value_verified', 'native_write_allowed', 'fixture_bytes'}
                or row['kind'] not in ('mutable-data-storage', 'constant') or type(row['bytes']) is not int
                or row['bytes'] not in (1, 2, 4, 8, 16) or row['native_write_allowed'] is not False
                or row['value_verified'] is not (row['kind'] == 'constant')
                or (row['fixture_bytes'] is not None and len(bytes.fromhex(row['fixture_bytes'])) != row['bytes'])):
            raise ValueError('Tutorial state cached readonly data scope differs')
    for name, baseline in baselines.items():
        context = package['contexts']['tutorial-' + name]
        context_keys = {'family', 'source_sha256', 'source', 'functions', 'leaves', 'fixtures', 'fixture_calls',
                        'fixture_boundaries', 'indirect_fixtures', 'handler_global', 'readonly_globals',
                        'packet_table', 'record_table', 'tables', *FLAGS}
        if name == 'drain':
            context_keys |= {'destructor', 'application', 'id_getter'}
        if (set(context) != context_keys or context['family'] != 'tutorial-' + name
                or context['source_sha256'] != package['source_sha256']
                or Path(context['source']).parent.name != package['source_sha256']
                or Path(context['source']).name != 'ProjectRED-Win64-Shipping.exe'
                or context['functions'] != {role: mapping[at] for role, at in baseline['functions'].items()}
                or any(context.get(key) is not False for key in FLAGS)):
            raise ValueError('Tutorial state consumer projection differs')
        roots = set(context['functions'].values())
        leaves = context['leaves']
        if roots & set(leaves) or set(context['fixtures'].values()) & (roots | set(leaves)):
            raise ValueError('Tutorial state native scope overlaps fixtures')
        expected_leaves = {mapping[at]: text for at, text in baseline.get('leaves', {}).items()}
        admitted = {r['target']: r for r in package['relation']['leaves']}
        if set(leaves) != set(expected_leaves) or any(leaves[at] != admitted[at]['bytes'] for at in leaves):
            raise ValueError('Tutorial state cached leaves differ')
        for role, old in rule['fixtures'][name].items():
            if context['fixtures'].get(role) != mapping[old]:
                raise ValueError('Tutorial state cached fixture role differs')
        expected_calls = {}
        for old in baseline['functions'].values():
            for offset, target in rule['roots'][old]['calls'].items():
                if target.startswith('0x') and mapping[target] not in roots | set(leaves):
                    expected_calls.setdefault(mapping[target], []).append(mapping[hex(int(old, 16) + int(offset))])
        if name == 'drain':
            spec = rule['drain_indirect']
            site = mapping[hex(int(baseline['functions']['consumer'], 16) + spec['destructor_offset'])]
            expected_calls[mapping[baseline['destructor']]] = [site]
            if context['indirect_fixtures'] != [[site, spec['destructor_operand'], mapping[baseline['destructor']]]]:
                raise ValueError('Tutorial state cached destructor association differs')
        elif context['indirect_fixtures']:
            raise ValueError('Tutorial state unexpected indirect fixture')
        actual = {}
        for role, sites in context['fixture_calls'].items():
            actual.setdefault(context['fixtures'][role], []).extend(sites)
        if {at: sorted(sites) for at, sites in actual.items()} != {at: sorted(sites) for at, sites in expected_calls.items()}:
            raise ValueError('Tutorial state cached fixture caller coverage differs')
        if context['packet_table'] != mapping[rule['packet_table']] or context['record_table'] != mapping[rule['record_table']]:
            raise ValueError('Tutorial state cached packet tables differ')
        referenced = {at for root in baseline['functions'].values() for values in rule['roots'][root]['data'].values() for at in values}
        expected_readonly = {data[at]['target']: data[at]['fixture_bytes'] for at in referenced
                             if data[at].get('fixture_bytes') is not None}
        expected_tables = [dict(target=r['target'], bytes=r['bytes']) for old in (rule['packet_table'], rule['record_table'])
                           for r in action['package']['relation']['tables'] if r['baseline'] == old]
        if (context['readonly_globals'] != expected_readonly or context['tables'] != expected_tables
                or context['handler_global'] != action['package']['target_contexts']['tutorial-dispatch']['handler_global']):
            raise ValueError('Tutorial state cached source data projection differs')
        expected_boundaries = [dict(role=role, baseline=rule['fixtures'][name].get(role, '0x' + role.removeprefix('excluded_')),
                                   target=address, callers=context['fixture_calls'][role],
                                   kind='excluded-direct-call-entry', body_verified=False)
                               for role, address in context['fixtures'].items()]
        actual_boundaries = {row['role']: row for row in context['fixture_boundaries']}
        if (len(actual_boundaries) != len(expected_boundaries)
                or any(actual_boundaries.get(row['role']) != row for row in expected_boundaries)):
            raise ValueError('Tutorial state cached excluded-entry scope differs')
        if name == 'drain' and (context['destructor'] != context['fixtures']['destructor']
                or context['application'] != context['fixtures']['application']
                or context['id_getter'] != mapping[next(at for at, text in baseline['leaves'].items() if text == 'b8b1260000c3')]):
            raise ValueError('Tutorial state cached queue metadata differs')


def baselines_for_validation(rule):
    result = {}
    for name, pointer in rule['baselines'].items():
        path = HERE / 'knowledge/native-contexts' / pointer['file']
        if digest(path) != pointer['sha256']:
            raise ValueError('Tutorial state cached baseline context changed')
        result[name] = json.loads(path.read_bytes())
    return result
