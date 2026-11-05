"""Transfer the existing matching-task state/progress scope from reviewed code."""
import copy
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
RECIPE = 'quest-matching-state-transfer-v1'
POLICY = HERE / 'knowledge/quest-matching-state-transfer.json'
SHA = re.compile('[0-9a-f]{64}')
ADDRESS = re.compile('0x[0-9a-f]+')
FLAGS = dict(target_exports_verified=False, native_consumer_verified=False,
             consumer_semantic_verified=False, runtime_activated=False, profile_activated=False)

def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def tools():
    names = ('quest-action-transfer-rules-v1', 'quest-reader-transfer-rules-v1',
             'quest-input-seed-v2', 'update-native-version-result', 'update-native-contexts',
             'update-native-archive-wire', 'update-bindings', 'build-native-entry-code',
             'login-input-transfer-rules', 'extract-native-enums', 'portable-native-family')
    return {str(path): digest(path) for path in (Path(__file__).resolve(), POLICY,
            HERE / 'knowledge/quest-reader-transfer-rules.json',
            *(HERE / (name + '.py') for name in names))}

def policy():
    raw = POLICY.read_bytes()
    value = json.loads(raw)
    expected = {'schema', 'recipe', 'baseline_source_sha256', 'baseline_context', 'baseline_native',
                'baseline_export', 'roots', 'leaves', 'excluded', 'callbacks'}
    if (len(raw) > 16384 or set(value) != expected or type(value['schema']) is not int
            or value['schema'] != 1 or value['recipe'] != RECIPE
            or not SHA.fullmatch(value['baseline_source_sha256'])
            or set(value['roots']) != {'state', 'progress'}
            or set(value['leaves']) != {'copy', 'index_getter'}
            or set(value['excluded']) != {'factory', 'shared_move_release', 'bind_owner'}
            or set(value['callbacks']) != {'task_start', 'task_update'}):
        raise ValueError('Matching-task transfer policy scope differs')
    if any(spec['tails'] or spec['data'] for spec in value['roots'].values()):
        raise ValueError('Matching-task baseline contains unreviewed tail/data behavior')
    return value

def document(index, pointer, folder):
    return index.extension('quest-action-transfer-rules-v1').document(index, pointer, folder)

def baseline_context(index):
    rule = policy()
    path = HERE / 'knowledge/native-contexts' / rule['baseline_context']['file']
    if path.resolve().parent != (HERE / 'knowledge/native-contexts').resolve():
        raise ValueError('Matching-task baseline escapes repository contexts')
    if digest(path) != rule['baseline_context']['sha256']:
        raise ValueError('Matching-task baseline context changed')
    value = index.read_json(path)
    if value['source_sha256'] != rule['baseline_source_sha256']:
        raise ValueError('Matching-task baseline source differs')
    if ({name: value['functions'][name] for name in ('state', 'progress')}
            != {name: spec['address'] for name, spec in rule['roots'].items()}):
        raise ValueError('Matching-task baseline roles differ')
    if value['leaves'] != {spec['address']: spec['bytes'] for spec in rule['leaves'].values()}:
        raise ValueError('Matching-task baseline leaf roles differ')
    return path, value

def reader_context(index, args, pointer):
    seed = index.extension('quest-input-seed-v2')
    folder = Path(args.root) / 'knowledge/quest-reader-transfer-proofs-v1'
    if (not seed.exact_pointer(pointer) or Path(pointer['path']).name != 'manifest.json'
            or Path(pointer['path']).parent.name != pointer['sha256']):
        raise ValueError('Matching-task transfer needs an immutable reader proof')
    proof = document(index, pointer, folder)
    if (type(proof.get('schema')) is not int or proof['schema'] != 1
            or proof.get('recipe') != 'quest-reader-transfer-v1' or proof.get('method') != 'static'
            or any(proof.get(key) is not False for key in ('native_consumer_verified', 'runtime_activated', 'profile_activated'))):
        raise ValueError('Matching-task reader proof scope differs')
    index.extension('quest-reader-transfer-rules-v1').validate_package(proof['package'], proof['inputs'])
    return proof

def baseline_native(index, args):
    rule = policy()
    pointer = rule['baseline_native']
    proof = document(index, dict(path=str(Path(args.root) / pointer['path']), sha256=pointer['sha256']),
                     Path(args.root) / 'code-clues/quest-state-application-11316')
    context_path, context = baseline_context(index)
    if (proof.get('source_sha256') != rule['baseline_source_sha256']
            or proof.get('context_sha256') != digest(context_path)
            or type(proof.get('case_count')) is not int or proof['case_count'] != 324
            or len(proof.get('cases', [])) != 324 or proof.get('network_used') is not False
            or proof.get('native_functions') != [rule['roots'][name]['address'] for name in ('state', 'progress')]
                + [rule['leaves'][name]['address'] for name in ('copy', 'index_getter')]):
        raise ValueError('Matching-task reviewed native proof scope differs')
    return proof

def dependencies(index, args, reader_pointer):
    rule = policy()
    path, _ = baseline_context(index)
    baseline_native(index, args)
    reader_context(index, args, reader_pointer)
    files = tools()
    files[str(path.resolve())] = rule['baseline_context']['sha256']
    for key in ('baseline_native', 'baseline_export'):
        pointer = rule[key]
        path = (Path(args.root) / pointer['path']).resolve()
        if index.digest(path) != pointer['sha256']:
            raise ValueError('Matching-task selected baseline evidence changed')
        files[str(path)] = pointer['sha256']
        if key == 'baseline_export':
            receipt = index.receipt_for(path)
            if not receipt.is_file():
                raise ValueError('Matching-task baseline export receipt missing')
            files[str(receipt.resolve())] = index.digest(receipt)
    files.update(index.extension('portable-native-family').lineage_inputs(args, Path(reader_pointer['path'])))
    if files.get(str(Path(reader_pointer['path']).resolve())) != reader_pointer['sha256']:
        raise ValueError('Matching-task reader proof digest differs')
    args.source_store.source(rule['baseline_source_sha256'])
    return files

def transfer(index, args, reader_pointer):
    rule = policy()
    _, baseline = baseline_context(index)
    baseline_native(index, args)
    reader = reader_context(index, args, reader_pointer)
    sha = reader['inputs']['target_source_sha256']
    old_sha = rule['baseline_source_sha256']
    source = (Path(args.root) / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').resolve()
    if reader['inputs']['baseline_source_sha256'] != old_sha or old_sha == sha or not SHA.fullmatch(sha):
        raise ValueError('Matching-task ordered source identities differ')
    native = index.extension('build-native-entry-code')
    bindings = index.extension('update-bindings')
    root_api = index.extension('update-native-version-result')
    rules = index.extension('quest-action-transfer-rules-v1')
    common = index.extension('update-native-archive-wire')
    leaf_api = index.extension('login-input-transfer-rules')
    before = args.source_store.image(native, old_sha)
    after = args.source_store.image(native, sha)
    export_pointer = rule['baseline_export']
    export_path = Path(args.root) / export_pointer['path']
    report = document(index, dict(path=str(export_path), sha256=export_pointer['sha256']),
                      Path(args.root) / 'ghidra/request-exports' / old_sha)
    if report.get('new_source_sha256', report.get('source_sha256')) != old_sha:
        raise ValueError('Matching-task baseline export source differs')
    roots = {name: int(spec['address'], 16) for name, spec in rule['roots'].items()}
    old_rows = {name: bindings.rows(native, before, at) for name, at in roots.items()}
    for name, rows in old_rows.items():
        matches = [fn for fn in report['functions'] if fn['address'] == hex(roots[name])]
        if (len(matches) != 1 or matches[0].get('decompilation_completed') is not True
                or [(int(row['address'], 16), row['bytes'].lower()) for row in matches[0]['instructions']]
                != [(row['address'], row['bytes']) for row in rows]):
            raise ValueError('Matching-task baseline whole export coverage differs')
    reviewed = dict(roots={spec['address']: {key: value for key, value in spec.items() if key != 'address'}
                           for spec in rule['roots'].values()})
    mapping = {}
    checks = rules.resolve(native, bindings, root_api, before, after, reviewed, mapping)
    leaves = []
    leaf_roles = {}
    for role, spec in rule['leaves'].items():
        old_at = int(spec['address'], 16)
        raw = bytes.fromhex(spec['bytes'])
        if root_api.image_bytes(before, old_at, len(raw)) != raw:
            raise ValueError('Matching-task baseline leaf bytes changed')
        candidates = rules.masked_hits(after, old_at, raw, [])
        if len(candidates) != 1:
            raise ValueError('Matching-task exact leaf missing or ambiguous: ' + role)
        target = candidates[0]
        common.add_link(mapping, old_at, target)
        leaf_api.pair_leaf(native, leaf_api.leaf_rows(native, before, old_at, raw),
                          leaf_api.leaf_rows(native, after, target, raw), mapping)
        leaves.append(dict(role=role, baseline=hex(old_at), target=hex(target), bytes=raw.hex()))
        leaf_roles[role] = hex(target)
    # Callbacks and direct excluded branches are bound to complete source rows.
    fixtures, fixture_calls, callback_returns, indirect = {}, {}, {}, []
    progress = roots['progress']
    for role, spec in rule['callbacks'].items():
        old_call = progress + spec['offset']
        rows = [row for row in old_rows['progress'] if row['address'] == old_call]
        if (len(rows) != 1 or rows[0]['call'] is not True or rows[0]['direct_target'] is not None
                or rows[0]['operands'] != spec['operand']):
            raise ValueError('Matching-task callback source association differs')
        target = hex(mapping[old_call])
        fixtures[role] = spec['fixture']
        fixture_calls[role] = [target]
        callback_returns[role] = hex(mapping[old_call] + len(bytes.fromhex(rows[0]['bytes'])))
        indirect.append([target, spec['operand'], spec['fixture']])
    boundaries = {}
    for role, spec in rule['excluded'].items():
        at = int(spec['address'], 16)
        target = mapping[at]
        boundary = index.extension('quest-reader-transfer-rules-v1').check_boundary(
            native, bindings, before, after, at, target)
        sites = [hex(mapping[progress + offset]) for offset in spec['offsets']]
        if any(rule['roots']['progress']['calls'].get(str(offset)) != spec['address'] for offset in spec['offsets']):
            raise ValueError('Matching-task excluded source callsite differs')
        fixtures[role] = hex(target)
        fixture_calls[role] = sites
        boundaries[role] = boundary
    context = dict(schema=1, family='quest-matching-state', source=str(source), source_sha256=sha,
        functions={name: hex(mapping[at]) for name, at in roots.items()},
        leaves={row['target']: row['bytes'] for row in leaves}, leaf_roles=leaf_roles,
        fixtures=fixtures, fixture_calls=fixture_calls, fixture_boundaries=boundaries,
        callback_returns=callback_returns, indirect_fixtures=indirect, tables=[], readonly_globals={},
        existing_task_only=True, **FLAGS)
    package = dict(schema=1, recipe=RECIPE, method='static', baseline_source_sha256=old_sha,
        source_sha256=sha, reader_proof=copy.deepcopy(reader_pointer),
        baseline_native_proof=copy.deepcopy(rule['baseline_native']),
        contexts={'quest-matching-state': context},
        export_addresses=[context['functions'][name] for name in ('state', 'progress')],
        relation=dict(mapping={hex(a): hex(b) for a, b in sorted(mapping.items())},
                      rootchecks=checks, leaves=leaves), **FLAGS)
    validate_package(package, sha, reader_pointer)
    return package

def validate_package(package, sha=None, reader_pointer=None):
    rule = policy()
    expected = {'schema', 'recipe', 'method', 'baseline_source_sha256', 'source_sha256',
                'reader_proof', 'baseline_native_proof', 'contexts', 'export_addresses', 'relation', *FLAGS}
    if (not isinstance(package, dict) or set(package) != expected
            or type(package['schema']) is not int or package['schema'] != 1
            or package['recipe'] != RECIPE or package['method'] != 'static'
            or package['baseline_source_sha256'] != rule['baseline_source_sha256']
            or not isinstance(package['source_sha256'], str) or not SHA.fullmatch(package['source_sha256'])
            or package['source_sha256'] == rule['baseline_source_sha256']
            or (sha is not None and package['source_sha256'] != sha)
            or (reader_pointer is not None and package['reader_proof'] != reader_pointer)
            or package['baseline_native_proof'] != rule['baseline_native']
            or any(package.get(key) is not False for key in FLAGS)
            or set(package['contexts']) != {'quest-matching-state'}):
        raise ValueError('Matching-task static package scope differs')
    relation = package['relation']
    if set(relation) != {'mapping', 'rootchecks', 'leaves'}:
        raise ValueError('Matching-task static relation shape differs')
    mapping = relation['mapping']
    if (not 159 <= len(mapping) <= 512 or any(not ADDRESS.fullmatch(a) or not ADDRESS.fullmatch(b)
                                            for a, b in mapping.items())
            or len(set(mapping.values())) != len(mapping)):
        raise ValueError('Matching-task mapping scope or alias partition differs')
    def mapped(at):
        return mapping[at]
    checks = {row['baseline']: row for row in relation['rootchecks']}
    roots = {name: spec['address'] for name, spec in rule['roots'].items()}
    if len(checks) != 2 or len(relation['rootchecks']) != 2 or set(checks) != set(roots.values()):
        raise ValueError('Matching-task whole root coverage differs')
    for name, at in roots.items():
        spec = {key: value for key, value in rule['roots'][name].items() if key != 'address'}
        row = checks[at]
        expected_row = dict(baseline=at, target=mapped(at), candidates=row.get('candidates'),
                            whole_instruction_shape_verified=True, **spec)
        if (row != expected_row or row.get('whole_instruction_shape_verified') is not True
                or type(row['candidates']) is not int or not 1 <= row['candidates'] <= 32):
            raise ValueError('Matching-task whole instruction policy differs')
    leaves = relation['leaves']
    if len(leaves) != 2 or {row['role'] for row in leaves} != set(rule['leaves']):
        raise ValueError('Matching-task leaf scope differs')
    for row in leaves:
        spec = rule['leaves'][row['role']]
        if row != dict(role=row['role'], baseline=spec['address'], target=mapped(spec['address']), bytes=spec['bytes']):
            raise ValueError('Matching-task leaf source projection differs')
    leaf_roles = {row['role']: row['target'] for row in leaves}
    functions = {name: mapped(at) for name, at in roots.items()}
    if package['export_addresses'] != [functions[name] for name in ('state', 'progress')]:
        raise ValueError('Matching-task export projection differs')
    if len(set(functions.values()) | set(leaf_roles.values())) != 4:
        raise ValueError('Matching-task roots and leaves overlap')
    fixtures = {name: mapped(spec['address']) for name, spec in rule['excluded'].items()}
    fixtures.update({name: spec['fixture'] for name, spec in rule['callbacks'].items()})
    calls = {name: [mapped(hex(int(roots['progress'], 16) + offset)) for offset in spec['offsets']]
             for name, spec in rule['excluded'].items()}
    returns = {}
    indirect = []
    for role, spec in rule['callbacks'].items():
        at = int(roots['progress'], 16) + spec['offset']
        target = mapped(hex(at))
        calls[role] = [target]
        returns[role] = hex(int(target, 16) + spec['size'])
        indirect.append([target, spec['operand'], spec['fixture']])
    boundaries = {name: dict(baseline=spec['address'], target=mapped(spec['address']),
                             kind='exact-unwind-entry', body_verified=False)
                  for name, spec in rule['excluded'].items()}
    if len(set(fixtures.values())) != 4 or set(fixtures.values()) & (set(functions.values()) | set(leaf_roles.values())):
        raise ValueError('Matching-task fixture alias partition differs')
    context = package['contexts']['quest-matching-state']
    expected_context = dict(schema=1, family='quest-matching-state', source=context.get('source'),
        source_sha256=package['source_sha256'], functions=functions,
        leaves={row['target']: row['bytes'] for row in leaves}, leaf_roles=leaf_roles,
        fixtures=fixtures, fixture_calls=calls, fixture_boundaries=boundaries,
        callback_returns=returns, indirect_fixtures=indirect, tables=[], readonly_globals={},
        existing_task_only=True, **FLAGS)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
    if (canonical(context) != canonical(expected_context)
            or not isinstance(context['source'], str) or not Path(context['source']).is_absolute()
            or Path(context['source']).name != 'ProjectRED-Win64-Shipping.exe'
            or Path(context['source']).parent.name != package['source_sha256']
            or Path(context['source']).parent.parent.name != 'client-code-snapshots'):
        raise ValueError('Matching-task native context projection differs')
