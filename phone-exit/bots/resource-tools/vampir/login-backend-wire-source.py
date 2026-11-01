"""Validate a frozen, explicit source inventory for the Login backend experiment.

This is source preparation, not a semantic adapter. It neither runs native
scenarios nor adds a publication or runtime admission. All addresses come from
the reviewed JSON recipe or proved child contexts; Markdown is never parsed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SCOPE = 'static_login_backend_wire_preparation'
SHAPES = {'publisher': (43, 214), 'backend': (120, 488),
          'wire.append': (19, 69), 'wire.cleanup': (37, 133)}


def load(name):
    s = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def whole_digest(rows):
    # Includes every instruction and its relative location, including tails and
    # conditional fallthroughs. This exact-SHA recipe grants no cross-SHA reuse.
    base = rows[0]['address']
    return hashlib.sha256(canonical([[r['address']-base, r['bytes']] for r in rows])).hexdigest()


def tools():
    names = ('login-backend-wire-source.py', 'login-state-flow-rules.py',
        'collect-requested-functions.py', 'InspectVampirSdkProfile.java')
    return (load('login-backend-wire-case-contracts').tools()
        | load('update-native-login-send-handoff').select().tools()
        | load('update-native-archive-wire').tools()
        | {str(HERE/n): digest(HERE/n) for n in names})


def fragment(native, image, at, encoded, *, tail_target=None):
    raw = bytes.fromhex(encoded)
    if not raw or len(raw) > 512 or image.containing(at) is not None:
        raise ValueError('Backend fragment extent/unwind boundary differs')
    if load('login-dispatch-rules').data(image, at, len(raw)) != raw:
        raise ValueError('Backend fragment source bytes differ')
    rows = load('login-handler-transfer-rules').decode(native, image, at, len(raw))
    locations = {r['address'] for r in rows}
    if sum(len(bytes.fromhex(r['bytes'])) for r in rows) != len(raw):
        raise ValueError('Backend fragment has an instruction gap')
    for r in rows:
        if r['call']:
            raise ValueError('Backend fragment contains an unreviewed call')
        if r['branch'] and r['direct_target'] not in locations:
            if r is not rows[-1] or tail_target is None or r['mnemonic'] != 'jmp' or r['direct_target'] != tail_target:
                raise ValueError('Backend fragment external branch differs')
    if tail_target is None and rows[-1]['mnemonic'] != 'ret':
        raise ValueError('Backend returning fragment does not return')
    if tail_target is not None and rows[-1]['direct_target'] != tail_target:
        raise ValueError('Backend tail fragment target differs')
    return rows


def checked_export(root, sha, pointer):
    p = Path(pointer['path']).resolve()
    folder = (Path(root)/'ghidra/request-exports'/sha).resolve()
    if not p.is_relative_to(folder) or p.name != 'details.json' or digest(p) != pointer['sha256']:
        raise ValueError('Backend whole export provenance differs')
    value = json.loads(p.read_text('utf-8'))
    if value.get('new_source_sha256', value.get('source_sha256')) != sha:
        raise ValueError('Backend whole export source differs')
    return value


def check_coverage(export, at, rows):
    found = [f for f in export['functions'] if int(f['address'], 16) == at]
    if len(found) != 1:
        raise ValueError('Backend export root missing or ambiguous')
    f = found[0]
    if any(f.get(k) is not True for k in ('decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
        raise ValueError('Backend whole export is incomplete')
    actual = [(int(r['address'], 16), r['bytes'].lower()) for r in f['instructions']]
    wanted = [(r['address'], r['bytes'].lower()) for r in rows]
    if len(actual) != len(set(a for a, _ in actual)) or sorted(actual) != sorted(wanted):
        raise ValueError('Backend whole export instructions differ')
    return f


def verify(recipe, root):
    started = time.perf_counter()
    required = {'schema', 'kind', 'source_sha256', 'source', 'handoff_context', 'wire_context',
        'prepare_check', 'new_functions', 'returning_fragments', 'tail_fragments', 'source_inputs',
        'table_links', 'matrix_sha256', 'matrix_summary', 'limits'}
    if (not isinstance(recipe, dict) or set(recipe) != required or recipe['schema'] != 1
            or type(recipe['schema']) is not int or recipe['kind'] != 'source_recipe_not_native_admission'
            or set(recipe['new_functions']) != set(SHAPES)):
        raise ValueError('Backend source recipe fields/scope differ')
    core, native, bindings = load('portable-native-family'), load('build-native-entry-code'), load('update-bindings')
    root = Path(root)
    index = load('knowledge-index').api()
    store = bindings.SourceStore(index, root)
    image = store.image(native, recipe['source_sha256'])
    source = root/'client-code-snapshots'/recipe['source_sha256']/'ProjectRED-Win64-Shipping.exe'
    if Path(recipe['source']).resolve() != source.resolve():
        raise ValueError('Backend source recipe path differs')
    handoff = core.checked(root, recipe['handoff_context'], 'generated-native-contexts')
    wire = core.checked(root, recipe['wire_context'], 'generated-native-contexts')
    # The checked pointers retain the complete child proof lineage. Validate
    # semantics as already published; no child verifier/native suite is called.
    args = SimpleNamespace(root=root, knowledge=HERE/'knowledge', source_store=store)
    load('update-native-login-send-handoff').select().validate(index, args, handoff)
    load('update-native-archive-wire').validate(index, args, wire)
    if any(c['source_sha256'] != recipe['source_sha256'] or not c.get('transfer_proof') for c in (handoff, wire)):
        raise ValueError('Backend children need same-source proved publications')
    proof = core.checked(root, handoff['transfer_proof'], 'native-login-send-handoff-proofs')
    if proof['dependencies']['prepare_check'] != recipe['prepare_check']:
        raise ValueError('Backend independent prepared expectation differs')
    prepared = load('login-send-handoff-oracle').prepared_rows(
        core.checked(root, recipe['prepare_check'], 'native-adapter-checks'))
    load('login-backend-wire-oracle').validate_schema(wire['packets']['game-login'])
    functions = dict(handoff['functions'])
    functions.update({'wire.'+k: v for k, v in wire['bindings'].items() if k in ('length', 'convert', 'string-writer')})
    functions.update({'wire.archive.'+k: v for k, v in wire['archive'].items() if k not in ('table', 'growth')})
    functions['wire.login-writer'] = wire['packets']['game-login']['writer']
    new_rows, artifacts = {}, {}
    for role, item in recipe['new_functions'].items():
        if set(item) != {'address', 'instruction_count', 'body_bytes', 'instructions_sha256', 'export'}:
            raise ValueError('Backend source function fields differ')
        at = int(item['address'], 16)
        rr = bindings.rows(native, image, at)
        if ((len(rr), sum(len(bytes.fromhex(r['bytes'])) for r in rr)) != SHAPES[role]
                or (item['instruction_count'], item['body_bytes']) != SHAPES[role]
                or whole_digest(rr) != item['instructions_sha256']):
            raise ValueError('Backend source whole shape differs: '+role)
        export = checked_export(root, recipe['source_sha256'], item['export'])
        f = check_coverage(export, at, rr)
        load('audit-launcher-shape-11318').normalize_function(native, image, f)
        functions[role] = item['address']
        new_rows[role] = rr
        artifacts[item['export']['path']] = item['export']['sha256']
    leaves = dict(handoff['leaves'])
    leaves.update({at: item['bytes'] for at, item in wire['archive_leaves'].items()})
    leaves[wire['bindings']['encoder']] = wire['encoder_leaf']['bytes']
    if set(recipe['returning_fragments']) != {'packet_id', 'archive_buffer', 'cleanup_final'}:
        raise ValueError('Backend added returning fragment roles differ')
    for item in recipe['returning_fragments'].values():
        fragment(native, image, int(item['address'], 16), item['bytes'])
        leaves[item['address']] = item['bytes']
    tails = recipe['tail_fragments']
    if set(tails) != {'service', 'cleanup_wrapper', 'cleanup_base'}:
        raise ValueError('Backend tail fragment roles differ')
    for item in tails.values():
        fragment(native, image, int(item['address'], 16), item['bytes'], tail_target=int(item['target'], 16))
    whole = {int(a, 16) for a in functions.values()}
    returning = {int(a, 16) for a in leaves}
    tail_addresses = {int(i['address'], 16) for i in tails.values()}
    if (len(functions) != 29 or len(whole) != 29 or len(leaves) != 13 or len(returning) != 13
            or len(tail_addresses) != 3 or whole & returning or whole & tail_addresses or returning & tail_addresses):
        raise ValueError('Backend exact whole/returning/tail inventory differs')
    for at, raw in leaves.items():
        fragment(native, image, int(at, 16), raw)
    if (tails['service']['target'] != functions['backend']
            or tails['cleanup_wrapper']['target'] != functions['wire.cleanup']
            or tails['cleanup_base']['target'] != recipe['returning_fragments']['cleanup_final']['address']):
        raise ValueError('Backend declared source tail relation differs')
    append = new_rows['wire.append']
    if (append[-1]['mnemonic'], append[-1]['operands'], append[-1]['address']-append[0]['address']) != ('jmp', 'rax', 66):
        raise ValueError('Backend append source virtual tail differs')
    cleanup = new_rows['wire.cleanup']
    if not any(r['mnemonic'] == 'jmp' and r['direct_target'] == int(tails['cleanup_base']['address'], 16) for r in cleanup):
        raise ValueError('Backend cleanup source tail differs')
    wanted_links = [dict(table=wire['archive']['table'], slot=slot, target=wire['archive'][role])
        for slot, role in ((0xc0, 'u32'), (0xd0, 'u16'), (0xd8, 'u16'), (0x88, 'raw'),
            (0x28, 'string'), (0x60, 'u16'), (0xb8, 'u64'), (0xc8, 'u32'), (0xe0, 'u8'), (0xf0, 'bool'))]
    wanted_links.extend((dict(table=wire['packets']['game-login']['table'], slot=0x10, target=functions['wire.login-writer']),
        dict(table=wire['packets']['game-login']['table'], slot=0x28, target=recipe['returning_fragments']['packet_id']['address']),
        dict(table=recipe['source_inputs']['service_primary_table']['address'], slot=0x38, target=tails['service']['address'])))
    if canonical(recipe['table_links']) != canonical(wanted_links):
        raise ValueError('Backend source table relation inventory differs')
    for link in recipe['table_links']:
        value = load('login-dispatch-rules').data(image, int(link['table'], 16)+link['slot'], 8)
        if int.from_bytes(value, 'little') != int(link['target'], 16):
            raise ValueError('Backend source table slot differs')
    if set(recipe['source_inputs']) != {'service_global', 'gate', 'diagnostic_pointer', 'archive_flags', 'archive_table',
            'service_initial_table', 'service_primary_table', 'service_secondary_table', 'cleanup_wrapper_table',
            'cleanup_table', 'cleanup_base_table', 'cleanup_final_table'}:
        raise ValueError('Backend source input inventory differs')
    for item in recipe['source_inputs'].values():
        at = int(item['address'], 16)
        if 'bytes' in item:
            if load('login-dispatch-rules').data(image, at, len(bytes.fromhex(item['bytes']))).hex() != item['bytes']:
                raise ValueError('Backend source data differs')
        elif load('login-state-flow-rules').virtual_span(image, at, item['size_bytes']) != item:
            raise ValueError('Backend zero-fill provider span differs')
    contract = load('login-backend-wire-case-contracts')
    matrix = contract.scenarios()
    if (hashlib.sha256(canonical(matrix)).hexdigest() != recipe['matrix_sha256']
            or contract.summary() != recipe['matrix_summary']):
        raise ValueError('Backend planned matrix differs')
    # Compare expectations without executing or reseeding native code. This is
    # solely a bound for the upcoming initial-growth-only storage fixture.
    oracle = load('login-backend-wire-oracle')
    body_sizes = [len(oracle.login_body(row)) for row in prepared.values()]
    if min(body_sizes) != 91 or max(body_sizes) != 807 or max(body_sizes)+11 >= 1024:
        raise ValueError('Backend prepared byte/allocation bounds changed')
    for role in ('handoff_context', 'wire_context', 'prepare_check'):
        artifacts.update(core.lineage_inputs(args, recipe[role]['path']))
    if any(digest(p) != sha for p, sha in artifacts.items()):
        raise ValueError('Backend evidence changed during source preparation')
    metrics = store.validate()
    return dict(schema=1, scope=SCOPE, method='static', source_sha256=recipe['source_sha256'],
        recipe_sha256=hashlib.sha256(canonical(recipe)).hexdigest(), functions=functions,
        whole_roots=len(whole), returning_leaves=len(returning), tail_fragments=len(tail_addresses),
        planned_matrix=recipe['matrix_summary'], matrix_executed=False,
        body_bytes=dict(minimum=min(body_sizes), maximum=max(body_sizes)),
        parent_native_suites_replayed=0, new_jvm=0, native_executed=False,
        capability_admitted=False, runtime_activated=False, profile_activated=False,
        network_used=False, source_metrics=metrics, artifacts=artifacts,
        duration_seconds=round(time.perf_counter()-started, 6), limits=recipe['limits'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    before = digest(args.recipe)
    tool_inputs = tools()
    report = verify(json.loads(args.recipe.read_text('utf-8')), args.root)
    if digest(args.recipe) != before or tools() != tool_inputs:
        raise ValueError('Backend recipe changed during verification')
    report['recipe_file_sha256'] = before
    report['tools'] = tool_inputs
    path = load('research-workflow').snapshot(args.root, 'login-backend-wire-source-checks', report)
    print(json.dumps(dict(report=str(path), sha256=digest(path), scope=SCOPE, native_executed=False)))
