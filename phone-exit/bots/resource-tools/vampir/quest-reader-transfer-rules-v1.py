"""Reviewed static QuestSync/Tutorial reader closure; never packet admission.

The seven INPUT roots arrive from the finished seed. This rule checks the
remaining roots, declared leaves, pointer tables and fixture entry boundaries.
Fixture bodies and target packet effects require a separate semantic recipe.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
POLICY = HERE / 'knowledge/quest-reader-transfer-rules.json'
RECIPE = 'quest-reader-transfer-rules-v1'
COUNTS = dict(seed_roots=7, transferred_roots=15, total_roots=22)
FLAGS = dict(native_consumer_verified=False, consumer_semantic_verified=False, target_exports_verified=False,
             runtime_activated=False, profile_activated=False)
ROLE_MAP = dict(input_constructor='constructor', input_buffer_constructor='buffer_constructor',
                input_u16='u16', input_u32='u32', input_u64='u64', input_bool='bool', input_raw='raw')
SHA = re.compile('[0-9a-f]{64}')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def tools():
    names = ('update-native-version-result', 'update-native-archive-wire', 'update-native-contexts',
             'update-bindings', 'login-input-transfer-rules', 'version-system-transfer-rules',
             'build-native-entry-code', 'build-object-zero-init-code', 'extract-native-enums')
    return {str(p): digest(p) for p in (Path(__file__).resolve(), POLICY,
            *(HERE / (name + '.py') for name in names))}


def address(value):
    if not isinstance(value, str) or not re.fullmatch('0x[0-9a-f]+', value):
        raise ValueError('Quest reader address is not canonical')
    return int(value, 16)


def policy():
    raw = POLICY.read_bytes()
    if len(raw) > 256 * 1024: raise ValueError('Quest reader reviewed rule budget exceeded')
    value = json.loads(raw)
    if (set(value) != {'schema', 'recipe', 'baseline_source_sha256', 'consumers', 'roots',
                      'leaves', 'tables', 'packets', 'boundaries'} or value['schema'] != 1
            or type(value['schema']) is not int or value['recipe'] != RECIPE
            or set(value['consumers']) != {'quest-sync', 'tutorial-update'}
            or len(value['roots']) != 15 or len(value['leaves']) != 9 or len(value['tables']) != 13):
        raise ValueError('Quest reader reviewed rule shape differs')
    return value


def document(index, pointer):
    if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
            or not isinstance(pointer['sha256'], str) or not SHA.fullmatch(pointer['sha256'])
            or index.digest(pointer['path']) != pointer['sha256']):
        raise ValueError('Quest reader selected context SHA differs')
    raw = Path(pointer['path']).read_bytes()
    if len(raw) > 32 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != pointer['sha256']:
        raise ValueError('Quest reader selected context changed or exceeds budget')
    return json.loads(raw)


def check_policy(rows, at, spec):
    calls = {str(row['address'] - at): hex(row['direct_target']) if row['direct_target'] is not None
             else row['operands'] for row in rows if row['call']}
    data = {str(row['address'] - at): [hex(ref) for ref in row['rip_references']]
            for row in rows if row['rip_references']}
    if calls != spec['calls']: raise ValueError('Quest reader reviewed call-site policy differs: ' + hex(at))
    if data != spec['data']: raise ValueError('Quest reader undeclared RIP data: ' + hex(at))


def exact_leaf_hits(image, at, raw):
    hits = []
    for section in image.pe.sections:
        if section['name'] != '.text': continue
        first = max(section['rva'], at - image.pe.base - 65536)
        last = min(section['rva'] + section['raw_size'] - len(raw), at - image.pe.base + 65536)
        if last < first: continue
        cursor, stop = image.offset(first), image.offset(last) + len(raw)
        while cursor < stop:
            found = image.data.find(raw, cursor, stop)
            if found < 0: break
            hits.append(image.pe.base + section['rva'] + found - section['raw']); cursor = found + 1
            if len(hits) > 32: raise ValueError('Quest packet ID candidate budget exceeded')
    return hits


def anchor_packets(api, common, before, after, reviewed, mapping):
    for name, spec in reviewed['packets'].items():
        old = address(spec['id_getter']); raw = b'\xb8' + struct.pack('<I', spec['id']) + b'\xc3'
        if api.image_bytes(before, old, len(raw)) != raw:
            raise ValueError('Quest packet ID baseline differs: ' + name)
        hits = exact_leaf_hits(after, old, raw)
        if len(hits) != 1: raise ValueError('Quest packet ID missing or ambiguous: ' + name)
        common.add_link(mapping, old, hits[0]); table = address(spec['table'])
        hits = api.table_candidates(after, table, mapping[old], 0x28, 0x30)
        if len(hits) != 1: raise ValueError('Quest packet ID-linked table missing or ambiguous: ' + name)
        common.add_link(mapping, table, hits[0])
        reader = struct.unpack('<Q', api.image_bytes(after, hits[0] + 0x20, 8))[0]
        common.add_link(mapping, address(spec['reader']), reader)


def resolve_roots(native, bindings, api, common, before, after, roots, mapping):
    rows = {at: bindings.rows(native, before, at) for at in sorted(roots)}
    choices = {at: api.candidates(native, bindings, before, after, at) for at in rows}
    pending, reports = set(rows), []
    while pending:
        progress = False
        for at in sorted(pending):
            hits = []
            for target in choices[at]:
                if at in mapping and mapping[at] != target: continue
                local = dict(mapping)
                try:
                    common.add_link(local, at, target)
                    common.pair_rows(native, rows[at], bindings.rows(native, after, target), local)
                except ValueError: continue
                hits.append((target, local))
            if len(hits) != 1: continue
            target, local = hits[0]; mapping.clear(); mapping.update(local)
            reports.append(dict(baseline=hex(at), target=hex(target), candidates=len(choices[at])))
            pending.remove(at); progress = True
        if not progress:
            raise ValueError('Quest reader ambiguous call-constrained roots: ' + ','.join(hex(at) for at in sorted(pending)))
    return reports


def check_boundary(native, bindings, before, after, old, target):
    # Only the callable entry is proved. Its allocator/cleanup body is a fixture.
    for image, at in ((before, old), (after, target)):
        part = image.containing(at)
        if part is None or image.roots[part][0] + image.pe.base != at:
            raise ValueError('Quest fixture is not an exact unwind entry: ' + hex(at))
    return dict(baseline=hex(old), target=hex(target), kind='exact-unwind-entry',
                body_verified=False)


def check_table(api, before, after, spec, mapping):
    old = address(spec['baseline']); target = mapping.get(old)
    if target is None: raise ValueError('Quest table has no caller or seed linkage: ' + hex(old))
    a = bytes.fromhex(spec['bytes']); b = api.image_bytes(after, target, len(a))
    if not a or len(a) % 8 or len(a) > 152 or api.image_bytes(before, old, len(a)) != a:
        raise ValueError('Quest baseline table bytes differ')
    av = struct.unpack('<' + 'Q' * (len(a) // 8), a); bv = struct.unpack('<' + 'Q' * (len(b) // 8), b)
    if any((av[i] == av[j]) != (bv[i] == bv[j]) for i in range(len(av)) for j in range(i)):
        raise ValueError('Quest table alias partition differs')
    for slot, text in spec['used'].items():
        offset = address(slot); value = address(text)
        if offset % 8 or offset + 8 > len(a) or av[offset // 8] != value or mapping.get(value) != bv[offset // 8]:
            raise ValueError('Quest table used role differs: ' + hex(old) + '+' + slot)
    common = load('update-native-archive-wire')
    for old_value, value in zip(av, bv): common.add_link(mapping, old_value, value)
    return dict(baseline=hex(old), target=hex(target), kind=spec['kind'],
        baseline_bytes=a.hex(), bytes=b.hex(), sha256=hashlib.sha256(b).hexdigest(),
        used={slot: hex(mapping[address(value)]) for slot, value in spec['used'].items()},
        excluded_slots=[hex(slot) for slot in range(0, len(a), 8) if hex(slot) not in spec['used']],
        unselected_bodies_verified=False)


def export_coverage(index, args, context, native, bindings, image):
    wanted = {address(text) for text in context['functions'].values()}; available = set()
    for run, expected in context.get('exports', {}).items():
        if not isinstance(run, str) or Path(run).name != run or not run.startswith('run-'):
            raise ValueError('Quest consumer export name differs')
        path = Path(args.root) / 'ghidra/request-exports' / context['source_sha256'] / run / 'details.json'
        if index.digest(path) != expected: raise ValueError('Quest baseline export SHA differs')
        raw = path.read_bytes()
        if len(raw) > 32 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Quest baseline export changed or exceeds budget')
        report = json.loads(raw)
        if report.get('new_source_sha256', report.get('source_sha256')) != context['source_sha256']:
            raise ValueError('Quest baseline export source differs')
        for function in report.get('functions', []):
            at = address(function['address'])
            if at not in wanted or function.get('decompilation_completed') is not True: continue
            actual = {(address(row['address']), row['bytes'].lower()) for row in function.get('instructions', [])}
            needed = {(row['address'], row['bytes'].lower()) for row in bindings.rows(native, image, at)}
            if needed <= actual: available.add(at)
    if available != wanted: raise ValueError('Quest baseline whole export coverage missing: ' + ','.join(hex(at) for at in sorted(wanted - available)))


def transfer(index, args, seed_proof):
    reviewed = policy(); inputs = seed_proof['inputs']
    oldsha = inputs['baseline']['source_sha256']; sha = inputs['target']['source_sha256']
    if oldsha != reviewed['baseline_source_sha256'] or oldsha == sha:
        raise ValueError('Quest reader reviewed baseline source differs')
    baseline = document(index, inputs['baseline']['context']); current = document(index, inputs['target']['context'])
    if baseline['source_sha256'] != oldsha or current['source_sha256'] != sha:
        raise ValueError('Quest reader seed VersionResult source differs')
    contexts = {}
    for name, item in reviewed['consumers'].items():
        pointer = inputs['consumers'][name]
        if pointer['sha256'] != item['context_sha256']: raise ValueError('Quest consumer reviewed context differs')
        context = document(index, pointer)
        if context['source_sha256'] != oldsha or any(context.get(k) != item[k] for k in ('functions', 'leaves', 'bindings')):
            raise ValueError('Quest consumer baseline roles differ')
        contexts[name] = context
    mapping = {}; common = load('update-native-archive-wire'); native = load('build-native-entry-code')
    bindings = load('update-bindings'); api = load('update-native-version-result'); leaves_api = load('login-input-transfer-rules')
    before = args.source_store.image(native, oldsha); after = args.source_store.image(native, sha)
    for context in contexts.values(): export_coverage(index, args, context, native, bindings, before)
    oldinput, newinput = baseline['native_input'], current['native_input']
    pairs = {item['role']: item for item in seed_proof['mappings']}
    if len(seed_proof['mappings']) != 7 or set(pairs) != set(ROLE_MAP.values()):
        raise ValueError('Quest reader requires seven finished seed mappings')
    for role, input_role in ROLE_MAP.items():
        old = address(oldinput['functions'][input_role]); target = address(newinput['functions'][input_role])
        if (pairs[input_role]['baseline'], pairs[input_role]['target']) != (hex(old), hex(target)) or any(
                address(context['functions'][role]) != old for context in contexts.values()):
            raise ValueError('Quest reader seed role/source linkage differs')
        common.add_link(mapping, old, target)
    seed_mapping = {address(a): address(b) for a, b in seed_proof['transfer_relation']['mapping'].items()}
    oldtable, newtable = address(oldinput['table']), address(newinput['table'])
    if (seed_mapping.get(oldtable) != newtable or oldinput['table_bytes'] != reviewed['tables'][hex(oldtable)]['bytes']
            or api.image_bytes(after, newtable, 152).hex() != newinput['table_bytes']):
        raise ValueError('Quest reader seed INPUT table differs')
    common.add_link(mapping, oldtable, newtable)
    av = struct.unpack('<19Q', bytes.fromhex(oldinput['table_bytes'])); bv = struct.unpack('<19Q', bytes.fromhex(newinput['table_bytes']))
    for old, target in zip(av, bv):
        if seed_mapping.get(old) != target: raise ValueError('Quest seed INPUT pointer identity differs')
        common.add_link(mapping, old, target)
    for old, spec in oldinput['leaves'].items():
        target = seed_mapping.get(address(old)); target_spec = newinput['leaves'].get(hex(target)) if target else None
        if target_spec is None or spec['bytes'] != reviewed['leaves'][old]['bytes']:
            raise ValueError('Quest reader seed leaf scope differs')
        common.add_link(mapping, address(old), target)
        if api.image_bytes(after, target, len(bytes.fromhex(target_spec['bytes']))).hex() != target_spec['bytes']:
            raise ValueError('Quest reader seed target leaf bytes differ')
    anchor_packets(api, common, before, after, reviewed, mapping)
    roots = {address(at) for at in reviewed['roots']}
    reports = resolve_roots(native, bindings, api, common, before, after, roots, mapping)
    for item in reports:
        at = address(item['baseline']); spec = reviewed['roots'][hex(at)]
        oldrows = bindings.rows(native, before, at); check_policy(oldrows, at, spec)
        newrows = bindings.rows(native, after, mapping[at]); common.pair_rows(native, oldrows, newrows, mapping)
        item.update(roles=spec['roles'], calls=copy.deepcopy(spec['calls']), data=copy.deepcopy(spec['data']),
                    whole_instruction_shape_verified=True)
    leaf_reports = []
    for text, spec in reviewed['leaves'].items():
        at = address(text); raw = bytes.fromhex(spec['bytes'])
        if at not in mapping: raise ValueError('Quest leaf lacks caller/table/seed linkage: ' + text)
        if api.image_bytes(before, at, len(raw)) != raw: raise ValueError('Quest baseline leaf bytes differ')
        oldrows = leaves_api.leaf_rows(native, before, at, raw)
        if {str(r['address'] - at): [hex(x) for x in r['rip_references']] for r in oldrows if r['rip_references']} != spec['data']:
            raise ValueError('Quest leaf has undeclared data')
        newrows = leaves_api.leaf_rows(native, after, mapping[at], raw)
        leaves_api.pair_leaf(native, oldrows, newrows, mapping)
        actual = api.image_bytes(after, mapping[at], len(raw))
        leaf_reports.append(dict(baseline=text, target=hex(mapping[at]), baseline_bytes=raw.hex(),
            bytes=actual.hex(), sha256=hashlib.sha256(actual).hexdigest(), data=copy.deepcopy(spec['data']),
            kind='exact-virtual-tail' if raw in (leaves_api.DISPATCH, leaves_api.BYTE_DISPATCH) else 'returning-leaf'))
    tables = []
    for text, spec in reviewed['tables'].items():
        old = address(text)
        if old not in mapping: raise ValueError('Quest table lacks explicit caller linkage: ' + text)
        # Descriptor slots can introduce a fixture entry (Tutorial reserve).
        for slot, value in spec['used'].items():
            target = struct.unpack('<Q', api.image_bytes(after, mapping[old] + address(slot), 8))[0]
            common.add_link(mapping, address(value), target)
        tables.append(check_table(api, before, after, dict(spec, baseline=text), mapping))
    boundaries = []
    for name, roles in reviewed['boundaries'].items():
        for role, text in roles.items():
            old = address(text)
            if old not in mapping: raise ValueError('Quest fixture lacks declared caller/descriptor linkage')
            item = check_boundary(native, bindings, before, after, old, mapping[old])
            item.update(consumer=name, role=role); boundaries.append(item)
    memcpy_old, memcpy_new = address(baseline['helpers']['memcpy']), address(current['helpers']['memcpy'])
    if seed_mapping.get(memcpy_old) != memcpy_new: raise ValueError('Quest memcpy seed identity differs')
    load('update-native-contexts').memcpy_identity(native, before, memcpy_old)
    load('update-native-contexts').memcpy_identity(native, after, memcpy_new)
    common.add_link(mapping, memcpy_old, memcpy_new)
    boundaries.append(dict(consumer='shared-input', role='memcpy', baseline=hex(memcpy_old), target=hex(memcpy_new),
        kind='import-thunk', identity=dict(dll='VCRUNTIME140.dll', name='memcpy'), body_verified=False))
    target_contexts = {}
    for name, context in contexts.items():
        target_contexts[name] = dict(source_sha256=sha,
            source=str(Path(args.root) / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'),
            functions={role: hex(mapping[address(text)]) for role, text in context['functions'].items()},
            leaves={hex(mapping[address(text)]): api.image_bytes(after, mapping[address(text)], len(bytes.fromhex(raw))).hex()
                    for text, raw in context['leaves'].items()},
            bindings=[[hex(mapping[address(table)]), slot, hex(mapping[address(target)])] for table, slot, target in context['bindings']],
            fixtures={role: hex(mapping[address(text)]) for role, text in reviewed['boundaries'][name].items()},
            consumer_semantic_verified=False)
    return dict(schema=1, recipe=RECIPE, method='static', baseline_source_sha256=oldsha, target_source_sha256=sha,
        counts=copy.deepcopy(COUNTS), target_contexts=target_contexts,
        relation=dict(mapping={hex(a): hex(b) for a, b in sorted(mapping.items())},
            rootchecks=sorted(reports, key=lambda r: address(r['baseline'])), leaves=leaf_reports,
            tables=tables, boundaries=boundaries), **FLAGS)


def validate_package(package, inputs):
    reviewed = policy()
    expected = {'schema', 'recipe', 'method', 'baseline_source_sha256', 'target_source_sha256',
                'counts', 'target_contexts', 'relation', *FLAGS}
    if (not isinstance(package, dict) or set(package) != expected or type(package['schema']) is not int
            or package['schema'] != 1 or package['recipe'] != RECIPE or package['method'] != 'static'
            or package['counts'] != COUNTS or any(package.get(k) is not False for k in FLAGS)
            or package['baseline_source_sha256'] != reviewed['baseline_source_sha256']
            or package['baseline_source_sha256'] != inputs['baseline_source_sha256']
            or package['target_source_sha256'] != inputs['target_source_sha256']):
        raise ValueError('Quest static package scope or admission differs')
    for name, spec in reviewed['consumers'].items():
        if inputs['consumers'][name]['sha256'] != spec['context_sha256']:
            raise ValueError('Quest static package consumer source differs')
    relation = package['relation']
    if set(relation) != {'mapping', 'rootchecks', 'leaves', 'tables', 'boundaries'}:
        raise ValueError('Quest static relation fields differ')
    mapping = {address(a): address(b) for a, b in relation['mapping'].items()}
    if not 22 <= len(mapping) <= 4096: raise ValueError('Quest static mapping budget differs')
    def mapped(text):
        if address(text) not in mapping: raise ValueError('Quest static role lacks mapping: ' + text)
        return hex(mapping[address(text)])
    roots = {text for c in reviewed['consumers'].values() for text in c['functions'].values()}
    if len({mapped(text) for text in roots}) != 22: raise ValueError('Quest static roots alias or lack coverage')
    source_leaves = set(reviewed['leaves'])
    if roots & source_leaves or {mapped(text) for text in roots} & {mapped(text) for text in source_leaves}:
        raise ValueError('Quest static roots and leaves alias')
    if len({mapped(text) for text in source_leaves}) != len(source_leaves):
        raise ValueError('Quest static leaf identities alias')
    reports = {r['baseline']: r for r in relation['rootchecks']}
    if len(reports) != 15 or len(relation['rootchecks']) != 15 or set(reports) != set(reviewed['roots']):
        raise ValueError('Quest static whole-root coverage differs')
    for text, spec in reviewed['roots'].items():
        item = reports[text]
        if (set(item) != {'baseline', 'target', 'candidates', 'roles', 'calls', 'data', 'whole_instruction_shape_verified'}
                or item['target'] != mapped(text) or type(item['candidates']) is not int or not 1 <= item['candidates'] <= 32
                or item['roles'] != spec['roles'] or item['calls'] != spec['calls'] or item['data'] != spec['data']
                or item['whole_instruction_shape_verified'] is not True):
            raise ValueError('Quest static whole-root policy differs')
    leaves = {r['baseline']: r for r in relation['leaves']}
    if len(leaves) != 9 or len(relation['leaves']) != 9 or set(leaves) != set(reviewed['leaves']):
        raise ValueError('Quest static leaf coverage differs')
    for text, spec in reviewed['leaves'].items():
        item = leaves[text]; raw = bytes.fromhex(item['bytes'])
        kind = 'exact-virtual-tail' if spec['bytes'] in ('488b024c8bc2488bd1498bc848ff6020', '488b0141b80100000048ffa090000000') else 'returning-leaf'
        if (set(item) != {'baseline', 'target', 'baseline_bytes', 'bytes', 'sha256', 'data', 'kind'}
                or item['target'] != mapped(text) or item['baseline_bytes'] != spec['bytes']
                or len(raw) != len(bytes.fromhex(spec['bytes'])) or hashlib.sha256(raw).hexdigest() != item['sha256']
                or any(raw[i] != value for i, value in enumerate(bytes.fromhex(spec['bytes']))
                       if i not in spec['relocation_bytes'])
                or item['data'] != spec['data'] or item['kind'] != kind
                or (kind == 'exact-virtual-tail' and item['bytes'] != spec['bytes'])):
            raise ValueError('Quest static leaf policy differs')
    tables = {r['baseline']: r for r in relation['tables']}
    if len(tables) != 13 or len(relation['tables']) != 13 or set(tables) != set(reviewed['tables']):
        raise ValueError('Quest static table coverage differs')
    for text, spec in reviewed['tables'].items():
        item = tables[text]; a = bytes.fromhex(spec['bytes']); b = bytes.fromhex(item['bytes'])
        if (set(item) != {'baseline', 'target', 'kind', 'baseline_bytes', 'bytes', 'sha256', 'used', 'excluded_slots', 'unselected_bodies_verified'}
                or item['target'] != mapped(text) or item['kind'] != spec['kind'] or item['baseline_bytes'] != spec['bytes']
                or len(b) != len(a) or hashlib.sha256(b).hexdigest() != item['sha256']
                or item['used'] != {slot: mapped(value) for slot, value in spec['used'].items()}
                or item['excluded_slots'] != [hex(slot) for slot in range(0, len(a), 8) if hex(slot) not in spec['used']]
                or item['unselected_bodies_verified'] is not False):
            raise ValueError('Quest static table policy differs')
        av = struct.unpack('<' + 'Q' * (len(a) // 8), a); bv = struct.unpack('<' + 'Q' * (len(b) // 8), b)
        if any(mapping.get(old) != target for old, target in zip(av, bv)) or any(
                (av[i] == av[j]) != (bv[i] == bv[j]) for i in range(len(av)) for j in range(i)):
            raise ValueError('Quest static table pointer/alias identity differs')
    boundaries = {(r['consumer'], r['role']): r for r in relation['boundaries']}
    wanted = {(name, role) for name, roles in reviewed['boundaries'].items() for role in roles} | {('shared-input', 'memcpy')}
    if set(boundaries) != wanted or len(boundaries) != len(relation['boundaries']):
        raise ValueError('Quest static fixture boundary coverage differs')
    for (name, role), item in boundaries.items():
        text = item['baseline'] if name == 'shared-input' else reviewed['boundaries'][name][role]
        keys = {'consumer', 'role', 'baseline', 'target', 'kind', 'body_verified'} | ({'identity'} if name == 'shared-input' else set())
        if (set(item) != keys or item['baseline'] != text or item['target'] != mapped(text) or item['body_verified'] is not False
                or item['kind'] != ('import-thunk' if name == 'shared-input' else 'exact-unwind-entry')
                or (name == 'shared-input' and item['identity'] != {'dll': 'VCRUNTIME140.dll', 'name': 'memcpy'})):
            raise ValueError('Quest static fixture boundary scope differs')
    boundary_rows = list(boundaries.values())
    occupied = {mapped(text) for text in roots | source_leaves}
    if any(item['target'] in occupied for item in boundary_rows) or any(
            (a['baseline'] == b['baseline']) != (a['target'] == b['target'])
            for i, a in enumerate(boundary_rows) for b in boundary_rows[:i]):
        raise ValueError('Quest fixture boundary aliases executed code or changes identity partition')
    if set(package['target_contexts']) != set(reviewed['consumers']): raise ValueError('Quest target consumer scope differs')
    for name, spec in reviewed['consumers'].items():
        context = package['target_contexts'][name]
        if (set(context) != {'source_sha256', 'source', 'functions', 'leaves', 'bindings', 'fixtures', 'consumer_semantic_verified'}
                or context['source_sha256'] != inputs['target_source_sha256'] or context['consumer_semantic_verified'] is not False
                or Path(context['source']).name != 'ProjectRED-Win64-Shipping.exe'
                or Path(context['source']).parent.name != inputs['target_source_sha256']
                or context['functions'] != {role: mapped(text) for role, text in spec['functions'].items()}
                or context['leaves'] != {mapped(text): leaves[text]['bytes'] for text in spec['leaves']}
                or context['bindings'] != [[mapped(table), slot, mapped(target)] for table, slot, target in spec['bindings']]
                or context['fixtures'] != {role: mapped(text) for role, text in reviewed['boundaries'][name].items()}):
            raise ValueError('Quest target context projection differs')
