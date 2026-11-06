"""Transfer whole Create/JSON paths and their initialized fixture contracts."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/create-producer-current.json'
RECIPE = 'create-producer-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
BASELINE = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def barrier(inputs):
    if any(digest(name) != expected for name, expected in inputs.items()):
        raise ValueError('Create producer retained input changed')


def checked(pointer, root, folder):
    path = Path(pointer['path']).resolve()
    if (path.parent.parent != root / folder or path.name != 'manifest.json'
            or path.parent.name != pointer['sha256'] or digest(path) != pointer['sha256']):
        raise ValueError('Create producer parent proof path or hash differs')
    return json.loads(path.read_bytes())


def definition(context_path, root):
    context_path, root = Path(context_path).resolve(), Path(root).resolve()
    context = json.loads(context_path.read_bytes())
    if (context.get('schema'), context.get('recipe'), context.get('source_sha256'),
            context.get('baseline_sha256')) != (1, RECIPE, SOURCE, BASELINE):
        raise ValueError('Create producer context/source differs')
    if (len(context['roots']) != 15 or len(context['mapping']) != 82
            or set(context['parents']) != {'producer', 'json', 'class_source'}):
        raise ValueError('Create producer explicit root or parent scope differs')
    inputs = {str(path): digest(path) for path in (context_path, Path(__file__).resolve(),
        *(HERE / (name + '.py') for name in ('build-native-entry-code', 'update-bindings',
            'update-native-contexts', 'verify-create-packets-current', 'audit-client-release', 'research-workflow')))}
    parents = {}
    for name, category, count in (('producer', 'release-character-create-producer', 37),
            ('json', 'release-appearance-json-keys', 36), ('class_source', 'release-create-class-source', 144)):
        pointer = context['parents'][name]
        parent = checked(pointer, root, 'code-clues/' + category)
        if (parent['source_sha256'] != BASELINE or parent['native_execution'] is not True
                or parent['network_used'] is not False or len(parent['cases']) != count or not parent['limits']):
            raise ValueError('Create producer inherited proof boundary differs')
        inputs[pointer['path']] = pointer['sha256']
        parents[name] = parent
    for sha in (SOURCE, BASELINE):
        inputs[str(root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe')] = sha
    pointer = context['current_packets']
    if digest(pointer['path']) != pointer['sha256']:
        raise ValueError('Create producer current packet parent changed')
    packets = load('verify-create-packets-current').verify_report(pointer['path'], root=root)
    inputs.update(packets['definition']['inputs'])
    inputs[pointer['path']] = pointer['sha256']
    for run, expected in context['exports'].items():
        path = root / 'ghidra/request-exports' / SOURCE / run / 'details.json'
        if digest(path) != expected or json.loads(path.read_bytes())['new_source_sha256'] != SOURCE:
            raise ValueError('Create producer current whole export differs')
        inputs[str(path)] = expected
    resource = Path(parents['json']['definition_report']).resolve()
    if resource.parent.parent != root / 'code-clues/release-appearance-resources' or digest(resource) != resource.parent.name:
        raise ValueError('Create JSON definition report differs')
    resources = json.loads(resource.read_bytes())
    archive = Path(resources['source']['path']).resolve()
    inputs[str(resource)] = digest(resource)
    inputs[str(archive)] = resources['source']['sha256']
    definitions = {1 if row['package'].endswith('F') else 0:
        {item['group_name']: item['id'] for item in row['groups']} for row in resources['packages']}
    expected = dict(zip(('Height', 'Chest', 'Pelvis', 'Shape', 'Waist', 'Thigh', 'Head'), range(1, 8)))
    if definitions != {0: expected, 1: expected}:
        raise ValueError('Create JSON numeric group definitions differ')
    for package in resources['packages']:
        for field in ('source', 'blob', 'file'):
            # Resource package records are retained by their immutable report;
            # the complete physical archive is hashed at both endpoints.
            if isinstance(package.get(field), dict) and 'path' in package[field] and 'sha256' in package[field]:
                inputs[package[field]['path']] = package[field]['sha256']
    barrier(inputs)
    return context, parents, dict(recipe=RECIPE, source_sha256=SOURCE, inputs=inputs)


def transfer(context, parents, root):
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    signature = load('update-native-contexts').signature
    images = {sha: native.Image((root / 'client-code-snapshots' / sha /
        'ProjectRED-Win64-Shipping.exe').read_bytes()) for sha in (BASELINE, SOURCE)}
    old, new = images[BASELINE], images[SOURCE]
    roots = {int(a, 16): int(b, 16) for a, b in context['roots'].items()}
    expected = {int(a, 16): int(b, 16) for a, b in context['mapping'].items()}
    mapping = {int(a, 16): int(b, 16) for a, b in context['seeds'].items()}
    pairs, visited, tables = [], set(), set()

    def source(image, at, count):
        offset = image.offset(at - image.pe.base)
        value = image.data[offset:offset + count]
        if len(value) != count:
            raise ValueError('Create producer source data bounds differ')
        return value

    def link(a, b):
        if a in mapping and mapping[a] != b:
            raise ValueError('Create producer relocation conflicts')
        mapping[a] = b

    def table(at, slots):
        for slot in slots:
            link(int.from_bytes(source(old, at + slot, 8), 'little'),
                 int.from_bytes(source(new, mapping[at] + slot, 8), 'little'))

    def whole(address, target, *, static_only=False):
        before, after = bindings.rows(native, old, address), bindings.rows(native, new, target)
        if signature(native, before) != signature(native, after):
            raise ValueError('Create producer whole instruction/control flow changed at ' + hex(address))
        locations = {row['address'] for row in before}
        for a, b in zip(before, after):
            if len(a['rip_references']) != len(b['rip_references']):
                raise ValueError('Create producer RIP dependency count differs')
            for left, right in zip(a['rip_references'], b['rip_references']):
                link(left, right)
            if (a['call'] or a['branch']) and a['direct_target'] and a['direct_target'] not in locations:
                link(a['direct_target'], b['direct_target'])
        pairs.append(dict(baseline=hex(address), current=hex(target), instructions=len(before), static_only=static_only))

    for _ in range(32):
        progress = False
        for encoded, slots in context['tables'].items():
            at = int(encoded, 16)
            if at in mapping and at not in tables:
                table(at, slots)
                tables.add(at)
                progress = True
        for at in sorted(roots.keys() & mapping.keys() - visited):
            if mapping[at] != roots[at]:
                raise ValueError('Create producer root binding differs')
            whole(at, mapping[at], static_only=at == 0x1414ae540)
            visited.add(at)
            progress = True
        if not progress:
            break
    if visited != roots.keys() or mapping != expected or len(tables) != 2:
        raise ValueError('Create producer root/table relocation closure differs')
    for encoded, raw in context['constants'].items():
        at, raw = int(encoded, 16), bytes.fromhex(raw)
        if source(old, at, len(raw)) != raw or source(new, mapping[at], len(raw)) != raw:
            raise ValueError('Create producer literal/sentinel/dispatch value changed')
    for encoded, raw in context['leaves'].items():
        at, raw = int(encoded, 16), bytes.fromhex(raw)
        if source(old, at, len(raw)) != raw or source(new, mapping[at], len(raw)) != raw:
            raise ValueError('Create number-text leaf changed')
    # Numeric value wrappers dispatch through this table. Validate every
    # consumed slot, including the integer getter outside the old root list.
    numeric = int(context['numeric_table'], 16)
    numeric_methods = []
    for slot in context['numeric_slots']:
        a = int.from_bytes(source(old, numeric + slot, 8), 'little')
        b = int.from_bytes(source(new, mapping[numeric] + slot, 8), 'little')
        link(a, b)
        try:
            whole(a, b, static_only=True)
        except ValueError as error:
            if str(error) != 'Binding is not an explicit unwind root':
                raise
            # Tiny ABI leaves have no PE unwind row. They must terminate
            # linearly, contain no calls/jumps/RIP data, and match in full.
            decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
            decoder.detail = True
            found = []
            for ins in decoder.disasm(source(old, a, 32), a):
                found.append(ins)
                if ins.mnemonic == 'ret':
                    break
                if ins.mnemonic == 'jmp' and hex(a) in context['numeric_tail_forwarders']:
                    break
                if (ins.group(native.capstone.CS_GRP_CALL) or ins.group(native.capstone.CS_GRP_JUMP)
                        or any(op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP for op in ins.operands)):
                    raise ValueError('Create numeric leaf is not closed at ' + hex(a) + ': ' + ins.mnemonic + ' ' + ins.op_str)
            if not found or found[-1].mnemonic not in ('ret', 'jmp'):
                raise ValueError('Create numeric leaf did not terminate')
            count = sum(ins.size for ins in found)
            if found[-1].mnemonic == 'jmp' and source(old, a, count).hex() != context['numeric_tail_forwarders'][hex(a)]:
                raise ValueError('Create numeric virtual tail differs')
            if source(old, a, count) != source(new, b, count):
                raise ValueError('Create numeric leaf bytes differ')
        numeric_methods.append(dict(slot=slot, baseline=hex(a), current=hex(b)))
    if parents['producer']['sentinel'] != 0 or sum(row['dispatched'] for row in parents['producer']['cases']) != 13:
        raise ValueError('Create producer inherited case outcomes differ')
    return dict(pairs=pairs, core_roots=15, core_relocations=82,
        numeric_methods=numeric_methods, leaf_count=4, tables=3,
        relocations={hex(a): hex(b) for a, b in sorted(mapping.items())},
        inherited_cases=dict(producer=37, json=36, class_source=144),
        source_ui_constructor_verified=True, initialized_numeric_context_only=True)


def verify(*, root=ROOT, context_path=CONTEXT):
    root = Path(root).resolve()
    context, parents, selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        report = checked(pointer, root, 'code-clues/' + RECIPE)
        if (report.get('definition') != selected or report.get('native_execution') is not False
                or report.get('native_proofs_reused') is not True or report.get('core_roots') != 15):
            raise ValueError('Create producer cached scope differs')
        return dict(report=pointer['path'], sha256=pointer['sha256'], reused=True)
    result = transfer(context, parents, root)
    barrier(selected['inputs'])
    report = dict(recipe=RECIPE, source_sha256=SOURCE, baseline_sha256=BASELINE,
        definition=selected, method='source_transfer', native_execution=False,
        native_proofs_reused=True, runtime_admitted=False, network_used=False, **result,
        limits=['Whole initialized producer/JSON/number paths and raw class getter transfer with consistent source relocations.',
                '37 producer, 36 JSON and 144 class-source constructor/getter scenarios are inherited.',
                'History construction and all engine/UI/culture/rules/storage/JSON setters/writer/free effects retain fixtures.',
                'Cold formatter initialization callbacks and low-refcount destructors remain unexecuted.',
                'Numeric keys use explicit Latin or Arabic rules and current unchanged BoneGroup data; native JSON bytes are not claimed.',
                'The owner constructor retains UI-provider fixtures; no loaded asset, full game engine, creation admission or online Create proof.'])
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    pointer = dict(path=str(path), sha256=digest(path))
    workflow.atomic(cache, workflow.canonical(pointer))
    return dict(report=str(path), sha256=pointer['sha256'], reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
