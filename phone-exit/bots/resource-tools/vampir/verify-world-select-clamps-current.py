"""Execute only the two changed Select110 item readers on bounded inputs."""
import argparse
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/world-select-clamps-current.json'
RECIPE = 'world-select-clamps-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
ROOTS = {
    0x145786e50: (97, ((0x78, 1), (0x50, 8))),
    0x145789880: (8, ((0x80, 1), (0x78, 1), (0x80, 1))),
}


def load(name):
    import importlib.util
    path = HERE / (name + '.py')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    import hashlib
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError('Current Select110 clamp: ' + reason)


def definition(root, context_path):
    context = json.loads(context_path.read_bytes())
    require(context['recipe'] == RECIPE and context['source_sha256'] == SOURCE
            and len(context['exports']) in (1, 2), 'wrong source or export scope')
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    tools = [HERE / (name + '.py') for name in ('native-request-harness-11316', 'build-native-entry-code',
        'extract-native-enums', 'audit-launcher-shape-11318', 'native-publication-v2',
        'research-workflow', 'audit-client-release')]
    runtime = load('native-publication-v2').runtime_files()
    inputs = {str(path.resolve()): digest(path) for path in (Path(__file__), context_path, *tools, *runtime)}
    inputs[str(source)] = SOURCE
    for run, expected in context['exports'].items():
        path = root / 'ghidra/request-exports' / SOURCE / run / 'details.json'
        require(path.resolve().is_relative_to(root / 'ghidra/request-exports' / SOURCE), 'export escaped scope')
        inputs[str(path)] = expected
    return context, dict(recipe=RECIPE, source_sha256=SOURCE, inputs=inputs)


def execute(root, context):
    harness = load('native-request-harness-11316')
    h = harness.make_harness(context['exports'], set(ROOTS), root=root, source_sha256=SOURCE, copy_thunk=None)
    native = load('build-native-entry-code')
    for fragment in h.fragments:
        load('audit-launcher-shape-11318').normalize_function(native, h.image, fragment)
    item, archive, table = (h.scratch + offset for offset in (0x2000, 0x3000, 0x4000))
    machine, x = h.uc, h.x
    machine.mem_write(archive, struct.pack('<Q', table))
    state = {}
    for slot in (0x50, 0x78, 0x80):
        hook = h.scratch + 0x5000 + slot
        def read(uc, slot=slot):
            require(uc.reg_read(x.UC_X86_REG_RCX) == archive, 'archive receiver differs')
            index = state['consumed']
            actual_slot, width = state['slots'][index]
            require(actual_slot == slot, 'archive call order differs')
            state['consumed'] += 1
            if index == state['reject']:
                h.finish(0)
                return
            target = uc.reg_read(x.UC_X86_REG_RDX)
            require(h.scratch <= target <= h.scratch + 0x40000 - width, 'archive target escapes scratch')
            uc.mem_write(target, state['values'][index].to_bytes(width, 'little'))
            h.finish(1)
        h.add_fixture(hook, read)
        machine.mem_write(table + slot, struct.pack('<Q', hook))
    cases = []
    for address, (limit, slots) in ROOTS.items():
        for raw, reject in [(value, None) for value in (0, limit - 1, limit, limit + 1, 255)] + [
                (255, index) for index in range(len(slots))]:
            values = (raw, 0x123456789abcdef0) if len(slots) == 2 else (3, raw, 9)
            state.update(consumed=0, slots=slots, reject=reject, values=values)
            initial = b'\xa5' * 56
            machine.mem_write(item - 16, initial)
            machine.reg_write(x.UC_X86_REG_RDX, archive)
            result = h.call(address, item, budget=150)
            expected = bytearray(initial)
            reads = len(slots) if reject is None else reject
            if len(slots) == 2:
                if reads >= 1:
                    expected[24] = min(raw, limit)
                if reads == 2:
                    struct.pack_into('<Q', expected, 32, values[1])
            else:
                if reads >= 1:
                    expected[24] = values[0]
                if reads >= 2:
                    expected[25] = min(raw, limit)
                if reads == 3:
                    expected[26] = values[2]
            require(result & 0xff == int(reject is None) and
                    state['consumed'] == (len(slots) if reject is None else reject + 1) and
                    bytes(machine.mem_read(item - 16, len(initial))) == bytes(expected),
                    'clamp, early refusal or storage guard differs')
            cases.append(dict(reader=hex(address), raw=raw, rejected_at=reject,
                              limit=limit, passed=True))
    return cases


def verify(*, root=ROOT, context_path=CONTEXT):
    import hashlib
    root = Path(root).resolve()
    context, selected = definition(root, Path(context_path).resolve())
    def barrier():
        require(all(digest(name) == expected for name, expected in selected['inputs'].items()),
                'retained input changed')
    barrier()
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    reused = cache.is_file()
    if reused:
        pointer = json.loads(cache.read_bytes())
        path = root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
        require(path == Path(pointer['path']).resolve() and digest(path) == pointer['sha256'], 'cache changed')
        report = json.loads(path.read_bytes())
    else:
        report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, definition=selected,
            native_execution=True, network_used=False, runtime_admitted=False,
            current_bounds={'player+0x1d8 item+8': 97, 'player+0x250 item+9': 8},
            cases=execute(root, context),
            limits=['Only two whole item readers execute. Archive scalar reads are explicit fixtures.',
                    'Boundary and refusal cases compare writes and canaries; no container or world admission.'])
    require(report['definition'] == selected and report.get('recipe') == RECIPE
            and report.get('source_sha256') == SOURCE and report.get('native_execution') is True
            and report.get('network_used') is False and report.get('runtime_admitted') is False
            and len(report.get('cases', [])) == 15 and all(row['passed'] is True for row in report['cases']),
            'proof boundary differs')
    barrier()
    if not reused:
        path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
        pointer = dict(path=str(path), sha256=digest(path))
        workflow.atomic(cache, workflow.canonical(pointer))
    return dict(report=str(path), sha256=pointer['sha256'], reused=reused)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(root=args.root)))
