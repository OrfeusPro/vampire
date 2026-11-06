"""Compare the changed Select110 Block2B8 constructor on guarded allocations."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
CONTEXT = HERE / 'knowledge/native-contexts/world-player-constructor-current.json'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
BASELINE = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
RECIPE = 'world-player-constructor-current-v1'
POINTER_FIELDS = (0, 0x28, 0x48)
ZERO_FIELDS = ((8, 0x24), (0x30, 0x41), (0x50, 0x59))
PADDING = ((0x24, 0x28), (0x41, 0x48), (0x59, 0x60))


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
        raise ValueError('Current world player constructor ' + message)


def barrier(inputs):
    require(all(digest(path) == sha for path, sha in inputs.items()), 'retained input changed')


def definition(context_path, root):
    context_path = Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    require((context.get('schema'), context.get('recipe'), context.get('source_sha256'), context.get('baseline_sha256'))
            == (1, RECIPE, SOURCE, BASELINE), 'context/source differs')
    require((context.get('constructor'), context.get('baseline_constructor'), context.get('time_constructor'),
             context.get('baseline_time_constructor')) == ('0x145799d00', '0x145789c10', '0x1457a38c0', '0x1457eca60'),
            'root roles differ')
    inputs = {str(context_path): digest(context_path), str(Path(__file__).resolve()): digest(__file__)}
    pointer = context['baseline_proof']
    path = Path(pointer['path']).resolve()
    require(path == root / 'code-clues/character-select-result-replay.json' and digest(path) == pointer['sha256'],
            'baseline semantic proof changed')
    baseline = json.loads(path.read_bytes())
    require(baseline.get('sha256') == BASELINE and baseline.get('native_execution') is True
            and baseline.get('network_ready') is False and len(baseline.get('cases', [])) == 256,
            'baseline semantic proof scope differs')
    inputs[str(path)] = pointer['sha256']
    for sha in (SOURCE, BASELINE):
        inputs[str(root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe')] = sha
    for run, sha in context['exports'].items():
        inputs[str(root / 'ghidra/request-exports' / SOURCE / run / 'details.json')] = sha
    for name in ('build-native-entry-code', 'extract-native-enums', 'audit-launcher-shape-11318',
                 'audit-client-release', 'research-workflow', 'update-native-harness', 'native-publication-v2'):
        path = HERE / (name + '.py')
        inputs[str(path)] = digest(path)
    for path in load('native-publication-v2').runtime_files():
        inputs[str(path)] = digest(path)
    barrier(inputs)
    return context, baseline, dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, baseline_sha256=BASELINE,
        inputs=inputs, runtime=load('update-native-harness').runtime_inputs())


def execute(context, baseline_proof, root):
    native = load('build-native-entry-code')
    sys.path.insert(0, str(HERE.parents[2] / '.tools/vampir-analysis'))
    import unicorn
    from unicorn import x86_const as x
    require(unicorn.__version__ == '2.1.4' and native.capstone.__version__ == '5.0.6', 'native runtime differs')
    images = {}
    for sha in (BASELINE, SOURCE):
        raw = (root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').read_bytes()
        images[sha] = (raw, native.Image(raw))
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    fragments = {BASELINE: [], SOURCE: []}

    def checked_code(sha, address, data):
        raw, image = images[sha]
        off = image.offset(address - image.pe.base)
        require(raw[off:off + len(data)] == data, 'code differs from source')
        rows = list(decoder.disasm(data, address))
        require(sum(row.size for row in rows) == len(data) and rows[-1].mnemonic == 'ret', 'code gap or missing return')
        fragments[sha].append(dict(address=hex(address), bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(),
                                   instruction_count=len(rows)))
        return rows

    old_root = next(row for row in baseline_proof['ranges'] if row['start'] == context['baseline_constructor'])
    old_at, old_end = int(old_root['start'], 16), int(old_root['end_exclusive'], 16)
    old_raw, old_image = images[BASELINE]
    old_data = old_raw[old_root['file_offset']:old_root['file_offset'] + old_end - old_at]
    require(hashlib.sha256(old_data).hexdigest() == old_root['sha256'], 'baseline constructor range changed')
    old_rows = checked_code(BASELINE, old_at, old_data)
    require(len(old_rows) == 22 and old_image.pe.base + old_image.roots[old_image.containing(old_at)][1] == old_end,
            'baseline constructor whole range differs')
    old_time = int(context['baseline_time_constructor'], 16)
    old_time_off = old_image.offset(old_time - old_image.pe.base)
    old_time_rows = []
    for row in decoder.disasm(old_raw[old_time_off:old_time_off + 64], old_time):
        require(row.mnemonic in ('lea', 'mov', 'ret'), 'baseline time leaf gained side effects')
        old_time_rows.append(row)
        if row.mnemonic == 'ret':
            break
    require(old_time_rows[-1].mnemonic == 'ret' and len(old_time_rows) == 5, 'baseline time leaf is unbounded')
    checked_code(BASELINE, old_time, b''.join(bytes(row.bytes) for row in old_time_rows))

    current_raw, current_image = images[SOURCE]
    current_functions = {}
    for run in context['exports']:
        report = json.loads((root / 'ghidra/request-exports' / SOURCE / run / 'details.json').read_bytes())
        require(report['new_source_sha256'] == SOURCE, 'export source differs')
        current_functions.update({row['address']: row for row in report['functions']})
    for role in ('constructor', 'time_constructor'):
        function = current_functions[context[role]]
        require(function['decompilation_completed'] is True, 'current export incomplete')
        load('audit-launcher-shape-11318').normalize_function(native, current_image, function)
        code = b''.join(bytes.fromhex(row['bytes']) for row in function['instructions'])
        checked_code(SOURCE, int(context[role], 16), code)
    require(fragments[SOURCE][0]['instruction_count'] == 23, 'changed constructor shape differs')
    require(set(context['leaves']) == {'0x145790890', '0x1457fdef0'}, 'current leaf closure differs')
    for address, data in context['leaves'].items():
        rows = checked_code(SOURCE, int(address, 16), bytes.fromhex(data))
        require(all(row.mnemonic in ('lea', 'mov', 'xor', 'ret') for row in rows), 'current leaf gained side effects')

    def replay(sha, address, seed, offset):
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        allowed, pages = set(), set()
        for fragment in fragments[sha]:
            at, data = int(fragment['address'], 16), bytes.fromhex(fragment['bytes'])
            for page in range(at & ~4095, (at + len(data) + 4095) & ~4095, 4096):
                if page not in pages:
                    uc.mem_map(page, 4096)
                    pages.add(page)
            uc.mem_write(at, data)
            allowed.update(row.address for row in decoder.disasm(data, at))
        scratch, stop = 0x28000000, 0x2803f000
        uc.mem_map(scratch, 0x40000)
        obj = scratch + offset
        uc.mem_write(obj - 16, b'\xa7' * 16 + seed + b'\xa8' * 16)
        stack = scratch + 0x38008
        uc.mem_write(stack, struct.pack('<Q', stop))
        abi = {register: 0xabcd000000000000 + index for index, register in enumerate(
            (x.UC_X86_REG_RBX, x.UC_X86_REG_RBP, x.UC_X86_REG_RSI, x.UC_X86_REG_RDI,
             x.UC_X86_REG_R12, x.UC_X86_REG_R13, x.UC_X86_REG_R14, x.UC_X86_REG_R15))}
        abi.update({getattr(x, 'UC_X86_REG_XMM' + str(index)): (index << 96) | 0x123456789abcdef
                    for index in range(6, 16)})
        for register, value in abi.items():
            uc.reg_write(register, value)
        trace = []
        def instruction(machine, at, size, unused):
            if at == stop:
                machine.emu_stop()
            else:
                require(at in allowed, 'unreviewed instruction ' + hex(at))
                trace.append(at)
        def write(machine, access, at, size, value, unused):
            require(obj <= at <= obj + 0x60 - size or stack - 0x100 <= at <= stack + 0x40 - size,
                    'write escaped object or bounded stack')
        uc.hook_add(unicorn.UC_HOOK_CODE, instruction)
        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, write)
        uc.reg_write(x.UC_X86_REG_RSP, stack)
        uc.reg_write(x.UC_X86_REG_RCX, obj)
        uc.emu_start(address, 0, count=200)
        require(uc.reg_read(x.UC_X86_REG_RIP) == stop and uc.reg_read(x.UC_X86_REG_RAX) == obj
                and uc.reg_read(x.UC_X86_REG_RSP) == stack + 8
                and all(uc.reg_read(register) == value for register, value in abi.items()), 'Win64 ABI differs')
        require(bytes(uc.mem_read(obj - 16, 16)) == b'\xa7' * 16
                and bytes(uc.mem_read(obj + 0x60, 16)) == b'\xa8' * 16, 'object canary changed')
        value = bytes(uc.mem_read(obj, 0x60))
        for begin, end in ZERO_FIELDS:
            require(value[begin:end] == bytes(end - begin), 'initialized scalar bytes differ')
        for begin, end in PADDING:
            require(value[begin:end] == seed[begin:end], 'padding was unexpectedly initialized')
        return value, trace

    results, pointers = [], None
    seeds = [bytes([poison]) * 0x60 for poison in (0, 0xa5, 0xff)] + [bytes(range(0x60))]
    for index, seed in enumerate(seeds):
        for offset in (0x10000, 0x10108):
            before, old_trace = replay(BASELINE, old_at, seed, offset)
            after, new_trace = replay(SOURCE, int(context['constructor'], 16), seed, offset)
            relocations = {hex(field): [hex(struct.unpack_from('<Q', value, field)[0]) for value in (before, after)]
                           for field in POINTER_FIELDS}
            require(pointers is None or relocations == pointers, 'vtable assignments vary by allocation')
            pointers = relocations
            normalized = []
            for value in (before, after):
                canonical = bytearray(value)
                for field in POINTER_FIELDS:
                    canonical[field:field + 8] = bytes(8)
                normalized.append(bytes(canonical))
            require(normalized[0] == normalized[1], 'non-pointer initialized fields differ')
            require(0x145790890 in new_trace and int(context['time_constructor'], 16) in new_trace
                    and 0x1457fdef0 in new_trace and old_time in old_trace, 'real nested constructor closure did not execute')
            results.append(dict(seed=index, object_alignment_offset=offset & 15,
                baseline_sha256=hashlib.sha256(before).hexdigest(), current_sha256=hashlib.sha256(after).hexdigest(),
                canonical_sha256=hashlib.sha256(normalized[0]).hexdigest(), abi_preserved=True, guards_preserved=True))
    return dict(cases=results, pointer_relocations=pointers, source_ranges=fragments,
                object_size=0x60, zero_fields=[list(row) for row in ZERO_FIELDS], padding=[list(row) for row in PADDING])


def validate(report, selected):
    require(report.get('recipe') == RECIPE and report.get('source_sha256') == SOURCE
            and report.get('definition') == selected and report.get('baseline_sha256') == BASELINE
            and report.get('constructor_equivalent') is True and report.get('native_execution') is True
            and report.get('runtime_admitted') is False and report.get('network_used') is False
            and report.get('object_size') == 0x60 and len(report.get('cases', [])) == 8
            and all(row.get('abi_preserved') is True and row.get('guards_preserved') is True for row in report['cases'])
            and report.get('limits'), 'receipt scope differs')


def verify(context_path=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    c, parent, selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['path']).resolve()
        require(path == root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
                and digest(path) == pointer['sha256'], 'cache pointer differs')
        validate(json.loads(path.read_bytes()), selected)
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    result = execute(c, parent, root)
    barrier(selected['inputs'])
    report = dict(schema=1, recipe=RECIPE, source_sha256=SOURCE, baseline_sha256=BASELINE, definition=selected,
        constructor_equivalent=True, native_execution=True, network_used=False, runtime_admitted=False,
        limits=['Exact whole old/current constructor and real nested current leaf/TimeBase helpers execute on guarded 96-byte storage.',
                'Comparison normalizes only the three explicitly recorded vtable relocations. Padding must retain its initial bytes.',
                'Eight bounded seed/alignment cases, no engine callbacks, account, network or world-session admission.'], **result)
    validate(report, selected)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    sha = digest(path)
    workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=sha)))
    return dict(report=str(path), sha256=sha, reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context)))
