"""Execute the current native Viper cold CDO owner with bounded engine fixtures."""
import argparse
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
CONTEXT = HERE / 'knowledge/native-contexts/viper-cold-cdo-11322.json'
ROOT = Path('F:/PhoneExit Resources/Vampir')
RECIPE = 'viper-cold-cdo-current-v1'
SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def definition(context_path, root):
    context_path = Path(context_path).resolve()
    parent_path = HERE / 'knowledge/native-contexts/viper-cdo-11322.json'
    c = json.loads(context_path.read_bytes())
    parent = json.loads(parent_path.read_bytes())
    if c.get('recipe') != RECIPE or c.get('source_sha256') != SOURCE or parent.get('source_sha256') != SOURCE:
        raise ValueError('Cold CDO source/context differs')
    files = [context_path, parent_path, HERE / 'knowledge/native-contexts/preset-defaults-11322.json',
             Path(__file__).resolve()]
    files.extend(HERE / (name + '.py') for name in ('verify-viper-cdo-current', 'native-request-harness-11316',
        'build-native-entry-code', 'audit-launcher-shape-11318', 'build-object-zero-init-code',
        'extract-native-enums', 'knowledge-index', 'audit-client-release', 'research-workflow', 'update-native-harness'))
    inputs = {str(path.resolve()): digest(path) for path in files}
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    inputs[str(source)] = SOURCE
    for run, sha in (parent['exports'] | c['exports']).items():
        inputs[str(root / 'ghidra/request-exports' / SOURCE / run / 'details.json')] = sha
    barrier(inputs)
    return dict(recipe=RECIPE, source_sha256=SOURCE, inputs=inputs,
                runtime=load('update-native-harness').runtime_inputs())


def barrier(inputs):
    if any(digest(path) != sha for path, sha in inputs.items()):
        raise ValueError('Cold CDO retained input changed')


def execute(context_path=CONTEXT, *, root=None):
    spec = spec_from_file_location('viper_cdo_base', HERE / 'verify-viper-cdo-current.py')
    base = module_from_spec(spec)
    spec.loader.exec_module(base)
    root = Path(root or base.ROOT).resolve()
    context_path = Path(context_path).resolve()
    context = json.loads(context_path.read_bytes())
    parent = json.loads(base.CONTEXT.read_bytes())
    ctor_path = HERE / 'knowledge/native-contexts/preset-defaults-11322.json'
    ctor = json.loads(ctor_path.read_bytes())
    if (context['schema'], context['recipe'], context['source_sha256']) != (1, 'viper-cold-cdo-current-v1', base.SHA):
        raise ValueError('Cold CDO context/source differs')
    if parent['source_sha256'] != base.SHA or ctor['source_sha256'] != base.SHA:
        raise ValueError('Cold CDO parent source differs')
    if set(context['functions']) != {'class_getter', 'cold_cdo', 'build_initializer'}:
        raise ValueError('Cold CDO owner roots differ')
    cold = {role: int(address, 16) for role, address in context['functions'].items()}
    used_parent = {role: int(parent['functions'][role], 16) for role in
        ('allocation', 'completion', 'postconstruct', 'preset', 'data_asset', 'uobject')}
    roles = {**used_parent, **cold}
    exports = parent['exports'] | context['exports']
    leaves = {int(address, 16): data for address, data in parent['leaves'].items()}
    leaves[0x14140e350] = '488d4108c3'
    h = base.load('native-request-harness-11316').make_harness(exports, set(roles.values()),
        leaves=leaves, root=root, source_sha256=base.SHA, copy_thunk=None)
    native = base.load('build-native-entry-code')
    normalizer = base.load('audit-launcher-shape-11318')
    role_by_address = {address: role for role, address in roles.items()}
    shapes = {}
    for exported in h.fragments:
        shape = normalizer.normalize_function(native, h.image, exported)
        shapes[role_by_address[int(exported['address'], 16)]] = len(shape['shape'])
    anchors = {name: int(address, 16) for name, address in context['anchors'].items()}
    hooks = {name: int(address, 16) for name, address in (parent['fixtures'] | context['fixtures']).items()}
    del hooks['name']  # The CDO owner obtains a nonempty name and takes the lookup-miss branch.
    memset = int(parent['memset'], 16)
    hooks['memset'] = memset
    hooks['class_register'] = anchors['class_register']

    def source(address, size):
        pos = h.image.offset(address - h.image.pe.base)
        return h.raw[pos:pos + size]

    def source_pointer(address):
        return struct.unpack('<Q', source(address, 8))[0]

    package_name = '/Script/NnFramework'
    class_name = 'NnDataAssetForCustomizePreset'
    for key, name in (('class_package', package_name), ('class_name', class_name)):
        expected = (name + '\0').encode('utf-16-le')
        if source(anchors[key], len(expected)) != expected:
            raise ValueError('Cold CDO class identity differs')
    if (source_pointer(anchors['finish_cdo_slot']) != 0x141403bd0
            or source_pointer(anchors['initializer_delegate_slot']) != hooks['initializer_delegate_cleanup']):
        raise ValueError('Cold CDO completion slot differs')
    thunk = source(memset, 6)
    if thunk[:2] != b'\xff\x25':
        raise ValueError('Cold CDO memset thunk differs')
    iat = memset + 6 + struct.unpack_from('<i', thunk, 2)[0]
    binding = base.load('build-object-zero-init-code').import_at(h.raw, h.image, iat)
    if (binding['dll'].lower(), binding['name']) != ('vcruntime140.dll', 'memset'):
        raise ValueError('Cold CDO zero branch is not named memset')

    import unicorn
    uc, x = h.uc, h.x
    obj, cls, parent_class, parent_cdo, outer, ctx, entries, chunks, chunk = (
        h.scratch + offset for offset in (0x10000, 0x12000, 0x13000, 0x14000, 0x15000,
            0x16000, 0x17000, 0x18000, 0x19000))
    gs = 0x30000000
    uc.mem_map(gs, 0x110000)
    uc.reg_write(x.UC_X86_REG_GS_BASE, gs)

    def store_q(address, value):
        uc.mem_write(address, struct.pack('<Q', value))

    def store_i(address, value):
        uc.mem_write(address, struct.pack('<I', value))

    def read_q(address):
        return struct.unpack('<Q', bytes(uc.mem_read(address, 8)))[0]

    def read_i(address):
        return struct.unpack('<I', bytes(uc.mem_read(address, 4)))[0]

    store_q(gs + 0x58, gs + 0x1000)
    store_q(gs + 0x1000, gs + 0x2000)
    for row in parent['globals']:
        address = int(row['address'], 16)
        page = address & ~4095
        if not any(start <= page <= end for start, end, _ in uc.mem_regions()):
            uc.mem_map(page, 4096)
        uc.mem_write(address, bytes.fromhex(row['value']))

    name = 0x80000001
    events, executed, initializers = [], [], []
    hooks['class_postconstruct'] = h.scratch + 0x1b000
    hook_role = {address: role for role, address in hooks.items()}

    def track_roots(machine, address, size, unused):
        if address in role_by_address:
            executed.append(role_by_address[address])

    def require(condition, detail):
        if not condition:
            raise ValueError('Cold CDO ' + detail)

    def fixture(machine):
        role = hook_role[machine.reg_read(x.UC_X86_REG_RIP)]
        a, b, c, d = [machine.reg_read(reg) for reg in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        stack = machine.reg_read(x.UC_X86_REG_RSP)
        events.append(role)
        if role == 'class_register':
            size, alignment, flags = (read_i(stack + n) for n in (0x28, 0x30, 0x38))
            require((a, b, c) == (anchors['class_package'], anchors['class_name'], anchors['class_global'])
                and (size, alignment, flags) == (0x78, 8, 0x10000000)
                and read_q(stack + 0x50) == roles['preset'], 'class registration arguments differ')
            store_q(c, cls)
            store_q(cls, h.scratch + 0x1a000)
            store_q(h.scratch + 0x1a000 + 0x388, hooks['class_postconstruct'])
            for offset, value in ((0x20, outer), (0x40, parent_class), (0xb0, roles['preset'])):
                store_q(cls + offset, value)
            for offset, value in ((0x58, size), (0x5c, alignment), (0xd4, flags | 1)):
                store_i(cls + offset, value)
        elif role == 'stack_probe':
            size = machine.reg_read(x.UC_X86_REG_RAX)
            require(0x1000 < size <= 0x2000, 'stack probe size differs')
            return h.finish(size)
        elif role == 'parent_lookup':
            require((a, b & 0xff) == (parent_class, 1) and read_q(a + 0x110) == parent_cdo, 'parent CDO lookup differs')
        elif role == 'cdo_fname':
            require(a == cls, 'name class differs')
            store_q(b, name)
            return h.finish(b)
        elif role == 'object_lookup':
            require((a, b, c, d) == (0, outer, name, 1), 'named object lookup differs')
        elif role == 'heap':
            require((a, b) == (0x78, 8), 'allocation size/alignment differs')
            return h.finish(obj)
        elif role == 'memset':
            require((a, b, c) == (obj, 0, 0x78), 'fresh memory write differs')
            machine.mem_write(obj, bytes(c))
            return h.finish(obj)
        elif role == 'register':
            require((a, b) == (obj, name) and read_q(obj + 0x10) == cls and read_q(obj + 0x20) == outer
                and read_i(obj + 8) == 0x231, 'fresh CDO object header differs')
            store_i(obj + 0xc, 0)
            machine.mem_write(chunk, struct.pack('<QII', obj, 0, 0))
        elif role == 'set_flags':
            require((a, b) == (chunk, 0x8400000), 'object-array registration differs')
            store_i(a + 8, read_i(a + 8) | b)
        elif role == 'class_property_iterator':
            require((read_q(a), read_q(a + 8)) == (cls, 0), 'nonempty property initialization list outside model')
        elif role == 'context':
            return h.finish(ctx)
        elif role == 'push':
            require(read_q(a) == obj and read_q(a + 8) == parent_cdo and read_q(cls + 0x110) == obj,
                'initializer ownership differs')
            initializers.append(bytes(machine.mem_read(a + 0x10, 4)).hex())
            require(initializers[-1] == '00000100', 'cold initializer unexpectedly copies defaults')
            store_q(entries, a)
            store_i(ctx + 0x18, 1)
            store_i(ctx + 0x28, 1)
        elif role == 'initializer':
            require(read_i(ctx + 0x18) == 1, 'constructor initializer stack differs')
            return h.finish(read_q(entries))
        elif role == 'immediate':
            return h.finish(1)
        elif role == 'outer_package':
            require(a == cls, 'package classification argument differs')
            return h.finish(outer)
        elif role == 'clear_object_flag':
            require((a, b) == (obj, 0x200), 'final object flag cleanup differs')
            store_i(a + 8, read_i(a + 8) & ~b)
        elif role == 'post_owner':
            require((a, b) == (obj, 0), 'postconstruct notification differs')
        elif role == 'post_initialize':
            require((a, b, c) == (obj, 0, 0) and d in (0, 1) and read_q(stack) == 0x1417dd9f6,
                'post-initialization helper boundary differs')
        elif role == 'initializer_cleanup':
            require(h.scratch + 0x30000 <= a < h.scratch + 0x38000,
                'initializer delegate cleanup receiver differs')
        elif role == 'post_properties':
            require(a == obj and source_pointer(read_q(obj) + 0x50) == hooks['post_properties'],
                'PostInitProperties virtual callback differs')
        elif role == 'class_postconstruct':
            require((a, b, c) == (cls, obj, 0), 'class postconstruction callback differs')
        elif role in ('empty_delegates', 'empty_container'):
            require(b == 0, 'nonempty initializer queue outside model')
        elif role not in ('feature_setting', 'base_class', 'security', 'uobject_service', 'bookkeeping',
                'initializer_delegate_cleanup'):
            raise ValueError('Unhandled cold CDO fixture ' + role)
        return h.finish()

    uc.hook_add(unicorn.UC_HOOK_CODE, track_roots)
    for address in hooks.values():
        h.add_fixture(address, fixture)
    cases = []
    vector = bytes(36) + struct.pack('<7fB', *([0.5] * 7), 0)
    for poison in (0, 0xa5, 0xff):
        for address in (cls, parent_class, parent_cdo, outer, ctx, entries):
            uc.mem_write(address, bytes(0x400))
        uc.mem_write(parent_cdo + 0x30, bytes([0xd3]) * len(vector))
        uc.mem_write(obj - 16, bytes([0x47]) * 16 + bytes([poison]) * 0x78 + bytes([0x83]) * 16)
        store_q(parent_class + 0x110, parent_cdo)
        store_q(anchors['class_global'], 0)
        store_q(chunks, chunk)
        store_q(0x14b3e1ab0, chunks)
        store_i(0x14b3e1ac4, 1)
        store_q(ctx + 0x10, entries)
        store_i(ctx + 0x1c, 8)
        events.clear()
        executed.clear()
        initializers.clear()
        require(h.call(cold['class_getter']) == cls, 'class getter did not publish class')
        try:
            h.call(cold['cold_cdo'], cls, budget=150000)
        except unicorn.UcError as error:
            raise ValueError('Cold CDO native dependency at ' + hex(uc.reg_read(x.UC_X86_REG_RIP))) from error
        expected_roots = ['class_getter', 'cold_cdo', 'allocation', 'build_initializer',
            'preset', 'data_asset', 'uobject', 'completion', 'postconstruct']
        require(executed == expected_roots, 'root sequence differs')
        require(events.count('heap') == events.count('memset') == 1 and len(initializers) == 1,
            'allocation or initialization count differs')
        require(read_q(cls + 0x110) == obj and read_i(obj + 8) == 0x31 and read_i(ctx + 0x18) == read_i(ctx + 0x28) == 0,
            'publication, flags or context cleanup differs')
        require(bytes(uc.mem_read(obj + 0x30, len(vector))) == vector, 'default vector differs')
        require(bytes(uc.mem_read(obj - 16, 16)) == bytes([0x47]) * 16
            and bytes(uc.mem_read(obj + 0x78, 16)) == bytes([0x83]) * 16, 'object guards changed')
        trace = list(events)
        events.clear()
        executed.clear()
        before = bytes(uc.mem_read(obj, 0x78))
        h.call(cold['cold_cdo'], cls)
        require(executed == ['cold_cdo'] and events == ['stack_probe', 'security']
            and bytes(uc.mem_read(obj, 0x78)) == before, 'warm reuse changed object or called an allocator')
        cases.append(dict(poison=poison, default_bytes=vector.hex(), cold_roots=expected_roots,
            cold_fixtures=trace, initializer_bytes=initializers[0], warm_reused=True, guards_unchanged=True))

    paths = [context_path, base.CONTEXT, ctor_path, Path(__file__), h.source, *(Path(row['path']) for row in h.evidence)]
    paths += [HERE / (name + '.py') for name in ('verify-viper-cdo-current', 'native-request-harness-11316',
        'build-native-entry-code', 'audit-launcher-shape-11318', 'build-object-zero-init-code',
        'extract-native-enums', 'knowledge-index', 'audit-client-release')]
    inputs = {str(path.resolve()): base.digest(path) for path in paths}
    require(inputs[str(h.source.resolve())] == base.SHA
        and all(inputs[str(Path(row['path']).resolve())] == row['sha256'] for row in h.evidence), 'proof inputs changed')
    report = dict(schema=1, recipe=context['recipe'], source_sha256=base.SHA, inputs=inputs, whole_roots=shapes,
        class_path=package_name + '.' + class_name, native_cases=cases, native_execution=True,
        loaded_preset_verified=False, runtime_admitted=False, network_used=False,
        limits=['Generated class getter executes; its class registration backend and active UClass metadata are fixtures.',
            'Cold owner, named allocation miss, zeroing, native initializer, constructors and immediate completion execute.',
            'Superclass CDO, object lookup, no property initializer list, context/bookkeeping and package flags are fixtures.',
            'Post-initialization helper, initializer delegate cleanup, PostInitProperties and UClass postconstruction are fixtures.',
            'No delayed initialization, package deserializer, PostLoad, later appearance overrides or live Viper Create.'])
    path = base.load('audit-client-release').save_snapshot(root / 'code-clues/viper-cold-cdo-current-v1', report)
    return dict(report=str(path), sha256=base.digest(path), native_cases=len(cases))


def validate(report, selected):
    if (report.get('definition') != selected or report.get('source_sha256') != SOURCE
            or report.get('recipe') != RECIPE or report.get('native_execution') is not True
            or report.get('runtime_admitted') is not False or report.get('network_used') is not False
            or report.get('loaded_preset_verified') is not False or not report.get('limits')
            or [case['poison'] for case in report.get('native_cases', [])] != [0, 0xa5, 0xff]
            or any(case.get('warm_reused') is not True or case.get('guards_unchanged') is not True
                   for case in report['native_cases'])):
        raise ValueError('Cold CDO receipt boundary differs')


def verify(context_path=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    selected = definition(context_path, root)
    workflow = load('research-workflow')
    key = hashlib.sha256(workflow.canonical(selected)).hexdigest()
    cache = root / 'knowledge' / (RECIPE + '-cache') / (key + '.json')
    if cache.is_file():
        pointer = json.loads(cache.read_bytes())
        path = Path(pointer['path']).resolve()
        if (path != root / 'code-clues' / RECIPE / pointer['sha256'] / 'manifest.json'
                or digest(path) != pointer['sha256']):
            raise ValueError('Cold CDO cache pointer differs')
        validate(json.loads(path.read_bytes()), selected)
        return dict(report=str(path), sha256=pointer['sha256'], reused=True)
    result = execute(context_path, root=root)
    barrier(selected['inputs'])
    report = json.loads(Path(result['report']).read_bytes())
    if any(selected['inputs'].get(path) != sha for path, sha in report['inputs'].items()):
        raise ValueError('Cold CDO executed inputs differ')
    report['definition'] = selected
    validate(report, selected)
    path = load('audit-client-release').save_snapshot(root / 'code-clues' / RECIPE, report)
    sha = digest(path)
    workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=sha)))
    return dict(report=str(path), sha256=sha, reused=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(verify(args.context, root=args.root)))
