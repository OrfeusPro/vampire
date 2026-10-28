"""Pure source-linked transfers for Version string combiners and platform accessors.

The caller supplies independently proved Version caller edges. These rules do
not execute native code, select releases, publish evidence or admit a runtime.
"""
import copy
import hashlib
import struct
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

HERE = Path(__file__).resolve().parent
COMBINERS = ('first', 'second', 'copy', 'append', 'grow')
COMBINER_FIXTURES = {'resize', 'append_grow', 'copy', 'quantize', 'allocator', 'overflow'}
PLATFORM = ('selector', 'store', 'lookup')
PLATFORM_FIXTURES = {'platform_text', 'name_ctor', 'free', 'equals', 'store_type', 'store_resolve', 'value_at'}
FAMILIES = {'version-combiner', 'version-platform'}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tools():
    own = ('version-string-transfer-rules.py', 'update-native-version-prepare.py')
    return {**load('update-native-archive-wire').tools(),
            **{str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in own}}


def functions(family, context):
    if family == 'version-combiner':
        values = context.get('functions', {})
        if set(values) != set(COMBINERS):
            raise ValueError('Version combiner root roles differ')
        return {role: int(values[role], 16) for role in COMBINERS}
    if family == 'version-platform':
        return {role: int(context[role], 16) for role in PLATFORM}
    raise ValueError('Unregistered Version string family')


def roots(family, context):
    values = functions(family, context)
    required = COMBINER_FIXTURES if family == 'version-combiner' else PLATFORM_FIXTURES
    fixtures = {key: int(at, 16) for key, at in context.get('fixtures', {}).items()}
    if set(fixtures) != required or len(set(fixtures.values())) != len(fixtures):
        raise ValueError('Version string fixture roles alias or differ')
    result = set(values.values())
    copy = int(context['helpers']['memcpy'], 16)
    if len(result) != len(values) or result & set(fixtures.values()) or copy in result | set(fixtures.values()):
        raise ValueError('Version string roots, fixtures or memcpy alias')
    return result


def image_bytes(image, at, size):
    return load('update-native-contexts').image_bytes(image, at, size)


def call_sites(native, bindings, image, selected):
    return {hex(row['address']): hex(row['direct_target']) if row['direct_target'] is not None else row['operands']
            for at in selected.values() for row in bindings.rows(native, image, at) if row['call']}


def call_closure(family, native, bindings, image, context):
    selected = functions(family, context)
    edges = [row['direct_target'] for at in selected.values() for row in bindings.rows(native, image, at) if row['call']]
    fixtures = {int(at, 16) for at in context['fixtures'].values()}
    external = fixtures | ({int(context['helpers']['memcpy'], 16)} if family == 'version-combiner' else set())
    if not external <= set(edges) or set(edges) - (external | set(selected.values())):
        raise ValueError('Version string direct call/fixture closure differs')


def unwind(image, at, role):
    part = image.containing(at)
    if part is None or image.roots[part][0] + image.pe.base != at:
        raise ValueError('Version string fixture is not a concrete unwind entry: ' + role)


def same_input(before, after, old, new, size, role):
    read = load('update-native-version-prepare').data_input
    a, b = read(before, old, size), read(after, new, size)
    if a != b:
        raise ValueError('Version string typed data changed: ' + role)
    return b


def fixture_boundaries(family, before, after, baseline, current, mapping):
    common = load('update-native-archive-wire')
    result = {}
    for role, text in current['fixtures'].items():
        old, new = int(baseline['fixtures'][role], 16), int(text, 16)
        if family == 'version-combiner' and role == 'copy':
            # This replaced entry is a five-byte tail thunk to the already
            # proved memcpy import, followed by eleven trap padding bytes.
            for image, at, expected in ((before, old, int(baseline['helpers']['memcpy'], 16)),
                                        (after, new, int(current['helpers']['memcpy'], 16))):
                raw = image_bytes(image, at, 16)
                if at % 16 or raw[0] != 0xe9 or raw[5:] != b'\xcc' * 11 or at + 5 + struct.unpack_from('<i', raw, 1)[0] != expected:
                    raise ValueError('Version combiner internal copy thunk changed')
            result[role] = dict(address=text, kind='memcpy-tail-fixture', target=current['helpers']['memcpy'],
                                scope='Replaced tail thunk; memcpy destination, not an unknown short-copy body')
        elif family == 'version-combiner' and role == 'quantize':
            # The optional allocator virtual call is outside the native scope.
            # Preserve the complete 29-byte dispatch boundary and three traps,
            # allowing only relocation of its one eight-byte global input.
            expected = bytes.fromhex('448bc2488bd1488b0d000000004885c97504488bc2c3488b0148ff6060cccccc')
            inputs = []
            for image, at in ((before, old), (after, new)):
                raw = image_bytes(image, at, 32)
                if at % 16 or raw[:9] + b'\0' * 4 + raw[13:] != expected:
                    raise ValueError('Version combiner quantize dispatch boundary changed')
                inputs.append(at + 13 + struct.unpack_from('<i', raw, 9)[0])
            common.add_link(mapping, inputs[0], inputs[1])
            data = same_input(before, after, *inputs, 8, 'unexecuted quantize manager')
            result[role] = dict(address=text, kind='quantize-dispatch-fixture', manager=hex(inputs[1]), input=data,
                                scope='Replaced fixture; allocator object and virtual destination are not executed')
        else:
            unwind(before, old, role)
            unwind(after, new, role)
            result[role] = dict(address=text, kind='unwind-fixture', scope='Replaced fixture; body not executed')
    return result


def platform_data(native, bindings, before, after, baseline, current, mapping):
    result = []
    roles = {25: ('empty', '\0'), 68: ('android', 'Android\0'), 96: ('ios', 'IOS\0'), 124: ('windows', 'Windows\0')}
    old_selector = int(baseline['selector'], 16)
    refs = {row['address'] - old_selector: row['rip_references']
            for row in bindings.rows(native, before, old_selector) if row['rip_references']}
    if set(refs) != set(roles) or any(len(values) != 1 for values in refs.values()):
        raise ValueError('Version platform selector static roles changed')
    for offset, (role, text) in roles.items():
        old = refs[offset][0]
        new = mapping[old]
        expected = text.encode('utf-16le')
        if image_bytes(before, old, len(expected)) != expected or image_bytes(after, new, len(expected)) != expected:
            raise ValueError('Version platform selector literal changed: ' + role)
        result.append(dict(role=role, offset=offset, address=hex(new), bytes=expected.hex()))
    old_store = int(baseline['store'], 16)
    refs = {row['address'] - old_store: row['rip_references']
            for row in bindings.rows(native, before, old_store) if row['rip_references']}
    expected_refs = {4: [int(baseline['cache'], 16)], 24: [int(baseline['descriptor'], 16)],
                     31: [int(baseline['factory'], 16)], 43: [int(baseline['cache'], 16)]}
    if refs != expected_refs:
        raise ValueError('Version platform store static role linkage changed')
    cache = same_input(before, after, int(baseline['cache'], 16), int(current['cache'], 16), 8, 'platform cache')
    result.append(dict(role='cache', address=current['cache'], input=cache, scope='Seeded synthetic pointer'))
    expected = 'ENnOsType\0'.encode('utf-16le')
    for image, text in ((before, baseline['descriptor']), (after, current['descriptor'])):
        if image_bytes(image, int(text, 16), len(expected)) != expected:
            raise ValueError('Version platform enum name descriptor changed')
    result.append(dict(role='descriptor', address=current['descriptor'], bytes=expected.hex(),
                       scope='Enum type name argument only; resolver and reflection construction remain fixtures'))
    for image, text in ((before, baseline['factory']), (after, current['factory'])):
        unwind(image, int(text, 16), 'factory argument')
    result.append(dict(role='factory', address=current['factory'], kind='unwind-argument',
                       scope='Function address passed to resolver fixture; factory body is not executed'))
    if any(row['rip_references'] for row in bindings.rows(native, before, int(baseline['lookup'], 16))):
        raise ValueError('Version platform lookup has undeclared static data')
    return result


def transfer(family, native, bindings, before, after, baseline, mapping):
    """Relocate complete source roles using independently established caller edges."""
    roots(family, baseline)
    call_closure(family, native, bindings, before, baseline)
    common = load('update-native-archive-wire')
    old_functions = functions(family, baseline)
    for role, old in old_functions.items():
        # first/second or selector/store/lookup come from the Version caller;
        # copy/append/grow are then constrained by those actual native calls.
        if old not in mapping:
            raise ValueError('Version string root lacks independent caller edge: ' + role)
        common.pair_rows(native, bindings.rows(native, before, old), bindings.rows(native, after, mapping[old]), mapping)
    if call_sites(native, bindings, before, old_functions) != baseline['call_sites']:
        raise ValueError('Version string baseline call-site roles changed')

    def mapped(text):
        old = int(text, 16)
        if old not in mapping:
            raise ValueError('Version string address lacks exact call/data relocation: ' + text)
        return hex(mapping[old])

    current = copy.deepcopy(baseline)
    current['helpers'] = dict(memcpy=mapped(baseline['helpers']['memcpy']))
    current['fixtures'] = {role: mapped(at) for role, at in baseline['fixtures'].items()}
    if family == 'version-combiner':
        current['functions'] = {role: mapped(at) for role, at in baseline['functions'].items()}
        if any(row['rip_references'] for at in old_functions.values() for row in bindings.rows(native, before, at)):
            raise ValueError('Version combiner has undeclared static data')
        data = []
    else:
        for role in PLATFORM + ('cache', 'factory', 'descriptor'):
            current[role] = mapped(baseline[role])
        data = platform_data(native, bindings, before, after, baseline, current, mapping)
    roots(family, current)
    boundaries = fixture_boundaries(family, before, after, baseline, current, mapping)
    current['call_sites'] = call_sites(native, bindings, after, functions(family, current))
    call_closure(family, native, bindings, after, current)
    current['verify_whole_exports'] = True
    return current, dict(family=family, roots={role: hex(at) for role, at in functions(family, current).items()},
                         typed_inputs=data, fixtures=boundaries,
                         scope='Whole declared roots only; allocator, copy, FName, resolver and value-at boundaries remain fixtures')
