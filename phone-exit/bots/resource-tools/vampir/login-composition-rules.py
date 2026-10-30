"""Join independently proved Login reader and handler into an exact shared scope.

Child adapters prove relocation. This rule proves their source, table, ID, leaf,
fixture and root agreement; a new native suite must prove the composition itself.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'login-response-composition'
FORMAT = 'login-response-composition-v1'
PACKET = {'constructor', 'reader', 'time_constructor', 'period_constructor', 'time_reader', 'period_reader'}
INPUT = {'constructor', 'buffer_constructor', 'bool', 'raw', 'std_string', 'string', 'time', 'u16', 'u32', 'u64',
         'utf8_convert', 'utf8_core', 'utf8_length', 'utf8_scalar'}
HANDLER = {'handler', 'gate'}
NAMES = {'packet.' + name for name in PACKET} | {'input.' + name for name in INPUT} | {'handler.' + name for name in HANDLER}
FIELDS = {'packet_bytes', 'functions', 'leaves', 'helpers', 'packet_table', 'id_getter',
          'reader_context', 'handler_context', 'verify_whole_exports'}
META = {'schema', 'family', 'format', 'source', 'source_sha256', 'layout', 'exports', 'transfer_proof', 'release_id', 'provenance'}
SHA = re.compile('[0-9a-f]{64}')
ADDRESS = re.compile('0x[0-9a-f]+')


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec); spec.loader.exec_module(module); return module


def tools():
    return {**load('update-native-login-input').select('login-strings-buffer').tools(),
        **load('update-native-login-full').select().tools(),
        str(HERE / 'login-composition-rules.py'): hashlib.sha256((HERE / 'login-composition-rules.py').read_bytes()).hexdigest()}


def address(value):
    if not isinstance(value, str) or not ADDRESS.fullmatch(value):
        raise ValueError('Composition address differs')
    return int(value, 16)


def pointer(value):
    if (not isinstance(value, dict) or set(value) != {'path', 'sha256'} or not isinstance(value['path'], str)
            or not value['path'] or not isinstance(value['sha256'], str) or not SHA.fullmatch(value['sha256'])):
        raise ValueError('Composition component pointer differs')
    return value


def leaf_bytes(leaves):
    if not isinstance(leaves, dict): raise ValueError('Composition leaf inventory differs')
    for at, code in leaves.items():
        address(at)
        if not isinstance(code, str) or not code or not re.fullmatch('(?:[0-9a-f]{2})+', code):
            raise ValueError('Composition leaf byte declaration differs')
    return leaves


def functional(c):
    if (set(c) - META != FIELDS or c.get('schema') != 1 or c.get('family') != FAMILY or c.get('format') != FORMAT
            or not isinstance(c.get('source_sha256'), str) or not SHA.fullmatch(c['source_sha256'])
            or not isinstance(c.get('source'), str) or not c['source']
            or type(c.get('packet_bytes')) is not int or c['packet_bytes'] != 352
            or c.get('verify_whole_exports') is not True or set(c.get('functions', {})) != NAMES
            or set(c.get('helpers', {})) != {'memcpy'} or len(leaf_bytes(c.get('leaves'))) != 6):
        raise ValueError('Composition fields or bounded native scope differ')
    for value in (*c['functions'].values(), *c['helpers'].values(), c['packet_table'], c['id_getter']): address(value)
    if c['leaves'].get(c['id_getter']) != 'b804000000c3': raise ValueError('Composition packet ID leaf differs')
    pointer(c['reader_context']); pointer(c['handler_context'])
    if c['reader_context'] == c['handler_context']: raise ValueError('Composition component pointers alias')
    return {key: copy.deepcopy(c[key]) for key in FIELDS}


def roots(c):
    functional(c)
    values = {address(value) for value in c['functions'].values()}
    leaves = {address(value) for value in c['leaves']}
    if len(values) != 22 or values & leaves or address(c['helpers']['memcpy']) in values | leaves:
        raise ValueError('Composition native roots, leaves or memcpy alias')
    return values


def compose(reader, handler, reader_pointer, handler_pointer):
    """Construct a bounded projection after both child proofs have been admitted.

    Layout is stamped and checked by the owning adapter. No child native result
    is widened to a shared-packet claim by constructing this projection.
    """
    pointer(reader_pointer); pointer(handler_pointer)
    if (reader.get('family') != 'login-strings-buffer' or handler.get('family') != 'login-full-handler'
            or reader.get('native_strings') is not True or handler.get('format') != 'login-full-handler-v1'
            or reader.get('layout', {}).get('packet_bytes') != 352 or handler.get('packet_bytes') != 352
            or set(reader.get('functions', {})) != PACKET or set(reader.get('input', {}).get('functions', {})) != INPUT
            or set(handler.get('functions', {})) != HANDLER):
        raise ValueError('Composition independently proved component roles differ')
    if (reader['source_sha256'] != handler['source_sha256'] or Path(reader['source']).resolve() != Path(handler['source']).resolve()
            or reader['helpers'] != handler['helpers'] or reader['packet_table'] != handler['packet_table']
            or reader['id_getter'] != handler['id_getter']):
        raise ValueError('Composition component source/helper/table/ID linkage differs')
    if (reader['input'].get('source_sha256') != reader['source_sha256']
            or Path(reader['input'].get('source', reader['source'])).resolve() != Path(reader['source']).resolve()
            or set(reader['input'].get('string_fixtures', {})) != {'growth', 'utf16_allocate', 'assign', 'free', 'cpp_free', 'security'}):
        raise ValueError('Composition native input source or storage fixture roles differ')
    functions = {**{'packet.' + key: value for key, value in reader['functions'].items()},
        **{'input.' + key: value for key, value in reader['input']['functions'].items()},
        **{'handler.' + key: value for key, value in handler['functions'].items()}}
    leaves = dict(leaf_bytes(reader['leaves']))
    for at, code in leaf_bytes(handler['leaves']).items():
        if at in leaves and leaves[at] != code: raise ValueError('Composition shared leaf bytes conflict')
        leaves[at] = code
    c = dict(schema=1, family=FAMILY, format=FORMAT, source=reader['source'], source_sha256=reader['source_sha256'],
        packet_bytes=352, functions=functions, leaves=leaves, helpers=copy.deepcopy(reader['helpers']),
        packet_table=reader['packet_table'], id_getter=reader['id_getter'], reader_context=copy.deepcopy(reader_pointer),
        handler_context=copy.deepcopy(handler_pointer), verify_whole_exports=True)
    needed = roots(c); protected = needed | {address(at) for at in leaves}
    storage = reader['input']['string_fixtures']; fixtures = handler['fixtures']
    if (storage['free'] != fixtures.get('free') or reader['string_constructor'] != fixtures.get('unsupported_141426950')):
        raise ValueError('Composition shared storage fixture aliases differ')
    hooks = [address(value) for value in fixtures.values()]
    shared = {address(storage['free']), address(reader['string_constructor'])}
    incoming = [address(value) for value in storage.values()] + [address(reader['string_constructor'])]
    if (len(set(hooks)) != len(hooks) or len(set(incoming)) != len(incoming)
            or set(hooks) & set(incoming) != shared or (set(hooks) | set(incoming)) & protected
            or address(c['helpers']['memcpy']) in set(hooks) | set(incoming)):
        raise ValueError('Composition fixture aliases shadow native code or change shared roles')
    exports = dict(reader.get('exports', {}))
    for run, sha in handler.get('exports', {}).items():
        if run in exports and exports[run] != sha: raise ValueError('Composition component export hashes conflict')
        exports[run] = sha
    if exports: c['exports'] = exports
    return c


def export_coverage(root, c, native, bindings, image):
    """Validate the child closure and exact outer 22-root code/data coverage."""
    needed = roots(c); core = load('portable-native-family')
    reader = core.checked(root, c['reader_context'], 'generated-native-contexts')
    handler = core.checked(root, c['handler_context'], 'generated-native-contexts')
    expected = compose(reader, handler, c['reader_context'], c['handler_context'])
    if (functional(c) != functional(expected) or c['source_sha256'] != expected['source_sha256']
            or Path(c['source']).resolve() != Path(expected['source']).resolve()):
        raise ValueError('Composition projection differs from checked component pointers')
    load('update-native-login-input').select('login-strings-buffer').export_coverage(root, reader, native, bindings, image)
    load('update-native-login-full').select().export_coverage(root, handler, native, bindings, image)
    gate_context = core.checked(root, handler['gate_context'], 'generated-native-contexts')
    gate = address(handler['functions']['gate'])
    wanted = {at: bindings.rows(native, image, at) for at in needed - {gate}}
    wanted[gate] = load('result-gate-transfer-rules').rows(native, image, gate_context)
    records = {}
    for run, sha in c.get('exports', {}).items():
        if not isinstance(run, str) or Path(run).name != run or not run.startswith('run-'):
            raise ValueError('Composition export name differs')
        path = Path(root) / 'ghidra/request-exports' / c['source_sha256'] / run / 'details.json'
        if core.digest(path) != sha: raise ValueError('Composition export hash changed')
        report = json.loads(path.read_text('utf-8'))
        if report.get('new_source_sha256', report.get('source_sha256')) != c['source_sha256']:
            raise ValueError('Composition export source differs')
        for function in report['functions']:
            at = address(function['address'])
            if at not in needed: continue
            if any(function.get(flag) is not True for flag in ('decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                raise ValueError('Composition export whole coverage flags differ')
            actual = [(address(row['address']), row['bytes'].lower()) for row in function['instructions']]
            exact = [(row['address'], row['bytes'].lower()) for row in wanted[at]]
            if len(actual) != len(set(address_ for address_, _ in actual)) or sorted(actual) != sorted(exact):
                raise ValueError('Composition export exact instruction/code-data boundary differs')
            if at in records and records[at] != sorted(actual): raise ValueError('Conflicting composition exports')
            records[at] = sorted(actual)
            if at != gate: load('audit-launcher-shape-11318').normalize_function(native, image, function)
    if set(records) != needed: raise ValueError('Composition exports lack all exact 22 roots')
