"""Whole insert/rehash and signed-byte name construction, with explicit services."""
import copy
import hashlib
import json
from pathlib import Path
import re
from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
FAMILY = 'login-container'
CURRENT = 'login-container-v1'
REFERENCE = 'reference-registration-container'
FUNCTIONS = {'register', 'insert', 'rehash', 'name_getter', 'string_constructor'}
FIXTURES = {'utf8_length', 'diagnostic_allocate', 'utf8_convert', 'log', 'free', 'security',
    'node_allocate', 'node_free', 'bucket_reset', 'name_reserve', 'name_grow', 'container_failure', 'name_failure'}
EXTRA = {'insert_scale', 'insert_failure', 'rehash_failure', 'packet_name'}
SHAPES = {'register': (101, 395), 'insert': (204, 760), 'rehash': (113, 429),
    'name_getter': (10, 33), 'string_constructor': (128, 470)}
META = {'schema', 'source', 'source_sha256', 'family', 'format', 'layout', 'exports', 'transfer_proof', 'release_id', 'provenance'}
FIELDS = {'functions', 'bindings', 'leaves', 'fixtures', 'fixture_boundaries', 'globals', 'literals', 'extra_data',
    'call_sites', 'registration_context', 'packet_bytes', 'packet_allocation_bytes', 'owner_bytes', 'node_bytes', 'verify_whole_exports'}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


def tools(): return {str(HERE/'login-container-rules.py'): hashlib.sha256((HERE/'login-container-rules.py').read_bytes()).hexdigest()}


def address(value):
    if not isinstance(value, str) or not re.fullmatch('0x[0-9a-f]+', value): raise ValueError('Container address differs')
    return int(value, 16)


def functional(c):
    if (set(c)-META != FIELDS or type(c.get('schema')) is not int or c['schema'] != 1
            or c.get('family') != FAMILY or c.get('format') not in (CURRENT, REFERENCE)
            or not isinstance(c.get('source_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', c['source_sha256'])
            or not isinstance(c.get('source'), str) or not c['source']
            or set(c.get('functions', {})) != FUNCTIONS or set(c.get('call_sites', {})) != FUNCTIONS
            or set(c.get('fixtures', {})) != FIXTURES or set(c.get('fixture_boundaries', {})) != FIXTURES
            or set(c.get('globals', {})) != {'cookie'} or set(c.get('literals', {})) != {'empty_utf16','log_format','log_owner'}
            or set(c.get('extra_data', {})) != EXTRA or c.get('verify_whole_exports') is not True):
        raise ValueError('Container fields or whole-source scope differ')
    for key, wanted in (('packet_bytes', 352), ('packet_allocation_bytes', 344), ('owner_bytes', 72), ('node_bytes', 40)):
        if type(c.get(key)) is not int or c[key] != wanted: raise ValueError('Container layout differs: '+key)
    p = c['registration_context']
    if (not isinstance(p, dict) or set(p) != {'path','sha256'} or not isinstance(p['path'], str) or not p['path']
            or not isinstance(p['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', p['sha256'])):
        raise ValueError('Container registration pointer differs')
    return {key: copy.deepcopy(value) for key, value in c.items() if key not in META}


def roots(c):
    functional(c); values = {address(at) for at in c['functions'].values()}
    if len(values) != 5: raise ValueError('Container roots alias')
    b = c['bindings']; reg = load('login-registration-rules')
    if set(b) != reg.BINDINGS: raise ValueError('Container registration bindings differ')
    for at in b.values(): address(at)
    for key in ('register', 'insert', 'name_getter'):
        if c['functions'][key] != b[key]: raise ValueError('Container function binding differs')
    if c['leaves'] != {b['id_getter']: 'b804000000c3'}: raise ValueError('Container native ID differs')
    leaf = address(b['id_getter']); hooks = [address(at) for at in c['fixtures'].values()]
    if len(hooks) != len(set(hooks)) or values & set(hooks) or leaf in values or leaf in hooks:
        raise ValueError('Container fixtures shadow native roots or leaf')
    return values


def data(image, at, size): return load('version-system-transfer-rules').image_bytes(image, at, size)


def cstring(image, at):
    out = bytearray()
    for i in range(128):
        byte = data(image, at+i, 1); out += byte
        if byte == b'\0': return bytes(out)
    raise ValueError('Container literal exceeds bound')


def calls(rows):
    return {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands'] for r in rows if r['call']}


def direct(rows, offset):
    row = next((r for r in rows if r['address']-rows[0]['address'] == offset), {})
    if row.get('call') is not True or row.get('direct_target') is None: raise ValueError('Container direct callee differs')
    return row['direct_target']


def whole(native, bindings, image, at, role):
    rr = bindings.rows(native, image, at)
    if not rr or rr[0]['address'] != at or (len(rr), sum(len(bytes.fromhex(r['bytes'])) for r in rr)) != SHAPES[role]:
        raise ValueError('Container whole instruction/chained-unwind shape differs: '+role)
    return rr


def project(native, bindings, image, registration, registration_pointer, *, format=CURRENT):
    old = load('login-registration-rules'); old.roots(registration)
    if registration.get('format') != 'login-registration-v1' or not registration.get('transfer_proof'):
        raise ValueError('Container anchor needs a proved registration context')
    b = copy.deepcopy(registration['bindings'])
    functions = {key: b[key] for key in ('register', 'insert', 'name_getter')}
    rr = {key: whole(native, bindings, image, address(at), key) for key,at in functions.items()}
    functions['rehash'] = hex(direct(rr['insert'], 0x202))
    functions['string_constructor'] = hex(direct(rr['name_getter'], 0x13))
    for key in ('rehash', 'string_constructor'): rr[key] = whole(native, bindings, image, address(functions[key]), key)
    fixtures = {key: value for key,value in registration['fixtures'].items() if key not in ('insert','name_getter')}
    fixtures.update(node_allocate=hex(direct(rr['insert'], 0x2c)), node_free=hex(direct(rr['insert'], 0xc4)),
        bucket_reset=hex(direct(rr['rehash'], 0x57)), container_failure=hex(direct(rr['insert'], 0x2f2)),
        name_reserve=hex(direct(rr['string_constructor'], 0x5a)), name_grow=hex(direct(rr['string_constructor'], 0x77)),
        name_failure=hex(direct(rr['string_constructor'], 0x1d0)))
    if (direct(rr['rehash'], 0x1a7) != address(fixtures['container_failure'])
            or [len(calls(rr[key])) for key in ('register','insert','rehash','name_getter','string_constructor')] != [11,4,2,1,3]):
        raise ValueError('Container caller inventory differs')
    extra = {}; used = {key:set() for key in rr}
    for role, key, offset, size in (('insert_scale','insert',0x1a5,4), ('insert_failure','insert',0x2eb,None),
            ('rehash_failure','rehash',0x1a0,None), ('packet_name','name_getter',9,None)):
        row = next((r for r in rr[key] if r['address']-address(functions[key]) == offset), {})
        refs = row.get('rip_references', [])
        if len(refs) != 1: raise ValueError('Container typed RIP source differs: '+role)
        at = refs[0]; raw = data(image, at, size) if size else cstring(image, at)
        extra[role] = dict(address=hex(at), bytes=raw.hex()); used[key].add(row['address'])
    for key in FUNCTIONS-{'register'}:
        if {r['address'] for r in rr[key] if r['rip_references']} != used[key]: raise ValueError('Undeclared container RIP input')
    if bytes.fromhex(extra['packet_name']['bytes']) != b'PktLoginResult\0': raise ValueError('Container packet name literal differs')
    for key,value in registration['literals'].items():
        raw = bytes.fromhex(value['bytes'])
        if data(image,address(value['address']),len(raw)) != raw: raise ValueError('Container inherited registration literal differs')
    if (data(image,address(b['id_getter']),6) != bytes.fromhex('b804000000c3')
            or int.from_bytes(data(image,address(b['packet_table'])+0x28,8),'little') != address(b['id_getter'])
            or int.from_bytes(data(image,address(b['packet_table'])+0x38,8),'little') != address(functions['name_getter'])):
        raise ValueError('Container packet virtual source links differ')
    c = dict(schema=1, family=FAMILY, format=format, source=registration['source'], source_sha256=registration['source_sha256'],
        functions=functions, bindings=b, leaves={b['id_getter']:'b804000000c3'}, fixtures=fixtures,
        fixture_boundaries={key:old.fixture_boundary(image,address(at)) for key,at in fixtures.items()},
        globals=copy.deepcopy(registration['globals']), literals=copy.deepcopy(registration['literals']), extra_data=extra,
        call_sites={key:calls(value) for key,value in rr.items()}, registration_context=copy.deepcopy(registration_pointer),
        packet_bytes=352, packet_allocation_bytes=344, owner_bytes=72, node_bytes=40, verify_whole_exports=True)
    roots(c); return c, rr


def validate_static(root, native, bindings, image, c):
    roots(c)
    parent = load('portable-native-family').checked(root,c['registration_context'],'generated-native-contexts')
    candidate, rr = project(native,bindings,image,parent,c['registration_context'],format=c['format'])
    if candidate['source_sha256'] != c['source_sha256'] or Path(candidate['source']).resolve() != Path(c['source']).resolve() or functional(candidate) != functional(c):
        raise ValueError('Container source projection differs')
    return rr


def transfer(root, native, bindings, before, after, baseline, mapping, registration, *, registration_pointer):
    previous = validate_static(root,native,bindings,before,baseline)
    current, rows = project(native,bindings,after,registration,registration_pointer)
    common = load('update-native-archive-wire')
    for key in sorted(FUNCTIONS): common.pair_rows(native,previous[key],rows[key],mapping)
    for group in ('functions','bindings','fixtures'):
        for key,at in baseline[group].items(): common.add_link(mapping,address(at),address(current[group][key]))
    for key in EXTRA:
        if baseline['extra_data'][key]['bytes'] != current['extra_data'][key]['bytes']: raise ValueError('Container typed literal/scale changed')
        common.add_link(mapping,address(baseline['extra_data'][key]['address']),address(current['extra_data'][key]['address']))
    return current, dict(method='whole_insert_rehash_and_signed_byte_name', shapes={k:list(v) for k,v in SHAPES.items()},
        native_owner=False, native_dispatch=False, services='Explicit allocation, sized free, bucket reset, reserve, UTF8/log/security fixtures; no OOM/SEH/concurrent mutation claim')


def export_coverage(root, c, native, bindings, image):
    rr = validate_static(root,native,bindings,image,c); wanted = {address(c['functions'][k]):rows for k,rows in rr.items()}; available=set()
    for run,expected in c.get('exports',{}).items():
        if Path(run).name != run or not run.startswith('run-'): raise ValueError('Container export name differs')
        p=Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json';raw=p.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected: raise ValueError('Container export changed')
        report=json.loads(raw)
        if report.get('new_source_sha256',report.get('source_sha256'))!=c['source_sha256']: raise ValueError('Container export source differs')
        for fn in report['functions']:
            at=address(fn['address'])
            if at not in wanted: continue
            if any(fn.get(flag) is not True for flag in ('decompilation_completed','block_coverage_complete','direct_flow_coverage_complete')):
                raise ValueError('Container whole/chained export incomplete')
            actual=[(address(r['address']),r['bytes'].lower()) for r in fn['instructions']]
            exact=[(r['address'],r['bytes'].lower()) for r in wanted[at]]
            if len(actual)!=len({a for a,_ in actual}) or sorted(actual)!=sorted(exact): raise ValueError('Container export exact instruction body differs')
            load('audit-launcher-shape-11318').normalize_function(native,image,fn);available.add(at)
    if available!=set(wanted): raise ValueError('Container exports lack whole roots')
