"""Typed relocation of LoginResult nested layout and complete native input readers.

Pure rules only: callers supply independently proved source mappings, complete
exports and semantic execution. Fixture bodies never acquire native admission.
"""
import copy
import hashlib
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
FAMILIES = ('login-nested', 'login-strings-buffer')
FUNCTIONS = ('constructor', 'reader', 'time_constructor', 'period_constructor', 'time_reader', 'period_reader')
INPUT_NAMES = {'constructor', 'u16', 'u32', 'time', 'u64', 'bool', 'raw', 'string', 'std_string',
               'utf8_length', 'utf8_convert', 'utf8_core', 'utf8_scalar', 'buffer_constructor'}
METADATA = {'schema', 'source', 'source_sha256', 'exports', 'family', 'layout', 'transfer_proof', 'release_id', 'provenance'}
BASE_FIELDS = {'helpers', 'functions', 'leaves', 'packet_table', 'time_table', 'period_table', 'id_getter',
               'string_reader', 'string_constructor', 'verify_whole_exports'}
INPUT_FIELDS = {'source_sha256', 'exports', 'functions', 'leaves', 'table', 'call_sites', 'table_bytes',
                'string_fixtures', 'cookie', 'buffer_construction'}
INPUT_FIXTURES = {'growth', 'utf16_allocate', 'assign', 'free', 'cpp_free', 'security'}
DISPATCH = bytes.fromhex('488b024c8bc2488bd1498bc848ff6020')
BYTE_DISPATCH = bytes.fromhex('488b0141b80100000048ffa090000000')
CALL_ROLES = {
    'constructor': {60: 'root:time_constructor', 123: 'root:time_constructor', 163: 'root:period_constructor',
                    213: 'string_constructor'},
    'reader': {26: 'qword ptr [rax + 0x58]', 44: 'string_reader', 64: 'string_reader', 84: 'string_reader',
               107: 'qword ptr [rax + 0x70]', 125: 'dispatch', 148: 'qword ptr [rax + 0x70]',
               169: 'qword ptr [rax + 0x50]', 187: 'string_reader', 213: 'qword ptr [rax + 0x50]',
               237: 'qword ptr [rax + 0x88]', 261: 'string_reader', 287: 'qword ptr [rax + 0x88]',
               311: 'dispatch', 334: 'string_reader', 357: 'string_reader', 380: 'dispatch',
               406: 'qword ptr [rax + 0x60]', 426: 'qword ptr [rax + 0x60]', 446: 'qword ptr [rax + 0x88]',
               466: 'string_reader', 488: 'qword ptr [rax + 0x60]', 508: 'qword ptr [rax + 0x60]'},
    'time_constructor': {9: 'time_base'},
    'period_constructor': {36: 'time_base', 56: 'time_base', 69: 'time_base', 82: 'time_base'},
    'time_reader': {17: 'qword ptr [rax + 0x28]'},
    'period_reader': {26: 'qword ptr [rax + 0x88]', 43: 'dispatch', 59: 'dispatch', 75: 'dispatch',
                      91: 'dispatch', 110: 'qword ptr [rax + 0x88]'}}


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = module_from_spec(spec); spec.loader.exec_module(value); return value


def tools():
    return {**load('update-native-version-result').tools(), **load('version-system-transfer-rules').tools(),
            str(Path(__file__).resolve()): hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def address(text): return load('version-system-transfer-rules').address(text)


def functional(family, context):
    if family not in FAMILIES: raise ValueError('Unreviewed Login input family')
    fields = BASE_FIELDS | ({'input', 'native_strings', 'function_budget', 'budget_scope'} if family == FAMILIES[1] else set())
    if set(context) - METADATA - {'constructor_defaults'} != fields or context.get('verify_whole_exports') is not True:
        raise ValueError('Login input functional fields or native scope differ')
    if set(context['functions']) != set(FUNCTIONS) or set(context['helpers']) != {'memcpy'}:
        raise ValueError('Login input function/helper roles differ')
    if 'constructor_defaults' in context and set(context['constructor_defaults']) != {'0x130', '0x134'}:
        raise ValueError('Login constructor default roles differ')
    for value in context['functions'].values(): address(value)
    for key in ('packet_table', 'time_table', 'period_table', 'id_getter', 'string_reader', 'string_constructor'):
        address(context[key])
    address(context['helpers']['memcpy'])
    for key, raw in context['leaves'].items():
        address(key)
        if not isinstance(raw, str) or not 1 <= len(bytes.fromhex(raw)) <= 512:
            raise ValueError('Login input bounded leaf declaration differs')
    expected = 6 if family == FAMILIES[1] else 3
    if len(context['leaves']) != expected: raise ValueError('Login input bounded leaf count differs')
    if family == FAMILIES[1]:
        ni = context['input']
        if (context['native_strings'] is not True or type(context['function_budget']) is not int
                or context['function_budget'] != 20 or context['budget_scope'] != 'login-result-buffer'):
            raise ValueError('Login native input budget differs')
        if set(ni) - {'source'} != INPUT_FIELDS or set(ni['functions']) != INPUT_NAMES or set(ni['string_fixtures']) != INPUT_FIXTURES:
            raise ValueError('Login native input function/fixture fields differ')
        exports = ni['exports']
        if (ni['source_sha256'] != context['source_sha256'] or not isinstance(exports, dict) or len(exports) > 4096
                or any(not isinstance(run, str) or Path(run).name != run or not run.startswith('run-')
                    or not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha) for run, sha in exports.items())):
            raise ValueError('Login embedded input source or export scope differs')
        if 'source' in ni and Path(ni['source']).resolve() != Path(context['source']).resolve():
            raise ValueError('Login embedded input path differs')
        if len(ni['leaves']) != 3 or set(ni['leaves']) - set(context['leaves']):
            raise ValueError('Login embedded input leaf scope differs')
        for key, value in ni['leaves'].items():
            if set(value) != {'bytes'} or value['bytes'] != context['leaves'][key]:
                raise ValueError('Login embedded input leaf declaration differs')
        for value in (*ni['functions'].values(), *ni['string_fixtures'].values(), ni['cookie'], ni['table']): address(value)
        mode = ni['buffer_construction']
        if (set(mode) != {'base_table', 'reading_mode', 'reading_endian'} or type(mode['reading_mode']) is not int
                or mode['reading_mode'] != 1 or type(mode['reading_endian']) is not int or mode['reading_endian'] != 0):
            raise ValueError('Login buffer construction mode/endian differs')
        address(mode['base_table'])
        if len(bytes.fromhex(ni['table_bytes'])) != 152: raise ValueError('Login input table byte scope differs')
    result = {key: copy.deepcopy(context[key]) for key in fields}
    if 'constructor_defaults' in context: result['constructor_defaults'] = copy.deepcopy(context['constructor_defaults'])
    return result


def roots(family, context):
    functional(family, context)
    values = [address(value) for value in context['functions'].values()]
    if family == FAMILIES[1]: values.extend(address(value) for value in context['input']['functions'].values())
    wanted = 20 if family == FAMILIES[1] else 6
    if len(set(values)) != wanted: raise ValueError('Login executed roots alias')
    executed = set(values); leaves = {address(at) for at in context['leaves']}
    hooks = {address(context['string_constructor']), address(context['helpers']['memcpy'])}
    if family == FAMILIES[0]: hooks.add(address(context['string_reader']))
    else:
        if context['string_reader'] != context['input']['functions']['string']:
            raise ValueError('Login native string reader linkage differs')
        hooks.update(address(value) for value in context['input']['string_fixtures'].values())
    if (executed & leaves or (executed | leaves) & hooks or len(hooks) != (8 if family == FAMILIES[1] else 3)):
        raise ValueError('Login roots, executed leaves or fixture boundaries alias')
    if context['leaves'].get(context['id_getter']) != 'b804000000c3': raise ValueError('Login packet ID is not 4')
    return executed


def calls(rows):
    return {hex(r['address']): {'target': hex(r['direct_target']) if r['direct_target'] is not None else r['operands']}
            for part in rows.values() for r in part if r['call']}


def leaf_rows(native, image, at, raw):
    utility = load('version-system-transfer-rules'); actual = utility.image_bytes(image, at, len(raw))
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    instructions = list(decoder.disasm(actual, at))
    if not instructions or sum(i.size for i in instructions) != len(raw): raise ValueError('Login bounded leaf instruction gap')
    tail = raw in (DISPATCH, BYTE_DISPATCH)
    if tail:
        if actual != raw or instructions[-1].mnemonic != 'jmp': raise ValueError('Login typed dispatch leaf changed')
    elif instructions[-1].mnemonic != 'ret': raise ValueError('Login bounded leaf return boundary differs')
    result = []; locations = {i.address for i in instructions}
    for ins in instructions:
        call = ins.group(native.capstone.CS_GRP_CALL); branch = ins.group(native.capstone.CS_GRP_JUMP)
        target = ins.operands[0].imm if (call or branch) and ins.operands and ins.operands[0].type == native.X86_OP_IMM else None
        if call or (branch and target not in locations and not (tail and ins is instructions[-1])):
            raise ValueError('Login bounded leaf external edge')
        result.append(dict(address=ins.address, bytes=ins.bytes.hex(), mnemonic=ins.mnemonic, operands=ins.op_str,
            call=call, branch=branch, direct_target=target, rip_references=[ins.address + ins.size + op.mem.disp
                for op in ins.operands if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP]))
    return result


def pair_leaf(native, before, after, mapping):
    if load('update-native-contexts').signature(native, before) != load('update-native-contexts').signature(native, after):
        raise ValueError('Login bounded leaf instruction/control shape changed')
    common = load('update-native-archive-wire')
    for a, b in zip(before, after):
        common.add_link(mapping, a['address'], b['address'])
        if a['direct_target'] is not None: common.add_link(mapping, a['direct_target'], b['direct_target'])
        if len(a['rip_references']) != len(b['rip_references']): raise ValueError('Login bounded leaf data edge count differs')
        if a['branch'] and a['direct_target'] is None and a['operands'] != b['operands']:
            raise ValueError('Login bounded leaf virtual dispatch differs')
        for old, new in zip(a['rip_references'], b['rip_references']): common.add_link(mapping, old, new)


def table(before, after, old, mapping, size, used):
    utility = load('version-system-transfer-rules'); version = load('update-native-version-result')
    if old not in mapping: raise ValueError('Login table lacks constructor/caller linkage')
    raw = utility.image_bytes(before, old, size)
    item = version.table_links(before, after, old, mapping[old], raw.hex(), mapping, used)
    a = struct.unpack('<' + 'Q' * (size // 8), raw); b = struct.unpack('<' + 'Q' * (size // 8), bytes.fromhex(item['bytes']))
    if any((a[i] == a[j]) != (b[i] == b[j]) for i in range(len(a)) for j in range(i)):
        raise ValueError('Login table alias partition differs')
    return item


def _default_data(before, after, baseline, mapping, rows):
    utility = load('version-system-transfer-rules')
    expected = {12: baseline['packet_table'], 168: None, 187: None, 194: None}
    rips = {r['address'] - address(baseline['functions']['constructor']): r['rip_references'] for r in rows['constructor'] if r['rip_references']}
    if set(rips) != set(expected) or any(len(values) != 1 for values in rips.values()) or rips[12] != [address(baseline['packet_table'])]:
        raise ValueError('Login constructor RIP layout differs')
    defaults = {'0x130': hex(rips[168][0]), '0x134': hex(rips[194][0])}
    if baseline.get('constructor_defaults', defaults) != defaults: raise ValueError('Login constructor default provenance differs')
    data = []
    for offset, raw, role in ((168, b'\1\0\0\0', 'uint32@0x130'), (187, b'\0\0', 'empty-utf16'), (194, b'\1\0\0\0', 'uint32@0x134')):
        old = rips[offset][0]; target = mapping[old]
        if utility.image_bytes(before, old, len(raw)) != raw or utility.image_bytes(after, target, len(raw)) != raw:
            raise ValueError('Login exact constructor data changed: ' + role)
        data.append(dict(role=role, address=hex(target), bytes=raw.hex()))
    for role, offset in (('time_constructor', 14), ('period_constructor', 15)):
        actual = {r['address'] - address(baseline['functions'][role]): r['rip_references'] for r in rows[role] if r['rip_references']}
        wanted = {offset: [address(baseline['time_table' if role == 'time_constructor' else 'period_table'])]}
        if role == 'period_constructor': wanted[41] = [address(baseline['time_table'])]
        if actual != wanted: raise ValueError('Login nested constructor table RIP layout differs')
    return {key: hex(mapping[address(value)]) for key, value in defaults.items()}, data


def _call_roles(baseline, rows):
    dispatch = [address(at) for at, raw in baseline['leaves'].items() if bytes.fromhex(raw) == DISPATCH]
    called = [r['direct_target'] for role in ('time_constructor', 'period_constructor') for r in rows[role] if r['call']]
    if len(dispatch) != 1 or not called or len(set(called)) != 1 or hex(called[0]) not in baseline['leaves']:
        raise ValueError('Login nested returning/dispatch leaf linkage differs')
    roles = {'dispatch': dispatch[0], 'time_base': called[0], 'string_constructor': address(baseline['string_constructor']),
             'string_reader': address(baseline['string_reader'])}
    for role, parts in rows.items():
        origin = address(baseline['functions'][role]); actual = {r['address'] - origin: r for r in parts if r['call']}
        if set(actual) != set(CALL_ROLES[role]): raise ValueError('Login nested call-site layout differs')
        for offset, name in CALL_ROLES[role].items():
            row = actual[offset]
            if name.startswith('qword ptr '):
                if row['direct_target'] is not None or row['rip_references'] or row['operands'] != name:
                    raise ValueError('Login nested virtual role differs')
            else:
                target = address(baseline['functions'][name[5:]]) if name.startswith('root:') else roles[name]
                if row['direct_target'] != target: raise ValueError('Login nested direct callee role differs')
    return roles


def cpp_free_boundary(before, after, baseline, current):
    utility = load('version-system-transfer-rules')
    for image, owner in ((before, baseline), (after, current)):
        where = address(owner['string_fixtures']['cpp_free']); raw = utility.image_bytes(image, where, 5)
        if raw[0] != 0xe9 or where + 5 + struct.unpack_from('<i', raw, 1)[0] != address(owner['string_fixtures']['free']):
            raise ValueError('Login C++ free fixture tail boundary differs')


def transfer(family, native, bindings, before, after, baseline, mapping):
    current = functional(family, baseline); roots(family, baseline)
    common = load('update-native-archive-wire'); utility = load('version-system-transfer-rules'); version = load('update-native-version-result')
    version.resolve_roots(native, bindings, before, after, {address(v) for v in baseline['functions'].values()}, mapping)
    old_rows = {}; new_rows = {}
    for role, text in baseline['functions'].items():
        old = address(text); target = mapping[old]; utility.concrete(before, old); utility.concrete(after, target)
        a, b = bindings.rows(native, before, old), bindings.rows(native, after, target)
        common.pair_rows(native, a, b, mapping); old_rows[role], new_rows[role] = a, b
    roles = _call_roles(baseline, old_rows)
    defaults, data = _default_data(before, after, baseline, mapping, old_rows)
    tables = []
    for key, reader, size in (('packet_table', 'reader', 80), ('time_table', 'time_reader', 48), ('period_table', 'period_reader', 48)):
        old = address(baseline[key]); used = {0x20, 0x28} if key == 'packet_table' else {0x20}
        item = table(before, after, old, mapping, size, used)
        raw = utility.image_bytes(before, old, size)
        if struct.unpack_from('<Q', raw, 0x20)[0] != address(baseline['functions'][reader]):
            raise ValueError('Login table reader role differs')
        if key == 'packet_table' and struct.unpack_from('<Q', raw, 0x28)[0] != address(baseline['id_getter']):
            raise ValueError('Login packet ID slot differs')
        item['role'] = key; tables.append(item)
    if family == FAMILIES[1]:
        ni = baseline['input']; input_rows = {}
        for role, text in ni['functions'].items():
            old = address(text)
            if old not in mapping: raise ValueError('Login input requires independent target mapping: ' + role)
            utility.concrete(before, old); utility.concrete(after, mapping[old])
            a = bindings.rows(native, before, old); b = bindings.rows(native, after, mapping[old])
            common.pair_rows(native, a, b, mapping); input_rows[role] = a
        if calls(input_rows) != ni['call_sites']: raise ValueError('Login baseline input call sites differ')
        table_item = table(before, after, address(ni['table']), mapping, 152, version.SLOTS)
        if utility.image_bytes(before, address(ni['table']), 152).hex() != ni['table_bytes']:
            raise ValueError('Login input table declaration differs')
        for slot, role in version.SLOTS.items():
            if struct.unpack_from('<Q', bytes.fromhex(ni['table_bytes']), slot)[0] != address(ni['functions'][role]):
                raise ValueError('Login input table role differs')
        table_item['role'] = 'input'; tables.append(table_item)
        base = table(before, after, address(ni['buffer_construction']['base_table']), mapping, 152, set())
        base['role'] = 'overwritten-buffer-base'; tables.append(base)
        data.extend(version.static_inputs(native, bindings, before, after, {'native_input': ni}, mapping))
    leaves = {}; leaf_reports = []
    for text, raw_hex in baseline['leaves'].items():
        old = address(text); raw = bytes.fromhex(raw_hex)
        if old not in mapping: raise ValueError('Login bounded leaf lacks caller/table linkage')
        if utility.image_bytes(before, old, len(raw)) != raw: raise ValueError('Login baseline bounded leaf bytes differ')
        a = leaf_rows(native, before, old, raw); b = leaf_rows(native, after, mapping[old], raw)
        pair_leaf(native, a, b, mapping)
        actual = utility.image_bytes(after, mapping[old], len(raw)); leaves[hex(mapping[old])] = actual.hex()
        leaf_reports.append(dict(address=hex(mapping[old]), size=len(raw), bytes_sha256=hashlib.sha256(actual).hexdigest(),
                                 kind='exact-virtual-tail' if raw in (DISPATCH, BYTE_DISPATCH) else 'returning-leaf'))
        for row in a:
            for ref in row['rip_references']:
                if ref in {address(baseline['time_table']), address(baseline['period_table']), address(baseline['packet_table'])}:
                    continue
                if family == FAMILIES[1] and ref == address(baseline['input']['buffer_construction']['base_table']): continue
                item = table(before, after, ref, mapping, 48, set()); item['role'] = 'overwritten-time-base'; tables.append(item)
    def mapped(text):
        old = address(text)
        if old not in mapping: raise ValueError('Login undeclared relocated address: ' + text)
        return hex(mapping[old])
    current.update(functions={k: mapped(v) for k, v in baseline['functions'].items()}, leaves=leaves, constructor_defaults=defaults,
                   helpers={'memcpy': mapped(baseline['helpers']['memcpy'])})
    for key in ('packet_table', 'time_table', 'period_table', 'id_getter', 'string_reader', 'string_constructor'): current[key] = mapped(baseline[key])
    fixtures = {}
    for key in ('string_constructor',) + (('string_reader',) if family == FAMILIES[0] else ()):
        utility.concrete(before, address(baseline[key])); utility.concrete(after, address(current[key]))
        fixtures[key] = dict(address=current[key], kind='unwind-fixture', scope='Replaced fixture; body not executed')
    memcpy = utility.import_thunk(before, after, address(baseline['helpers']['memcpy']), address(current['helpers']['memcpy']), 'memcpy', mapping)
    if family == FAMILIES[1]:
        old = baseline['input']; ni = copy.deepcopy(old)
        ni['functions'] = {key: mapped(value) for key, value in old['functions'].items()}
        ni['leaves'] = {mapped(at): {'bytes': leaves[mapped(at)]} for at in old['leaves']}
        ni['table'] = mapped(old['table']); ni['table_bytes'] = next(t['bytes'] for t in tables if t['role'] == 'input')
        ni['cookie'] = mapped(old['cookie']); ni['buffer_construction']['base_table'] = mapped(old['buffer_construction']['base_table'])
        ni['string_fixtures'] = {key: mapped(value) for key, value in old['string_fixtures'].items()}
        ni['call_sites'] = version.call_sites(native, bindings, after, ni['functions'])
        for key, at in old['string_fixtures'].items():
            if key == 'cpp_free':
                cpp_free_boundary(before, after, old, ni)
                kind = 'exact-tail-to-free-fixture'
            else:
                utility.concrete(before, address(at)); utility.concrete(after, address(ni['string_fixtures'][key])); kind = 'unwind-fixture'
            fixtures[key] = dict(address=ni['string_fixtures'][key], kind=kind, scope='Replaced storage/CRT fixture; body not executed')
        current['input'] = ni
    roots(family, dict(current, source_sha256=baseline['source_sha256'], source=baseline['source']))
    _call_roles(current, new_rows)
    return current, dict(tables=tables, typed_inputs=data, leaves=leaf_reports, fixtures=fixtures, memcpy=memcpy,
                         nested_call_roles={key: hex(value) for key, value in roles.items()},
                         excluded_scope='Unexecuted virtual slots, endian-swap/error branches and fixture bodies require separate proof.',
                         mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})
