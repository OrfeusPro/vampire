"""Pure typed relocation of bounded Login continuation and pre-gate errors.

Whole-handler instructions are compared, but only the twelve declared pre-gate
fixtures and four error codes gain semantic coverage from the caller's replay.
Other handler calls, tables and static anchors never admit extra native roots.
"""
import copy
import hashlib
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
FAMILIES = ('login-continuation', 'login-handler-early')
METADATA = {'schema', 'source', 'source_sha256', 'exports', 'family', 'layout', 'transfer_proof', 'release_id', 'provenance'}
CONTINUATION_FIELDS = {'anchors', 'base_table', 'call_sites', 'flag', 'functions', 'getter', 'helpers',
                       'helpers_captured', 'leaves', 'singleton', 'table', 'verify_whole_exports'}
EARLY_FIELDS = {'functions', 'fixtures', 'helpers', 'call_sites', 'gate', 'verify_whole_exports'}
EARLY_FIXTURES = {'string_init', 'log', 'free', 'localizer', 'localized', 'popup54', 'optional_9818',
                  'optional_prepare', 'error_9818', 'optional_90021', 'error_90021', 'error_finish'}
EARLY_CALLS = {'string_init': (45, 1451), 'log': (103,), 'free': (117, 543, 869, 1505, 1519),
               'localizer': (332, 1456), 'localized': (348, 1472), 'popup54': (1491,),
               'optional_9818': (1351,), 'optional_prepare': (927, 1367), 'error_9818': (1377,),
               'optional_90021': (1321,), 'error_90021': (1334,), 'error_finish': (1341, 1384)}
EARLY_RIPS = {31, 50, 57, 64, 77, 289, 295, 306, 317, 417, 648, 739, 747, 766,
              892, 944, 982, 1056, 1189, 1281, 1288, 1394, 1400, 1411, 1418, 1436}
CONTINUATION_RIPS = {'constructor': {31, 44, 51, 83, 105, 127, 149, 174, 202, 213, 225, 237, 249, 261, 273, 288},
                     'reset': {649, 785}}
CAPTURE_LEAF = bytes.fromhex('83790c00c7410800000000740733d2e9eca80000c3')
CALLBACK_LEAF = bytes.fromhex('488bc18b0a48ff20')
WINDOW = 65536


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec); spec.loader.exec_module(module); return module


def tools():
    names = ('login-handler-transfer-rules.py', 'verify-login-handler-early-11320.py', 'verify-login-continuation-context.py')
    return {**load('update-native-version-result').tools(), **load('version-system-transfer-rules').tools(),
            **{str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}}


def address(value): return load('version-system-transfer-rules').address(value)


def functional(family, context):
    fields = CONTINUATION_FIELDS if family == FAMILIES[0] else EARLY_FIELDS if family == FAMILIES[1] else None
    if fields is None: raise ValueError('Unreviewed Login handler family')
    if set(context) - METADATA != fields or context.get('verify_whole_exports') is not True:
        raise ValueError('Login handler functional fields or optional native scope differ')
    if set(context['helpers']) != {'memcpy'}: raise ValueError('Login handler helper roles differ')
    address(context['helpers']['memcpy'])
    names = {'constructor', 'reset'} if family == FAMILIES[0] else {'handler'}
    if set(context['functions']) != names or set(context['call_sites']) != names:
        raise ValueError('Login handler executed/call-site roles differ')
    for role, value in context['functions'].items():
        address(value)
        if not isinstance(context['call_sites'][role], dict): raise ValueError('Login handler call-site declaration differs')
        for at, target in context['call_sites'][role].items():
            address(at)
            if not isinstance(target, str): raise ValueError('Login handler call target declaration differs')
    if family == FAMILIES[0]:
        if (not isinstance(context['anchors'], list) or len(context['anchors']) != 6
                or not isinstance(context['helpers_captured'], list) or len(context['helpers_captured']) != 22
                or set(context['leaves']) != {context['getter']}):
            raise ValueError('Continuation anchor/helper/leaf scope differs')
        for key in ('base_table', 'flag', 'getter', 'singleton', 'table'): address(context[key])
        for value in context['helpers_captured']: address(value)
        for anchor in context['anchors']:
            if set(anchor) != {'address', 'bytes'} or not 1 <= len(bytes.fromhex(anchor['bytes'])) <= 64:
                raise ValueError('Continuation anchor declaration differs')
            address(anchor['address'])
        code = bytes.fromhex(context['leaves'][context['getter']])
        getter = address(context['getter'])
        if (len(code) != 8 or code[:3] != b'\x48\x8b\x05' or code[7:] != b'\xc3'
                or getter + 7 + struct.unpack_from('<i', code, 3)[0] != address(context['singleton'])):
            raise ValueError('Continuation getter/singleton leaf differs')
    else:
        if set(context['fixtures']) != EARLY_FIXTURES: raise ValueError('Pre-gate fixture roles differ')
        for value in context['fixtures'].values(): address(value)
        address(context['gate'])
    return {key: copy.deepcopy(context[key]) for key in fields}


def roots(family, context):
    functional(family, context)
    values = [address(value) for value in context['functions'].values()]
    fixture = [address(value) for value in (context['helpers_captured'] if family == FAMILIES[0] else context['fixtures'].values())]
    leaf = {address(context['getter'])} if family == FAMILIES[0] else set()
    memcpy = address(context['helpers']['memcpy'])
    if (len(values) != len(set(values)) or len(fixture) != len(set(fixture))
            or set(values) & (set(fixture) | leaf) or set(fixture) & leaf or memcpy in set(values) | set(fixture) | leaf):
        raise ValueError('Login handler roots, leaves or fixture roles alias')
    if family == FAMILIES[1] and address(context['gate']) in set(values) | set(fixture) | {memcpy}:
        raise ValueError('Excluded result gate aliases pre-gate scope')
    return set(values)


def call_sites(rows):
    return {role: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in parts if r['call']} for role, parts in rows.items()}


def decode(native, image, at, size):
    raw = load('version-system-transfer-rules').image_bytes(image, at, size)
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); cs.detail = True
    rows = list(cs.disasm(raw, at))
    if not rows or sum(row.size for row in rows) != len(raw): raise ValueError('Login static window instruction gap')
    result = []
    for row in rows:
        call, branch = row.group(native.capstone.CS_GRP_CALL), row.group(native.capstone.CS_GRP_JUMP)
        target = row.operands[0].imm if (call or branch) and row.operands and row.operands[0].type == native.X86_OP_IMM else None
        result.append(dict(address=row.address, bytes=row.bytes.hex(), mnemonic=row.mnemonic, operands=row.op_str,
            call=call, branch=branch, direct_target=target, rip_references=[row.address + row.size + op.mem.disp for op in row.operands
                if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP]))
    return result


def pair_static(native, before, after, mapping):
    common = load('update-native-archive-wire')
    if load('update-native-contexts').signature(native, before) != load('update-native-contexts').signature(native, after):
        raise ValueError('Login static window instruction/control shape changed')
    for a, b in zip(before, after):
        common.add_link(mapping, a['address'], b['address'])
        if a['direct_target'] is not None: common.add_link(mapping, a['direct_target'], b['direct_target'])
        if len(a['rip_references']) != len(b['rip_references']): raise ValueError('Login static window data edge count changed')
        if (a['call'] or a['branch']) and a['direct_target'] is None and not a['rip_references'] and a['operands'] != b['operands']:
            raise ValueError('Login static window indirect dispatch changed')
        for old, new in zip(a['rip_references'], b['rip_references']): common.add_link(mapping, old, new)


def table(before, after, old, mapping, size, used):
    utility = load('version-system-transfer-rules'); version = load('update-native-version-result')
    if old not in mapping: raise ValueError('Login handler table lacks a checked code reference')
    raw = utility.image_bytes(before, old, size)
    result = version.table_links(before, after, old, mapping[old], raw.hex(), mapping, used)
    a = struct.unpack('<' + 'Q' * (size // 8), raw); b = struct.unpack('<' + 'Q' * (size // 8), bytes.fromhex(result['bytes']))
    if any((a[i] == a[j]) != (b[i] == b[j]) for i in range(len(a)) for j in range(i)):
        raise ValueError('Login handler pointer-table alias partition differs')
    return result


def typed_data(before, after, mapping, old, size, expected, role):
    utility = load('version-system-transfer-rules')
    if old not in mapping: raise ValueError('Login handler data lacks a checked code reference: ' + role)
    a, b = utility.data_input(before, old, size), utility.data_input(after, mapping[old], size)
    if a != b or (isinstance(expected, bytes) and a != dict(storage='file', bytes=expected.hex())) or (expected == 'pe-zero-fill' and a['storage'] != expected):
        raise ValueError('Login handler typed data changed: ' + role)
    return dict(role=role, address=hex(mapping[old]), size=size, input=b)


def find_anchor(native, bindings, before, after, anchor, mapping):
    utility = load('version-system-transfer-rules'); old = address(anchor['address']); raw = bytes.fromhex(anchor['bytes'])
    if utility.image_bytes(before, old, len(raw)) != raw: raise ValueError('Continuation baseline anchor bytes differ')
    expected = decode(native, before, old, len(raw)); choices = [mapping[old]] if old in mapping else []
    if not choices:
        # Only a bounded relocation candidate search. Known constructor/getter
        # and singleton edges below eliminate same-shaped unrelated windows.
        prefix = bytes.fromhex(expected[0]['bytes'])[:1 if expected[0]['call'] else 3]
        decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
        ignored = set()
        for ins in decoder.disasm(raw, old):
            offset = ins.address - old
            if (ins.group(native.capstone.CS_GRP_CALL) or ins.group(native.capstone.CS_GRP_JUMP)) and ins.operands and ins.operands[0].type == native.X86_OP_IMM:
                ignored.update(range(offset + ins.imm_offset, offset + ins.imm_offset + ins.imm_size))
            if any(op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP for op in ins.operands):
                ignored.update(range(offset + ins.disp_offset, offset + ins.disp_offset + ins.disp_size))
        fixed = [(offset, value) for offset, value in enumerate(raw) if offset not in ignored]
        for section in after.pe.sections:
            if section['name'] != '.text': continue
            first = max(section['rva'], old - after.pe.base - WINDOW)
            last = min(section['rva'] + section['raw_size'] - len(raw), old - after.pe.base + WINDOW)
            if last < first: continue
            cursor, end = after.offset(first), after.offset(last) + 1
            while cursor < end:
                cursor = after.data.find(prefix, cursor, end)
                if cursor < 0: break
                if all(after.data[cursor + offset] == value for offset, value in fixed):
                    choices.append(after.pe.base + section['rva'] + cursor - section['raw'])
                cursor += 1
                if len(choices) > 4096: raise ValueError('Continuation static anchor candidate budget exceeded')
    hits = []
    for target in sorted(set(choices)):
        try:
            rows = decode(native, after, target, len(raw)); revised = dict(mapping)
            pair_static(native, expected, rows, revised)
            part = after.containing(target)
            if part is None: continue
            owner = after.pe.base + after.roots[part][0]
            whole = bindings.rows(native, after, owner); boundaries = {row['address'] for row in whole}
            if not {row['address'] for row in rows} <= boundaries: continue
            hits.append((target, revised))
        except (ValueError, KeyError): continue
    if len(hits) != 1: raise ValueError('Missing or ambiguous caller-constrained continuation anchor: ' + hex(old))
    target, revised = hits[0]
    for a, b in revised.items(): load('update-native-archive-wire').add_link(mapping, a, b)
    return dict(address=hex(target), bytes=utility.image_bytes(after, target, len(raw)).hex())


def continuation(native, bindings, before, after, baseline, current, mapping, rows):
    utility = load('version-system-transfer-rules'); version = load('update-native-version-result'); common = load('update-native-archive-wire')
    rips = {}
    for role, parts in rows.items():
        origin = address(baseline['functions'][role]); refs = {r['address'] - origin: r['rip_references'] for r in parts if r['rip_references']}
        if set(refs) != CONTINUATION_RIPS[role] or any(len(values) != 1 for values in refs.values()):
            raise ValueError('Continuation RIP role layout differs')
        rips[role] = {offset: values[0] for offset, values in refs.items()}
    if (rips['constructor'][31] != address(baseline['base_table']) or rips['constructor'][44] != address(baseline['singleton'])
            or rips['constructor'][202] != address(baseline['table']) or rips['reset'][649] != address(baseline['flag'])):
        raise ValueError('Continuation table/global role linkage differs')
    tables = []
    for at in sorted(set(rips['constructor'].values()) - {address(baseline['singleton'])}):
        final = at == address(baseline['table']); base = at == address(baseline['base_table'])
        item = table(before, after, at, mapping, 48 if final or base else 8, {40} if final else set())
        item['scope'] = 'Final reset slot executes' if final else 'Stored vptr only; pointed-to code not admitted'
        tables.append(item)
    final = next(row for row in tables if row['address'] == hex(mapping[address(baseline['table'])]))
    if struct.unpack_from('<Q', bytes.fromhex(final['bytes']), 40)[0] != mapping[address(baseline['functions']['reset'])]:
        raise ValueError('Continuation actual final reset slot differs')
    data = [typed_data(before, after, mapping, address(baseline[key]), size, 'pe-zero-fill', key)
            for key, size in (('singleton', 8), ('flag', 1))]
    data.append(typed_data(before, after, mapping, rips['reset'][785], 4, bytes(4), 'reset uint32 default'))
    getter = address(baseline['getter']); code = bytes.fromhex(baseline['leaves'][baseline['getter']])
    spec = dict(bytes=code.hex(), sha256=hashlib.sha256(code).hexdigest())
    if getter not in mapping: common.add_link(mapping, getter, version.leaf_candidate(native, before, after, getter, spec, mapping))
    a, b = decode(native, before, getter, len(code)), decode(native, after, mapping[getter], len(code))
    pair_static(native, a, b, mapping)
    current['leaves'] = {hex(mapping[getter]): utility.image_bytes(after, mapping[getter], len(code)).hex()}
    direct = {r['direct_target'] for part in rows.values() for r in part if r['call'] and r['direct_target'] is not None}
    captured = {address(at) for at in baseline['helpers_captured']}
    if direct - roots(FAMILIES[0], baseline) != captured: raise ValueError('Continuation exact helper call closure differs')
    fixture = []
    for at in sorted(captured):
        target = mapping[at]
        if before.containing(at) is None:
            raw = utility.image_bytes(before, at, len(CAPTURE_LEAF))
            if raw != CAPTURE_LEAF: raise ValueError('Continuation bounded clear fixture changed')
            old, new = decode(native, before, at, len(raw)), decode(native, after, target, len(raw)); pair_static(native, old, new, mapping)
            for image, rr in ((before, old), (after, new)):
                if rr[-1]['mnemonic'] != 'ret' or [(r['address'] - rr[0]['address'], r['mnemonic']) for r in rr if r['branch']] != [(11, 'je'), (15, 'jmp')]:
                    raise ValueError('Continuation clear fixture tail layout differs')
                utility.concrete(image, next(r['direct_target'] for r in rr if r['mnemonic'] == 'jmp'))
            kind = 'bounded-clear-tail-fixture'
        else:
            utility.concrete(before, at); utility.concrete(after, target); kind = 'unwind-fixture'
        fixture.append(dict(address=hex(target), kind=kind, scope='Replaced helper; body not executed'))
    current['anchors'] = []
    for number, anchor in enumerate(baseline['anchors']):
        if number == 4:
            if address(anchor['address']) != address(baseline['table']) or anchor['bytes'] != utility.image_bytes(before, address(baseline['table']), 48).hex():
                raise ValueError('Continuation table anchor declaration differs')
            current['anchors'].append(dict(address=final['address'], bytes=final['bytes']))
        else: current['anchors'].append(find_anchor(native, bindings, before, after, anchor, mapping))
    for key in ('base_table', 'table', 'singleton', 'flag', 'getter'): current[key] = hex(mapping[address(baseline[key])])
    current['helpers_captured'] = [hex(mapping[address(at)]) for at in baseline['helpers_captured']]
    return dict(tables=tables, typed_inputs=data, fixtures=fixture, static_anchors=current['anchors'])


def early(native, bindings, before, after, baseline, current, mapping, rows):
    utility = load('version-system-transfer-rules'); origin = address(baseline['functions']['handler'])
    calls = {r['address'] - origin: r for r in rows['handler'] if r['call']}
    if 213 not in calls or calls[213]['direct_target'] != address(baseline['gate']):
        raise ValueError('Pre-gate excluded gate linkage differs')
    for role, offsets in EARLY_CALLS.items():
        for offset in offsets:
            if offset not in calls or calls[offset]['direct_target'] != address(baseline['fixtures'][role]):
                raise ValueError('Pre-gate exact fixture call role differs: ' + role)
    refs = {r['address'] - origin: r['rip_references'] for r in rows['handler'] if r['rip_references']}
    if set(refs) != EARLY_RIPS or any(len(values) != 1 for values in refs.values()):
        raise ValueError('Pre-gate whole-handler RIP layout differs')
    refs = {offset: values[0] for offset, values in refs.items()}
    literals = {31: ('Recv PktLoginResult\0').encode('utf-16le'),
                1288: ('PktLoginResultHandler::OnHandler() - JoinedCountryCode( %s )\0').encode('utf-16le'),
                1411: ('COMMON_SERVER_WATING_FULL\0').encode('utf-16le')}
    exact = {50: bytes.fromhex('00ffffff'), 57: struct.pack('<dd', 1.0, 1.0), 64: struct.pack('<f', 3.0),
             289: struct.pack('<I', 250), 739: bytes.fromhex('00000000a3e1c141'), 747: struct.pack('<d', 0.5),
             1056: bytes(4), 1281: bytes(2), 1394: struct.pack('<I', 250), **literals}
    zero = {77: 8, 417: 1, 648: 1, 766: 8, 892: 8, 944: 8, 982: 1, 1189: 1}
    typed = [typed_data(before, after, mapping, refs[offset], len(raw), raw, 'handler RIP+' + str(offset)) for offset, raw in exact.items()]
    typed.extend(typed_data(before, after, mapping, refs[offset], size, 'pe-zero-fill', 'handler global+' + str(offset)) for offset, size in zero.items())
    tables = [table(before, after, refs[offset], mapping, 32, set()) for offset in (295, 1400)]
    callbacks = []
    for offset in (306, 1418):
        utility.concrete(before, refs[offset]); utility.concrete(after, mapping[refs[offset]])
        callbacks.append(dict(address=hex(mapping[refs[offset]]), scope='Stored popup callback; not invoked'))
    for offset in (317, 1436):
        for image, at in ((before, refs[offset]), (after, mapping[refs[offset]])):
            if utility.image_bytes(image, at, len(CALLBACK_LEAF)) != CALLBACK_LEAF:
                raise ValueError('Pre-gate stored callback dispatch leaf changed')
        callbacks.append(dict(address=hex(mapping[refs[offset]]), bytes=CALLBACK_LEAF.hex(), scope='Stored callback thunk; not invoked'))
    excluded = set(calls) - {offset for offsets in EARLY_CALLS.values() for offset in offsets}
    current['fixtures'] = {key: hex(mapping[address(at)]) for key, at in baseline['fixtures'].items()}
    current['gate'] = hex(mapping[address(baseline['gate'])])
    fixtures = []
    for role, text in baseline['fixtures'].items():
        old = address(text); target = mapping[old]
        if role in ('log', 'localizer'):
            size = 3 if role == 'log' else 8
            a = utility.image_bytes(before, old, size); b = utility.image_bytes(after, target, size)
            if role == 'log':
                if a != b'\xc2\0\0' or b != a: raise ValueError('Pre-gate logging return fixture changed')
            else:
                if a[:3] != b'\x48\x8b\x05' or b[:3] != a[:3] or a[7:] != b'\xc3' or b[7:] != a[7:]:
                    raise ValueError('Pre-gate localizer getter fixture changed')
                old_rows, new_rows = decode(native, before, old, size), decode(native, after, target, size)
                pair_static(native, old_rows, new_rows, mapping)
                at = old_rows[0]['rip_references'][0]
                typed.append(typed_data(before, after, mapping, at, 8, 'pe-zero-fill', 'localizer fixture singleton'))
            kind = 'bounded-returning-fixture'
        else:
            utility.concrete(before, old); utility.concrete(after, target); kind = 'unwind-fixture'
        fixtures.append(dict(role=role, address=hex(target), kind=kind, scope='Replaced pre-gate service; body not executed'))
    return dict(typed_inputs=typed, tables=tables, fixtures=fixtures, callbacks=callbacks,
                excluded_calls=[dict(offset=offset, target=hex(mapping[calls[offset]['direct_target']]) if calls[offset]['direct_target'] is not None else calls[offset]['operands'],
                                     scope='Not executed by the four covered pre-gate error paths') for offset in sorted(excluded)])


def transfer(family, native, bindings, before, after, baseline, mapping):
    current = functional(family, baseline); expected = roots(family, baseline)
    common = load('update-native-archive-wire'); version = load('update-native-version-result'); utility = load('version-system-transfer-rules')
    version.resolve_roots(native, bindings, before, after, expected, mapping)
    old_rows, new_rows = {}, {}
    for role, text in baseline['functions'].items():
        old = address(text); target = mapping[old]; utility.concrete(before, old); utility.concrete(after, target)
        a, b = bindings.rows(native, before, old), bindings.rows(native, after, target)
        common.pair_rows(native, a, b, mapping); old_rows[role], new_rows[role] = a, b
    if call_sites(old_rows) != baseline['call_sites']: raise ValueError('Login handler baseline call-site declaration differs')
    detail = continuation(native, bindings, before, after, baseline, current, mapping, old_rows) if family == FAMILIES[0] else early(native, bindings, before, after, baseline, current, mapping, old_rows)
    current['functions'] = {role: hex(mapping[address(text)]) for role, text in baseline['functions'].items()}
    current['call_sites'] = call_sites(new_rows)
    memcpy = address(baseline['helpers']['memcpy'])
    if memcpy not in mapping: common.add_link(mapping, memcpy, load('update-native-contexts').find_memcpy(native, before, after, memcpy))
    current['helpers'] = {'memcpy': hex(mapping[memcpy])}
    detail['memcpy'] = utility.import_thunk(before, after, memcpy, mapping[memcpy], 'memcpy', mapping)
    roots(family, current)
    detail['mapping'] = {hex(a): hex(b) for a, b in sorted(mapping.items())}
    detail['scope'] = 'Two native continuation roots/getter with explicit helper fixtures' if family == FAMILIES[0] else 'One whole handler, four pre-gate error codes only; result gate and success paths not executed'
    return current, detail
