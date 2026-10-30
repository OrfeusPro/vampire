"""Typed one-root result gate with explicit code and two-level inline switch data.

This pure rule validates relocation and complete exports. Semantic replay and
publication belong to the caller. Inline bytes never become admitted code.
"""
import copy
import hashlib
from importlib.util import spec_from_file_location, module_from_spec
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
METADATA = {'schema', 'source', 'source_sha256', 'exports', 'family', 'layout', 'transfer_proof', 'release_id', 'provenance'}
FIELDS = {'function', 'helpers', 'fixtures', 'switch', 'call_sites', 'verify_whole_exports'}
SWITCH_FIELDS = {'code_end', 'unwind_end', 'table', 'index', 'dispatch_start', 'dispatch',
                 'table_bytes', 'index_bytes', 'dispatch_bytes', 'input_first', 'input_count'}
OFFSETS = dict(code_end=1047, unwind_end=1291, table=1048, index=1064, dispatch_start=497, dispatch=541)
INDEXED = {523: ('index', 4, 4), 531: ('table', 3, 4)}
RIP_OFFSETS = {162, 308, 327, 334, 341, 354, 422, 514, 601, 624, 643, 684, 807, 861}
CALL_OFFSETS = {36, 142, 152, 173, 178, 194, 208, 222, 240, 292, 322, 380, 394, 412, 433, 438, 454, 465,
                578, 587, 611, 619, 638, 654, 659, 675, 726, 740, 751, 765, 779, 797, 872, 877, 893,
                904, 918, 932, 939, 952, 961, 975, 1001, 1015}
WINDOW = 65536


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = module_from_spec(spec); spec.loader.exec_module(module); return module


def tools():
    names = ('result-gate-transfer-rules.py', 'version-gate-switch-11320.py', 'verify-version-result-handler-context.py')
    return {**load('update-native-version-result').tools(), **load('version-system-transfer-rules').tools(),
            **{str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}}


def address(value): return load('version-system-transfer-rules').address(value)


def functional(c):
    if set(c) - METADATA != FIELDS or c.get('verify_whole_exports') is not True:
        raise ValueError('Result gate functional fields or optional native scope differ')
    at = address(c['function']); switch = c['switch']
    if (not isinstance(switch, dict) or set(switch) != SWITCH_FIELDS or type(switch['input_first']) is not int
            or switch['input_first'] != 0x519 or type(switch['input_count']) is not int or switch['input_count'] != 227):
        raise ValueError('Result gate input/index layout differs')
    for key, offset in OFFSETS.items():
        if address(switch[key]) != at + offset: raise ValueError('Result gate code/data partition differs: ' + key)
    if (len(bytes.fromhex(switch['table_bytes'])) != 16 or len(bytes.fromhex(switch['index_bytes'])) != 227
            or len(bytes.fromhex(switch['dispatch_bytes'])) != 46 or max(bytes.fromhex(switch['index_bytes'])) > 3):
        raise ValueError('Result gate inline table byte scope differs')
    if set(c['helpers']) != {'memcpy'} or set(c['fixtures']) != {'gate_state', 'gate_error'}:
        raise ValueError('Result gate helper/fixture roles differ')
    for value in (*c['helpers'].values(), *c['fixtures'].values()): address(value)
    if not isinstance(c['call_sites'], dict): raise ValueError('Result gate call-site declaration differs')
    for text, value in c['call_sites'].items():
        address(text)
        if not isinstance(value, str) or not re.fullmatch('0x[0-9a-fA-F]+', value):
            raise ValueError('Result gate requires explicit direct call targets')
    return {key: copy.deepcopy(c[key]) for key in FIELDS}


def roots(c):
    functional(c); root = address(c['function']); hooks = [address(at) for at in (*c['helpers'].values(), *c['fixtures'].values())]
    if root in hooks or len(hooks) != len(set(hooks)): raise ValueError('Result gate root and fixture roles alias')
    return {root}


def dispatch_bytes(image, c):
    s = c['switch']; first = address(s['dispatch_start']); table, index = address(s['table']), address(s['index'])
    if image.pe.base != 0x140000000: raise ValueError('Result gate image-base ABI differs')
    return (bytes.fromhex('8d83e7faffff3de20000000f87e3010000488d15')
        + struct.pack('<i', image.pe.base - (first + 24)) + bytes.fromhex('48980fb68402')
        + struct.pack('<i', index - image.pe.base) + bytes.fromhex('8b8c82')
        + struct.pack('<i', table - image.pe.base) + bytes.fromhex('4803caffe1'))


def rows(native, image, c):
    """Decode exact code only; validate the inline arrays and dispatch separately."""
    roots(c); entry = address(c['function']); s = c['switch']; utility = load('version-system-transfer-rules')
    fragment = image.containing(entry)
    if (fragment is None or image.roots[fragment][0] + image.pe.base != entry
            or fragment[1] + image.pe.base != address(s['unwind_end'])):
        raise ValueError('Result gate explicit unwind range differs')
    raw = utility.image_bytes(image, entry, address(s['code_end']) - entry)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    instructions = list(decoder.disasm(raw, entry)); result = []
    if len(instructions) != 251 or sum(row.size for row in instructions) != len(raw) or instructions[-1].mnemonic != 'ret':
        raise ValueError('Result gate exact code boundary/instruction count differs')
    local = {row.address for row in instructions}
    for ins in instructions:
        call, branch = ins.group(native.capstone.CS_GRP_CALL), ins.group(native.capstone.CS_GRP_JUMP)
        direct = ins.operands[0].imm if (call or branch) and ins.operands and ins.operands[0].type == native.X86_OP_IMM else None
        if branch and ((direct is None and ins.address != address(s['dispatch'])) or (direct is not None and direct not in local)):
            raise ValueError('Result gate branch leaves declared code or changes indirect dispatch')
        if call and direct is None: raise ValueError('Result gate unexpected indirect call/import')
        result.append(dict(address=ins.address, bytes=ins.bytes.hex(), mnemonic=ins.mnemonic, operands=ins.op_str,
            call=call, branch=branch, direct_target=direct, rip_references=[ins.address + ins.size + op.mem.disp for op in ins.operands
                if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP]))
    if {r['address'] - entry for r in result if r['call']} != CALL_OFFSETS:
        raise ValueError('Result gate direct call layout differs')
    if {r['address'] - entry for r in result if r['rip_references']} != RIP_OFFSETS:
        raise ValueError('Result gate RIP input layout differs')
    calls = {hex(r['address']): hex(r['direct_target']) for r in result if r['call']}
    if calls != c['call_sites']: raise ValueError('Result gate call-site declaration differs')
    by_offset = {r['address'] - entry: r for r in result}
    for offset, role in ((36, 'gate_state'), (961, 'gate_error'), (1001, 'gate_error')):
        if by_offset[offset]['direct_target'] != address(c['fixtures'][role]):
            raise ValueError('Result gate fixture callee role differs')
    raw_table = bytes.fromhex(s['table_bytes']); raw_index = bytes.fromhex(s['index_bytes']); dispatch = dispatch_bytes(image, c)
    for text, wanted in ((s['table'], raw_table), (s['index'], raw_index), (s['dispatch_start'], dispatch)):
        if utility.image_bytes(image, address(text), len(wanted)) != wanted:
            raise ValueError('Result gate inline table/dispatch bytes changed')
    if bytes.fromhex(s['dispatch_bytes']) != dispatch or utility.image_bytes(image, address(s['code_end']), 1) != b'\x90':
        raise ValueError('Result gate typed dispatch or code/data alignment differs')
    targets = [image.pe.base + value for value in struct.unpack('<4I', raw_table)]
    if (any(target not in local for target in targets) or targets[0] != targets[3]
            or len(set(targets)) != 3 or len(set(targets[:3])) != 3):
        raise ValueError('Result gate RVA target boundary/alias layout differs')
    for offset, (role, disp_offset, disp_size) in INDEXED.items():
        ins = next(value for value in instructions if value.address == entry + offset)
        if (ins.disp_offset != disp_offset or ins.disp_size != disp_size or ins.operands[-1].type != native.X86_OP_MEM
                or ins.operands[-1].mem.disp != address(s[role]) - image.pe.base):
            raise ValueError('Result gate typed indexed displacement role differs')
    if by_offset[514]['rip_references'] != [image.pe.base]: raise ValueError('Result gate image-base linkage differs')
    return result


def signature(native, code):
    """The two reviewed image-relative indexed displacements have typed roles."""
    adjusted = copy.deepcopy(code); decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    origin = code[0]['address']
    for row in adjusted:
        offset = row['address'] - origin
        if offset in INDEXED:
            _, start, size = INDEXED[offset]; raw = bytearray.fromhex(row['bytes']); ins = next(decoder.disasm(bytes(raw), row['address']))
            if (ins.disp_offset, ins.disp_size) != (start, size): raise ValueError('Result gate indexed mask layout differs')
            raw[start:start + size] = bytes(size); row['bytes'] = raw.hex()
    return load('update-native-contexts').signature(native, adjusted)


def pair_rows(native, before, after, mapping):
    if signature(native, before) != signature(native, after): raise ValueError('Result gate whole instruction/control shape changed')
    common = load('update-native-archive-wire')
    for a, b in zip(before, after):
        common.add_link(mapping, a['address'], b['address'])
        if a['direct_target'] is not None: common.add_link(mapping, a['direct_target'], b['direct_target'])
        if len(a['rip_references']) != len(b['rip_references']): raise ValueError('Result gate data edge count changed')
        for old, new in zip(a['rip_references'], b['rip_references']): common.add_link(mapping, old, new)


def target_context(before, after, baseline, at):
    c = functional(baseline); old = address(baseline['function']); delta = at - old; c['function'] = hex(at)
    for key in OFFSETS: c['switch'][key] = hex(address(baseline['switch'][key]) + delta)
    image_bytes = load('version-system-transfer-rules').image_bytes
    for key, name, size in (('table', 'table_bytes', 16), ('index', 'index_bytes', 227), ('dispatch_start', 'dispatch_bytes', 46)):
        c['switch'][name] = image_bytes(after, address(c['switch'][key]), size).hex()
    # Build the target call inventory from its exact code range, before rows()
    # admits any byte. Every callee still must compare against the old closure.
    native = load('build-native-entry-code'); decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    ins = list(decoder.disasm(image_bytes(after, at, 1047), at))
    c['call_sites'] = {hex(row.address): hex(row.operands[0].imm) for row in ins
                      if row.group(native.capstone.CS_GRP_CALL) and row.operands and row.operands[0].type == native.X86_OP_IMM}
    for offset, role in ((36, 'gate_state'), (961, 'gate_error')):
        text = c['call_sites'].get(hex(at + offset))
        if text is None: raise ValueError('Result gate target fixture call is missing')
        c['fixtures'][role] = text
    return c


def resolve(native, bindings, before, after, baseline, mapping):
    old = address(baseline['function']); expected = rows(native, before, baseline); hits = []
    if old in mapping: candidates = [mapping[old]]
    else:
        candidates = sorted({after.pe.base + span[0] for span in after.roots.values()
            if span[1] - span[0] == OFFSETS['unwind_end'] and abs(after.pe.base + span[0] - old) <= WINDOW})
        if len(candidates) > 4096: raise ValueError('Result gate candidate root budget exceeded')
    for at in candidates:
        try:
            c = target_context(before, after, baseline, at); actual = rows(native, after, c); revised = dict(mapping)
            pair_rows(native, expected, actual, revised); hits.append((c, revised))
        except (ValueError, KeyError, struct.error): continue
    if len(hits) != 1: raise ValueError('Missing or ambiguous complete typed result gate')
    c, revised = hits[0]
    for a, b in revised.items(): load('update-native-archive-wire').add_link(mapping, a, b)
    return c, expected, rows(native, after, c)


def typed_inputs(native, before, after, baseline, current, mapping, code):
    utility = load('version-system-transfer-rules'); entry = address(baseline['function'])
    refs = {row['address'] - entry: row['rip_references'][0] for row in code if row['rip_references']}
    literals = {162: b'NAME_SLANDER\0', 422: 'GUILDINVENTORY_SLOT_FULL\0'.encode('utf-16le'),
                624: '[AssetName]\0'.encode('utf-16le'), 643: 'ASSET_MAXVALUE_ERROR_MAIL\0'.encode('utf-16le'),
                807: 'GUILD_INVITE_NOTUSER_MESSAGE\0'.encode('utf-16le'), 861: 'CHAT_SPAM_MSG\0'.encode('utf-16le')}
    exact = {308: bytes(2), 327: bytes.fromhex('00ffffff'), 334: struct.pack('<dd', 1, 1), 341: struct.pack('<f', 3),
             601: struct.pack('<I', 250), 684: bytes(2), **literals}
    reports = []
    for offset, raw in exact.items():
        old = refs[offset]; new = mapping[old]
        if utility.image_bytes(before, old, len(raw)) != raw or utility.image_bytes(after, new, len(raw)) != raw:
            raise ValueError('Result gate exact typed input changed at offset ' + str(offset))
        reports.append(dict(offset=offset, address=hex(new), bytes=raw.hex(), scope='Exact compiled literal/constant; service behavior is separate'))
    old = refs[354]; new = mapping[old]
    a, b = utility.data_input(before, old, 8), utility.data_input(after, new, 8)
    if a != b or a['storage'] != 'pe-zero-fill': raise ValueError('Result gate logging singleton storage changed')
    reports.append(dict(offset=354, address=hex(new), input=b, scope='Synthetic state; actual logging provider not executed'))
    calls = {row['address'] - entry: row['direct_target'] for row in code if row['call']}
    returning = {380: bytes.fromhex('c20000'), 587: bytes.fromhex('488b4108c3')}
    getter_offsets = {36, 142, 178}; fixtures = []
    checked = set()
    for offset, old in sorted(calls.items()):
        if old in checked: continue
        checked.add(old); new = mapping[old]
        if offset in returning:
            raw = returning[offset]
            if utility.image_bytes(before, old, len(raw)) != raw or utility.image_bytes(after, new, len(raw)) != raw:
                raise ValueError('Result gate bounded returning boundary changed')
            kind = 'bounded-returning-leaf'
        elif offset in getter_offsets:
            a, b = utility.image_bytes(before, old, 8), utility.image_bytes(after, new, 8)
            if a[:3] != b'\x48\x8b\x05' or b[:3] != a[:3] or a[7:] != b'\xc3' or b[7:] != a[7:]:
                raise ValueError('Result gate singleton getter boundary changed')
            old_slot, new_slot = old + 7 + struct.unpack_from('<i', a, 3)[0], new + 7 + struct.unpack_from('<i', b, 3)[0]
            load('update-native-archive-wire').add_link(mapping, old_slot, new_slot)
            x, y = utility.data_input(before, old_slot, 8), utility.data_input(after, new_slot, 8)
            if x != y or x['storage'] != 'pe-zero-fill': raise ValueError('Result gate getter storage changed')
            kind = 'bounded-singleton-getter'
        else:
            utility.concrete(before, old); utility.concrete(after, new); kind = 'unwind-entry'
        fixtures.append(dict(offset=offset, address=hex(new), kind=kind,
            scope='Explicit replay fixture; body not executed' if old in {address(v) for v in baseline['fixtures'].values()} else 'Excluded callee; body not admitted'))
    return reports, fixtures


def export_coverage(root, c, native, bindings, image):
    wanted = rows(native, image, c); entry = address(c['function']); available = False; declarations = {}
    for run, expected in c.get('exports', {}).items():
        if not isinstance(run, str) or Path(run).name != run or not run.startswith('run-'):
            raise ValueError('Invalid result gate export name')
        path = Path(root) / 'ghidra/request-exports' / c['source_sha256'] / run / 'details.json'
        if load('update-native-contexts').digest(path) != expected: raise ValueError('Result gate export changed')
        d = json.loads(path.read_text('utf-8'))
        if d.get('new_source_sha256', d.get('source_sha256')) != c['source_sha256']:
            raise ValueError('Result gate export source differs')
        for f in d.get('functions', []):
            if int(f['address'], 16) != entry: continue
            if any(f.get(key) is not True for key in ('decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
                raise ValueError('Result gate export whole code/data coverage incomplete')
            current = [(int(r['address'], 16), r['bytes'].lower()) for r in f.get('instructions', [])]
            if len(current) != len(set(at for at, _ in current)): raise ValueError('Result gate export duplicates instructions')
            exact = [(r['address'], r['bytes'].lower()) for r in wanted]
            if sorted(current) != sorted(exact): raise ValueError('Result gate export exact code/data separation differs')
            canonical = json.dumps(sorted(current), sort_keys=True)
            if entry in declarations and declarations[entry] != canonical: raise ValueError('Result gate conflicting complete exports')
            declarations[entry] = canonical; available = True
    if not available: raise ValueError('Result gate complete export is missing')


def transfer(native, bindings, before, after, baseline, mapping):
    roots(baseline); current, old_rows, new_rows = resolve(native, bindings, before, after, baseline, mapping)
    utility = load('version-system-transfer-rules'); common = load('update-native-archive-wire')
    for key in ('table', 'index'): common.add_link(mapping, address(baseline['switch'][key]), address(current['switch'][key]))
    if current['switch']['index_bytes'] != baseline['switch']['index_bytes']:
        raise ValueError('Result gate dispatch index semantics changed')
    old_targets = [before.pe.base + value for value in struct.unpack('<4I', bytes.fromhex(baseline['switch']['table_bytes']))]
    new_targets = [after.pe.base + value for value in struct.unpack('<4I', bytes.fromhex(current['switch']['table_bytes']))]
    for a, b in zip(old_targets, new_targets): common.add_link(mapping, a, b)
    data, boundaries = typed_inputs(native, before, after, baseline, current, mapping, old_rows)
    memcpy = address(baseline['helpers']['memcpy'])
    if memcpy not in mapping: common.add_link(mapping, memcpy, load('update-native-contexts').find_memcpy(native, before, after, memcpy))
    current['helpers'] = {'memcpy': hex(mapping[memcpy])}
    thunk = utility.import_thunk(before, after, memcpy, mapping[memcpy], 'memcpy', mapping)
    roots(current); rows(native, after, current)
    return current, dict(code_instructions=251, code_bytes=1047, inline_index_bytes=227,
        indexed_displacements={str(offset): list(spec) for offset, spec in INDEXED.items()},
        target_rva_slots=[hex(at) for at in new_targets], target_alias_partition=[[0, 3], [1], [2]], typed_inputs=data,
        callee_boundaries=boundaries, memcpy=thunk, scope='One native result gate with explicit code/data partition; external services remain fixtures or excluded',
        mapping={hex(a): hex(b) for a, b in sorted(mapping.items())})
