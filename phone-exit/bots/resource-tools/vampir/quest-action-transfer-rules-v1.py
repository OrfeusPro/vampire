"""Ordered static QuestUpdate wire and Tutorial dispatch closure, without admission.

Complete roots use bounded candidates and consistent instruction/data edges.
The only external root branches are the explicitly reviewed Tutorial tails.
Storage, application, endian and other packet branches remain entry fixtures.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
POLICY = HERE / 'knowledge/quest-action-transfer-rules.json'
RECIPE = 'quest-action-transfer-rules-v1'
LIMIT = 32 * 1024 * 1024
FLAGS = dict(target_exports_verified=False, native_consumer_verified=False,
             consumer_semantic_verified=False, runtime_activated=False, profile_activated=False)
DEPENDENCIES = {'input_seed', 'reader_transfer', 'output_context', 'output_check', 'baselines'}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def tools():
    names = ('quest-reader-transfer-rules-v1', 'quest-input-seed-v2', 'update-native-version-result',
             'update-native-archive-wire', 'update-native-contexts', 'update-bindings',
             'login-input-transfer-rules', 'version-system-transfer-rules',
             'build-native-entry-code', 'extract-native-enums', 'build-object-zero-init-code')
    return {str(p): digest(p) for p in (Path(__file__).resolve(), POLICY,
            *(HERE / (name + '.py') for name in names))}


def address(text):
    if not isinstance(text, str) or not re.fullmatch('0x[0-9a-f]+', text):
        raise ValueError('Action address must be canonical')
    return int(text, 16)


def policy():
    raw = POLICY.read_bytes()
    if len(raw) > 256 * 1024: raise ValueError('Action rule exceeds budget')
    value = json.loads(raw)
    if (type(value.get('schema')) is not int or value['schema'] != 1 or value.get('recipe') != RECIPE
            or len(value.get('roots', {})) != 19 or len(value.get('leaves', {})) != 11
            or len(value.get('tables', {})) != 10 or len(value.get('boundaries', {})) != 13):
        raise ValueError('Action reviewed policy shape differs')
    return value


def document(index, pointer, folder=None):
    if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
            or not isinstance(pointer['path'], str) or not Path(pointer['path']).is_absolute()
            or not isinstance(pointer['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', pointer['sha256'])):
        raise ValueError('Action dependency needs an exact absolute pointer')
    path = Path(pointer['path']).resolve()
    if folder is not None and not path.is_relative_to(Path(folder).resolve()):
        raise ValueError('Action dependency escapes its selected scope')
    with path.open('rb') as stream: raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT or hashlib.sha256(raw).hexdigest() != pointer['sha256']:
        raise ValueError('Action dependency changed or exceeds budget')
    value = json.loads(raw)
    if not isinstance(value, dict): raise ValueError('Action dependency must be an object')
    return value


def row_policy(rows, at):
    locations = {row['address'] for row in rows}
    def target(row): return hex(row['direct_target']) if row['direct_target'] is not None else row['operands']
    return dict(calls={str(row['address'] - at): target(row) for row in rows if row['call']},
        data={str(row['address'] - at): [hex(x) for x in row['rip_references']]
              for row in rows if row['rip_references']},
        tails={str(row['address'] - at): target(row) for row in rows
               if row['branch'] and not row['call'] and row['direct_target'] not in locations})


def pair(native, old, new, mapping, spec):
    """Instruction equality with only the source-declared external JMP edges."""
    if not old or row_policy(old, old[0]['address']) != {k: spec[k] for k in ('calls', 'data', 'tails')}:
        raise ValueError('Action call/data/tail policy differs')
    if load('update-native-contexts').signature(native, old) != load('update-native-contexts').signature(native, new):
        raise ValueError('Action whole instruction/control shape changed')
    common = load('update-native-archive-wire'); locations = {r['address'] for r in old}
    for a, b in zip(old, new):
        if a['branch'] and not a['call'] and a['direct_target'] not in locations:
            offset = str(a['address'] - old[0]['address'])
            if (a['mnemonic'] != 'jmp' or a['direct_target'] is None
                    or spec['tails'].get(offset) != hex(a['direct_target']) or b['mnemonic'] != 'jmp'):
                raise ValueError('Action external branch is outside typed tail policy')
        if a['call'] and a['direct_target'] is None and not a['rip_references'] and a['operands'] != b['operands']:
            raise ValueError('Action indirect caller changed')
        common.add_link(mapping, a['address'], b['address'])
        if a['direct_target'] is not None: common.add_link(mapping, a['direct_target'], b['direct_target'])
        if len(a['rip_references']) != len(b['rip_references']): raise ValueError('Action data edge count differs')
        for x, y in zip(a['rip_references'], b['rip_references']): common.add_link(mapping, x, y)


def resolve(native, bindings, api, before, after, reviewed, mapping):
    choices = {address(at): api.candidates(native, bindings, before, after, address(at)) for at in reviewed['roots']}
    pending, reports = set(choices), []
    while pending:
        progress = False
        for at in sorted(pending):
            hits = []
            for target in choices[at]:
                if at in mapping and mapping[at] != target: continue
                revised = dict(mapping)
                try:
                    load('update-native-archive-wire').add_link(revised, at, target)
                    pair(native, bindings.rows(native, before, at), bindings.rows(native, after, target),
                         revised, reviewed['roots'][hex(at)])
                except ValueError: continue
                hits.append((target, revised))
            if len(hits) != 1: continue
            target, revised = hits[0]; mapping.clear(); mapping.update(revised)
            reports.append(dict(baseline=hex(at), target=hex(target), candidates=len(choices[at]),
                whole_instruction_shape_verified=True, **copy.deepcopy(reviewed['roots'][hex(at)])))
            pending.remove(at); progress = True
        if not progress: raise ValueError('Action ambiguous call-constrained roots: ' + ','.join(hex(x) for x in sorted(pending)))
    return sorted(reports, key=lambda r: address(r['baseline']))


def decode(native, image, at, size):
    raw = load('update-native-version-result').image_bytes(image, at, size)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    result = []
    for ins in decoder.disasm(raw, at):
        call = ins.group(native.capstone.CS_GRP_CALL); branch = ins.group(native.capstone.CS_GRP_JUMP)
        target = ins.operands[0].imm if (call or branch) and ins.operands and ins.operands[0].type == native.X86_OP_IMM else None
        result.append(dict(address=ins.address, bytes=ins.bytes.hex(), mnemonic=ins.mnemonic, operands=ins.op_str,
            call=call, branch=branch, direct_target=target, rip_references=[ins.address + ins.size + o.mem.disp
                for o in ins.operands if o.type == native.X86_OP_MEM and o.mem.base == native.X86_REG_RIP]))
    if not result or sum(len(bytes.fromhex(row['bytes'])) for row in result) != size:
        raise ValueError('Action bounded instruction window has a gap')
    return result


def masked_hits(image, old, raw, mask, predicate=None):
    """Bounded .text candidates only; every hit still needs decoded edge checks."""
    mask = set(mask); stable = [i for i in range(len(raw)) if i not in mask]
    if not stable: raise ValueError('Action byte candidate has no invariant prefix')
    begin = stable[0]; end = begin
    while end + 1 in stable: end += 1
    needle = raw[begin:end + 1]; hits = []
    for section in image.pe.sections:
        if section['name'] != '.text': continue
        first = max(section['rva'], old - image.pe.base - 65536)
        last = min(section['rva'] + section['raw_size'] - len(raw), old - image.pe.base + 65536)
        if last < first: continue
        cursor = image.offset(first) + begin; stop = image.offset(last) + len(raw)
        while cursor < stop:
            found = image.data.find(needle, cursor, stop)
            if found < 0: break
            base = found - begin; cursor = found + 1
            current = image.data[base:base + len(raw)]
            if len(current) == len(raw) and all(current[i] == raw[i] for i in stable):
                target = image.pe.base + section['rva'] + base - section['raw']
                if predicate is not None and not predicate(target): continue
                hits.append(target)
                if len(hits) > 32: raise ValueError('Action bounded byte candidate budget exceeded')
    return hits


def mutable_storage(image, at, size=8):
    """Validate the pointer slot's extent only, without reading its live value."""
    if type(at) is not int or type(size) is not int or size != 8:
        raise ValueError('Tutorial mutable pointer requires exactly eight bytes')
    found=[s for s in image.pe.sections if s['rva']<=at-image.pe.base
           and at-image.pe.base+size<=s['rva']+s['size'] and s['name']=='.data']
    if len(found)!=1:raise ValueError('Tutorial mutable global is outside bounded data storage')
    return found[0]['name']


def linked_leaf(native, leaf_api, api, before, after, at, spec, mapping):
    raw = bytes.fromhex(spec['bytes'])
    if api.image_bytes(before, at, len(raw)) != raw: raise ValueError('Action baseline leaf differs')
    old = leaf_api.leaf_rows(native, before, at, raw)
    if row_policy(old, at) != {k: spec[k] for k in ('calls', 'data', 'tails')}:
        raise ValueError('Action baseline leaf links differ')
    choices = [mapping[at]] if at in mapping else masked_hits(after, at, raw, spec['relocation_bytes'])
    hits = []
    for target in choices:
        revised = dict(mapping)
        try:
            load('update-native-archive-wire').add_link(revised, at, target)
            new = leaf_api.leaf_rows(native, after, target, raw); leaf_api.pair_leaf(native, old, new, revised)
        except ValueError: continue
        hits.append((target, revised))
    if len(hits) != 1: raise ValueError('Action leaf missing, ambiguous or not linked: ' + hex(at))
    target, revised = hits[0]; mapping.clear(); mapping.update(revised)
    actual = api.image_bytes(after, target, len(raw))
    return dict(baseline=hex(at), target=hex(target), baseline_bytes=raw.hex(), bytes=actual.hex(),
        sha256=hashlib.sha256(actual).hexdigest(), **{k: copy.deepcopy(spec[k]) for k in ('calls', 'data', 'tails')})


def transfer(index, args, dependencies):
    reviewed = policy()
    if not isinstance(dependencies, dict) or set(dependencies) != DEPENDENCIES:
        raise ValueError('Action requires five exact ordered dependencies')
    if set(dependencies['baselines']) != set(reviewed['baselines']): raise ValueError('Action baseline roles differ')
    contexts = {}
    for name, spec in reviewed['baselines'].items():
        pointer = dependencies['baselines'][name]
        if pointer['sha256'] != spec['context_sha256']: raise ValueError('Action reviewed baseline pointer differs')
        c = document(index, pointer, HERE / 'knowledge/native-contexts')
        if (c.get('source_sha256') != reviewed['baseline_source_sha256']
                or any(c.get(k) != spec[k] for k in ('functions', 'leaves'))):
            raise ValueError('Action source-bound baseline roles differ')
        contexts[name] = c
    seed = document(index, dependencies['input_seed'], Path(args.root) / 'knowledge/quest-input-seed-proofs-v2')
    reader = document(index, dependencies['reader_transfer'], Path(args.root) / 'knowledge/quest-reader-transfer-proofs-v1')
    if (seed.get('recipe') != 'quest-input-seed-v2' or seed.get('method') != 'static'
            or reader.get('recipe') != 'quest-reader-transfer-v1' or reader.get('method') != 'static'
            or reader['inputs']['seed'] != dependencies['input_seed']
            or any(seed.get(k) is not False or reader.get(k) is not False
                   for k in ('native_consumer_verified', 'runtime_activated', 'profile_activated'))):
        raise ValueError('Action INPUT seed/reader proof scope differs')
    load('quest-input-seed-v2').validate_relation(seed['transfer_relation'], seed['mappings'])
    reader_api = load('quest-reader-transfer-rules-v1'); reader_api.validate_package(reader['package'], reader['inputs'])
    oldsha = reviewed['baseline_source_sha256']; sha = seed['inputs']['target']['source_sha256']
    if (seed['inputs']['baseline']['source_sha256'] != oldsha or reader['inputs']['target_source_sha256'] != sha
            or sha == oldsha): raise ValueError('Action ordered source identities differ')
    output = document(index, dependencies['output_context'], Path(args.root) / 'knowledge/generated-native-contexts')
    report = document(index, dependencies['output_check'], Path(args.root) / 'knowledge/native-adapter-checks')
    archive = load('update-native-archive-wire'); archive.report_valid(report, output, dependencies['output_context']['sha256'])
    if output.get('family') != 'archive-wire' or output.get('source_sha256') != sha:
        raise ValueError('Action target OUTPUT source differs')
    output_proof = document(index, output['transfer_proof'], Path(args.root) / 'knowledge/native-archive-wire-proofs')
    if (output_proof.get('target') != {k:v for k,v in output.items() if k not in ('exports', 'transfer_proof', 'release_id')}
            or output_proof.get('runtime_activated') is not False): raise ValueError('Action OUTPUT proof linkage differs')
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    api, common, leaf_api = load('update-native-version-result'), archive, load('login-input-transfer-rules')
    before = args.source_store.image(native, oldsha); after = args.source_store.image(native, sha)
    for name in ('quest-update-wire', 'tutorial-dispatch'):
        reader_api.export_coverage(index, args, contexts[name], native, bindings, before)
    mapping = {}
    for values in (seed['transfer_relation']['mapping'], reader['package']['relation']['mapping']):
        for a, b in values.items(): common.add_link(mapping, address(a), address(b))
    # Explicit d00/current roles, never the differently addressed 1.13.20 relation.
    for role, name in reviewed['output_roles'].items():
        at = address(contexts['archive-wire']['archive'][name]); target = address(output['archive'][name])
        common.add_link(mapping, at, target)
        common.pair_rows(native, bindings.rows(native, before, at), bindings.rows(native, after, target), mapping)
    common.add_link(mapping, address(contexts['quest-update-wire']['output_table']), address(output['archive']['table']))
    # Packet ID 1810 anchors its packet table and the writer/reader slots.
    packet = reviewed['packets']['quest-update-wire']; ident = address(packet['id_getter'])
    raw_id = b'\xb8' + struct.pack('<I', packet['id']) + b'\xc3'
    hits = masked_hits(after, ident, raw_id, [])
    if len(hits) != 1: raise ValueError('QuestUpdate ID leaf missing or ambiguous')
    common.add_link(mapping, ident, hits[0]); oldtable = address(packet['table'])
    hits = api.table_candidates(after, oldtable, mapping[ident], 0x28, 48)
    if len(hits) != 1: raise ValueError('QuestUpdate packet table missing or ambiguous')
    common.add_link(mapping, oldtable, hits[0])
    for slot, value in reviewed['tables'][hex(oldtable)]['used'].items():
        common.add_link(mapping, address(value), struct.unpack('<Q', api.image_bytes(after, hits[0] + address(slot), 8))[0])
    rootchecks = resolve(native, bindings, api, before, after, reviewed, mapping)
    handler = address(contexts['tutorial-dispatch']['functions']['handler']); handler_table = address(contexts['tutorial-dispatch']['handler_table'])
    hits = api.table_candidates(after, handler_table, mapping[handler], 0x10, 24)
    if len(hits) != 1: raise ValueError('Tutorial handler table missing or ambiguous')
    common.add_link(mapping, handler_table, hits[0])
    leaves = [linked_leaf(native, leaf_api, api, before, after, address(at), spec, mapping)
              for at, spec in reviewed['leaves'].items()]
    # Registration is a selected exact window, with known ctor/table associations.
    reg = reviewed['registration']; at = address(reg['baseline']); raw = bytes.fromhex(reg['bytes'])
    if api.image_bytes(before, at, len(raw)) != raw: raise ValueError('Tutorial registration baseline changed')
    oldrows = decode(native, before, at, len(raw))
    def registration_candidate(target):
        try: pair(native, oldrows, decode(native, after, target, len(raw)), dict(mapping), reg)
        except ValueError: return False
        return True
    choices = masked_hits(after, at, raw, reg['relocation_bytes'], registration_candidate); hits = []
    for target in choices:
        revised = dict(mapping)
        try: pair(native, oldrows, decode(native, after, target, len(raw)), revised, reg)
        except ValueError: continue
        hits.append((target, revised))
    if len(hits) != 1: raise ValueError('Tutorial registration window missing, ambiguous or not source-linked')
    target, revised = hits[0]; mapping.clear(); mapping.update(revised); actual = api.image_bytes(after, target, len(raw))
    registration = dict(baseline=hex(at), target=hex(target), baseline_bytes=raw.hex(), bytes=actual.hex(),
        sha256=hashlib.sha256(actual).hexdigest(), calls=reg['calls'], data=reg['data'], tails=reg['tails'], owner_executed=False)
    tables = []
    for at, spec in reviewed['tables'].items():
        old = address(at)
        if old not in mapping: raise ValueError('Action table lacks caller/seed linkage: ' + at)
        a = bytes.fromhex(spec['bytes']); b = api.image_bytes(after, mapping[old], len(a))
        if api.image_bytes(before, old, len(a)) != a: raise ValueError('Action baseline table differs')
        av = struct.unpack('<' + 'Q' * (len(a)//8), a); bv = struct.unpack('<' + 'Q' * (len(b)//8), b)
        if any((av[i] == av[j]) != (bv[i] == bv[j]) for i in range(len(av)) for j in range(i)):
            raise ValueError('Action table alias topology differs')
        for slot, value in spec['used'].items():
            pos = address(slot)//8
            if av[pos] != address(value) or mapping.get(address(value)) != bv[pos]:
                raise ValueError('Action table selected role differs')
        for x,y in zip(av,bv): common.add_link(mapping,x,y)
        tables.append(dict(baseline=at,target=hex(mapping[old]),baseline_bytes=a.hex(),bytes=b.hex(),
            sha256=hashlib.sha256(b).hexdigest(),kind=spec['kind'],used={k:hex(mapping[address(v)]) for k,v in spec['used'].items()},
            excluded_slots=[hex(i) for i in range(0,len(a),8) if hex(i) not in spec['used']],unselected_bodies_verified=False))
    boundaries = []
    for role, at in reviewed['boundaries'].items():
        old = address(at)
        if old not in mapping: raise ValueError('Action fixture has no declared caller: ' + role)
        if role in reviewed['boundary_leaves']:
            spec=reviewed['boundary_leaves'][role];raw=bytes.fromhex(spec['bytes'])
            if api.image_bytes(before,old,len(raw))!=raw:raise ValueError('Action excluded scalar leaf differs')
            oldrows=decode(native,before,old,len(raw));newrows=decode(native,after,mapping[old],len(raw))
            pair(native,oldrows,newrows,mapping,spec)
            actual=api.image_bytes(after,mapping[old],len(raw))
            item=dict(baseline=at,target=hex(mapping[old]),kind='excluded-callable-leaf',body_verified=False,
                baseline_bytes=raw.hex(),bytes=actual.hex(),sha256=hashlib.sha256(actual).hexdigest())
        else:
            item = reader_api.check_boundary(native,bindings,before,after,old,mapping[old])
        item.update(role=role,consumer='quest-update-wire' if not role.startswith('tutorial_') else 'tutorial-dispatch')
        boundaries.append(item)
    old = address(reviewed['memcpy']); target = mapping.get(old)
    if target is None: raise ValueError('Action memcpy lacks caller linkage')
    load('update-native-contexts').memcpy_identity(native,before,old);load('update-native-contexts').memcpy_identity(native,after,target)
    boundaries.append(dict(consumer='shared-input',role='memcpy',baseline=hex(old),target=hex(target),kind='import-thunk',
        identity=dict(dll='VCRUNTIME140.dll',name='memcpy'),body_verified=False))
    global_spec = reviewed['mutable_global']; old = address(global_spec['address']); target = mapping[old]
    for image, where in ((before,old),(after,target)):
        mutable_storage(image,where)
    data=[dict(baseline=hex(old),target=hex(target),bytes=8,kind='mutable-pointer-storage',
        getter=hex(mapping[address(global_spec['getter'])]),value_verified=False,provider_executed=False)]
    target_contexts={}
    for name in ('quest-update-wire','tutorial-dispatch'):
        c=contexts[name]
        current=dict(source_sha256=sha,source=str(Path(args.root)/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'),
            functions={k:hex(mapping[address(v)]) for k,v in c['functions'].items()},
            leaves={hex(mapping[address(k)]):api.image_bytes(after,mapping[address(k)],len(bytes.fromhex(v))).hex() for k,v in c['leaves'].items()},
            bindings=[],fixtures={item['role']:item['target'] for item in boundaries
                if item['consumer']==name},consumer_semantic_verified=False)
        if name=='quest-update-wire':
            current.update({key:hex(mapping[address(c[key])]) for key in ('output_table','input_table','packet_table','output_growth')})
            current['output_table_sha256']=hashlib.sha256(api.image_bytes(after,address(current['output_table']),248)).hexdigest()
        else:
            current.update(handler_table=hex(mapping[address(c['handler_table'])]),handler_global=hex(target),
                registration_anchors={hex(mapping[address(k)]):api.image_bytes(after,mapping[address(k)],len(bytes.fromhex(v))).hex() for k,v in c['registration_anchors'].items()})
        for table in tables:
            if table['kind'].startswith('quest-') == (name == 'quest-update-wire'):
                current['bindings'] += [[table['target'],slot,table['used'][slot]]
                                        for slot in sorted(table['used'],key=address)]
        target_contexts[name]=current
    return dict(schema=1,recipe=RECIPE,method='static',baseline_source_sha256=oldsha,target_source_sha256=sha,
        counts=copy.deepcopy(reviewed['counts']),target_contexts=target_contexts,
        relation=dict(mapping={hex(a):hex(b) for a,b in sorted(mapping.items())},rootchecks=rootchecks,
            leaves=leaves,tables=tables,boundaries=boundaries,registration=registration,data=data),**FLAGS)


def validate_package(package, inputs):
    """Validate all cached evidence and projected roles without repeating transfer."""
    reviewed=policy();dependencies=inputs.get('dependencies',inputs)
    if not isinstance(dependencies,dict) or set(dependencies)!=DEPENDENCIES:raise ValueError('Action package dependencies differ')
    expected={'schema','recipe','method','baseline_source_sha256','target_source_sha256','counts','target_contexts','relation',*FLAGS}
    if (not isinstance(package,dict) or set(package)!=expected or type(package['schema']) is not int or package['schema']!=1
            or package['recipe']!=RECIPE or package['method']!='static' or package['baseline_source_sha256']!=reviewed['baseline_source_sha256']
            or not isinstance(package['target_source_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',package['target_source_sha256'])
            or package['counts']!=reviewed['counts'] or any(type(v) is not int for v in package['counts'].values())
            or any(package.get(k) is not False for k in FLAGS)):
        raise ValueError('Action package scope or admission differs')
    if 'target_source_sha256' in inputs and inputs['target_source_sha256']!=package['target_source_sha256']:
        raise ValueError('Action package target identity differs')
    for name,spec in reviewed['baselines'].items():
        if dependencies['baselines'][name]['sha256']!=spec['context_sha256']:raise ValueError('Action package baseline pointer differs')
    relation=package['relation']
    if set(relation)!={'mapping','rootchecks','leaves','tables','boundaries','registration','data'}:raise ValueError('Action relation shape differs')
    mapping={address(a):address(b) for a,b in relation['mapping'].items()}
    if not 19<=len(mapping)<=4096:raise ValueError('Action mapping budget differs')
    def mapped(at):
        if address(at) not in mapping:raise ValueError('Action role lacks mapping')
        return hex(mapping[address(at)])
    for field,specs in (('rootchecks',reviewed['roots']),('leaves',reviewed['leaves']),('tables',reviewed['tables'])):
        rows=relation[field];by={r['baseline']:r for r in rows}
        if len(by)!=len(rows) or set(by)!=set(specs):raise ValueError('Action '+field+' coverage differs')
        for at,spec in specs.items():
            item=by[at]
            if item['target']!=mapped(at):raise ValueError('Action projected evidence target differs')
            if field=='rootchecks':
                wanted=dict(baseline=at,target=mapped(at),candidates=item.get('candidates'),whole_instruction_shape_verified=True,**spec)
                if item!=wanted or type(item['candidates']) is not int or not 1<=item['candidates']<=32:raise ValueError('Action root policy differs')
            else:
                raw=bytes.fromhex(item['bytes']);old=bytes.fromhex(spec['bytes'])
                if item['baseline_bytes']!=spec['bytes'] or len(raw)!=len(old) or hashlib.sha256(raw).hexdigest()!=item['sha256']:
                    raise ValueError('Action byte evidence differs')
                if field=='leaves':
                    if (set(item)!={'baseline','target','baseline_bytes','bytes','sha256','calls','data','tails'}
                            or any(raw[i]!=v for i,v in enumerate(old) if i not in spec['relocation_bytes'])
                            or any(item[k]!=spec[k] for k in ('calls','data','tails'))):
                        raise ValueError('Action leaf policy differs')
                else:
                    a=struct.unpack('<'+'Q'*(len(old)//8),old);b=struct.unpack('<'+'Q'*(len(raw)//8),raw)
                    if (set(item)!={'baseline','target','baseline_bytes','bytes','sha256','kind','used','excluded_slots','unselected_bodies_verified'}
                            or item['kind']!=spec['kind'] or item['used']!={k:mapped(v) for k,v in spec['used'].items()}
                            or item['excluded_slots']!=[hex(i) for i in range(0,len(old),8) if hex(i) not in spec['used']]
                            or item['unselected_bodies_verified'] is not False or any(mapping.get(x)!=y for x,y in zip(a,b))
                            or any((a[i]==a[j])!=(b[i]==b[j]) for i in range(len(a)) for j in range(i))):
                        raise ValueError('Action table role/alias partition differs')
    boundaries={r['role']:r for r in relation['boundaries']}
    if set(boundaries)!=set(reviewed['boundaries'])|{'memcpy'} or len(boundaries)!=len(relation['boundaries']):raise ValueError('Action boundary coverage differs')
    occupied={mapped(at) for at in set(reviewed['roots'])|set(reviewed['leaves'])}
    if len(occupied)!=30:raise ValueError('Action roots/leaves alias')
    for role,item in boundaries.items():
        at=reviewed['memcpy'] if role=='memcpy' else reviewed['boundaries'][role]
        consumer='shared-input' if role=='memcpy' else ('tutorial-dispatch' if role.startswith('tutorial_') else 'quest-update-wire')
        keys={'consumer','role','baseline','target','kind','body_verified'}|({'identity'} if role=='memcpy' else set())
        if role in reviewed['boundary_leaves']:keys|={'baseline_bytes','bytes','sha256'}
        kind='import-thunk' if role=='memcpy' else ('excluded-callable-leaf' if role in reviewed['boundary_leaves'] else 'exact-unwind-entry')
        if (set(item)!=keys or item['consumer']!=consumer or item['baseline']!=at or item['target']!=mapped(at)
                or item['target'] in occupied or item['body_verified'] is not False
                or item['kind']!=kind
                or (role=='memcpy' and item['identity']!={'dll':'VCRUNTIME140.dll','name':'memcpy'})):
            raise ValueError('Action fixture boundary differs')
        if role in reviewed['boundary_leaves']:
            spec=reviewed['boundary_leaves'][role];a=bytes.fromhex(spec['bytes']);b=bytes.fromhex(item['bytes'])
            if (item['baseline_bytes']!=spec['bytes'] or len(b)!=len(a)
                    or any(b[i]!=v for i,v in enumerate(a) if i not in spec['relocation_bytes'])
                    or hashlib.sha256(b).hexdigest()!=item['sha256']):
                raise ValueError('Action excluded callable leaf bytes differ')
    values=list(boundaries.values())
    if any((a['baseline']==b['baseline'])!=(a['target']==b['target']) for i,a in enumerate(values) for b in values[:i]):
        raise ValueError('Action fixture identity partition differs')
    reg=relation['registration'];spec=reviewed['registration'];raw=bytes.fromhex(reg['bytes']);old=bytes.fromhex(spec['bytes'])
    if (set(reg)!={'baseline','target','baseline_bytes','bytes','sha256','calls','data','tails','owner_executed'}
            or reg['baseline']!=spec['baseline'] or reg['target']!=mapped(spec['baseline']) or reg['baseline_bytes']!=spec['bytes']
            or len(raw)!=len(old) or hashlib.sha256(raw).hexdigest()!=reg['sha256'] or reg['owner_executed'] is not False
            or any(raw[i]!=v for i,v in enumerate(old) if i not in spec['relocation_bytes'])
            or any(reg[k]!=spec[k] for k in ('calls','data','tails'))):raise ValueError('Action registration window differs')
    spec=reviewed['mutable_global'];wanted=[dict(baseline=spec['address'],target=mapped(spec['address']),bytes=8,
        kind='mutable-pointer-storage',getter=mapped(spec['getter']),value_verified=False,provider_executed=False)]
    if relation['data']!=wanted:raise ValueError('Action global pointer scope differs')
    if set(package['target_contexts'])!={'quest-update-wire','tutorial-dispatch'}:raise ValueError('Action consumer projection scope differs')
    for name,c in package['target_contexts'].items():
        base=reviewed['baselines'][name]
        keys={'source_sha256','source','functions','leaves','bindings','fixtures','consumer_semantic_verified'}
        keys|={'output_table','input_table','packet_table','output_growth','output_table_sha256'} if name=='quest-update-wire' else {'handler_table','handler_global','registration_anchors'}
        bindings=[[r['target'],slot,r['used'][slot]] for r in relation['tables']
                  if r['kind'].startswith('quest-')==(name=='quest-update-wire') for slot in sorted(r['used'],key=address)]
        fixtures={r['role']:r['target'] for r in relation['boundaries'] if r['consumer']==name}
        if (set(c)!=keys or c['source_sha256']!=package['target_source_sha256'] or Path(c['source']).parent.name!=package['target_source_sha256']
                or Path(c['source']).name!='ProjectRED-Win64-Shipping.exe' or c['consumer_semantic_verified'] is not False
                or c['bindings']!=bindings or c['fixtures']!=fixtures
                or c['functions']!={k:mapped(v) for k,v in base['functions'].items()}
                or c['leaves']!={mapped(k):next(r['bytes'] for r in relation['leaves'] if r['baseline']==k) for k in base['leaves']}):
            raise ValueError('Action consumer context projection differs')
        if name=='quest-update-wire':
            wanted=dict(output_table=mapped('0x149670920'),input_table=mapped('0x1496706e8'),
                        packet_table=mapped('0x149965670'),output_growth=mapped(reviewed['boundaries']['output_growth']),
                        output_table_sha256=next(r['sha256'] for r in relation['tables'] if r['baseline']=='0x149670920'))
            if any(c[k]!=v for k,v in wanted.items()):raise ValueError('Action wire table projection differs')
        else:
            anchors={}
            registration_spec=reviewed['registration']
            start=address(registration_spec['baseline']);target_start=address(reg['target'])
            for at,raw_anchor in registration_spec['anchors'].items():
                offset=address(at)-start;target=hex(target_start+offset)
                if mapped(at)!=target:raise ValueError('Action registration anchor instruction linkage differs')
                anchors[target]=raw[offset:offset+len(bytes.fromhex(raw_anchor))].hex()
            if (c['handler_table']!=mapped('0x149dc5298') or c['handler_global']!=mapped(reviewed['mutable_global']['address'])
                    or c['registration_anchors']!=anchors):raise ValueError('Action dispatch source projection differs')
