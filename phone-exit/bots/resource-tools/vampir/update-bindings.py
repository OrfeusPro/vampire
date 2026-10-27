"""Resolve explicit recipes and verify closed instruction dependencies, not names."""
import hashlib
from pathlib import Path
import struct
import re


def source(index, root, sha):
    if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):
        raise ValueError('Full binding source SHA required')
    path = root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha: raise ValueError('Binding source SHA changed')
    return raw


def rows(native, image, at):
    part = image.containing(at)
    if part is None or image.roots[part][0]+image.pe.base != at:
        raise ValueError('Binding is not an explicit unwind root')
    fragments = native.decode_ranges(image,{image.roots[part]})
    if sum(len(bytes.fromhex(r['bytes'])) for f in fragments for r in f['instructions']) > 65536:
        raise ValueError('Binding function budget exceeded')
    return [r for f in fragments for r in f['instructions']]


def closed_shape(native, image, address, bindings, recipe):
    """Normalize only declared callees/data and internal branch destinations."""
    result = []
    instructions = rows(native,image,address)
    locations = {r['address'] for r in instructions}
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    decoder.detail = True
    for row in instructions:
        raw = bytearray.fromhex(row['bytes'])
        ins = next(decoder.disasm(bytes(raw),row['address']))
        links = []
        if row['call'] or row['branch']:
            target = row['direct_target']
            if target in locations:
                links.append(('local',target-address))
            elif row['call'] and target is not None:
                key = recipe.get('calls',{}).get(str(row['address']-address))
                if key is None or (bindings is not None and bindings.get(key) != hex(target)):
                    raise ValueError('Undeclared or changed callee at '+hex(row['address']))
                links.append(('call',key))
            else: raise ValueError('Unreviewed indirect or external branch')
            raw[ins.imm_offset:ins.imm_offset+ins.imm_size] = bytes(ins.imm_size)
        for target in row['rip_references']:
            spec = recipe.get('data',{}).get(str(row['address']-address))
            if not spec or not 1 <= spec.get('size',0) <= 4096:
                raise ValueError('Undeclared data reference')
            off = image.offset(target-image.pe.base)
            value = image.data[off:off+spec['size']]
            if len(value)!=spec['size'] or hashlib.sha256(value).hexdigest() != spec['sha256']:
                raise ValueError('Changed contract data')
            links.append(('data',spec['sha256']))
            raw[ins.disp_offset:ins.disp_offset+ins.disp_size] = bytes(ins.disp_size)
        result.append((row['address']-address,raw.hex(),links))
    return result


def shape_candidates(native, image, old_image, recipe, old_bindings):
    """Bounded whole-function search; only declared relocations are normalized."""
    address = int(recipe['baseline_address'],16)
    window = recipe.get('search_window')
    if type(window) is not int or not 0 <= window <= 0x100000:
        raise ValueError('Closed-shape search window must be 0..1048576 bytes')
    expected = closed_shape(native,old_image,address,old_bindings,recipe)
    old_root = old_image.roots[old_image.containing(address)]
    size = old_root[1]-old_root[0]
    roots = [r for r in image.roots if abs(image.pe.base+r[0]-address) <= window and r[1]-r[0] == size]
    if len(roots)>4096:raise ValueError('Closed-shape root search budget exceeded')
    candidates=[]
    for root in roots:
        candidate=image.pe.base+root[0]
        try:
            if closed_shape(native,image,candidate,None,recipe)==expected:
                candidates.append(hex(candidate))
        except (ValueError,StopIteration):continue
        if len(candidates)>32:raise ValueError('Closed-shape candidate budget exceeded')
    return candidates


def candidate_callees(native,image,address,recipe):
    instructions=rows(native,image,address)
    locations={r['address'] for r in instructions}
    result=[]
    for row in instructions:
        if row['call'] and row['direct_target'] not in locations:
            key=recipe.get('calls',{}).get(str(row['address']-address))
            if key is None or row['direct_target'] is None:raise ValueError('Unreviewed callee')
            result.append((key,hex(row['direct_target'])))
    return result


def prune_candidates(native,image,candidates,known,recipes):
    """Remove inconsistent call edges to a fixed point, including deep chains."""
    candidates={key:list(values) for key,values in candidates.items()}
    changed=True
    while changed:
        changed=False
        for key,values in candidates.items():
            valid=[]
            for address in values:
                edges=candidate_callees(native,image,int(address,16),recipes[key])
                if all(target in candidates.get(callee,[known[callee]] if callee in known else [])
                       for callee,target in edges):valid.append(address)
            if values!=valid:candidates[key]=valid;changed=True
    return candidates


def resolve(index, args, model, sha, discoveries):
    native = index.extension('build-native-entry-code')
    raw = source(index,args.root,sha); image = native.Image(raw)
    old_images = {}
    def baseline(identity):
        if identity not in old_images:old_images[identity]=native.Image(source(index,args.root,identity))
        return old_images[identity]
    anchors = {}
    for discovery in discoveries:
        for found in (discovery.get('result') or {}).get('candidates',[]):
            anchors[found['id']] = found
    outcomes = {}
    for c in model['contracts']:
        known = dict(c['bindings'].get(sha,{}))
        pending = list(c['recipes']); gaps = []; searched = {}
        for _ in range(len(pending)+1):
            progress = False
            for recipe in pending[:]:
                key, method = recipe['key'],recipe['method']
                if key in known:
                    try:
                        at=int(known[key],16); part=image.containing(at)
                        if part is None or image.roots[part][0]+image.pe.base!=at:
                            raise ValueError('Reviewed binding is not an unwind root')
                    except ValueError as error: gaps.append(key+': '+str(error)); del known[key]
                    pending.remove(recipe); progress = True; continue
                candidates = []
                try:
                    if method == 'anchor':
                        a = anchors.get(recipe['anchor'],{})
                        if a.get('state') == 'candidate': candidates = a.get('roots',[])
                    elif method == 'prefix':
                        old_sha = recipe['baseline_sha256']; old_image = baseline(old_sha); old=old_image.data
                        at = int(recipe['baseline_address'],16)
                        old_rows = rows(native,old_image,at)
                        length = recipe.get('prefix_bytes',39)
                        if not 16 <= length <= 128: raise ValueError('Prefix length budget exceeded')
                        off = old_image.offset(at-old_image.pe.base); needle = old[off:off+length]
                        cursor = 0; hits=0
                        while True:
                            cursor = raw.find(needle,cursor)
                            if cursor < 0: break
                            hits+=1
                            if hits>4096:raise ValueError('Prefix byte-candidate budget exceeded')
                            try:
                                candidate = image.pe.address(cursor); rows(native,image,candidate)
                                candidates.append(hex(candidate))
                            except ValueError: pass
                            cursor += 1
                            if len(candidates)>32: raise ValueError('Candidate budget exceeded')
                    elif method == 'closed_shape':
                        old_image=baseline(recipe['baseline_sha256'])
                        candidates=shape_candidates(native,image,old_image,recipe,c['bindings'].get(recipe['baseline_sha256'],{}))
                        searched[key]=candidates
                        pending.remove(recipe); progress=True; continue
                    elif method in ('direct_call','vtable'):
                        if recipe['from'] not in known: continue
                        origin = int(known[recipe['from']],16)
                        if method == 'direct_call':
                            found = next((r for r in rows(native,image,origin) if r['address']-origin == recipe['offset']),None)
                            if found and found['call'] and found['direct_target'] is not None:
                                candidates = [hex(found['direct_target'])]
                        else:
                            slot=recipe['slot']
                            if not isinstance(slot,int) or not 0<=slot<=1024 or slot%8:
                                raise ValueError('Vtable slot budget differs')
                            if 'rip_offset' in recipe:
                                ins=next((r for r in rows(native,image,origin) if r['address']-origin==recipe['rip_offset']),None)
                                if not ins or ins['mnemonic']!='lea' or len(ins['rip_references'])!=1:
                                    raise ValueError('Vtable LEA binding differs')
                                origin=ins['rip_references'][0]
                            off = image.offset(origin-image.pe.base)+recipe['slot']
                            candidates = [hex(struct.unpack_from('<Q',raw,off)[0])]
                    if len(set(candidates)) != 1:
                        gaps.append(key+': missing or ambiguous '+method+' candidate')
                    else:
                        rows(native,image,int(candidates[0],16)); known[key] = candidates[0]
                except (ValueError,KeyError,StopIteration) as error: gaps.append(key+': '+str(error))
                pending.remove(recipe); progress = True
            if not progress: break
        if searched:
            recipes={r['key']:r for r in c['recipes']}
            searched=prune_candidates(native,image,searched,known,recipes)
            for key,candidates in searched.items():
                if len(candidates)==1:known[key]=candidates[0]
                else:gaps.append(key+': missing or ambiguous closed_shape candidate')
        gaps.extend(r['key']+': dependency unresolved' for r in pending)
        if not c['recipes']: gaps.append('No declared function binding coverage')
        # Relocated candidates require the declared closure, even if their prefix matches.
        shapes = {}
        for recipe in c['recipes']:
            if recipe['key'] not in known or recipe.get('method') not in ('prefix','closed_shape'): continue
            try:
                old_sha = recipe['baseline_sha256']
                old_image = baseline(old_sha)
                old_bindings = c['bindings'].get(old_sha,{})
                old_shape = closed_shape(native,old_image,int(recipe['baseline_address'],16),old_bindings,recipe)
                new_shape = closed_shape(native,image,int(known[recipe['key']],16),known,recipe)
                if old_shape != new_shape: raise ValueError('Instruction/control-flow shape changed')
                shapes[recipe['key']] = hashlib.sha256(repr(new_shape).encode()).hexdigest()
            except ValueError as error: gaps.append(recipe['key']+': '+str(error))
        # Prune until stable: a failure at any depth must invalidate every caller,
        # regardless of recipe order. Mutually verified closed cycles remain valid.
        changed=True
        while changed:
            changed=False
            for recipe in c['recipes']:
                if recipe['key'] not in shapes:continue
                missing=set(recipe.get('calls',{}).values())-set(shapes)
                if missing:
                    gaps.append(recipe['key']+': callee closure not verified: '+', '.join(sorted(missing)))
                    del shapes[recipe['key']];changed=True
        verification={}
        for recipe in c['recipes']:
            key=recipe['key']
            if key in shapes:
                previous=recipe['baseline_address']
                verification[key]=dict(state='unchanged' if known[key]==previous else 'moved_verified',
                    baseline_sha256=recipe['baseline_sha256'],baseline_address=previous,
                    address=known[key],closed_shape_sha256=shapes[key],
                    scope='declared_instruction_callee_data_closure',runtime_activated=False)
            else:verification[key]=dict(state='requires_review',runtime_activated=False)
        outcomes[c['id']] = dict(bindings=known,queue=gaps,closed_shapes=shapes,
            verification=verification,search_candidates=searched)
    if source(index,args.root,sha) != raw: raise ValueError('Binding source changed during resolution')
    for identity,old_image in old_images.items():
        if source(index,args.root,identity)!=old_image.data:raise ValueError('Baseline binding source changed during resolution')
    return dict(source_sha256=sha,contracts=outcomes)
