"""Fixed Login context batch: candidate matching only, followed by native checks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE=Path(__file__).resolve().parent
OLD='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
NEW='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
NAMES=('login-prepare','login-prepare-sdk','login-prepare-metadata','login-metadata',
       'login-result','login-result-input','login-result-string','login-result-buffer',
       'login-result-body-handler','login-result-handler','login-post-state','login-continuation',
       'login-result-registration')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run(root,exports=(),alignment=None):
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    images={}
    for sha in (OLD,NEW):
        raw=(root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Login alignment source SHA changed')
        images[sha]=native.Image(raw)
    contexts={name:json.loads((HERE/'knowledge/native-contexts'/(name+'-11316.json')).read_text('utf-8')) for name in NAMES}
    roots=set()
    def gather(value):
        if isinstance(value,dict):
            for k,v in value.items():
                if k=='functions':roots.update(int(at,16) for at in v.values())
                if k in ('prepare','constructor') and isinstance(v,str):roots.add(int(v,16))
                gather(v)
        elif isinstance(value,list):
            for v in value:gather(v)
    for context in contexts.values():gather(context)
    if len(roots)!=38:raise ValueError('Explicit Login root set changed')
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    cached={}
    def rows(sha,at):
        key=(sha,at)
        if key not in cached:
            try:cached[key]=bindings.rows(native,images[sha],at)
            except ValueError:cached[key]=None
        return cached[key]
    def shape(items):
        if items is None:return None
        positions={r['address']:n for n,r in enumerate(items)};result=[]
        for row in items:
            data=bytearray.fromhex(row['bytes']);ins=next(decoder.disasm(data,row['address']));edge=None
            if row['call'] or row['branch']:
                target=row['direct_target']
                if target is not None:
                    edge=('local',positions[target]) if target in positions else ('external',)
                    data[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
            if row['rip_references']:data[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
            result.append((data.hex(),edge))
        return result
    mapped={0x1467ce030:0x1467ce500,0x1456d7570:0x1456d7950,0x1467cd7b0:0x1467cdc80}
    if alignment:
        previous=json.loads(Path(alignment).read_text('utf-8'))
        if previous['source_sha256']!=NEW or previous['baseline_sha256']!=OLD:
            raise ValueError('Candidate alignment source differs')
        mapped.update({int(a,16):int(b,16) for a,b in previous['roots'].items()})
    candidates={};unknown={};links={};calls={}
    def add(a,b):links.setdefault(a,set()).add(b)
    # The gate has verified inline data and its own source-specific validator.
    gate_old=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11316.json').read_text('utf-8'))
    gate_new=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11318.json').read_text('utf-8'))
    for name in ('gate_state','gate_error'):add(int(gate_old['fixtures'][name],16),int(gate_new['fixtures'][name],16))
    def bind(old,new):
        mapped[old]=new;add(old,new)
        for a,b in zip(rows(OLD,old),rows(NEW,new)):
            add(a['address'],b['address'])
            for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
            if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
            if a['call']:calls[a['address']]=(b['address'],hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
    for old in sorted(roots-{0x1467cd7b0}):
        expected=shape(rows(OLD,old));hits=[]
        if expected is None:unknown[hex(old)]='Old root is not linearly decodable';continue
        if old in mapped:hits=[mapped[old]] if shape(rows(NEW,mapped[old]))==expected else []
        elif alignment and hex(old) in previous['candidates']:
            hits=[int(at,16) for at in previous['candidates'][hex(old)] if shape(rows(NEW,int(at,16)))==expected]
        else:
            off=images[OLD].offset(old-images[OLD].pe.base);prefix=images[OLD].data[off:off+4]
            for begin,end,unwind in images[NEW].ranges:
                current=begin+images[NEW].pe.base
                if abs(current-old)>0x10000:continue
                part=images[NEW].containing(current)
                if images[NEW].roots[part][0]!=begin:continue
                off=images[NEW].offset(begin)
                if images[NEW].data[off:off+4]!=prefix:continue
                if shape(rows(NEW,current))==expected:hits.append(current)
        candidates[hex(old)]=[hex(at) for at in sorted(set(hits))]
        if len(set(hits))!=1:unknown[hex(old)]='Missing/ambiguous complete instruction/control shape';continue
        bind(old,hits[0])
    # Identical wrappers are resolved by an already matched native caller,
    # never by choosing the closest address or the first candidate.
    for old_text in list(unknown):
        old=int(old_text,16);referenced=links.get(old,set())
        if len(referenced)==1 and hex(next(iter(referenced))) in candidates.get(old_text,[]):
            bind(old,next(iter(referenced)));del unknown[old_text]
    add(0x1467cd7b0,0x1467cdc80)
    report=dict(source_sha256=NEW,baseline_sha256=OLD,tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        roots={hex(a):hex(b) for a,b in mapped.items()},candidates=candidates,unknown=unknown,
        semantic_verification=False,network_used=False)
    if exports:
        if unknown:raise ValueError('Unresolved Login roots: '+repr(unknown))
        generate(root,native,images,contexts,mapped,links,calls,exports,shape,report)
    target=load('research-workflow').snapshot(root,'login-batch-alignment-11318',report)
    return target,report


def generate(root,native,images,contexts,mapped,links,calls,exports,shape,report):
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    def add(a,b):
        links.setdefault(a,set()).add(b)
        if len(links[a])!=1:raise ValueError('Ambiguous Login link '+hex(a))
    def address(at):
        value=int(at,16)
        if len(links.get(value,()))==1:return hex(next(iter(links[value])))
        try:images[OLD].offset(value-images[OLD].pe.base)
        except ValueError:return at
        raise ValueError('Unmapped Login context address '+at)
    def data(sha,at,size):
        im=images[sha];off=im.offset(at-im.pe.base);return im.data[off:off+size]
    def decode(raw,at):
        result=[]
        for ins in decoder.disasm(raw,at):
            branch=ins.group(native.capstone.CS_GRP_JUMP);call=ins.group(native.capstone.CS_GRP_CALL)
            target=ins.operands[0].imm if (branch or call) and ins.operands[0].type==native.capstone.x86.X86_OP_IMM else None
            refs=[ins.address+ins.size+op.mem.disp for op in ins.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]
            result.append(dict(address=ins.address,bytes=ins.bytes.hex(),call=call,branch=branch,direct_target=target,rip_references=refs,operands=ins.op_str))
        if sum(len(bytes.fromhex(r['bytes'])) for r in result)!=len(raw):raise ValueError('Bounded Login instruction gap')
        return result
    def compare(old,new,size):
        before=decode(data(OLD,old,size),old);after=decode(data(NEW,new,size),new)
        if shape(before)!=shape(after):raise ValueError('Bounded Login shape changed '+hex(old))
        add(old,new)
        for a,b in zip(before,after):
            add(a['address'],b['address'])
            for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
            if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
            if a['call']:calls[a['address']]=(b['address'],hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
    # These fixed small tables are bound by constructor references. Their slots
    # resolve shared leaves (including the packet ID) independently of offsets.
    def visit(value):
        if isinstance(value,dict):
            for v in value.values():yield from visit(v)
            yield value
        elif isinstance(value,list):
            for v in value:yield from visit(v)
    all_objects=[item for context in contexts.values() for item in visit(context)]
    tables={}
    for item in all_objects:
        for spec in item.get('tables',[]):tables[int(spec['address'],16)]=len(bytes.fromhex(spec['bytes']))
        if 'table_bytes' in item:tables[int(item['table'],16)]=len(bytes.fromhex(item['table_bytes']))
    for old,size in tables.items():
        if old not in links:continue
        new=int(address(hex(old)),16)
        for slot in range(0,size-size%8,8):
            a,b=(struct.unpack('<Q',data(sha,at+slot,8))[0] for sha,at in ((OLD,old),(NEW,new)))
            if 0x140000000<=a<0x150000000:add(a,b)
    literal_old=int(contexts['login-result']['packet_table'],16)+0x50
    literal_new=int(address(contexts['login-result']['packet_table']),16)+0x50
    literal=b'PktLoginResult\0'
    if data(OLD,literal_old,len(literal))!=literal or data(NEW,literal_new,len(literal))!=literal:
        raise ValueError('Adjacent LoginResult name literal changed')
    add(literal_old,literal_new)
    # The tag is reached through its actual global pointer, not an assumed
    # literal delta. Values are read from the new immutable source.
    old=int(contexts['login-prepare']['globals']['tag_pointer'],16);new=int(address(hex(old)),16)
    add(struct.unpack('<Q',data(OLD,old,8))[0],struct.unpack('<Q',data(NEW,new,8))[0])
    # Explicit source windows outside the 38-root set: registration arguments
    # and the continuation factory link. Candidate locations are source-pinned;
    # complete bounded instructions and every resulting reference must agree.
    registration=contexts['login-result-registration']
    add(int(registration['bindings']['owner'],16),0x1467b5130)
    old=int(registration['window']['address'],16)
    compare(old,0x1467b51a4,len(bytes.fromhex(registration['window']['bytes'])))
    leaves={}
    for item in all_objects:
        for at,spec in item.get('leaves',{}).items():
            leaves[int(at,16)]=spec['bytes'] if isinstance(spec,dict) else spec
    # Iterate because a getter leaf can supply a singleton needed by another
    # context. No leaf target is invented when its caller/table link is absent.
    remaining=dict(leaves)
    while remaining:
        ready=[at for at in remaining if len(links.get(at,()))==1]
        if not ready:raise ValueError('Unmapped Login leaves '+repr([hex(at) for at in remaining]))
        for at in ready:
            compare(at,int(address(hex(at)),16),len(bytes.fromhex(remaining.pop(at))))
    continuation=contexts['login-continuation']
    factory=next(s for s in continuation['anchors'] if s['address']=='0x14665bb9a')
    compare(0x14665bb9a,0x14665c06a,len(bytes.fromhex(factory['bytes'])))
    # Current gate code/data boundaries are already proved by its dedicated
    # validator. Callees remain explicit fixtures; unsupported ones still reject.
    gate=load('version-gate-switch-11318')
    gate_rows=gate.rows(native,images[NEW],NEW)
    old_gate=contexts['login-result-handler']['call_sites']['gate']
    new_gate={hex(r['address']):hex(r['direct_target']) if r['direct_target'] is not None else r['operands'] for r in gate_rows if r['call']}
    old_targets=[int(v,16) for v in old_gate.values() if v.startswith('0x')]
    new_targets=[int(v,16) for v in new_gate.values() if v.startswith('0x')]
    if len(old_targets)!=len(new_targets):raise ValueError('Gate callee count changed')
    for a,b in zip(old_targets,new_targets):add(a,b)
    # Registration helper is a fixed additional root, sourced from the window.
    old_register=int(registration['bindings']['register'],16);new_register=int(address(hex(old_register)),16)
    binding=load('update-bindings')
    before=binding.rows(native,images[OLD],old_register);after=binding.rows(native,images[NEW],new_register)
    if shape(before)!=shape(after):raise ValueError('Registration helper shape changed')
    for a,b in zip(before,after):
        if a['call']:calls[a['address']]=(b['address'],hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
    available={};digests={}
    for export in exports:
        export=Path(export).resolve()
        if not export.is_relative_to((root/'ghidra/request-exports'/NEW).resolve()) or export.name!='details.json':raise ValueError('Export outside current source library')
        raw=export.read_bytes();d=json.loads(raw)
        if d['new_source_sha256']!=NEW:raise ValueError('Export source differs')
        available[export.parent.name]={int(f['address'],16) for f in d['functions'] if f.get('decompilation_completed')}
        digests[export.parent.name]=hashlib.sha256(raw).hexdigest()
    def selected(item):
        roots=set()
        for nested in visit(item):
            roots.update(int(address(at),16) for at in nested.get('functions',{}).values())
            for key in ('prepare','constructor'):
                if key in nested and isinstance(nested[key],str):roots.add(int(address(nested[key]),16))
        if item is registration:roots.update(int(address(registration['bindings'][k]),16) for k in ('handler','register','packet_constructor'))
        found={}
        while roots:
            run=max(available,key=lambda run:len(available[run]&roots))
            if not available[run]&roots:raise ValueError('Missing declared Login export '+repr([hex(v) for v in roots]))
            roots-=available[run];found[run]=digests[run]
        return found
    def payload(at,size):return data(NEW,int(address(at),16),size)
    def convert(value,key=None,parent=None,chosen=None):
        if key=='source_sha256':return NEW
        if key=='source':return str(root/'client-code-snapshots'/NEW/'ProjectRED-Win64-Shipping.exe')
        if key=='exports':return chosen
        if key=='leaves':
            return {address(at):(dict(bytes=(raw:=payload(at,len(bytes.fromhex(spec['bytes'])))).hex(),sha256=hashlib.sha256(raw).hexdigest()) if isinstance(spec,dict) else payload(at,len(bytes.fromhex(spec))).hex()) for at,spec in value.items()}
        if key in ('tables','anchors','tail_calls'):
            result=[]
            for spec in value:
                raw=payload(spec['address'],len(bytes.fromhex(spec['bytes'])))
                converted={k:convert(v,k,spec,chosen) for k,v in spec.items() if k not in ('bytes','sha256')}
                converted['bytes']=raw.hex()
                if 'sha256' in spec:converted['sha256']=hashlib.sha256(raw).hexdigest()
                result.append(converted)
            return result
        if key=='window':
            raw=payload(value['address'],len(bytes.fromhex(value['bytes'])))
            return dict(address=address(value['address']),bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
        if key=='table_bytes':return payload(parent['table'],len(bytes.fromhex(value))).hex()
        if key=='call_sites':
            if value and not next(iter(value)).startswith('0x'):
                return {k:(new_gate if k=='gate' else convert(v,'call_sites',value,chosen)) for k,v in value.items()}
            return {hex(calls[int(at,16)][0]):dict(target=calls[int(at,16)][1]) if isinstance(v,dict) else calls[int(at,16)][1] for at,v in value.items()}
        if isinstance(value,dict):return {k:convert(v,k,value,chosen) for k,v in value.items()}
        if isinstance(value,list):return [convert(v,chosen=chosen) for v in value]
        if isinstance(value,str) and re.fullmatch('0x[0-9a-fA-F]+',value):return address(value)
        return value
    generated={}
    for name,context in contexts.items():
        current=convert(context,chosen=selected(context))
        if 'gate' in current.get('functions',{}) or 'native_handler' in current:
            current['switch_gate']='version-gate-11318'
            if 'native_handler' in current:current['native_handler']['switch_gate']='version-gate-11318'
        else:current['verify_whole_exports']=True
        target=HERE/'knowledge/native-contexts'/(name+'-11318.json')
        generated[target]=json.dumps(current,ensure_ascii=False,indent=2)+'\n'
    for path,content in generated.items():path.write_text(content,encoding='utf-8')
    report['contexts']=[str(path) for path in generated]
    report['registration_helper']=hex(new_register)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--alignment',type=Path);parser.add_argument('--export',type=Path,action='append',default=[]);args=parser.parse_args()
    path,report=run(args.root,args.export,args.alignment);print(json.dumps(dict(report=str(path),roots=report['roots'],unknown=report['unknown'])))
