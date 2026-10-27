"""Relocate only the fixed CharacterList package using whole shapes and actual links."""
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
NAMES=('waiting-end','character-list-envelope','character-record','character-extensions',
       'character-list-records','character-list-handler')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def generate(root,alignment,exports,dry_run=False):
    root=Path(root);alignment=Path(alignment)
    report=json.loads(alignment.read_text('utf-8'))
    if report['source_sha256']!=NEW or report['baseline_sha256']!=OLD or report['unknown']:
        raise ValueError('Unresolved CharacterList alignment')
    if report['tool_sha256']!=hashlib.sha256((HERE/'align-character-list-batch-11318.py').read_bytes()).hexdigest():
        raise ValueError('CharacterList alignment tool changed')
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    images={}
    for sha in (OLD,NEW):
        raw=(root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('CharacterList source SHA changed')
        images[sha]=native.Image(raw)
    contexts={name:json.loads((HERE/'knowledge/native-contexts'/(name+'-11316.json')).read_text('utf-8')) for name in NAMES}
    semantic_roots=set()
    def declared_roots(value):
        if isinstance(value,dict):
            if 'source_sha256' in value and value['source_sha256']!=OLD:
                raise ValueError('Historical CharacterList context source differs')
            for key,item in value.items():
                if key=='functions':semantic_roots.update(int(at,16) for at in item.values())
                if key in ('prepare','constructor') and isinstance(item,str):semantic_roots.add(int(item,16))
                declared_roots(item)
        elif isinstance(value,list):
            for item in value:declared_roots(item)
    for context in contexts.values():declared_roots(context)
    if len(semantic_roots)!=40 or {int(at,16) for at in report['roots']}!=semantic_roots:
        raise ValueError('CharacterList alignment declared root set differs')
    fragments={}
    for sha,image in images.items():
        fragments[sha]={}
        for part,owner_root in image.roots.items():fragments[sha].setdefault(owner_root,[]).append(part)
    def source_rows(sha,at):
        image=images[sha];part=image.containing(at)
        if part is None or image.roots[part][0]+image.pe.base!=at:raise ValueError('CharacterList function is not a root')
        root_at=image.roots[part]
        return [row for piece in native.decode_ranges(image,{root_at},functions=fragments[sha][root_at])
                for row in piece['instructions']]
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    links={};calls={}
    def add(a,b):
        links.setdefault(a,set()).add(b)
        if len(links[a])!=1:raise ValueError('Ambiguous CharacterList reference '+hex(a))
    def address(at):
        value=int(at,16)
        if len(links.get(value,()))==1:return hex(next(iter(links[value])))
        if value<0x140000000 or value>=0x150000000:return at
        raise ValueError('Unmapped CharacterList address '+at)
    def data(sha,at,size):
        im=images[sha];off=im.offset(at-im.pe.base);return im.data[off:off+size]
    def decode(raw,at):
        result=[]
        for ins in decoder.disasm(raw,at):
            branch=ins.group(native.capstone.CS_GRP_JUMP);call=ins.group(native.capstone.CS_GRP_CALL)
            target=ins.operands[0].imm if (branch or call) and ins.operands[0].type==native.capstone.x86.X86_OP_IMM else None
            refs=[ins.address+ins.size+op.mem.disp for op in ins.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]
            result.append(dict(address=ins.address,bytes=ins.bytes.hex(),call=call,branch=branch,
                               direct_target=target,rip_references=refs,operands=ins.op_str))
        if sum(len(bytes.fromhex(r['bytes'])) for r in result)!=len(raw):raise ValueError('CharacterList instruction gap')
        return result
    def shape(rows):
        positions={r['address']:i for i,r in enumerate(rows)};out=[]
        for row in rows:
            raw=bytearray.fromhex(row['bytes']);ins=next(decoder.disasm(raw,row['address']));edge=None
            if row['direct_target'] is not None:
                target=row['direct_target'];edge=('local',positions[target]) if target in positions else ('external',)
                raw[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
            if row['rip_references']:raw[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
            out.append((raw.hex(),edge))
        return out
    def bind(before,after):
        if shape(before)!=shape(after):raise ValueError('CharacterList whole/bounded shape differs '+hex(before[0]['address']))
        for a,b in zip(before,after):
            add(a['address'],b['address'])
            for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
            if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
            if a['call']:calls[a['address']]=(b['address'],hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
    def compare(old,new,size):bind(decode(data(OLD,old,size),old),decode(data(NEW,new,size),new))
    # Re-check shapes in the same source images; an alignment is only a candidate.
    for a,b in report['roots'].items():
        old,new=int(a,16),int(b,16)
        if old==0x1467cd7b0:continue
        bind(source_rows(OLD,old),source_rows(NEW,new))
    add(0x1467cd7b0,0x1467cdc80)
    gate=load('version-gate-switch-11318')
    gate_rows=gate.rows(native,images[NEW],NEW)
    old_gate=contexts['character-list-handler']['call_sites']['gate']
    new_gate={hex(r['address']):hex(r['direct_target']) if r['direct_target'] is not None else r['operands'] for r in gate_rows if r['call']}
    before=[int(v,16) for v in old_gate.values() if v.startswith('0x')]
    after=[int(v,16) for v in new_gate.values() if v.startswith('0x')]
    if len(before)!=len(after):raise ValueError('CharacterList gate calls changed')
    for a,b in zip(before,after):add(a,b)
    old_gate_context=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11316.json').read_text('utf-8'))
    new_gate_context=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11318.json').read_text('utf-8'))
    for name in ('gate_state','gate_error'):
        add(int(old_gate_context['fixtures'][name],16),int(new_gate_context['fixtures'][name],16))
    # The registration owner was independently ported in the Login package.
    previous=json.loads((HERE/'knowledge/native-contexts/login-result-registration-11318.json').read_text('utf-8'))
    owner=int(previous['bindings']['owner'],16)
    registration_windows={}
    for context in contexts.values():
        window=context.get('registration')
        if not window:continue
        old=int(window['address'],16);old_owner=int(window['owner'],16)
        add(old_owner,owner)
        expected=bytes.fromhex(window['bytes'])
        if data(OLD,old,len(expected))!=expected:raise ValueError('Old CharacterList registration bytes differ')
        # The historical WaitingEnd window cut the first MOV immediate. Keep
        # that source record intact, but require its exact enclosing MOV and
        # start the new proof at a real instruction boundary.
        if old==0x1467b5186:
            if data(OLD,old-2,2)!=b'\xb9\x08':raise ValueError('WaitingEnd enclosing MOV differs')
            old-=2;expected=b'\xb9\x08'+expected
        before=decode(expected,old);wanted=shape(before)
        guessed=owner+old-old_owner;hits=[]
        # Local offsets within a large owner can move independently of the
        # owner itself. Search only instruction boundaries in this explicit
        # owner, bounded to 4 KiB around the historical relative position.
        image=images[NEW];owner_part=image.containing(owner)
        if owner_part is None or image.roots[owner_part][0]+image.pe.base!=owner:
            raise ValueError('CharacterList registration owner differs')
        owner_root=image.roots[owner_part]
        parts=[part for part,root_at in image.roots.items() if root_at==owner_root
               and part[0]+image.pe.base<=guessed+0x1000+len(expected)
               and part[1]+image.pe.base>=guessed-0x1000]
        owner_rows=[row for fragment in native.decode_ranges(image,{owner_root},functions=parts)
                    for row in fragment['instructions']]
        instruction_addresses={r['address'] for r in owner_rows}
        for row in owner_rows:
            at=row['address']
            if abs(at-guessed)>0x1000 or data(NEW,at,4)!=expected[:4]:continue
            try:after=decode(data(NEW,at,len(expected)),at)
            except ValueError:continue
            if any(r['address'] not in instruction_addresses for r in after):continue
            if shape(after)!=wanted:continue
            # Many registration windows share the same opcodes. The handler
            # vtable's +10 slot identifies the already source-matched handler.
            old_table=int(context['bindings']['handler_table'],16)
            old_handler=int(context['functions']['handler'],16)
            new_handler=int(report['roots'][hex(old_handler)],16)
            table_sites=[i for i,r in enumerate(before) if old_table in r['rip_references']]
            if len(table_sites)!=1:raise ValueError('CharacterList registration table site differs')
            refs=after[table_sites[0]]['rip_references']
            if len(refs)!=1:continue
            try:slot=struct.unpack('<Q',data(NEW,refs[0]+0x10,8))[0]
            except ValueError:continue
            if slot==new_handler:hits.append((at,after))
        if len(hits)!=1:raise ValueError('CharacterList registration window missing or ambiguous')
        bind(before,hits[0][1])
        at=hits[0][0];raw=data(NEW,at,len(expected))
        registration_windows[window['address']]=dict(address=hex(at),owner=hex(owner),bytes=raw.hex(),
            instructions=[[hex(i.address),i.mnemonic,i.op_str] for i in decoder.disasm(raw,at)])
    def objects(value):
        if isinstance(value,dict):
            yield value
            for v in value.values():yield from objects(v)
        elif isinstance(value,list):
            for v in value:yield from objects(v)
    items=[o for context in contexts.values() for o in objects(context)]
    blocks={int(b['address'],16):b for o in items for b in o.get('blocks',[])}
    # Packet name is adjacent to its source-linked vtable, not an arbitrary delta.
    packet=int(contexts['character-list-envelope']['bindings']['packet_table'],16)
    notify=int(contexts['waiting-end']['bindings']['notify_table'],16)
    leaves={int(at,16):(spec['bytes'] if isinstance(spec,dict) else spec) for o in items for at,spec in o.get('leaves',{}).items()}
    # Registration supplies constructors; constructor leaves supply tables;
    # table slots can supply further leaves. Resolve those dependencies together.
    while leaves or blocks:
        for table in (packet,notify):
            if len(links.get(table,()))==1:add(table+0x50,int(address(hex(table)),16)+0x50)
        ready_blocks=[at for at in blocks if len(links.get(at,()))==1]
        ready_leaves=[at for at in leaves if len(links.get(at,()))==1]
        if not ready_blocks and not ready_leaves:
            raise ValueError('Unmapped CharacterList blocks/leaves '+repr([hex(at) for at in set(blocks)|set(leaves)]))
        for at in ready_blocks:
            block=blocks.pop(at);new=int(address(hex(at)),16);size=len(bytes.fromhex(block['bytes']))
            old_bytes,new_bytes=data(OLD,at,size),data(NEW,new,size)
            if old_bytes!=bytes.fromhex(block['bytes']):raise ValueError('Old CharacterList block differs')
            if at in (packet+0x50,notify+0x50):
                if old_bytes!=new_bytes:raise ValueError('CharacterList packet name changed')
                continue
            for offset in range(0,size-size%8,8):
                a,b=(struct.unpack_from('<Q',v,offset)[0] for v in (old_bytes,new_bytes))
                if 0x140000000<=a<0x150000000:add(a,b)
                elif a!=b:raise ValueError('CharacterList non-pointer block data changed')
        for at in ready_leaves:compare(at,int(address(hex(at)),16),len(bytes.fromhex(leaves.pop(at))))
    digests={};export_functions=set()
    for export in exports:
        path=Path(export).resolve()
        if not path.is_relative_to((root/'ghidra/request-exports'/NEW).resolve()) or path.name!='details.json':
            raise ValueError('CharacterList export outside source library')
        raw=path.read_bytes();document=json.loads(raw)
        if document['new_source_sha256']!=NEW:raise ValueError('CharacterList export source differs')
        digests[path.parent.name]=hashlib.sha256(raw).hexdigest()
        export_functions.update(int(f['address'],16) for f in document['functions'] if f.get('decompilation_completed'))
    required={int(v,16) for a,v in report['roots'].items() if a in report['candidates'] or a=='0x1467cd7b0'}
    missing_exports=required-export_functions
    if missing_exports and not dry_run:raise ValueError('CharacterList exports missing '+repr([hex(at) for at in missing_exports]))
    def payload(at,encoded):return data(NEW,int(address(at),16),len(bytes.fromhex(encoded)))
    def convert(value,key=None,parent=None):
        if key=='source_sha256':return NEW
        if key=='source':return str(root/'client-code-snapshots'/NEW/'ProjectRED-Win64-Shipping.exe')
        if key=='exports':return digests
        if key=='table_bytes':
            at=int(parent['table'],16);old_bytes=bytes.fromhex(value)
            if data(OLD,at,len(old_bytes))!=old_bytes:
                raise ValueError('Historical CharacterList inline table bytes differ')
            return payload(parent['table'],value).hex()
        if key=='leaves':
            result={}
            for at,spec in value.items():
                raw=payload(at,spec['bytes'] if isinstance(spec,dict) else spec)
                result[address(at)]=dict(bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest()) if isinstance(spec,dict) else raw.hex()
            return result
        if key=='blocks':
            return [dict(address=address(b['address']),bytes=(raw:=payload(b['address'],b['bytes'])).hex(),
                         sha256=hashlib.sha256(raw).hexdigest()) for b in value]
        if key=='registration':
            return registration_windows[value['address']]
        if key=='call_sites':
            if value and not next(iter(value)).startswith('0x'):
                return {k:(new_gate if k=='gate' else convert(v,'call_sites')) for k,v in value.items()}
            return {hex(calls[int(at,16)][0]):dict(target=calls[int(at,16)][1]) if isinstance(v,dict) else calls[int(at,16)][1] for at,v in value.items()}
        if key and key.endswith('_bytes'):
            raise ValueError('Unreviewed CharacterList byte field '+key)
        if isinstance(value,dict):
            if any(re.fullmatch('0x[0-9a-fA-F]+',k) for k in value):
                raise ValueError('Unreviewed CharacterList address-keyed map '+str(key))
            return {k:convert(v,k,value) for k,v in value.items()}
        if isinstance(value,list):return [convert(v) for v in value]
        if isinstance(value,str) and re.fullmatch('0x[0-9a-fA-F]+',value):return address(value)
        return value
    generated={}
    for name,context in contexts.items():
        current=convert(context)
        if name=='character-list-handler':current['switch_gate']='version-gate-11318'
        else:current['verify_whole_exports']=True
        generated[HERE/'knowledge/native-contexts'/(name+'-11318.json')]=json.dumps(current,ensure_ascii=False,indent=2)+'\n'
    result=dict(source_sha256=NEW,baseline_sha256=OLD,alignment=dict(path=str(alignment),sha256=hashlib.sha256(alignment.read_bytes()).hexdigest()),
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),exports=digests,
                contexts={str(p):hashlib.sha256(s.encode()).hexdigest() for p,s in generated.items()},
                missing_exports=sorted(hex(at) for at in missing_exports),
                dry_run=dry_run,semantic_verification=False,network_used=False)
    if dry_run:return result
    for path,content in generated.items():path.write_text(content,encoding='utf-8')
    return load('research-workflow').snapshot(root,'character-list-contexts-11318',result)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--alignment',type=Path,required=True)
    parser.add_argument('--export',type=Path,action='append',default=[])
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args();result=generate(args.root,args.alignment,args.export,args.dry_run)
    print(json.dumps(result,ensure_ascii=False) if args.dry_run else result)
