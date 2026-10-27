"""Explicit input-archive/VersionResult context candidate; native replay is mandatory."""
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


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run(root,export=None):
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    images={}
    for sha in (OLD,NEW):
        raw=(root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Source SHA changed')
        images[sha]=native.Image(raw)
    context=json.loads((HERE/'knowledge/native-contexts/version-result-11316.json').read_text('utf-8'))
    roots={int(v,16) for v in context['native_input']['functions'].values()}|{int(context['reader'],16)}
    if len(roots)!=15:raise ValueError('Explicit input root set changed')
    current={at:(at if at<0x144000000 else at+(0x3e0 if at==0x1456dc5e0 else 0x300)) for at in roots}
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    links={};calls={}
    def add(a,b):
        previous=links.setdefault(a,b)
        if previous!=b:raise ValueError('Ambiguous input address mapping '+hex(a))
    def compare(before,after):
        if len(before)!=len(after):raise ValueError('Input instruction count changed')
        positions=[{r['address']:n for n,r in enumerate(rows)} for rows in (before,after)]
        for a,b in zip(before,after):
            add(a['address'],b['address']);encoded=[];edges=[]
            for row,pos in zip((a,b),positions):
                data=bytearray.fromhex(row['bytes']);ins=next(decoder.disasm(data,row['address']))
                edge=None
                if row['call'] or row['branch']:
                    target=row['direct_target']
                    if target is not None:
                        edge=('local',pos[target]) if target in pos else ('external',)
                        data[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
                if row['rip_references']:data[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
                encoded.append(data);edges.append(edge)
            if encoded[0]!=encoded[1] or edges[0]!=edges[1]:raise ValueError('Input instruction/control shape changed')
            if len(a['rip_references'])!=len(b['rip_references']):raise ValueError('Input RIP arity changed')
            for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
            if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
            if a['call']:calls[a['address']]=(b['address'],hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
    for a,b in current.items():compare(bindings.rows(native,images[OLD],a),bindings.rows(native,images[NEW],b))
    old_table=int(context['native_input']['table'],16)
    if old_table not in links:raise ValueError('Input table lacks constructor reference')
    for slot in range(0,len(bytes.fromhex(context['native_input']['table_bytes'])),8):
        values=[]
        for sha,at in ((OLD,old_table),(NEW,links[old_table])):
            im=images[sha];values.append(struct.unpack_from('<Q',im.data,im.offset(at-im.pe.base)+slot)[0])
        add(*values)
    # Packet constructor/ID and archive leaves are bounded bytes, not unwind roots.
    add(int(context['constructor'],16),0x1456d8070);add(int(context['id_getter'],16),0x14148a940)
    leaves={**context['native_input']['leaves'],**context['leaves']}
    for at,item in leaves.items():
        old=int(at,16)
        if old not in links:raise ValueError('Leaf lacks caller binding '+at)
        new=links[old];size=len(bytes.fromhex(item['bytes']));rows=[]
        for sha,address in ((OLD,old),(NEW,new)):
            im=images[sha];off=im.offset(address-im.pe.base);raw=im.data[off:off+size];part=[]
            for ins in decoder.disasm(raw,address):
                refs=[ins.address+ins.size+op.mem.disp for op in ins.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]
                part.append(dict(address=ins.address,bytes=ins.bytes.hex(),call=ins.group(native.capstone.CS_GRP_CALL),branch=ins.group(native.capstone.CS_GRP_JUMP),direct_target=None,rip_references=refs))
            if sum(len(bytes.fromhex(r['bytes'])) for r in part)!=size:raise ValueError('Leaf instruction gap')
            rows.append(part)
        compare(*rows)
    old_packet_table=int(context['packet_table'],16)
    for item in context['tables']:
        old_at=int(item['address'],16)
        if old_at in links:continue
        # Only the adjacent, explicitly reviewed public packet-name literal.
        if old_at!=old_packet_table+0x50 or bytes.fromhex(item['bytes'])!=b'PktVersionResult\0':
            raise ValueError('Unreviewed packet literal placement')
        new_at=links[old_packet_table]+0x50;im=images[NEW];off=im.offset(new_at-im.pe.base)
        if im.data[off:off+17]!=b'PktVersionResult\0':raise ValueError('Packet name literal changed')
        add(old_at,new_at)
    report=dict(source_sha256=NEW,baseline_sha256=OLD,roots={hex(a):hex(b) for a,b in current.items()},
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),semantic_verification=False,network_used=False)
    if export:
        export=Path(export).resolve()
        if not export.is_relative_to((root/'ghidra/request-exports'/NEW).resolve()) or export.name!='details.json':raise ValueError('Export outside source library')
        d=json.loads(export.read_text('utf-8'));available={int(f['address'],16) for f in d['functions'] if f.get('decompilation_completed')}
        if d['new_source_sha256']!=NEW or not set(current.values())<=available:raise ValueError('Missing input root exports')
        exports={export.parent.name:hashlib.sha256(export.read_bytes()).hexdigest()}
        def address(at):
            value=int(at,16)
            if value in links:return hex(links[value])
            try:images[OLD].offset(value-images[OLD].pe.base)
            except ValueError:return at
            raise ValueError('Unmapped input context address '+at)
        def payload(at,size):
            new=int(address(at),16);im=images[NEW];off=im.offset(new-im.pe.base);return im.data[off:off+size]
        def convert(value,key=None,parent=None):
            if key=='source_sha256':return NEW
            if key=='source':return str(root/'client-code-snapshots'/NEW/'ProjectRED-Win64-Shipping.exe')
            if key=='exports':return exports
            if key=='leaves':
                return {address(at):dict(bytes=(raw:=payload(at,len(bytes.fromhex(item['bytes'])))).hex(),sha256=hashlib.sha256(raw).hexdigest()) for at,item in value.items()}
            if key=='tables':
                return [dict(address=address(item['address']),bytes=(raw:=payload(item['address'],len(bytes.fromhex(item['bytes'])))).hex(),sha256=hashlib.sha256(raw).hexdigest()) for item in value]
            if key=='table_bytes':return payload(parent['table'],len(bytes.fromhex(value))).hex()
            if key=='call_sites':return {hex(calls[int(at,16)][0]):dict(target=calls[int(at,16)][1]) if isinstance(v,dict) else calls[int(at,16)][1] for at,v in value.items()}
            if isinstance(value,dict):return {k:convert(v,k,value) for k,v in value.items()}
            if isinstance(value,list):return [convert(v) for v in value]
            if isinstance(value,str) and re.fullmatch('0x[0-9a-fA-F]+',value):return address(value)
            return value
        candidate=convert(context);candidate['verify_whole_exports']=True
        target=HERE/'knowledge/native-contexts/version-result-11318.json'
        target.write_text(json.dumps(candidate,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        report['context']=str(target)
    path=load('research-workflow').snapshot(root,'version-result-alignment-11318',report)
    return path,report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'));parser.add_argument('--export',type=Path)
    args=parser.parse_args();path,r=run(args.root,args.export);print(json.dumps(dict(report=str(path),roots=r['roots'])))
