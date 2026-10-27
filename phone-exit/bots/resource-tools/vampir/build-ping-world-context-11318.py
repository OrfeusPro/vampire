"""Build the fixed Ping/world source context; no IO, auth or automatic admission."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
OLD='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
WORLD_ROOTS=tuple(int(a,16) for a in ('14561bca0 1456baaf0 1456db410 1456e8280 1456f00c0 '
    '145821fb0 1458220f0 14584f120 14584f3d0 14584f4f0 145dafa00 145db2bb0 '
    '145db30e0 1467cf320').split())


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(root,alignment,exports):
    root=Path(root);alignment=Path(alignment);prior=json.loads(alignment.read_bytes())
    if prior['source_sha256']!=SHA or prior['baseline_sha256']!=OLD:
        raise ValueError('Ping/world alignment source differs')
    native=load('build-native-entry-code');images={}
    for sha in (OLD,SHA):
        path=root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Ping/world source SHA changed')
        images[sha]=native.Image(raw)
    links={int(a,16):{int(b,16) for b in values} for a,values in prior['links'].items()}
    def add(a,b):
        links.setdefault(a,set()).add(b)
        if len(links[a])!=1:raise ValueError('Ambiguous Ping/world reference '+hex(a))
    def relocate(at):
        if len(links.get(at,()))!=1:raise ValueError('Missing Ping/world reference '+hex(at))
        return next(iter(links[at]))
    def data(sha,at,size):
        im=images[sha];off=im.offset(at-im.pe.base);return im.data[off:off+size]
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    def rows(sha,at):
        im=images[sha];part=im.containing(at)
        if part is None or im.roots[part][0]+im.pe.base!=at:raise ValueError('Ping/world must use explicit unwind root')
        owner=im.roots[part];parts=[p for p,r in im.roots.items() if r==owner]
        return [r for f in native.decode_ranges(im,{owner},functions=parts) for r in f['instructions']]
    def shape(rr):
        positions={r['address']:i for i,r in enumerate(rr)};out=[]
        for r in rr:
            raw=bytearray.fromhex(r['bytes']);ins=next(decoder.disasm(raw,r['address']));edge=None
            if r['direct_target'] is not None:
                target=r['direct_target'];edge=('local',positions[target]) if target in positions else ('external',)
                raw[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
            if r['rip_references']:raw[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
            out.append((raw.hex(),edge))
        return out
    roots={old:relocate(old) for old in WORLD_ROOTS};roots[0x14679c450]=0x14679c920
    for old,new in roots.items():
        before,after=rows(OLD,old),rows(SHA,new)
        if shape(before)!=shape(after):raise ValueError('Ping/world whole shape differs '+hex(old))
        add(old,new)
        for a,b in zip(before,after):
            add(a['address'],b['address'])
            for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
            if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
    # The existing singleton GET is a short leaf. Compare MOV RIP,RET and use
    # its actual relocated pointer, never a guessed global-address delta.
    get=relocate(0x1445cd3c0)
    old_leaf=data(OLD,0x1445cd3c0,8);new_leaf=data(SHA,get,8)
    if old_leaf[:3]!=b'\x48\x8b\x05' or old_leaf[-1:]!=b'\xc3' or new_leaf[:3]!=old_leaf[:3] or new_leaf[-1:]!=b'\xc3':
        raise ValueError('Ping clock singleton leaf changed')
    add(0x14b564a40,get+7+struct.unpack_from('<i',new_leaf,3)[0])
    if 0x1445cd3c0+7+struct.unpack_from('<i',old_leaf,3)[0]!=0x14b564a40:
        raise ValueError('Old Ping singleton global differs')
    leaves={hex(get):new_leaf.hex()}
    for at,size in ((0x1456d7c70,23),(0x1456e5080,6),(0x144ab0f40,8),(0x145595140,8)):
        raw=data(SHA,at,size);ins=list(decoder.disasm(raw,at))
        if not ins or ins[-1].mnemonic!='ret' or sum(i.size for i in ins)!=size:
            raise ValueError('Ping leaf boundary differs')
        leaves[hex(at)]=raw.hex()
    if data(SHA,0x1456e5080,6)!=b'\xb8\x11\0\0\0\xc3':raise ValueError('Ping packet ID differs')
    table=0x149928290;handler_table=0x149dc7fa8
    if data(SHA,table+0x50,14)!=b'PktPingResult\0':raise ValueError('Ping packet name differs')
    for base,slot,target in ((table,0x20,0x1456db7f0),(table,0x28,0x1456e5080),(handler_table,0x10,0x14679c920)):
        if struct.unpack('<Q',data(SHA,base+slot,8))[0]!=target:raise ValueError('Ping table target differs')
    ctor=list(decoder.disasm(data(SHA,0x1456d7c70,23),0x1456d7c70))
    if ctor[0].mnemonic!='lea' or ctor[0].address+ctor[0].size+ctor[0].operands[1].mem.disp!=table or ctor[1].op_str!='qword ptr [rcx], rax':
        raise ValueError('Ping constructor table store differs')
    register=0x1467b53fc;owner=0x1467b5130;size=75;window=data(SHA,register,size)
    part=images[SHA].containing(register)
    if part is None or images[SHA].roots[part][0]+images[SHA].pe.base!=owner:raise ValueError('Ping registration owner differs')
    ins=list(decoder.disasm(window,register))
    if sum(i.size for i in ins)!=size or [(i.mnemonic,i.op_str) for i in ins[-4:]]!=[
        ('mov','r8, rdi'),('mov','rdx, rax'),('mov','rcx, rsi'),('call','0x1467cbb90')]:
        raise ValueError('Ping registration arguments differ')
    if not any(i.mnemonic=='call' and i.operands[0].imm==0x1456d7c70 for i in ins):raise ValueError('Ping registered constructor differs')
    lea=[i for i in ins if i.mnemonic=='lea']
    if len(lea)!=1 or lea[0].address+lea[0].size+lea[0].operands[1].mem.disp!=handler_table:raise ValueError('Ping registered handler table differs')
    # Receiver's source multiplier must remain exact binary64 -0.0001.
    refs=[x for r in rows(SHA,roots[0x1467cf320]) for x in r['rip_references']]
    multipliers=[at for at in refs if data(SHA,at,8)==struct.pack('<d',-0.0001)]
    if len(multipliers)!=1:raise ValueError('Ping receiver multiplier differs')
    blocks={hex(table):data(SHA,table,0x50).hex(),hex(handler_table):data(SHA,handler_table,0x18).hex(),
            hex(register):window.hex(),hex(multipliers[0]):data(SHA,multipliers[0],8).hex()}
    digests={};available=set()
    for export in exports:
        path=Path(export).resolve()
        if not path.is_relative_to((root/'ghidra/request-exports'/SHA).resolve()) or path.name!='details.json':raise ValueError('Ping export outside source library')
        doc=json.loads(path.read_bytes())
        if doc['new_source_sha256']!=SHA:raise ValueError('Ping export source differs')
        digests[path.parent.name]=digest(path)
        available.update(int(f['address'],16) for f in doc['functions'] if f.get('decompilation_completed'))
    if set(roots.values())-available:raise ValueError('Missing Ping/world exports '+repr([hex(a) for a in set(roots.values())-available]))
    context=dict(schema=1,source_sha256=SHA,source=str(root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'),
        baseline_sha256=OLD,alignment=dict(path=str(alignment),sha256=digest(alignment)),
        mapping={hex(a):hex(next(iter(b))) for a,b in links.items() if len(b)==1},
        functions={hex(a):hex(b) for a,b in roots.items()},leaves=leaves,blocks=blocks,exports=digests,
        ping=dict(constructor='0x1456d7c70',getter='0x1456e5080',reader='0x1456db7f0',handler='0x14679c920',
                  receiver='0x1467cf7f0',packet_table=hex(table),handler_table=hex(handler_table),
                  wrapper_getter='0x144ab0f40',config_getter='0x145595140',clock_global=hex(relocate(0x14b564a40)),
                  recovery=hex(relocate(0x144ab10f0)),registration=dict(address=hex(register),owner=hex(owner),bytes=window.hex())),
        copy_thunk='0x1487f60d9',network_used=False,profile_activated=False,
        tool_sha256=digest(Path(__file__)),limits=['Candidate whole shapes and explicit pointer/instruction links only; native replay required.',
        'Registration window static, not whole factory execution; engine globals/recovery remain fixtures.'])
    path=HERE/'knowledge/native-contexts/ping-world-11318.json';path.write_text(json.dumps(context,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return load('research-workflow').snapshot(root,'ping-world-context-11318',context)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    p.add_argument('--alignment',type=Path,required=True);p.add_argument('--export',type=Path,action='append',required=True)
    a=p.parse_args();print(build(a.root,a.alignment,a.export))
