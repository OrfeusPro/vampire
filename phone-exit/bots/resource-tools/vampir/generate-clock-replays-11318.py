"""Generate ordinary current Clock/Lobby/Ping replay files from pinned source links."""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
OLD='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
NEW='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
ROOTS={0x1415482f0,0x14156acd0,0x1415da870,0x1445d7cb0,0x1445d9ed0,0x144ab2280,0x1467ab7a0,0x1467cf680}


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def generate(root,alignment,exports):
    root=Path(root);alignment=Path(alignment);raw=alignment.read_bytes();report=json.loads(raw)
    if hashlib.sha256(raw).hexdigest()!=alignment.parent.name or report['source_sha256']!=NEW or report['baseline_sha256']!=OLD:
        raise ValueError('Clock alignment source/digest differs')
    if not ROOTS<={int(a,16) for a in report['roots']}:
        raise ValueError('Clock replay whole roots unresolved')
    native=load('build-native-entry-code');images={}
    for sha in (OLD,NEW):
        raw=(root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Clock generation source differs')
        images[sha]=native.Image(raw)
    links={int(a,16):int(bs[0],16) for a,bs in report['links'].items() if len(bs)==1}
    def address(at):
        if at not in links:raise ValueError('Unmapped clock address '+hex(at))
        return links[at]
    def data(sha,at,size):
        im=images[sha];off=im.offset(at-im.pe.base);return im.data[off:off+size]
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    def add(a,b):
        if a in links and links[a]!=b:raise ValueError('Clock relocation conflict '+hex(a))
        links[a]=b
    replacements={};windows={}
    def leaf(at,size,new=None):
        new=address(at) if new is None else new
        before,after=data(OLD,at,size),data(NEW,new,size)
        aa,bb=list(decoder.disasm(before,at)),list(decoder.disasm(after,new))
        if sum(i.size for i in aa)!=size or sum(i.size for i in bb)!=size or len(aa)!=len(bb):
            raise ValueError('Clock leaf coverage differs')
        add(at,new)
        for x,y in zip(aa,bb):
            add(x.address,y.address);encoded=[]
            for ins in (x,y):
                raw=bytearray(ins.bytes)
                if ins.imm_size and (ins.group(native.capstone.CS_GRP_CALL) or ins.group(native.capstone.CS_GRP_JUMP)):
                    a=x.operands[0].imm;b=y.operands[0].imm
                    if at<=a<at+size:
                        if b-new!=a-at:raise ValueError('Clock local leaf branch differs')
                    else:add(a,b)
                    raw[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
                refs=[op for op in ins.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]
                if refs:
                    xr=next(op for op in x.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP)
                    yr=next(op for op in y.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP)
                    add(x.address+x.size+xr.mem.disp,y.address+y.size+yr.mem.disp)
                    raw[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
                encoded.append(bytes(raw))
            if encoded[0]!=encoded[1]:raise ValueError('Clock leaf shape differs')
            replacements[x.bytes.hex()]=y.bytes.hex()
        replacements[before.hex()]=after.hex()
        windows[hex(new)]=dict(bytes=after.hex(),sha256=hashlib.sha256(after).hexdigest())
    # INIT is a leaf with no supplied whole-root identity. Candidate +300 is
    # admitted only after exact bounded shape and all native target/data links.
    leaf(0x1445d3d50,20,0x1445d4050)
    for at,size in ((0x1445d7bc0,111),(0x1445cd3c0,8),(0x144ab0d10,9),(0x1456d7870,27)):
        leaf(at,size)
    # The base vtable is an explicit bounded candidate. Verify every slot's
    # target code, rather than admitting a data-address delta as identity.
    table_old,table_new=0x149dc9320,0x149dcacb0
    for slot in range(0,0x40,8):
        a,b=(struct.unpack('<Q',data(sha,at+slot,8))[0] for sha,at in ((OLD,table_old),(NEW,table_new)))
        if a==0 and b==0:continue
        part=images[OLD].containing(a)
        if part is None:
            sizes={0x141403b70:3,0x1467cd5d0:5,0x1467cecc0:11}
            if a not in sizes:raise ValueError('Clock vtable target needs explicit leaf proof')
            leaf(a,sizes[a],b);continue
        parts=[r for r,owner in images[OLD].roots.items() if owner==images[OLD].roots[part]]
        if len(parts)!=1 or parts[0][0]+images[OLD].pe.base!=a:
            raise ValueError('Clock vtable target needs whole chained-range proof')
        leaf(a,parts[0][1]-parts[0][0],b)
    add(table_old,table_new)
    # Constructor links the packet vtable; its ID slot and producer send slot
    # establish identities absent from direct calls.
    for table,slot,target in ((0x149926a38,0x28,0x14140d380),(0x149dc9320,0x38,0x1467cf3e0)):
        current=address(table)
        if struct.unpack('<Q',data(OLD,table+slot,8))[0]!=target:raise ValueError('Old clock table target differs')
        add(target,struct.unpack('<Q',data(NEW,current+slot,8))[0])
    leaf(0x14140d380,6)
    current_exports={};available=set()
    for item in exports:
        path=Path(item).resolve()
        if path.name!='details.json' or not path.is_relative_to((root/'ghidra/request-exports'/NEW).resolve()):
            raise ValueError('Clock export outside current source library')
        raw=path.read_bytes();document=json.loads(raw)
        if document['new_source_sha256']!=NEW:raise ValueError('Clock export source differs')
        current_exports[path.parent.name]=hashlib.sha256(raw).hexdigest()
        available.update(int(f['address'],16) for f in document['functions'] if f['decompilation_completed'])
    if not {address(at) for at in ROOTS}<=available:raise ValueError('Clock whole export missing')
    class Port(ast.NodeTransformer):
        def visit_Assign(self,node):
            node=self.generic_visit(node)
            if isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and node.value.func.attr=='make_harness':
                return [node,ast.parse("load('verify-clock-replay-source-11318').verify(h)").body[0]]
            return node
        def visit_Constant(self,node):
            value=node.value
            if type(value)is int and 0x140000000<=value<0x150000000:value=address(value)
            elif isinstance(value,str):
                if value==OLD:value=NEW
                elif value in replacements:value=replacements[value]
                elif '11316' in value:value=value.replace('11316','11318') if value!='native-request-harness-11316' else value
                value=value.replace('1.13.16','1.13.18')
            return ast.copy_location(ast.Constant(value),node)
        def visit_Call(self,node):
            node=self.generic_visit(node)
            if isinstance(node.func,ast.Attribute) and node.func.attr=='make_harness':
                node.keywords.extend([ast.keyword(arg='source_sha256',value=ast.Name(id='SHA',ctx=ast.Load())),
                    ast.keyword(arg='copy_thunk',value=ast.Constant(0x1487f60d9))])
            return node
    generated={}
    for name in ('replay-login-clock','replay-login-ping'):
        source=HERE/(name+'-11316.py');tree=Port().visit(ast.parse(source.read_text('utf-8')))
        ast.fix_missing_locations(tree);text=ast.unparse(tree)+'\n'
        # Native replay evidence is invalidated when any shared verifier changes.
        text=text.replace("report = dict(source_sha256=SHA,", "report = dict(dependencies={n: hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in (Path(__file__).name, 'native-request-harness-11316.py', 'build-native-entry-code.py', 'build-object-zero-init-code.py', 'verify-clock-replay-source-11318.py', 'knowledge/native-contexts/clock-replays-11318.json')}, source_sha256=SHA,")
        compile(text,str(source),'exec');generated[HERE/(name+'-11318.py')]=text
    context=dict(source_sha256=NEW,baseline_sha256=OLD,exports=current_exports,
        alignment=dict(path=str(alignment),sha256=hashlib.sha256(alignment.read_bytes()).hexdigest()),
        mapping={hex(a):hex(b) for a,b in links.items()},byte_replacements=replacements,windows=windows,
        tables={hex(address(at)):data(NEW,address(at),size).hex() for at,size in ((0x149dc9320,0x40),(0x149926a38,0x30))},
        roots=[hex(address(at)) for at in sorted(ROOTS)],semantic_verification=False,network_used=False,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    context_path=HERE/'knowledge/native-contexts/clock-replays-11318.json'
    for path,text in generated.items():path.write_text(text,encoding='utf-8')
    context_path.write_text(json.dumps(context,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return load('research-workflow').snapshot(root,'clock-replay-generation-11318',context)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    p.add_argument('--alignment',type=Path,required=True);p.add_argument('--export',type=Path,action='append',required=True)
    args=p.parse_args();print(generate(args.root,args.alignment,args.export))
