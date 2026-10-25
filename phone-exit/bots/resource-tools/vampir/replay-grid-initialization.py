"""Bounded GridSlot initialization replay; object bytes are fixtures, never CDO defaults."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('grid_init_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
import unicorn
from unicorn import x86_const as x
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
LEAF=0x14174c9f0
LEAF_BYTES=bytes.fromhex('803d7c37ba090074184c8d05801c3207baa2000000488d0d241d3207e99f87deffc3')
ROOTS=(0x14358e000,0x1417cba90)
DIAGNOSTIC=0x1415351b0


def sha(raw):return hashlib.sha256(raw).hexdigest()


def run(request,base_request,callback_request):
    if native.capstone.__version__!='5.0.6' or unicorn.__version__!='2.1.4':raise ValueError('Unreviewed native tools')
    for req,roots in [(request,[LEAF]),(base_request,[ROOTS[1]]),(callback_request,[ROOTS[0]])]:
        if req['source_sha256']!=SHA or req['question']!='ui-nktileview-property-schema':raise ValueError('Unreviewed request source')
        if not set(map(hex,roots))<={f['address'] for f in req['functions']}:raise ValueError('Missing explicit root/leaf')
    raw=Path(request['source']).read_bytes()
    if sha(raw)!=SHA:raise ValueError('EXE changed')
    image=native.Image(raw);selected=set()
    for a in ROOTS:
        r=image.containing(a)
        if r is None or image.pe.base+image.roots[r][0]!=a:raise ValueError('Unwind root changed')
        selected.add(image.roots[r])
    fragments=native.decode_ranges(image,selected)
    off=image.offset(LEAF-image.pe.base)
    if image.containing(LEAF) is not None or raw[off:off+len(LEAF_BYTES)]!=LEAF_BYTES or raw[off+len(LEAF_BYTES):off+0x30]!=b'\xcc'*14:raise ValueError('Unreviewed diagnostic leaf bytes/padding')
    flag=LEAF+7+struct.unpack_from('<i',LEAF_BYTES,2)[0]
    ranges=[(image.pe.base+f['begin_rva'],image.pe.base+f['end_rva']) for f in fragments]+[(LEAF,LEAF+len(LEAF_BYTES))]
    pages={p for a,b in ranges for p in range(a&~4095,(b+4095)&~4095,4096)}
    pages|={a&~4095 for f in fragments for i in f['instructions'] for a in i['rip_references']}
    pages|={flag&~4095,DIAGNOSTIC&~4095}
    prepared=[]
    for page in pages:
        try:o=image.offset(page-image.pe.base);data=raw[o:o+4096]
        except ValueError:data=b''
        prepared.append((page,data))
    cases=[]
    for entry in ROOTS:
        contexts=['same','null','other'] if entry==ROOTS[1] else ['same','null']
        for pattern in [0,0x55,0xaa,0xff]:
            for flag_value in [0,1]:
                for context in contexts:
                    uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
                    for page,data in prepared:
                        uc.mem_map(page,4096)
                        if data:uc.mem_write(page,data)
                    base=0x20000000;uc.mem_map(base,0x80000)
                    obj,ctx,stack,stop=[base+n for n in [0x2000,0x4000,0x40008,0x50000]]
                    before=bytes([pattern])*0xb8
                    uc.mem_write(obj-0x20,before)
                    uc.mem_write(ctx,struct.pack('<Q',obj if context=='same' else 0 if context=='null' else obj+0x100))
                    uc.mem_write(ctx+8,bytes([pattern])*0x20)
                    uc.mem_write(flag,bytes([flag_value]));uc.mem_write(stack,struct.pack('<Q',stop))
                    uc.reg_write(x.UC_X86_REG_RSP,stack)
                    uc.reg_write(x.UC_X86_REG_RCX,ctx if entry==ROOTS[0] else obj)
                    uc.reg_write(x.UC_X86_REG_RDX,ctx)
                    trace=[];terminal=[]
                    def hook(machine,address,size,_):
                        if address==DIAGNOSTIC:
                            terminal.append('diagnostic_not_executed');machine.emu_stop();return
                        if not any(a<=address<b for a,b in ranges):raise ValueError('Execution escaped reviewed fragments '+hex(address))
                        trace.append(address)
                    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
                    uc.emu_start(entry,stop,count=1000)
                    diagnostic=(context!='null' and bool(flag_value)) if entry==ROOTS[0] else bool(flag_value) or context=='other'
                    if bool(terminal)!=diagnostic:raise ValueError('Unexpected diagnostic branch')
                    if not terminal and uc.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError('Native replay did not return')
                    after=bytes(uc.mem_read(obj-0x20,len(before)))
                    if after[:0x20]!=before[:0x20] or after[-0x20:]!=before[-0x20:]:raise ValueError('Object guard changed')
                    untouched=bytes(uc.mem_read(obj+0x4c,16))
                    if untouched!=bytes([pattern])*16:raise ValueError('Row/Span/Column bytes unexpectedly initialized')
                    if not diagnostic and entry==ROOTS[0] and context=='same':
                        expected=bytearray([pattern]*0x78)
                        struct.pack_into('<Q',expected,0,0x148ff5610)
                        for start,size in [(0x28,8),(0x30,8),(0x38,8),(0x40,8),(0x48,2),(0x5c,4),(0x60,8),(0x68,8),(0x70,8)]:expected[start:start+size]=b'\0'*size
                        if bytes(uc.mem_read(obj,0x78))!=expected:raise ValueError('Constructor writes differ')
                    if entry==ROOTS[0] and context=='null' and after!=before:raise ValueError('Null initializer changed object')
                    cases.append(dict(entry=hex(entry),pattern=pattern,context=context,flag=flag_value,
                                      terminal=terminal[0] if terminal else 'returned',preserved_member_bytes=untouched.hex(),instructions=len(trace)))
    return dict(source_sha256=SHA,fragments=fragments,leaf=dict(address=hex(LEAF),bytes=LEAF_BYTES.hex(),padding='cc'*14,flag=hex(flag)),cases=cases,
                limits=['Initial object/context/allocation/flag bytes are fixtures, not live CDO or archetype state.',
                        'Diagnostic entry is a terminal stop; its body and outcome are not executed or assumed to return.',
                        'Normal initialization executes reviewed native bodies without service callbacks; omitted defaults are not inferred.',
                        'No game process, game commands, current cooked compatibility or runtime geometry checked.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['request','base-request','callback-request','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=run(*[json.loads(v.read_bytes()) for v in [a.request,a.base_request,a.callback_request]])
    result['tool_sha256']=sha(Path(__file__).read_bytes())
    with a.output.open('x',encoding='utf8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(dict(output=str(a.output),cases=len(result['cases']))))
