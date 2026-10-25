"""Static GridSlot construction argument flow; no claims about omitted defaults."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('construction_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def inspect(request,class_request,callback_request):
    selected=set()
    raw=Path(request['source']).read_bytes()
    if sha(raw)!=SHA:raise ValueError('EXE changed')
    image=native.Image(raw)
    for req,roots in [(request,[0x1416ab8d0,0x1417cba90]),(class_request,[0x143579900]),(callback_request,[0x14358e000])]:
        if req['source_sha256']!=SHA or req['question']!='ui-nktileview-property-schema':raise ValueError('Wrong source/question')
        if not set(map(hex,roots))<={f['address'] for f in req['functions']}:raise ValueError('Missing explicit roots')
        for a in roots:
            r=image.containing(a)
            if r is None or image.pe.base+image.roots[r][0]!=a:raise ValueError('Wrong unwind root')
            selected.add(image.roots[r])
    fragments=native.decode_ranges(image,selected)
    rows={r['address']:r for f in fragments for r in f['instructions']}
    anchors={
        0x143579900:('mov','r11, rsp'),0x143579903:('sub','rsp, 0x78'),
        0x143579967:('lea','rax, [rip + 0x14692]'),0x14357996e:('mov','qword ptr [r11 - 0x30], rax'),
        0x14357999d:('call','0x1416ab8d0'),
        0x1416ab8df:('push','rdi'),0x1416ab8e0:('push','r14'),0x1416ab8e2:('push','r15'),0x1416ab8e4:('sub','rsp, 0x30'),
        0x1416ab943:('mov','rcx, qword ptr [rsp + 0x98]'),0x1416ab96e:('mov','qword ptr [rbx + 0xb0], rcx'),
        0x1416abacc:('call','qword ptr [rsp + 0xb0]'),0x1416abb4c:('mov','rax, r14'),0x1416abb67:('jmp','rax'),
        0x14358e006:('mov','rbx, qword ptr [rcx]'),0x14358e014:('call','0x1417cba90'),
        0x1417cbaaa:('call','0x14174c9f0'),0x1417cbad4:('mov','qword ptr [rdi], rbx'),
        0x1417cbadf:('mov','byte ptr [rdi + 0x12], 0')}
    for a,expected in anchors.items():
        if (rows[a]['mnemonic'],rows[a]['operands'])!=expected:raise ValueError('Instruction flow changed at '+hex(a))
    if rows[0x143579967]['rip_references']!=[0x14358e000]:raise ValueError('Another constructor callback')
    writes=[]
    for row in rows.values():
        if 0x14358e019<=row['address']<0x14358e048 and row['mnemonic']=='mov':
            writes.append(dict(address=hex(row['address']),bytes=row['bytes'],instruction=row['operands']))
    return dict(source_sha256=SHA,fragments=fragments,anchors={hex(a):dict(mnemonic=m,operands=o) for a,(m,o) in anchors.items()},
                callback_flow=dict(getter='0x143579900',callback='0x14358e000',getter_entry_stack_relative=-0x30,
                    helper_entry_stack_relative=0x50,helper_frame_stack_relative=0x98,destination_class_offset=0xb0,
                    note='Helper frame subtracts 0x48; saved callback is argument 10. It is stored, not invoked along this explicit store.'),
                initialization_writes=writes,base_initialization_callee='0x1417cba90',unresolved_base_callee='0x14174c9f0',
                limits=['Static instructions only; construction callbacks and CDO allocation/copy not executed.',
                        'Writes after the base call do not prove the preexisting state of untouched fields.',
                        'No zero/one default inferred for omitted Row/Column/Span; no historical cooked compatibility or runtime geometry established.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['request','class-request','callback-request','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=inspect(*[json.loads(path.read_bytes()) for path in [a.request,a.class_request,a.callback_request]])
    result['inspector_sha256']=sha(Path(__file__).read_bytes())
    result['requests']={str(path):sha(path.read_bytes()) for path in [a.request,a.class_request,a.callback_request]}
    with a.output.open('x',encoding='utf8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(dict(output=str(a.output),fragments=len(result['fragments']),writes=len(result['initialization_writes']))))
