"""Pin constructor fields -> class/CDO query selection and base-reset ordering."""
import copy
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIELDS = ['Default', 'ShortPath', 'ExcludeHiddenPath']
def sha(raw): return hashlib.sha256(raw).hexdigest()
def load(name, file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def validate_case(result):
    lifecycle = result['entry']=='lifecycle'
    fields = FIELDS if lifecycle else [result['entry']]
    selected = [f for f in fields if result['states'].get(f,'present') in ('present','missing_cdo')]
    events=result['events'];queries=[e for e in events if e['kind']=='query_cache_stub']
    if [e['field'] for e in queries]!=selected:
        raise ValueError('Wrong class/CDO selection')
    if any(e['base_state']!=result['before'] for e in queries):
        raise ValueError('Query happened after a base mutation')
    created=[e['field'] for e in events if e['kind']=='create_cdo']
    if created!=[f for f in selected if result['states'].get(f)=='missing_cdo']:
        raise ValueError('Unexpected CDO creation branch')
    expected=copy.deepcopy(result['before'])
    writes=[e for e in events if e['kind']=='travel_setter']
    expected_writes=[dict(kind='travel_setter',area_id=i,value=1.) for i in range(10,14)] if lifecycle and result['base_present'] else []
    if writes!=expected_writes:
        raise ValueError('Wrong base cost mutation')
    if writes:
        first_write=next(i for i,e in enumerate(events) if e['kind']=='travel_setter')
        if any(e['kind']=='query_cache_stub' for e in events[first_write:]):
            raise ValueError('Wrong query/reset event order')
        for i in range(10,14):expected['travel_costs'][i]=1.
        expected['minimum_cost']=min(expected['minimum_cost'],1.)
    if result['after']!=expected:
        raise ValueError('Unexpected mutation outside supported base costs')
    if not lifecycle and result['output_has_filter']!=bool(selected):
        raise ValueError('Wrong query output branch')
    if result['runtime_verified'] is not False:
        raise ValueError('Synthetic selection is not live runtime proof')


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    native=load('selection_evidence_native','build-native-entry-code.py')
    harness=load('selection_evidence_harness','recast-filter-selection-emulator.py')
    emulator=harness.FilterSelectionEmulator(root)
    extra=native.decode_ranges(emulator.image,{emulator.image.roots[emulator.image.containing(a)]
        for a in [0x1454d0020,0x145281400,0x14526ca50,0x145297f60,0x1452b7120,0x145688dd0]})
    fragments=emulator.selection_fragments+extra
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x1454d0034,'lea','rax, [rip + 0x43a2efd]'),(0x1454d003b,'mov','qword ptr [rdi], rax'),
        (0x1454da51f,'mov','rcx, qword ptr [rbx + 0x780]'),(0x1454da54a,'call','0x1452818e0'),
        (0x1454da591,'mov','rcx, qword ptr [rbx + 0x788]'),(0x1454da5bc,'call','0x1452818e0'),
        (0x1454da600,'mov','rcx, qword ptr [rbx + 0x790]'),(0x1454da62b,'call','0x1452818e0'),
        (0x1454da663,'mov','rcx, qword ptr [rbx + 0x400]'),(0x1454da677,'je','0x1454da6c8'),
        (0x1454da680,'movss','xmm6, dword ptr [rip + 0x34b2b00]'),
        (0x1454da68b,'call','0x14145ae70'),(0x1454da69c,'call','0x14145ae70'),
        (0x1454da6ad,'call','0x14145ae70'),(0x1454da6be,'call','0x14145ae70'),
        (0x1452818f4,'mov','rdi, qword ptr [r8]'),(0x145281905,'call','0x145267a60'),
        (0x145281923,'cmp','qword ptr [rax + rcx*8], r8'),(0x145281931,'cmp','qword ptr [rdi + 0x110], 0'),
        (0x14528193e,'call','0x1416aaaf0'),(0x145281943,'mov','rcx, qword ptr [rdi + 0x110]'),
        (0x145281953,'call','0x145281400'),(0x14528195c,'mov','qword ptr [rbx], rax'),
        (0x1452815e2,'mov','rcx, qword ptr [r14 + 0x400]'),(0x1452815f2,'call','0x143850680'),
        (0x145281666,'call','qword ptr [rax + 0x2c8]'),
        (0x1454dede4,'mov','rcx, qword ptr [rcx + 0x780]'),(0x1454dee0a,'call','0x1452818e0'),
        (0x1454dee94,'mov','rcx, qword ptr [rcx + 0x790]'),(0x1454deeba,'call','0x1452818e0'),
        (0x1454e07c4,'mov','rcx, qword ptr [rcx + 0x788]'),(0x1454e07ea,'call','0x1452818e0'),
        (0x14526cb2f,'lea','r14, [rsi + 0x400]'),(0x14526cd69,'mov','qword ptr [r14], rdi'),
        (0x145297f7a,'lea','rax, [rip + 0x4495c7f]'),(0x145297f81,'mov','qword ptr [rdi], rax'),
        (0x1452b7132,'mov','rsi, qword ptr [rcx + 0x400]'),(0x1452b7141,'call','0x1468e4100'),
        (0x1452b7152,'call','0x145299c20'),(0x1452b7169,'add','rsi, 0x10'),
        (0x1452b71ae,'mov','qword ptr [rsi], rbx'),(0x1452b7206,'cvttss2si','ecx, dword ptr [rbp + 0x5bc]'),
        (0x1452b7227,'mov','byte ptr [r12 + 0x428], al'),(0x1452b723a,'movsd','qword ptr [r12 + 0x410], xmm0'),
        (0x1452b724e,'and','word ptr [r12 + 0x420], ax'),(0x1452b7277,'mov','rbx, qword ptr [rsi + r15 + 0x18]'),
        (0x1452b72a6,'movss','xmm2, dword ptr [r14 + 0x30]'),(0x1452b72ac,'movzx','edx, byte ptr [rsi + r15 + 0x10]'),
        (0x1452b72b2,'call','qword ptr [rax + 0x10]'),(0x1452b72c3,'call','qword ptr [rax + 0x2e8]'),
        (0x1452b72d5,'call','rbx'),(0x145688edc,'call','0x1454dedd0'),
        (0x145689006,'call','0x1454dee80'),(0x14568902d,'call','0x1454e07b0'),(0x1456890bf,'call','0x14569bcf0')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed selection anchor '+hex(address))
        anchors.append(row)
    table=rows[0x1454d0034]['rip_references'][0];offset=emulator.image.offset(table+0x3a0-emulator.image.pe.base)
    raw=emulator.data[offset:offset+8]
    if struct.unpack('<Q',raw)[0]!=0x1454da500:raise ValueError('Changed NnRecastNavMesh lifecycle virtual slot')
    slot=dict(table=table,slot=0x3a0,target=0x1454da500,file_offset=offset,raw_hex=raw.hex())
    base_slots=[]
    for vtable in [table,rows[0x145297f7a]['rip_references'][0]]:
        offset=emulator.image.offset(vtable+0x8e0-emulator.image.pe.base);raw=emulator.data[offset:offset+8]
        if struct.unpack('<Q',raw)[0]!=0x1452b7120:raise ValueError('Changed base filter initializer virtual slot')
        base_slots.append(dict(table=vtable,slot=0x8e0,target=0x1452b7120,file_offset=offset,raw_hex=raw.hex()))
    address=rows[0x1454da680]['rip_references'][0];offset=emulator.image.offset(address-emulator.image.pe.base)
    raw=emulator.data[offset:offset+4]
    if raw!=struct.pack('<f',1.):raise ValueError('Changed base reset constant')
    constant=dict(address=address,file_offset=offset,raw_hex=raw.hex(),value=1.)
    proof_path=root/'code-clues/navigation-filter-code.json';proof_raw=proof_path.read_bytes();proof=json.loads(proof_raw)
    if proof['sha256']!=sha(emulator.data) or proof['filter_class_fields']!=harness.FIELDS:raise ValueError('Changed constructor field proof')
    cases=[]
    def run(name,**inputs):
        result=emulator.run(**inputs);validate_case(result);cases.append(dict(name=name,inputs=inputs,result=result))
    for field in FIELDS:
        for state in ['present','missing_cdo','null','wrong_parent']:
            run(field+'_'+state,entry=field,states={field:state})
    for flag in [False,True]:
        run('lifecycle_callback_'+str(flag),entry='lifecycle',callback_flag=flag,costs={10:2.,11:3.,12:4.,13:5.,25:17.})
    run('lifecycle_mixed_classes',entry='lifecycle',states={'Default':'missing_cdo','ShortPath':'wrong_parent','ExcludeHiddenPath':'null'})
    run('lifecycle_null_base',entry='lifecycle',base_present=False)
    report=dict(source=str(Path(json.loads((root/'code-clues/native-enums.json').read_bytes())['source'])),
        sha256=sha(emulator.data),constructor_proof_sha256=sha(proof_raw),
        emulator_sha256=sha((HERE/'recast-filter-selection-emulator.py').read_bytes()),
        dependencies={file:sha((HERE/file).read_bytes()) for file in ['recast-filter-apply-emulator.py','recast-portal-emulator.py']},
        class_fields=harness.FIELDS,wrappers=harness.WRAPPERS,anchors=anchors,fragments=fragments,
        lifecycle_vtable=slot,base_initializer_vtables=base_slots,base_reset_constant=constant,native_pages=list(emulator.pages.values()),cases=cases,
        base_initializer_static=dict(address=0x1452b7120,owner_shared_offset=0x400,shared_impl_offset=16,
            supported_area_array_offset=0x460,supported_area_stride=32,area_class_offset=24,area_id_offset=16,
            area_cdo_travel_cost_offset=48,entering_cost_getter_slot=0x2e8,executed=False),
        synthetic_global=dict(address=emulator.callback_flag_address,region='PE zero-fill .data',values=[0,1],runtime_value_verified=False),
        stubs=dict(filter_class_getter=0x145267a60,cdo_creation=0x1416aaaf0,class_pointer_callback=0x1416dceb0,
                   base_lifecycle=0x143801260,query_cache=0x145281400),
        summary=dict(native_cases=len(cases),class_field_to_query_verified=True,lifecycle_prefetch_before_base_reset_verified=True,
            base_reset_area_ids=[10,11,12,13],base_reset_value=1.,runtime_selection_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['The virtual slot function has not been assigned a reflected lifecycle name.',
            'Class ancestry and CDO storage are synthetic; native class/CDO loading and the query cache body are stubbed.',
            'The base lifecycle is a no-op stub; the base implementation creation and supported-area loop are static evidence only.',
            'The callback global flag is an explicit synthetic input in a PE zero-fill page; it is not read from a game process.',
            'Cache cloning/application are separately pinned static evidence here; the stub does not prove cached costs or cache lifetime.',
            'Null-base case proves the final mutation guard only after stubbed cache calls, not viability with a real cache.',
            'Active mesh coverage, runtime requests and real route traversability remain unverified.'])
    path=root/'code-clues/recast-filter-selection-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],anchors=len(anchors),fragments=len(fragments),sha256=sha(path.read_bytes()))));return report


if __name__=='__main__':main()
