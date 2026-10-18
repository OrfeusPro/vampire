"""Execute base initializer and compare explicit scenarios with a cost model."""
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def expected_state(areas,owner_5bc,owner_5d0,owner_644,blocked_flags):
    def f32(value):return struct.unpack('<f',struct.pack('<f',value))[0]
    maximum=struct.unpack('<f',bytes.fromhex('ffff7f7f'))[0]
    travel=[maximum]+[1.]*63;entering=[0.]*64;minimum=1.
    for area in areas:
        if area['class_state'] in ('null_class','null_cdo'):continue
        value=f32(area['travel']);travel[area['area_id']]=value;minimum=min(minimum,value)
        entering[area['area_id']]=f32(area['entering'])
    limit=f32(owner_5bc)
    return dict(travel_costs=travel,entering_costs=entering,minimum_cost=minimum,
        include_flags=65535^blocked_flags,exclude_flags=0,
        owner_5bc_truncated=math.trunc(limit) if -2147483648<=limit<2147483648 else -2147483648,
        impl_flag428=(owner_5d0>>11)&1,impl_double410=f32(owner_644))

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    module=load('base_evidence_harness','recast-base-filter-emulator.py');emulator=module.BaseFilterEmulator(root)
    native=load('base_evidence_native','build-native-entry-code.py')
    extra=native.decode_ranges(emulator.image,{emulator.image.roots[emulator.image.containing(a)] for a in [0x14526ef70,0x145297f60,0x1454d0020]})
    fragments=emulator.base_fragments+emulator.apply_fragments+extra
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x1452b7132,'mov','rsi, qword ptr [rcx + 0x400]'),(0x1452b713c,'mov','ecx, 0x430'),
        (0x1452b7141,'call','0x1468e4100'),(0x1452b714d,'mov','dl, 1'),(0x1452b7152,'call','0x145299c20'),
        (0x1452b715f,'mov','ecx, 0x18'),(0x1452b7169,'add','rsi, 0x10'),(0x1452b716d,'call','0x1468e4100'),
        (0x1452b71ae,'mov','qword ptr [rsi], rbx'),(0x1452b71bb,'call','0x14146d9e0'),
        (0x1452b7206,'cvttss2si','ecx, dword ptr [rbp + 0x5bc]'),(0x1452b720e,'mov','dword ptr [rax + 0x20], ecx'),
        (0x1452b721c,'mov','eax, dword ptr [rbp + 0x5d0]'),(0x1452b7222,'shr','eax, 0xb'),
        (0x1452b7227,'mov','byte ptr [r12 + 0x428], al'),(0x1452b722f,'movss','xmm0, dword ptr [rbp + 0x644]'),
        (0x1452b723a,'movsd','qword ptr [r12 + 0x410], xmm0'),(0x1452b7244,'movzx','eax, word ptr [rip + 0x62af961]'),
        (0x1452b724e,'and','word ptr [r12 + 0x420], ax'),(0x1452b7270,'mov','r15, qword ptr [rbp + 0x460]'),
        (0x1452b7277,'mov','rbx, qword ptr [rsi + r15 + 0x18]'),(0x1452b728e,'call','0x1416aaaf0'),
        (0x1452b7293,'mov','r14, qword ptr [rbx + 0x110]'),(0x1452b72a6,'movss','xmm2, dword ptr [r14 + 0x30]'),
        (0x1452b72ac,'movzx','edx, byte ptr [rsi + r15 + 0x10]'),(0x1452b72b2,'call','qword ptr [rax + 0x10]'),
        (0x1452b72c3,'call','qword ptr [rax + 0x2e8]'),(0x1452b72d5,'call','rbx'),
        (0x1452b72d9,'add','rsi, 0x20'),(0x1452b72dd,'cmp','edi, dword ptr [rbp + 0x468]'),
        (0x14146d9f8,'mov','qword ptr [rdx], 0'),(0x14146d9ff,'mov','qword ptr [rcx], rax'),
        (0x14526ef7e,'lea','rax, [rip + 0x44b2ca3]'),(0x14526ef8e,'mov','qword ptr [rbx], rax')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed base initializer anchor '+hex(address))
        anchors.append(row)
    if rows[0x14526ef7e]['rip_references'][0]!=emulator.area_vtable['table']:raise ValueError('Area getter class association changed')
    filter_proof_raw=(root/'code-clues/navigation-filter-code.json').read_bytes();filter_proof=json.loads(filter_proof_raw)
    selection_raw=(root/'code-clues/recast-filter-selection-evidence.json').read_bytes();selection=json.loads(selection_raw)
    selection_audit=json.loads((root/'code-clues/recast-filter-selection-audit.json').read_bytes())
    if selection_audit['source_report_sha256']!=sha(selection_raw) or selection['sha256']!=sha(emulator.data) or filter_proof['sha256']!=sha(emulator.data):raise ValueError('Changed upstream class/initializer evidence')
    if filter_proof['cost_field_offsets']!=dict(DefaultCost=48,FixedAreaEnteringCost=52):raise ValueError('Changed area cost fields')
    cases=[]
    def area(identifier,travel=1.,entering=0.,state='present'):
        return dict(area_id=identifier,travel=travel,entering=entering,class_state=state)
    def run(name,areas=None,**changes):
        inputs=dict(areas=[] if areas is None else areas,owner_5bc=2048.,owner_5d0=0,owner_644=1.,blocked_flags=0);inputs.update(changes)
        result=emulator.initialize(**inputs)
        if result['state']!=expected_state(**inputs):raise ValueError('Native base state mismatch '+name)
        if result['reference_counts']!=[1,1]:raise ValueError('Native reference transfer changed')
        expected=[]
        for i,record in enumerate(inputs['areas']):
            if record['class_state'] in ('create','null_cdo'):expected.append(dict(kind='cdo_load_stub',record_index=i,provided=record['class_state']=='create'))
            if record['class_state'] in ('present','create'):
                expected.extend(dict(kind=kind,area_id=record['area_id'],value=module.float32(record[key])) for kind,key in [('travel','travel'),('entering','entering')])
        if result['events']!=[dict(kind='allocate',bytes=0x430),dict(kind='allocate',bytes=0x18)]+expected:raise ValueError('Native base input/order mismatch '+name)
        cases.append(dict(name=name,inputs=inputs,result=result))
    run('empty')
    run('constructor_cost_values_not_runtime',[area(int(i),filter_proof['constructor_cost_writes'][name]['DefaultCost'],0.) for i,name in filter_proof['native_area_ids'].items()])
    for state in ['present','create','null_cdo','null_class']:run('class_state_'+state,[area(12,.5,2.,state)])
    run('record_order_low_then_high',[area(12,.5,2.),area(12,7.,3.)])
    run('record_order_high_then_low',[area(12,7.,3.),area(12,.5,2.)])
    run('negative_direct_CDO_costs',[area(11,-2.,-3.)])
    run('all_64_areas',[area(i,1.+i/10.,i/100.) for i in range(64)])
    for flags in [0,1,0x25,0x8000,0xffff]:run('global_mask_'+str(flags),blocked_flags=flags)
    for flags in [0,1,1<<11,0xffffffff]:run('owner_flags_'+str(flags),owner_5d0=flags)
    for value in [.0,.5,.999,1.,-1.]:run('owner_644_'+str(value),owner_644=value)
    for value in [.9,-.9,2048.75,2147483648.,-2147483904.,module.FLOAT_MAX]:run('owner_5bc_'+str(value),owner_5bc=value)
    report=dict(source=selection['source'],sha256=sha(emulator.data),filter_class_proof_sha256=sha(filter_proof_raw),
        selection_proof_sha256=sha(selection_raw),emulator_sha256=sha((HERE/'recast-base-filter-emulator.py').read_bytes()),
        dependencies={file:sha((HERE/file).read_bytes()) for file in ['recast-filter-apply-emulator.py','recast-portal-emulator.py']},
        anchors=anchors,fragments=fragments,leaves=emulator.leaves,entering_getter=emulator.entering_getter,
        area_vtable=emulator.area_vtable,initializer_vtables=selection['base_initializer_vtables'],
        native_pages=list(emulator.pages.values()),cases=cases,
        synthetic_global=dict(address=emulator.mask_address,size=2,region='PE zero-fill .data',runtime_value_verified=False),
        input_scope=dict(explicit_CDO_float32=True,base_area_vtable=True,old_implementation_ref_null=True,allocator_always_succeeds=True),
        summary=dict(native_cases=len(cases),complete_initializer_body_executed=True,cdo_cost_getter_executed=True,
            runtime_base_costs_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Inputs are explicit synthetic SupportedArea records, area CDO values, owner fields and a global polygon mask.',
            'Only two successful allocator requests and lazy CDO materialization are stubbed; no UE loader or live object access occurs.',
            'The old implementation reference starts null; replacement/destruction and allocation failure branches are not checked.',
            'The base NavArea virtual getter is used on synthetic CDOs. Effective Blueprint/runtime CDO values or custom getter overrides are not established.',
            'Owner fields 0x5bc/0x5d0/0x644 are described by offset, without assuming property names or current values.',
            'Constructor-valued scenario is not a claim that cooked/instance costs equal constructor defaults.',
            'Runtime mesh selection, requests, active costs and actual route traversability remain unverified.'])
    path=root/'code-clues/recast-base-filter-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],anchors=len(anchors),fragments=len(fragments),sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
