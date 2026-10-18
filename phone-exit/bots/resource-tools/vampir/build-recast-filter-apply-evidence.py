"""Verify base filter apply semantics against all saved presets and edge cases."""
import copy,hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
FLOAT_MAX=struct.unpack('<f',bytes.fromhex('ffff7f7f'))[0]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def model_apply(before,areas,ids,include,exclude):
    result=copy.deepcopy(before);result['include_flags']=include;result['exclude_flags']=exclude
    for area in areas:
        identifier=ids.get(area['AreaClass'])
        if identifier is None:continue
        if area['bIsExcluded']:
            result['travel_costs'][identifier]=FLOAT_MAX;result['minimum_cost']=min(result['minimum_cost'],FLOAT_MAX);continue
        if area['bOverrideTravelCost']:
            value=struct.unpack('<f',struct.pack('<f',area['TravelCostOverride']))[0];value=max(value,1.)
            result['travel_costs'][identifier]=value;result['minimum_cost']=min(result['minimum_cost'],value)
        if area['bOverrideEnteringCost']:
            value=struct.unpack('<f',struct.pack('<f',area['EnteringCostOverride']))[0]
            result['entering_costs'][identifier]=value if value>0 else 0.
    return result

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('apply_filter_evidence',HERE/'recast-filter-apply-emulator.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    emulator=module.FilterApplyEmulator(root);rows={r['address']:r for f in emulator.apply_fragments+emulator.leaves for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [(0x14526c49b,'lea','rax, [rip + 0x44ba546]'),(0x14526c4b1,'mov','word ptr [rbx + 0x38], 0xffff'),
        (0x14526c4b7,'mov','word ptr [rbx + 0x3c], cx'),(0x1452815e2,'mov','rcx, qword ptr [r14 + 0x400]'),
        (0x1452815f2,'call','0x143850680'),(0x145281666,'call','qword ptr [rax + 0x2c8]'),
        (0x145282a91,'mov','eax, dword ptr [rbx + rsi + 0x10]'),(0x145282a95,'test','al, 1'),
        (0x145282aa0,'call','0x14145d5b0'),(0x145282aa7,'test','al, 2'),(0x145282ab5,'maxss','xmm2, xmm6'),
        (0x145282abc,'call','0x14145ae70'),(0x145282ac1,'test','byte ptr [rbx + rsi + 0x10], 4'),
        (0x145282ad2,'maxss','xmm2, xmm7'),(0x145282ad9,'call','0x1414532b0'),
        (0x145282ae1,'add','rbx, 0x18'),(0x145299c49,'call','0x14523af10'),
        (0x145299c54,'lea','rax, [rip + 0x4491bfd]'),(0x145299c88,'mov','qword ptr [rdi + 0x10], rax'),
        (0x14529456a,'movsd','qword ptr [rcx + rax*8 + 0x10], xmm1'),
        (0x14529459a,'movsd','qword ptr [rcx + rax*8 + 0x210], xmm0'),
        (0x1452945bd,'mov','qword ptr [rcx + rax*8 + 0x10], rdx'),
        (0x1438507b4,'mov','rcx, qword ptr [r13 + 0x10]'),(0x1438507bb,'call','qword ptr [rax + 0x80]'),
        (0x145294b58,'movups','xmm0, xmmword ptr [rdx]'),(0x145294baa,'jne','0x145294b51')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed apply-filter anchor '+hex(address))
        anchors.append(row)
    # Both virtual dispatch tables are source data, not substituted callbacks.
    tables=[]
    for va,slots in [(0x1497269e8,{0x2c8:0x145282960}),
        (0x14972b858,{0x10:0x145294560,0x18:0x145294590,0x20:0x1452945b0,0x58:0x145294ad0,0x68:0x145294af0,0x80:0x145294b10})]:
        for slot,expected in slots.items():
            offset=emulator.image.offset(va+slot-emulator.image.pe.base)
            if struct.unpack_from('<Q',emulator.data,offset)[0]!=expected:raise ValueError('Changed filter virtual method')
            tables.append(dict(table=va,slot=slot,file_offset=offset,target=expected,raw_hex=emulator.data[offset:offset+8].hex()))
    proof_path=root/'code-clues/navigation-filter-code.json';proof_bytes=proof_path.read_bytes();proof=json.loads(proof_bytes)
    if proof['sha256']!=sha(emulator.data):raise ValueError('Changed filter schema EXE')
    bool_setters=[]
    for prop,mask in zip(proof['schemas']['area']['properties'][3:],[1,2,4]):
        pointer=struct.unpack_from('<Q',emulator.data,prop['descriptor_offset']+56)[0];offset=emulator.image.offset(pointer-emulator.image.pe.base);raw=emulator.data[offset:offset+5]
        if raw!=bytes([0x83,0x49,0x10,mask,0xc3]):raise ValueError('Changed area flag setter')
        bool_setters.append(dict(name=prop['name'],mask=mask,address=pointer,file_offset=offset,raw_hex=raw.hex()))
    clamp=rows[0x14528299c];offset=emulator.image.offset(clamp['rip_references'][0]-emulator.image.pe.base)
    if emulator.data[offset:offset+4]!=struct.pack('<f',1.):raise ValueError('Changed travel override clamp')
    constant=dict(file_offset=offset,raw_hex=emulator.data[offset:offset+4].hex(),value=1.)
    decoded_path=root/'maps/navigation-study/filter-resources/decoded.json';decoded_bytes=decoded_path.read_bytes();decoded=json.loads(decoded_bytes)
    if decoded['native_proof_sha256']!=sha(proof_bytes):raise ValueError('Changed decoded filter schema')
    audit=json.loads(decoded_path.with_name('audit.json').read_bytes())
    if audit['source_decoded_report_sha256']!=sha(decoded_bytes):raise ValueError('Changed filter resource audit')
    ids={('/Script/NnFramework.' if name.startswith('Nn') else '/Script/NavigationSystem.')+name:int(i) for i,name in proof['native_area_ids'].items()}
    cases=[]
    def run(name,areas,include=65535,exclude=0,variant_index=None):
        result=emulator.apply(areas,ids,include,exclude)
        expected=model_apply(result['before'],areas,ids,include,exclude)
        if result['after']!=expected:raise ValueError('Native filter application mismatch '+name)
        if result['before']['travel_costs']!=[FLOAT_MAX]+[1.]*63 or result['before']['entering_costs']!=[0.]*64:raise ValueError('Changed constructor cost arrays')
        effects=[{} for _ in areas]
        for event in result['setter_calls']:
            if event['address'] not in [0x145294560,0x145294590,0x1452945b0]:continue
            i=event['record_index']
            if not 0<=i<len(areas):raise ValueError('Invalid native record trace')
            effects[i]['area_id']=event['area_or_flags']
            if event['address']==0x1452945b0:effects[i]['excluded']=True
            else:effects[i]['travel_written' if event['address']==0x145294560 else 'entering_written']=struct.unpack('<f',struct.pack('<I',event['value_float32_bits']))[0]
        cases.append(dict(name=name,variant_index=variant_index,areas=areas,include_flags=include,exclude_flags=exclude,result=result,record_effects=effects))
    for variant in decoded['variants']:run(variant['path'],[a['properties'] for a in variant['decoded']['areas']],variant_index=variant['variant_index'])
    area_name='/Script/NnFramework.NnNavArea_HiddenPath'
    def area(mask=2,travel=2.,enter=3.,name=area_name):return dict(AreaClass=name,TravelCostOverride=travel,EnteringCostOverride=enter,bIsExcluded=bool(mask&1),bOverrideTravelCost=bool(mask&2),bOverrideEnteringCost=bool(mask&4))
    for mask in range(8):run('flag_mask_'+str(mask),[area(mask)])
    for value in [-2.,0.,.5,1.,2.,10.,FLOAT_MAX]:run('travel_clamp_'+str(value),[area(2,travel=value)])
    for value in [-2.,0.,.5,1.,2.]:run('enter_clamp_'+str(value),[area(4,enter=value)])
    run('include_exclude_flags',[],37,4);run('null_area_class',[area(name=None)])
    run('unregistered_area_class',[area(name='/Script/Unknown.Area')])
    run('repeated_area_override',[area(travel=2.),area(travel=7.)])
    run('excluded_then_override',[area(1),area(2)]);run('override_then_excluded',[area(2),area(1)])
    source=json.loads((root/'code-clues/native-enums.json').read_bytes())
    report=dict(source=source['source'],sha256=source['sha256'],native_filter_proof_sha256=sha(proof_bytes),source_decoded_report_sha256=sha(decoded_bytes),
        emulator_sha256=sha((HERE/'recast-filter-apply-emulator.py').read_bytes()),base_emulator_sha256=sha((HERE/'recast-portal-emulator.py').read_bytes()),
        anchors=anchors,fragments=emulator.apply_fragments,leaves=emulator.leaves,vtable_slots=tables,bool_setters=bool_setters,travel_clamp_constant=constant,
        native_pages=list(emulator.pages.values()),native_area_ids=ids,cases=cases,
        summary=dict(native_cases=len(cases),source_variants=len(decoded['variants']),native_apply_calls=emulator.apply_calls,
            static_class_stub_calls=emulator.static_class_stub_calls,travel_override_minimum=1.,entering_override_minimum=0.,
            base_state='fresh_native_constructor',runtime_filter_selection_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Native constructor and base filter initializer executed with synthetic class ancestry and a local class-to-ID TMap.',
            'The NavArea static-class getter is stubbed to the synthetic root. Zero-fill CRT is bounded; no UObject/CDO loading or live object lookup is performed.',
            'Source preset records come from cooked CDOs, but actual owner+0x400 state may already contain supported-area/CDO/runtime changes.',
            'Cloned default-filter lookup, caching and selection are static code evidence only; current runtime preset and traversability remain unverified.'])
    path=root/'code-clues/recast-filter-apply-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
