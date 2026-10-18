"""Check all source bindings and replay complete native base initialization."""
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-base-filter-evidence.json';raw=path.read_bytes();report=json.loads(raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256']
    assert sha((HERE/'recast-base-filter-emulator.py').read_bytes())==report['emulator_sha256']
    for file,digest in report['dependencies'].items():assert sha((HERE/file).read_bytes())==digest
    for name,key in [('navigation-filter-code.json','filter_class_proof_sha256'),('recast-filter-selection-evidence.json','selection_proof_sha256')]:
        proof=(root/'code-clues'/name).read_bytes();assert sha(proof)==report[key] and json.loads(proof)['sha256']==report['sha256']
    for fragment in report['fragments']+report['leaves']:
        offset=fragment['file_offset'];length=fragment['end_rva']-fragment['begin_rva'];assert sha(exe[offset:offset+length])==fragment['sha256']
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    for row in report['anchors']:
        data=bytes.fromhex(row['bytes']);assert exe[row['file_offset']:row['file_offset']+len(data)]==data
    for row in [report['area_vtable'],report['entering_getter'],*report['initializer_vtables']]:
        data=bytes.fromhex(row['raw_hex']);assert exe[row['file_offset']:row['file_offset']+len(data)]==data
    assert report['entering_getter']['raw_hex']=='f30f104134c3'
    assert report['area_vtable']['target']==report['entering_getter']['address']==0x14527f810
    assert report['summary']['runtime_base_costs_verified'] is False and report['summary']['navigation_ready'] is False
    def f32(x):return struct.unpack('<f',struct.pack('<f',x))[0]
    assert len(report['cases'])==30
    for case in report['cases']:
        inputs=case['inputs'];result=case['result'];maximum=f32(3.4028234663852886e38)
        travel=[maximum]+[1.]*63;entering=[0.]*64;minimum=1.;trace=[dict(kind='allocate',bytes=0x430),dict(kind='allocate',bytes=0x18)]
        for i,area in enumerate(inputs['areas']):
            if area['class_state'] in ('create','null_cdo'):trace.append(dict(kind='cdo_load_stub',record_index=i,provided=area['class_state']=='create'))
            if area['class_state'] in ('null_class','null_cdo'):continue
            identifier=area['area_id'];cost=f32(area['travel']);entry=f32(area['entering'])
            travel[identifier]=cost;entering[identifier]=entry;minimum=min(minimum,cost)
            trace.extend([dict(kind='travel',area_id=identifier,value=cost),dict(kind='entering',area_id=identifier,value=entry)])
        limit=f32(inputs['owner_5bc']);limit=math.trunc(limit) if -2147483648<=limit<2147483648 else -2147483648
        expected=dict(travel_costs=travel,entering_costs=entering,minimum_cost=minimum,
            include_flags=(~inputs['blocked_flags'])&65535,exclude_flags=0,owner_5bc_truncated=limit,
            impl_flag428=1 if inputs['owner_5d0']&2048 else 0,impl_double410=f32(inputs['owner_644']))
        assert result['state']==expected and result['events']==trace and result['reference_counts']==[1,1]
        assert result['constructor_and_area_loop_executed'] is True and result['runtime_verified'] is False
    spec=importlib.util.spec_from_file_location('audit_base_native',HERE/'recast-base-filter-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);emulator=module.BaseFilterEmulator(root)
    flag=report['synthetic_global']['address'];rva=flag-emulator.image.pe.base
    assert flag==0x14b566bac and any(s['rva']+s['raw_size']<=rva<rva+2<=s['rva']+s['size'] for s in emulator.image.pe.sections)
    for case in report['cases']:assert emulator.initialize(**case['inputs'])==case['result']
    result=dict(source_report_sha256=sha(raw),native_cases_checked=30,native_replays=30,
        constructor_and_CDO_loop_verified=True,runtime_base_costs_verified=False,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-base-filter-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
