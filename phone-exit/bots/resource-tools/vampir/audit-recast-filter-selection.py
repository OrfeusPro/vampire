"""Independent source/state checks and bounded native selection replays."""
import copy
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-filter-selection-evidence.json';raw=path.read_bytes();report=json.loads(raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256']
    assert sha((HERE/'recast-filter-selection-emulator.py').read_bytes())==report['emulator_sha256']
    for file,digest in report['dependencies'].items():assert sha((HERE/file).read_bytes())==digest
    proof_raw=(root/'code-clues/navigation-filter-code.json').read_bytes();proof=json.loads(proof_raw)
    assert sha(proof_raw)==report['constructor_proof_sha256'] and proof['sha256']==report['sha256']
    assert report['class_fields']==proof['filter_class_fields']==dict(Default=0x780,ShortPath=0x788,ExcludeHiddenPath=0x790)
    for fragment in report['fragments']:
        offset=fragment['file_offset'];length=fragment['end_rva']-fragment['begin_rva']
        assert sha(exe[offset:offset+length])==fragment['sha256']
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    for row in report['anchors']:
        data=bytes.fromhex(row['bytes']);assert exe[row['file_offset']:row['file_offset']+len(data)]==data
    for row in [report['lifecycle_vtable'],report['base_reset_constant'],*report['base_initializer_vtables']]:
        data=bytes.fromhex(row['raw_hex']);assert exe[row['file_offset']:row['file_offset']+len(data)]==data
    assert len(report['base_initializer_vtables'])==2
    for row in report['base_initializer_vtables']:
        assert row['slot']==0x8e0 and struct.unpack('<Q',bytes.fromhex(row['raw_hex']))[0]==0x1452b7120
    assert report['base_initializer_static']['address']==0x1452b7120 and report['base_initializer_static']['executed'] is False
    assert report['lifecycle_vtable']['slot']==0x3a0 and struct.unpack('<Q',bytes.fromhex(report['lifecycle_vtable']['raw_hex']))[0]==0x1454da500
    assert struct.unpack('<f',bytes.fromhex(report['base_reset_constant']['raw_hex']))[0]==1.
    assert len(report['cases'])==16
    for case in report['cases']:
        r=case['result'];inputs=case['inputs'];fields=['Default','ShortPath','ExcludeHiddenPath'] if r['entry']=='lifecycle' else [r['entry']]
        expected_fields=[f for f in fields if inputs.get('states',{}).get(f,'present') in ('present','missing_cdo')]
        queries=[e for e in r['events'] if e['kind']=='query_cache_stub']
        assert [e['field'] for e in queries]==expected_fields
        for q in queries:assert q['base_state']==r['before']
        writes=[e for e in r['events'] if e['kind']=='travel_setter'];after=copy.deepcopy(r['before'])
        if r['entry']=='lifecycle' and r['base_present']:
            assert [(e['area_id'],e['value']) for e in writes]==[(i,1.) for i in range(10,14)]
            after['travel_costs'][10:14]=[1.]*4;after['minimum_cost']=min(after['minimum_cost'],1.)
            assert all(e['kind']!='query_cache_stub' for e in r['events'][next(i for i,e in enumerate(r['events']) if e['kind']=='travel_setter'):])
        else:assert not writes
        assert r['after']==after and r['runtime_verified'] is False
        if r['entry']!='lifecycle':assert r['output_has_filter']==bool(expected_fields)
    spec=importlib.util.spec_from_file_location('selection_audit_native',HERE/'recast-filter-selection-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);emulator=module.FilterSelectionEmulator(root)
    flag=report['synthetic_global']['address'];rva=flag-emulator.image.pe.base
    assert flag==0x14b35a640 and any(s['rva']+s['raw_size']<=rva<s['rva']+s['size'] for s in emulator.image.pe.sections)
    for case in report['cases']:assert emulator.run(**{**case['inputs'],'costs':{int(k):v for k,v in case['inputs'].get('costs',{}).items()}})==case['result']
    result=dict(source_report_sha256=sha(raw),native_cases_checked=16,native_replays=16,
        class_field_binding_verified=True,runtime_selection_verified=False,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-filter-selection-audit.json').write_text(json.dumps(result,indent=2),'utf-8')
    print(json.dumps(result));return result

if __name__=='__main__':main()
