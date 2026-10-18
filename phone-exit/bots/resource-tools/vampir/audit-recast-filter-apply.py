"""Audit all recorded states and replay twelve native application scenarios."""
import copy,hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-filter-apply-evidence.json';report_bytes=path.read_bytes();report=json.loads(report_bytes)
    native=Path(report['source']).read_bytes();assert sha(native)==report['sha256']
    assert sha((HERE/'recast-filter-apply-emulator.py').read_bytes())==report['emulator_sha256']
    assert sha((HERE/'recast-portal-emulator.py').read_bytes())==report['base_emulator_sha256']
    for fragment in report['fragments']+report['leaves']:
        offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva'];assert sha(native[offset:offset+size])==fragment['sha256']
    for page in report['native_pages']:assert sha(native[page['file_offset']:page['file_offset']+4096])==page['sha256']
    for row in report['vtable_slots']+report['bool_setters']+[report['travel_clamp_constant']]:
        raw=bytes.fromhex(row['raw_hex']);assert native[row['file_offset']:row['file_offset']+len(raw)]==raw
    decoded_path=root/'maps/navigation-study/filter-resources/decoded.json';decoded_bytes=decoded_path.read_bytes();decoded=json.loads(decoded_bytes)
    assert sha(decoded_bytes)==report['source_decoded_report_sha256']
    assert sha((root/'code-clues/navigation-filter-code.json').read_bytes())==report['native_filter_proof_sha256']==decoded['native_proof_sha256']
    float_max=struct.unpack('<f',bytes.fromhex('ffff7f7f'))[0];ids=report['native_area_ids']
    assert len(report['cases'])==33
    for case in report['cases']:
        before=case['result']['before'];assert before['travel_costs']==[float_max]+[1.]*63 and before['entering_costs']==[0.]*64
        expected=copy.deepcopy(before);expected['include_flags']=case['include_flags'];expected['exclude_flags']=case['exclude_flags']
        for area,effect in zip(case['areas'],case['record_effects']):
            identifier=ids.get(area['AreaClass'])
            if identifier is None:assert effect=={};continue
            if area['bIsExcluded']:
                expected['travel_costs'][identifier]=float_max;assert effect==dict(area_id=identifier,excluded=True);continue
            applied={}
            if area['bOverrideTravelCost']:
                value=max(1.,struct.unpack('<f',struct.pack('<f',area['TravelCostOverride']))[0]);expected['travel_costs'][identifier]=value
                expected['minimum_cost']=min(expected['minimum_cost'],value);applied['travel_written']=value
            if area['bOverrideEnteringCost']:
                value=max(0.,struct.unpack('<f',struct.pack('<f',area['EnteringCostOverride']))[0]);expected['entering_costs'][identifier]=value;applied['entering_written']=value
            if applied:applied['area_id']=identifier
            assert effect==applied
        assert case['result']['after']==expected and case['result']['runtime_verified'] is False
        if case['variant_index'] is not None:
            variant=next(v for v in decoded['variants'] if v['variant_index']==case['variant_index'])
            assert case['areas']==[r['properties'] for r in variant['decoded']['areas']]
    spec=importlib.util.spec_from_file_location('filter_apply_audit_native',HERE/'recast-filter-apply-emulator.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);emulator=module.FilterApplyEmulator(root)
    selected=list(range(7))+[7,14,17,27,32]
    for i in selected:
        case=report['cases'][i];assert emulator.apply(case['areas'],ids,case['include_flags'],case['exclude_flags'])==case['result']
    result=dict(source_report_sha256=sha(report_bytes),native_cases_checked=33,native_replays=len(selected),runtime_filter_selection_verified=False,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-filter-apply-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
