"""Independently check the priority report and replay twelve native cases."""
import hashlib,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-area-priority-evidence.json';raw=path.read_bytes();report=json.loads(raw)
    native=Path(report['source']).read_bytes();assert sha(native)==report['sha256']
    assert sha((HERE/'recast-area-priority-emulator.py').read_bytes())==report['emulator_sha256']
    assert sha((HERE/'recast-portal-emulator.py').read_bytes())==report['base_emulator_sha256']
    for fragment in report['fragments']:
        offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva'];assert sha(native[offset:offset+size])==fragment['sha256']
    for page in report['native_pages']:assert sha(native[page['file_offset']:page['file_offset']+4096])==page['sha256']
    assert report['constructor_priorities']==[0]*64 and len(report['cases'])==72
    for case in report['cases']:
        sums=[a+b for a,b in zip(case['costs'],case['fixed_costs'])];assert len(sums)==64 and sums==case['sums']
        order=case['sorted_area_ids'];assert sorted(order)==list(range(64))
        assert [sums[i] for i in order]==sorted(sums)
        assert case['ranks']==[order.index(i) for i in range(64)]
        assert sorted(case['ranks'])==list(range(64))
    spec=importlib.util.spec_from_file_location('area_priority_audit',HERE/'recast-area-priority-emulator.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);emulator=module.AreaPriorityEmulator(root)
    assert emulator.math_import==report['math_import'] and emulator.constructor_priorities()==[0]*64
    selected=list(range(8))+[15,31,47,71]
    for i in selected:
        case=report['cases'][i];actual=emulator.priorities(case['costs'],case['fixed_costs'])
        assert actual=={key:value for key,value in case.items() if key!='name'}
    assert report['summary']['native_sort_calls']==report['shims']['logf_calls']==72
    equal=report['cases'][0];assert equal['all_equal_costs'] and equal['sorted_area_ids']!=list(range(64))
    result=dict(source_report_sha256=sha(raw),native_cases_checked=72,native_replays=len(selected),
        active_cost_arrays_verified=False,routes_verified=0,navigation_ready=False)
    out=root/'code-clues/recast-area-priority-audit.json';out.write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
