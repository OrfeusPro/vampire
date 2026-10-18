"""Independent static role/source checks and exact scalar branch replays."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-route-filter-evidence.json';raw=path.read_bytes();report=json.loads(raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256']
    assert sha((HERE/'recast-route-filter-emulator.py').read_bytes())==report['emulator_sha256']
    assert sha((HERE/'recast-portal-emulator.py').read_bytes())==report['base_emulator_sha256']
    selection_raw=(root/'code-clues/recast-filter-selection-evidence.json').read_bytes()
    assert sha(selection_raw)==report['selection_proof_sha256'] and json.loads(selection_raw)['sha256']==report['sha256']
    for fragment in report['fragments']:
        offset=fragment['file_offset'];length=fragment['end_rva']-fragment['begin_rva'];assert sha(exe[offset:offset+length])==fragment['sha256']
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    for row in report['anchors']:
        data=bytes.fromhex(row['bytes']);assert exe[row['file_offset']:row['file_offset']+len(data)]==data
    t=report['threshold'];data=bytes.fromhex(t['raw_hex']);assert exe[t['file_offset']:t['file_offset']+8]==data and struct.unpack('<d',data)[0]==9000000.
    assert report['caller_filter_arguments']==dict(argument6='Default',argument7='ShortPath',argument8='ExcludeHiddenPath')
    assert report['static_query_roles']['endpoint_calls_1452451b0']=='ExcludeHiddenPath'
    assert report['summary']['path_search_executed'] is False and report['summary']['runtime_request_verified'] is False
    assert report['executed_range']==dict(begin=0x14569bf90,end_before_call=0x14569bffe)
    assert len(report['cases'])==13
    for case in report['cases']:
        start,end=case['start'],case['end'];dx=start[0]-end[0];dy=start[1]-end[1];distance=dx*dx+dy*dy
        result=case['result'];assert result['distance_squared_xy']==distance
        assert result['filter']==('Default' if distance>=9000000. else 'ShortPath')
        assert result['runtime_verified'] is False and result['path_search_executed'] is False
    spec=importlib.util.spec_from_file_location('audit_route_branch',HERE/'recast-route-filter-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);emulator=module.RouteFilterBranchEmulator(root)
    for case in report['cases']:assert emulator.select(case['start'],case['end'])==case['result']
    result=dict(source_report_sha256=sha(raw),native_cases_checked=13,native_replays=13,
        path_search_executed=False,runtime_request_verified=False,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-route-filter-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
