"""Independent byte/branch audit and native replay of conditional actor tails."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-actor-tail.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    data=Path(report['source']).read_bytes();assert sha(data)==report['sha256']
    assert sha((HERE/'decode-recast-actor-tail.py').read_bytes())==report['builder_sha256']
    properties_raw=(root/'code-clues/recast-actor-properties.json').read_bytes();assert sha(properties_raw)==report['source_properties_sha256']
    properties=json.loads(properties_raw);assert report['actor_export']==properties['actor_export']
    folder=root/'maps/navigation-study/level';raw=(folder/report['actor_export']['file']).read_bytes()
    assert sha(raw)==report['actor_export']['export']['sha256']
    asset=(folder/'Nocturne-asset.bin').read_bytes();assert sha(asset)==report['asset_sha256'] and asset[:32].hex()==report['package_summary_prefix_hex']
    for f in report['fragments']:
        off=f['file_offset'];assert sha(data[off:off+f['end_rva']-f['begin_rva']])==f['sha256']
    for page in report['pages']:
        off=page['file_offset'];assert sha(data[off:off+4096])==page['sha256']
    for row in report['anchors']+[k['instruction'] for k in report['version_keys']]:
        b=bytes.fromhex(row['bytes']);off=row['file_offset'];assert data[off:off+len(b)]==b
    for key in report['version_keys']:
        b=bytes.fromhex(key['guid_hex']);assert data[key['file_offset']:key['file_offset']+16]==b and asset.count(b)==key['asset_occurrences']==0
        instruction=key['instruction'];b=bytes.fromhex(instruction['bytes'])
        assert instruction['address']+len(b)+struct.unpack('<i',b[-4:])[0]==key['address']
    assert [k['guid_hex'] for k in report['version_keys']]==['525dda5948493212785978b88be9b870','86181d60844f64acded316aad6c7ea0d']
    assert properties['decoded']['properties_end']==375 and struct.unpack_from('<IIi',raw,375)==(0,1,24)
    assert raw[387:411]==b'NnRecastNavMesh-Default\0'
    spec=importlib.util.spec_from_file_location('tail_audit_replay',HERE/'decode-recast-actor-tail.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    vm=module.TailReplay(root);assert vm.optional_absent(raw,375)==report['optional_guid_native_end']==379
    ends=[]
    for scenario in report['scenarios']:
        native=scenario['native'];decoded=scenario['decoded'];lv=native['label_version'];gv=native['guid_version']
        expected=379+(32 if lv>=4 else 0)+(32 if gv>=150 else 0)
        assert decoded['end']==native['end']==expected
        cursor=375
        for row in decoded['records']:
            assert row['begin']==cursor and row['end']>cursor
            assert raw[cursor:row['end']].hex()==row['raw_hex'];cursor=row['end']
        assert cursor==expected
        if lv>=4:assert next(r for r in decoded['records'] if r['name']=='actor_string')['value']=='NnRecastNavMesh-Default'
        if gv>=150:assert native['guid_words']==list(struct.unpack_from('<8I',raw,expected-32))
        assert vm.replay(raw,379,lv,gv)==native;ends.append(expected)
    assert ends==[411,411,411,443,443,379]
    summary=report['summary'];assert not any(summary[k] for k in ['archive_versions_verified','complete_actor_serialization_executed','property_boundary_verified','routes_verified','navigation_ready'])
    result=dict(valid=True,report_sha256=sha(report_raw),native_scenarios_replayed=len(ends),conditional_ends=ends,
        archive_versions_verified=False,property_boundary_verified=False,navigation_ready=False)
    (root/'code-clues/recast-actor-tail-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result
if __name__=='__main__':main()
