"""Independently audit initialized flags, adapter identity and actor tail replay."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-archive-initialization.json';report_raw=path.read_bytes();r=json.loads(report_raw)
    data=Path(r['source']).read_bytes();assert sha(data)==r['sha256']
    assert sha((HERE/'build-recast-archive-initialization.py').read_bytes())==r['builder_sha256']
    for p,value in r['source_report_sha256'].items():assert sha((root/p).read_bytes())==value
    for p,value in r['source_helper_sha256'].items():assert sha((HERE/p).read_bytes())==value
    for f in r['fragments']:
        off=f['file_offset'];assert sha(data[off:off+f['end_rva']-f['begin_rva']])==f['sha256']
    for page in r['pages']:
        off=page['file_offset'];assert sha(data[off:off+4096])==page['sha256']
    for row in r['anchors']+r['initialization_bindings']+r['initialization_leaves']:
        b=bytes.fromhex(row.get('raw_hex',row.get('bytes','')));off=row['file_offset'];assert data[off:off+len(b)]==b
    bindings={b['slot']:b['target'] for b in r['initialization_bindings']}
    assert bindings=={0x68:0x14159ca30,0x70:0x1414639e0,0xb0:0x1415a0530,0xf0:0x1415a0550}
    leaves={row['address']:row for row in r['initialization_leaves']}
    assert [i['operands'] for i in leaves[0x1415a0530]['instructions']]==['eax, byte ptr [rcx + 0x28]','al, 0xfe','al, dl','byte ptr [rcx + 0x28], al','']
    assert [i['operands'] for i in leaves[0x1415a0550]['instructions']]==['eax, byte ptr [rcx + 0x29]','al, 0xfe','al, dl','byte ptr [rcx + 0x29], al','']
    assert leaves[0x141599f90]['raw_hex']=='488b01488b00488b4008c3'
    assert [c['initial_flag_word'] for c in r['native_flag_cases']]==[0,65535,65278,64]
    assert [c['result_flag_word'] for c in r['native_flag_cases']]==[257,65535,65535,321]
    chain=r['native_composed_chain'];assert chain['flags_after_initialization_hex']=='0101' and chain['flags_after_package_hex']=='4301'
    assert chain['flag_bytes_after_versions_hex']=='43018010' and chain['version_lookup_substituted'] is False
    assert chain['native_custom_version_calls']==[dict(guid_hex='525dda5948493212785978b88be9b870',result=8),dict(guid_hex='86181d60844f64acded316aad6c7ea0d',result=170)]
    assert [a['size'] for a in chain['structured_allocations']]==[16,8,8]
    entry=r['actor_export'];raw=(root/'maps/navigation-study/level'/entry['file']).read_bytes();assert sha(raw)==entry['export']['sha256']
    assert chain['property_end_input']==375 and struct.unpack_from('<IIi',raw,375)==(0,1,24)
    assert raw[387:411]==b'NnRecastNavMesh-Default\0' and chain['actor_string']==[dict(begin=383,end=411,value='NnRecastNavMesh-Default')]
    assert chain['optional_guid_end']==379 and chain['actor_tail_end']==443 and chain['guid_words']==list(struct.unpack_from('<8I',raw,411))
    spec=importlib.util.spec_from_file_location('archive_init_audit_replay',HERE/'build-recast-archive-initialization.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    vm=m.InitializationReplay(root)
    assert vm.initialization_bindings==r['initialization_bindings'] and vm.initialization_leaves==r['initialization_leaves']
    assert [vm.flags(value) for value in [0,65535,65278,64]]==r['native_flag_cases']
    source=json.loads((root/'code-clues/recast-archive-transfer.json').read_bytes());assert vm.chain(raw,source['package_flags']['value'])==chain
    assert not any(r['summary'][k] for k in ['full_property_boundary_verified','active_mesh_verified','routes_verified','navigation_ready'])
    result=dict(valid=True,report_sha256=sha(report_raw),native_flag_cases_replayed=4,structured_adapter_replays=2,
        native_custom_version_results=[8,170],actor_tail_end=443,full_property_boundary_verified=False,navigation_ready=False)
    (root/'code-clues/recast-archive-initialization-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result
if __name__=='__main__':main()
