"""Independent source/byte checks and replay of Linker archive propagation."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-archive-transfer.json';report_raw=path.read_bytes();r=json.loads(report_raw)
    data=Path(r['source']).read_bytes();assert sha(data)==r['sha256']
    assert sha((HERE/'build-recast-archive-transfer.py').read_bytes())==r['builder_sha256']
    defaults_raw=(root/'code-clues/recast-archive-defaults.json').read_bytes();assert sha(defaults_raw)==r['source_defaults_sha256'];defaults=json.loads(defaults_raw)
    for f in r['fragments']:
        off=f['file_offset'];assert sha(data[off:off+f['end_rva']-f['begin_rva']])==f['sha256']
    for page in r['pages']:
        off=page['file_offset'];assert sha(data[off:off+4096])==page['sha256']
    for row in r['anchors']+r['vtable_bindings']+r['leaf_setters']+[r['read_forwarding'],r['native_direct_actor_dispatch']]:
        b=bytes.fromhex(row.get('raw_hex',row.get('bytes','')));assert data[row['file_offset']:row['file_offset']+len(b)]==b
    bindings={row['slot']:row for row in r['vtable_bindings']}
    assert {slot:row['target'] for slot,row in bindings.items()}=={0x58:0x141599fa0,0x60:0x1415a0140,0xb8:0x1415a0540,
        0xe0:0x1415a0a10,0xf8:0x1415a0a00,0x100:0x1415a0590,0x108:0x1415a0480}
    for row in bindings.values():assert row['table']==0x148a13918 and struct.unpack('<Q',bytes.fromhex(row['raw_hex']))[0]==row['target']
    constructor=next(a for a in r['anchors'] if a['address']==0x14172b61e);b=bytes.fromhex(constructor['bytes'])
    assert constructor['address']+len(b)+struct.unpack('<i',b[-4:])[0]==0x148a13918
    assert next(a for a in r['anchors'] if a['address']==0x14172b630)['operands']=='qword ptr [r14 + 0x240], rax'
    asset=(root/defaults['asset_file']).read_bytes();flags=r['package_flags'];assert sha(asset)==flags['asset_sha256']==defaults['asset_sha256']
    assert flags['offset']==36+struct.unpack_from('<i',asset,32)[0] and struct.unpack_from('<I',asset,flags['offset'])[0]==flags['value']==0x90022200
    for case in r['native_version_cases']:
        assert len(case['archives'])==(2 if case['reader_present'] else 1)
        for archive in case['archives']:
            b=bytes.fromhex(archive['container_rows_hex']);assert len(b)==80
            assert [b[:16].hex(),b[40:56].hex()]==['86181d60844f64acded316aad6c7ea0d','525dda5948493212785978b88be9b870']
            assert [struct.unpack_from('<i',b,offset)[0] for offset in [16,56]]==case['input_versions']
            assert archive['native_lookups']==case['input_versions']+[-1] and archive['pending_default_flag']==0
            assert archive['scalar_versions']==[522,1013,0] and archive['engine_version_raw_hex']=='010000000200000003000000'
    assert [case['result_archive_flags'] for case in r['native_flag_cases']]==[[67,67],[1,1],[3,3],[65,65]]
    spec=importlib.util.spec_from_file_location('archive_transfer_audit_replay',HERE/'build-recast-archive-transfer.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    vm=m.TransferReplay(root)
    assert vm.bindings==r['vtable_bindings'] and vm.leaves==r['leaf_setters']
    for case in r['native_version_cases']:assert vm.run_versions(case['input_versions'],case['reader_present'])==case
    for case in r['native_flag_cases']:assert vm.run_flags(case['package_flags'],case['initial_archive_flags'])==case
    assert vm.direct_actor_dispatch()==r['native_direct_actor_dispatch']
    assert r['read_forwarding']['raw_hex']=='488b89e8000000488b0148ffa070010000'
    assert not any(r['summary'][k] for k in ['full_export_archive_chain_verified','full_property_boundary_verified','routes_verified','navigation_ready'])
    result=dict(valid=True,report_sha256=sha(report_raw),version_cases_replayed=3,native_lookups_verified=15,flag_cases_replayed=4,
        embedded_archive_constructor_binding_verified=True,direct_actor_receives_embedded_archive_verified=True,
        full_export_archive_chain_verified=False,navigation_ready=False)
    (root/'code-clues/recast-archive-transfer-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result
if __name__=='__main__':main()
