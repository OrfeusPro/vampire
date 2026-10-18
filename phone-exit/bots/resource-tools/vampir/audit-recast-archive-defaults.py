"""Byte audit and independent checks of version-default evidence."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-archive-defaults.json';report_raw=path.read_bytes();r=json.loads(report_raw)
    data=Path(r['source']).read_bytes();assert sha(data)==r['sha256']
    assert sha((HERE/'build-recast-archive-defaults.py').read_bytes())==r['builder_sha256']
    properties_raw=(root/'code-clues/recast-actor-properties.json').read_bytes();assert sha(properties_raw)==r['source_properties_sha256']
    for f in r['fragments']:
        off=f['file_offset'];assert sha(data[off:off+f['end_rva']-f['begin_rva']])==f['sha256']
    for page in r['pages']:
        off=page['file_offset'];assert sha(data[off:off+4096])==page['sha256']
    for row in r['anchors']:
        b=bytes.fromhex(row['bytes']);assert data[row['file_offset']:row['file_offset']+len(b)]==b
    anchors={row['address']:row for row in r['anchors']}
    assert (anchors[0x140ff4af5]['mnemonic'],anchors[0x140ff4af5]['operands'])==('mov','edx, 0xaa')
    assert (anchors[0x140ff52cf]['mnemonic'],anchors[0x140ff52cf]['operands'])==('lea','edx, [r9 + 8]')
    for row,name,version in zip(r['registrations'],['FortniteMain','UE5-PrivateFrosty'],[170,8]):
        assert (row['name'],row['version'],row['callback'])==(name,version,0)
        b=bytes.fromhex(row['name_raw_hex']);assert b==(name+'\0').encode('utf-16le')
        assert data[row['name_file_offset']:row['name_file_offset']+len(b)]==b
        for pointer in row['initializer_pointer_records']:
            b=struct.pack('<Q',row['initializer']);assert pointer['raw_hex']==b.hex() and data[pointer['file_offset']:pointer['file_offset']+8]==b
    generated_folder=root/'maps/navigation-study/generated-chunks';generated_raw=(generated_folder/'index.json').read_bytes()
    assert sha(generated_raw)==r['generated_index_sha256'];generated=json.loads(generated_raw)
    sources={p['package_identity']:p for p in generated['packages']}
    for row in r['generated_package_prefixes']:
        part=next(p for p in sources[row['package']]['parts'] if p['role']=='asset');assert part['file']==row['file'] and part['sha256']==row['sha256']
        b=(generated_folder/row['file']).read_bytes();assert sha(b)==row['sha256'] and b[:32].hex()==row['prefix_hex']
        assert struct.unpack_from('<I6i',b)==(0x9e2a83c1,-8,0,0,0,0,0)
        assert row['decoded']['select_registered_defaults']
    assert len(r['generated_package_prefixes'])==34
    asset=(root/r['asset_file']).read_bytes();assert sha(asset)==r['asset_sha256'] and asset[:32].hex()==r['package_prefix_hex']
    assert struct.unpack_from('<I6i',asset)==(0x9e2a83c1,-8,0,0,0,0,0)
    spec=importlib.util.spec_from_file_location('defaults_audit_replay',HERE/'build-recast-archive-defaults.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    vm=m.DefaultsReplay(root)
    assert [vm.registration(row['initializer']) for row in r['registrations']]==[{k:v for k,v in row.items() if k!='initializer_pointer_records'} for row in r['registrations']]
    for row in r['native_summary_gate_cases']:
        assert vm.package_gate(row['input_versions'])==row
        assert row['defaults_selected']==(row['input_versions']==[0,0,0])
    assert r['native_summary_gate_cases'][0]['effective_scalar_versions']==[522,1013,0]
    prop=json.loads(properties_raw);actor=(root/'maps/navigation-study/level'/prop['actor_export']['file']).read_bytes()
    assert sha(actor)==prop['actor_export']['export']['sha256']
    assert m.tail.TailReplay(root).replay(actor,379,8,170)==r['actor_tail_with_registered_versions']
    assert not any(r['summary'][k] for k in ['runtime_archive_propagation_verified','full_property_boundary_verified','routes_verified','navigation_ready'])
    result=dict(valid=True,report_sha256=sha(report_raw),registered_versions=[170,8],generated_package_prefixes_verified=34,
        native_registration_replays=2,native_summary_gate_replays=4,runtime_archive_propagation_verified=False,navigation_ready=False)
    (root/'code-clues/recast-archive-defaults-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result
if __name__=='__main__':main()
