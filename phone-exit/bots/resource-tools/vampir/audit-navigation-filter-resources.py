"""Re-extract all filter source parts and validate native/schema/decoded bindings."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    directory=root/'maps/navigation-study/filter-resources';resource_bytes=(directory/'index.json').read_bytes();resources=json.loads(resource_bytes)
    decoded_path=directory/'decoded.json';decoded_bytes=decoded_path.read_bytes();decoded=json.loads(decoded_bytes)
    proof_bytes=(root/'code-clues/navigation-filter-code.json').read_bytes();proof=json.loads(proof_bytes)
    assert decoded['source_resource_report_sha256']==sha(resource_bytes) and decoded['native_proof_sha256']==sha(proof_bytes)
    native=Path(proof['source']).read_bytes();assert sha(native)==proof['sha256']
    for fragment in proof['fragments']:
        offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva'];assert sha(native[offset:offset+size])==fragment['sha256']
    for schema in proof['schemas'].values():
        for prop in schema['properties']:
            offset=prop['descriptor_offset'];assert native[offset:offset+64].hex()==prop['raw64_hex']
            assert native[prop['name_offset']:prop['name_offset']+len(prop['name'])+1]==prop['name'].encode()+b'\0'
    for row in proof['literals']+[proof['constructor_wrapper'],proof['area_struct_registry'],proof['filter_class_params']]:
        offset=row['file_offset'];raw=bytes.fromhex(row['raw_hex']);assert native[offset:offset+len(raw)]==raw
    pak=load('filter_audit_pak',HERE.parent/'rfnext/scan-pak.py');package=load('filter_audit_package',HERE/'inspect-ui.py');decoder=load('filter_audit_decoder',HERE/'decode-navigation-filter-resources.py')
    checked_parts=0;checked_areas=0
    for archive_index,archive in enumerate(resources['archives']):
        source=archive['source'];path=Path(source['path']);stat=path.stat();entries_path=root/'pak-extracted'/archive['archive']/'entries.json';entries_bytes=entries_path.read_bytes();entries=json.loads(entries_bytes)
        assert sha(entries_bytes)==archive['entries_sha256']
        with path.open('rb') as stream:
            head=stream.read(65536);stream.seek(max(0,stat.st_size-65536));fingerprint=sha(head+stream.read())
            assert (stat.st_size,stat.st_mtime_ns,fingerprint)==(source['size'],source['modified_ns'],source['sample_sha256'])
            for variant_index,variant in enumerate(resources['variants']):
                if variant['archive_index']!=archive_index:continue
                parts={}
                for part in variant['parts']:
                    assert part['record'] in entries
                    header=pak.header(stream,part['record']['offset'],entries[-1]['index_offset']);raw=pak.decode(stream,header)
                    assert sha(raw)==part['sha256'] and raw==(directory/part['file']).read_bytes();parts[part['role']]=raw;checked_parts+=1
                parsed=package.exports(parts['asset'],parts['body'],max_exports=100)
                assert parsed['exports']==[e['export'] for e in variant['exports']]
                for item in variant['imports']:
                    offset=item['file_offset'];raw=parts['asset'][offset:offset+32]
                    assert raw.hex()==item['raw_hex']
                    name,number=struct.unpack_from('<ii',raw,20)
                    assert item['name']==parsed['names'][name]+('_'+str(number-1) if number else '')
                    assert item['outer']==struct.unpack_from('<i',raw,16)[0]
                inheritance=variant['inheritance'];offset=inheritance['export_table_offset']
                assert parts['asset'][offset:offset+96].hex()==inheritance['export_table_bytes']
                assert struct.unpack_from('<i',parts['asset'],offset+4)[0]==inheritance['super_index']
                assert next(i['name'] for i in variant['imports'] if i['index']==inheritance['super_index'])==inheritance['super_name']=='NavigationQueryFilter'
                row=next(v for v in decoded['variants'] if v['variant_index']==variant_index)
                assert row['path']==variant['path']
                export=next(e for e in variant['exports'] if e['export']['index']==variant['cdo_export_index'])
                raw=(directory/export['file']).read_bytes();assert sha(raw)==export['export']['sha256']
                actual=json.loads(json.dumps(decoder.decode(raw,variant['imports'])))
                assert actual==row['decoded'];checked_areas+=len(row['decoded']['areas'])
    assert checked_parts==14 and checked_areas==15 and len(decoded['variants'])==7
    for path in {v['path'] for v in decoded['variants']}:
        variants=[v for v in decoded['variants'] if v['path']==path]
        assert all(v['decoded']==variants[0]['decoded'] for v in variants)
    result=dict(source_decoded_report_sha256=sha(decoded_bytes),native_proof_sha256=sha(proof_bytes),source_parts_reextracted=checked_parts,
        variants_checked=7,explicit_area_records=checked_areas,runtime_filter_selection_verified=False,routes_verified=0,navigation_ready=False)
    (directory/'audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
