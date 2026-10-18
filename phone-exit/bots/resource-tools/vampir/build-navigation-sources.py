"""Trace client navigation resource paths and preserve bounded archive evidence."""
import hashlib,importlib.util,json,os,re
from pathlib import Path
HERE=Path(__file__).resolve().parent

def references(raw):
    return [dict(path=m.group().decode('ascii'),byte_offset=m.start(),relation_verified=False)
            for m in re.finditer(rb'/Game/[A-Za-z0-9_/]+',raw)]

def main(root):
    spec=importlib.util.spec_from_file_location('nav_native',HERE/'build-native-entry-code.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));exe=Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    im=native.Image(exe);fragments=native.decode_ranges(im,{im.roots[im.containing(a)] for a in [0x14568ce80,0x14568cfc0,0x1455e4c40,0x14568f5c0]});rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[];literals=[]
    for address,name in [(0x14568cea3,'_Nav.bin'),(0x14568ced8,'RED/NavMesh'),(0x14568cffb,'_WPRefNav'),(0x14568d055,'/Game/RED/Blueprint/DataAsset/RefNavMesh'),(0x1455e4eb2,'ANnRefNavDataLoader::LoadWPRefNavMeshData()'),(0x1455e4f87,'Could not find RefNavFile : %s '),(0x14568f833,'NnUtilRefNavi::IsPathConnected()')]:
        row=rows[address];offset=im.offset(row['rip_references'][0]-im.pe.base);raw=name.encode('utf-16le')+b'\0\0'
        if row['mnemonic']!='lea' or exe[offset:offset+len(raw)]!=raw:raise ValueError('Changed nav literal '+name)
        anchors.append(row);literals.append(dict(text=name,encoding='utf-16le',file_offset=offset,bytes=raw.hex(),xref_address=address))
    for address,mnemonic,operands in [(0x14568ceb4,'call','0x141425fb0'),(0x14568ceeb,'call','0x14142d840'),(0x14568cf27,'call','0x14142d840'),(0x14568d00a,'call','0x141425fb0'),(0x14568d060,'call','0x14142d840'),(0x1455e4e1b,'call','0x14568cfc0'),(0x1455e4e55,'call','0x1417e3470'),(0x1455e4e94,'mov','qword ptr [rsi + 0x2c8], rbx')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed nav anchor')
        anchors.append(row)
    out=root/'maps/navigation-study';out.mkdir(exist_ok=True)
    assets=[];inventory=[];actor_candidates=[]
    for path in sorted((root/'pak-extracted').glob('*/entries.json')):
        raw=path.read_bytes();entries=json.loads(raw);inventory.append(dict(archive=path.parent.name,file=str(path.relative_to(root)),sha256=hashlib.sha256(raw).hexdigest(),entries=len(entries)-1))
        for row in entries[:-1]:
            exact=[p for p in row.get('paths',[]) if p.startswith('/Game/RED/Blueprint/DataAsset/RefNavMesh/')]
            if exact:assets.append(dict(archive=path.parent.name,record=row,paths=sorted(set(exact)),provenance=dict(file=str(path.relative_to(root)),sha256=hashlib.sha256(raw).hexdigest())))
    selected_assets=[a for a in assets if a['record'].get('paths',[None])[0]=='/Game/RED/Blueprint/DataAsset/RefNavMesh/Nocturne_WPRefNav']
    extracted=[];actor_candidates=[]
    spec=importlib.util.spec_from_file_location('nav_pak',HERE.parent/'rfnext/scan-pak.py');reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    for selected in selected_assets:
        folder=root/'pak-extracted'/selected['archive'];stamp=json.loads((folder/'source.json').read_text('utf-8'));archive=Path(stamp['path']);stat=archive.stat()
        with archive.open('rb') as stream:
            head=stream.read(65536);stream.seek(max(0,stat.st_size-65536));sample=hashlib.sha256(head+stream.read()).hexdigest()
        if stat.st_size!=stamp['size'] or stat.st_mtime_ns!=stamp['modified_ns'] or sample!=stamp['sample_sha256']:raise ValueError('Archive changed; rescan first')
        entries=json.loads((folder/'entries.json').read_text('utf-8'));asset_id=selected['record']['entry']
        with archive.open('rb') as stream:
            for eid in [asset_id,asset_id+1]:
                record=next(r for r in entries if r.get('entry')==eid)
                header=reader.header(stream,record['offset'],entries[-1]['index_offset'])
                if header is None or header['encrypted'] or header['usize']>1024*1024:raise ValueError('Unexpected navigation record')
                raw=reader.decode(stream,header);name=f"{selected['archive']}-Nocturne-ref-{eid}.bin";(out/name).write_bytes(raw)
                extracted.append(dict(file=name,record=record,size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),source=stamp,role='exact_named_asset_header' if eid==asset_id else 'adjacent_record_candidate_only',pair_relation_verified=eid==asset_id))
                if eid==asset_id:
                    if b'NnDataAssetRefNavMeshHeader\0' not in raw:raise ValueError('Missing expected asset class')
                else:actor_candidates.extend(dict(r,source_file=name) for r in references(raw))
    # Establish package ownership from export bounds, never adjacency alone.
    spec=importlib.util.spec_from_file_location('nav_package',HERE/'inspect-ui.py');package_reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(package_reader)
    spec=importlib.util.spec_from_file_location('nav_header',HERE/'decode-navigation-header.py');header_reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(header_reader)
    asset_record=next(r for r in extracted if r['role']=='exact_named_asset_header');body_record=next(r for r in extracted if r['role']=='adjacent_record_candidate_only')
    asset=(out/asset_record['file']).read_bytes();body=(out/body_record['file']).read_bytes();package=package_reader.exports(asset,body)
    if len(package['exports'])!=1 or package['exports'][0]['type']!='NnDataAssetRefNavMeshHeader':raise ValueError('Unexpected navigation export')
    export=package['exports'][0];start=export['offset']-len(asset);decoded=header_reader.decode(body[start:start+export['size']])
    body_record.update(role='verified_package_export_body',pair_relation_verified=True,export=export)
    for reference in actor_candidates:reference['relation_verified']=True
    schema=[]
    for address,name,field_offset,flag in [(0x1497f7048,'ChunkRef',0,3),(0x1497f7080,'AssetFilePath',8,21),(0x1497f70c0,'Bounds',24,25),(0x1497f7490,'NumMaxTiles',52,3),(0x1497f74c8,'NumChunks',56,3),(0x1497f7540,'RefNavMeshChunkHeader',64,22)]:
        import struct
        offset=im.offset(address-im.pe.base);raw=exe[offset:offset+56];pointer=struct.unpack_from('<Q',raw)[0];name_offset=im.offset(pointer-im.pe.base)
        if exe[name_offset:name_offset+len(name)+1]!=name.encode()+b'\0' or struct.unpack_from('<I',raw,24)[0]!=flag or struct.unpack_from('<I',raw,50)[0]!=field_offset:raise ValueError('Changed native nav descriptor')
        schema.append(dict(address=address,file_offset=offset,bytes=raw.hex(),name=name,name_offset=name_offset,object_offset=field_offset,property_flag=flag))
    targets={r['path'] for r in actor_candidates};matched={p:[] for p in targets}
    for entry in inventory:
        for row in json.loads((root/entry['file']).read_text('utf-8'))[:-1]:
            for path in set(row.get('paths',[]))&targets:matched[path].append(dict(archive=entry['archive'],record=row))
    report=dict(schema_version=1,source=source['source'],exe_sha256=source['sha256'],anchors=anchors,literals=literals,fragments=fragments,inventory=inventory,reference_assets=assets,extracted=extracted,package=package,decoded_header=decoded,native_descriptors=schema,external_actor_candidates=[dict(r,index_matches=matched[r['path']]) for r in actor_candidates],summary=dict(reference_asset_records=len(assets),nocturne_variants=len(selected_assets),external_actor_candidates=len(actor_candidates),external_actor_unique_paths=len(targets),external_actor_index_matches=sum(bool(v) for v in matched.values()),decoded_chunks=decoded['num_chunks'],native_anchors=len(anchors),routes_verified=0,navigation_ready=False),limitations=['The client has separate _Nav.bin path construction and a verified WPRefNav asset-loader path; a complete branch-selection model is not established.','The Nocturne header/body pair is verified by the cooked package export ranges, type, SHA and complete byte accounting.','Decoded header records contain chunk paths and axis-aligned bounds; these are not walkable polygons or proof of path connectivity.','Inventory matching is limited to recorded paths; missing matches do not prove absence from archives.','Recorded paths include both resource names and imports; a mentioning record is not necessarily a variant of the referenced asset.','No client execution, path solver or Android traversal performed.'])
    path=out/'index.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(summary=report['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest()),ensure_ascii=False));return report
if __name__=='__main__':main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir')))

