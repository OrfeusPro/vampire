"""Verify the Nocturne cooked level package and extract exact navigation exports."""
import hashlib,importlib.util,json,os
from collections import Counter
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main(root):
    folder=root/'pak-extracted/pakchunk1000_s3-Windows';source=json.loads((folder/'source.json').read_text('utf-8'));entries_raw=(folder/'entries.json').read_bytes();entries=json.loads(entries_raw);path=Path(source['path']);stat=path.stat()
    with path.open('rb') as f:
        head=f.read(65536);f.seek(max(0,stat.st_size-65536));fingerprint=hashlib.sha256(head+f.read()).hexdigest()
    if stat.st_size!=source['size'] or stat.st_mtime_ns!=source['modified_ns'] or fingerprint!=source['sample_sha256']:raise ValueError('Changed source PAK')
    spec=importlib.util.spec_from_file_location('nav_level_pak',HERE.parent/'rfnext/scan-pak.py');pak=importlib.util.module_from_spec(spec);spec.loader.exec_module(pak)
    spec=importlib.util.spec_from_file_location('nav_level_package',HERE/'inspect-ui.py');package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
    out=root/'maps/navigation-study/level';out.mkdir(parents=True,exist_ok=True);parts={};provenance=[]
    with path.open('rb') as stream:
        for eid,role in [(1141,'asset'),(1140,'body')]:
            row=next(r for r in entries if r.get('entry')==eid);header=pak.header(stream,row['offset'],entries[-1]['index_offset'])
            if not header or header['encrypted'] or header['usize']>32*1024**2:raise ValueError('Unexpected level record')
            raw=pak.decode(stream,header);parts[role]=raw;name=f'Nocturne-{role}.bin';(out/name).write_bytes(raw);provenance.append(dict(file=name,role=role,record=row,sha256=hashlib.sha256(raw).hexdigest()))
    parsed=package.exports(parts['asset'],parts['body'],max_exports=40000)
    world_exports=[e for e in parsed['exports'] if e['type']=='World' and e['outer']==0]
    if len(world_exports)!=1 or world_exports[0]['name']!='Nocturne' or '/Game/RED/Level/Field/Nocturne/Nocturne' not in parsed['names']:raise ValueError('Wrong level identity')
    selected=[]
    for export in parsed['exports']:
        if 'Nav' not in export['type']:continue
        start=export['offset']-len(parts['asset']);raw=parts['body'][start:start+export['size']]
        if hashlib.sha256(raw).hexdigest()!=export['sha256']:raise ValueError('Changed export')
        name=f"export-{export['index']}.bin";(out/name).write_bytes(raw);selected.append(dict(export=export,file=name,properties_decoded=False,walkability_verified=False))
    counts=dict(Counter(r['export']['type'] for r in selected))
    report=dict(source=source,entries_sha256=hashlib.sha256(entries_raw).hexdigest(),parts=provenance,package_identity='/Game/RED/Level/Field/Nocturne/Nocturne',world_export=world_exports[0],total_exports=len(parsed['exports']),navigation_exports=selected,counts=counts,package_pair_verified=True,export_bytes_accounted=True,external_chunk_payloads_extracted=False,routes_verified=0,navigation_ready=False,limitations=['Exact export identity, range and bytes verified; navigation properties and custom serializers are not decoded here.','Navigation link components are not validated graph edges; volume bounds are not walkable polygons.','No live traversal or path query executed.'])
    index=out/'index.json';index.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(exports=len(parsed['exports']),navigation_counts=counts,sha256=hashlib.sha256(index.read_bytes()).hexdigest()),ensure_ascii=False));return report
if __name__=='__main__':main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir')))
