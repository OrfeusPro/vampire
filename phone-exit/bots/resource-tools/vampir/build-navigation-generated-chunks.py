"""Verify Nocturne generated cooked packages and extract owned Recast data exports."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
PREFIX='/Game/RED/Level/Field/Nocturne/Nocturne/_Generated_/'

def package_path(data):
    if data[:4]!=bytes.fromhex('c1832a9e') or len(data)<36:raise ValueError('Not a cooked package')
    n=struct.unpack_from('<i',data,32)[0]
    if not 1<n<=4096 or 36+n>len(data) or data[35+n]!=0:raise ValueError('Invalid summary package path')
    raw=data[36:35+n]
    if b'\0' in raw:raise ValueError('Embedded NUL in summary path')
    return raw.decode('utf-8')

def validate_exports(parsed,asset_size,body_size):
    exports=parsed['exports'];by={e['index']:e for e in exports}
    cursor=asset_size
    for e in sorted(exports,key=lambda e:(e['offset'],e['size'])):
        if e['offset']!=cursor:raise ValueError('Export ranges have a gap or overlap')
        cursor+=e['size']
    if cursor!=asset_size+body_size-4:raise ValueError('Export bytes do not cover body')
    roots=[e for e in exports if e['type']=='World' and e['outer']==0]
    if len(roots)!=1 or roots[0]['name']!='Nocturne':raise ValueError('Wrong generated world identity')
    chunks=[e for e in exports if e['type']=='RecastNavMeshDataChunk']
    if not chunks:raise ValueError('No Recast data export')
    for chunk in chunks:
        actor=by.get(chunk['outer'])
        if not actor or actor['type']!='NavigationDataChunkActor':raise ValueError('Chunk has no owning navigation actor')
        level=by.get(actor['outer'])
        if not level or level['type']!='Level' or level['outer']!=roots[0]['index']:raise ValueError('Navigation actor is outside Nocturne world')
    return chunks

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    def load(name,path):
        s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
    pak=load('generated_nav_pak',HERE.parent/'rfnext/scan-pak.py');ui=load('generated_nav_package',HERE/'inspect-ui.py')
    search_dir=root/'maps/navigation-study/chunk-header-search';search_path=search_dir/'index.json';search=json.loads(search_path.read_text('utf-8'))
    selected=[]
    for h in search['hits']:
        if not any(m['text']=='RecastNavMeshDataChunk' for m in h['matches']):continue
        asset=(search_dir/h['file']).read_bytes()
        if hashlib.sha256(asset).hexdigest()!=h['sha256']:raise ValueError('Changed candidate header')
        identity=package_path(asset)
        if identity.startswith(PREFIX):selected.append((h,asset,identity))
    out=root/'maps/navigation-study/generated-chunks';out.mkdir(exist_ok=True)
    packages=[];issues=[];decoded_total=0;archives={}
    for hit,asset,identity in selected:
        archive=hit['archive']
        if archive not in archives:
            folder=root/'pak-extracted'/archive;metadata=(folder/'entries.json').read_bytes();entries=json.loads(metadata)
            source=json.loads((folder/'source.json').read_text('utf-8'));path=Path(source['path']);stat=path.stat()
            with path.open('rb') as f:
                head=f.read(65536);f.seek(max(0,stat.st_size-65536));sample=hashlib.sha256(head+f.read()).hexdigest()
            if (stat.st_size,stat.st_mtime_ns,sample)!=(source['size'],source['modified_ns'],source['sample_sha256']):raise ValueError('Changed generated PAK')
            archives[archive]=dict(source=source,entries_sha256=hashlib.sha256(metadata).hexdigest(),entries=entries,by_id={e['entry']:e for e in entries[:-1]})
        info=archives[archive];eid=hit['record']['entry'];accepted=[];rejected=[]
        with Path(info['source']['path']).open('rb') as stream:
            for candidate in [eid-1,eid+1]:
                row=info['by_id'].get(candidate)
                if not row or row.get('encrypted') or row.get('uasset') or row['uncompressed']>32*1024**2:continue
                decoded_total+=row['uncompressed']
                if decoded_total>512*1024**2:raise ValueError('Generated chunk extraction budget exceeded')
                header=pak.header(stream,row['offset'],info['entries'][-1]['index_offset'])
                if not header or header['encrypted'] or header['usize']!=row['uncompressed']:raise ValueError('Changed candidate body header')
                body=pak.decode(stream,header)
                try:
                    if body[-4:]!=bytes.fromhex('c1832a9e'):raise ValueError('Missing package end tag')
                    parsed=ui.exports(asset,body,max_exports=40000);chunks=validate_exports(parsed,len(asset),len(body))
                    accepted.append((row,body,parsed,chunks))
                except ValueError as exc:rejected.append(dict(entry=candidate,reason=str(exc)))
        if len(accepted)!=1:
            issues.append(dict(archive=archive,header_entry=eid,accepted_bodies=len(accepted),rejected=rejected));continue
        body_row,body,parsed,chunks=accepted[0];stem=archive+'-'+str(eid);parts=[]
        for role,data,record in [('asset',asset,hit['record']),('body',body,body_row)]:
            name=stem+'-'+role+'.bin';(out/name).write_bytes(data);parts.append(dict(file=name,record=record,role=role,sha256=hashlib.sha256(data).hexdigest()))
        nav=[]
        for export in parsed['exports']:
            if export['type'] not in ['RecastNavMeshDataChunk','NavigationDataChunkActor']:continue
            start=export['offset']-len(asset);data=body[start:start+export['size']]
            if hashlib.sha256(data).hexdigest()!=export['sha256']:raise ValueError('Changed navigation export')
            name=stem+'-export-'+str(export['index'])+'.bin';(out/name).write_bytes(data)
            nav.append(dict(file=name,export=export,payload_decoded=False))
        packages.append(dict(archive=archive,source=info['source'],entries_sha256=info['entries_sha256'],package_identity=identity,
            parts=parts,navigation_exports=nav,total_exports=len(parsed['exports']),package_pair_verified=True,owner_chain_verified=True,
            selected_runtime_version_verified=False,rejected_body_candidates=rejected))
    summary=dict(header_candidates=len(selected),packages=len(packages),recast_exports=sum(e['export']['type']=='RecastNavMeshDataChunk' for p in packages for e in p['navigation_exports']),
        recast_bytes=sum(e['export']['size'] for p in packages for e in p['navigation_exports'] if e['export']['type']=='RecastNavMeshDataChunk'),
        issues=len(issues),routes_verified=0,navigation_ready=False)
    report=dict(source_header_search_sha256=hashlib.sha256(search_path.read_bytes()).hexdigest(),packages=packages,issues=issues,summary=summary,
        limitations=['Generated cooked packages are distinct from the 20 external actor paths in WPRefNav header; that relation is not established.',
                     'All source versions retained; runtime patch selection and active coverage are unverified.',
                     'Export type/ownership/ranges verified; custom payload, graph connectivity and traversal are not decoded here.'])
    path=out/'index.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(summary));return report

if __name__=='__main__':main()
