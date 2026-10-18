"""Bounded search of cooked package headers; names identify candidates, not polygons."""
import hashlib,importlib.util,json,re,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
MAX_RECORD=1024**2
MAX_ARCHIVE=128*1024**2
MAX_TOTAL=1024**3

def matches(data,tokens):
    found=[]
    for token in sorted(tokens):
        needle=token.encode('ascii')
        for match in re.finditer(rb'(?<![A-Z0-9])'+re.escape(needle)+rb'(?![A-Z0-9])',data):
            found.append(dict(kind='external_actor_leaf',text=token,offset=match.start(),relation_verified=False))
    for text in ['NnDataAssetRefNavMeshHeader','NnDataAssetRefNavMeshChunk','NnRefNavMesh','NnRecastNavMesh','RecastNavMeshDataChunk','NavMeshDataChunk']:
        needle=text.encode('ascii')+b'\0';offset=data.find(needle)
        if offset>=0:found.append(dict(kind='navigation_class',text=text,offset=offset,relation_verified=False))
    return found

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    nav_path=root/'maps/navigation-study/index.json';nav=json.loads(nav_path.read_text('utf-8'))
    tokens={r['asset_file_path'].rsplit('/',1)[-1] for r in nav['decoded_header']['chunks']}
    spec=importlib.util.spec_from_file_location('nav_header_pak',HERE.parent/'rfnext/scan-pak.py')
    pak=importlib.util.module_from_spec(spec);spec.loader.exec_module(pak)
    folders=[];total=0
    for path in sorted((root/'pak-extracted').glob('*/entries.json')):
        raw=path.read_bytes();entries=json.loads(raw)
        selected=[r for r in entries[:-1] if r.get('uasset') and not r.get('encrypted') and r['uncompressed']<=MAX_RECORD]
        size=sum(r['uncompressed'] for r in selected);total+=size
        if size>MAX_ARCHIVE or total>MAX_TOTAL:raise ValueError('Header search budget exceeded')
        folders.append((path,raw,entries,selected))
    out=root/'maps/navigation-study/chunk-header-search';out.mkdir(exist_ok=True)
    reports=[];hits=[]
    for path,raw,entries,selected in folders:
        source=json.loads(path.with_name('source.json').read_text('utf-8'));archive=Path(source['path']);stat=archive.stat()
        with archive.open('rb') as stream:
            head=stream.read(65536);stream.seek(max(0,stat.st_size-65536));sample=hashlib.sha256(head+stream.read()).hexdigest()
        if (stat.st_size,stat.st_mtime_ns,sample)!=(source['size'],source['modified_ns'],source['sample_sha256']):
            raise ValueError('Changed PAK '+path.parent.name)
        report=dict(archive=path.parent.name,source=source,entries_sha256=hashlib.sha256(raw).hexdigest(),
            selected_records=len(selected),decoded_records=0,decoded_bytes=0,
            skipped_encrypted=sum(bool(r.get('encrypted')) for r in entries[:-1]),
            skipped_large_headers=[r['entry'] for r in entries[:-1] if r.get('uasset') and r['uncompressed']>MAX_RECORD],errors=[])
        started=time.monotonic()
        with archive.open('rb') as stream:
            for row in selected:
                try:
                    header=pak.header(stream,row['offset'],entries[-1]['index_offset'])
                    if not header or header['encrypted'] or header['usize']!=row['uncompressed']:raise ValueError('Changed PAK entry header')
                    data=pak.decode(stream,header);report['decoded_records']+=1;report['decoded_bytes']+=len(data)
                    found=matches(data,tokens)
                    if found:
                        name=path.parent.name+'-header-'+str(row['entry'])+'.bin';(out/name).write_bytes(data)
                        hits.append(dict(archive=path.parent.name,record=row,file=name,sha256=hashlib.sha256(data).hexdigest(),
                            matches=found,package_identity_verified=False,walkable_polygons_verified=False))
                except Exception as exc:report['errors'].append(dict(entry=row['entry'],error=str(exc)))
        report['elapsed_seconds']=round(time.monotonic()-started,2);reports.append(report)
        print(json.dumps(dict(archive=report['archive'],headers=report['decoded_records'],bytes=report['decoded_bytes'])),flush=True)
    result=dict(source_navigation_report_sha256=hashlib.sha256(nav_path.read_bytes()).hexdigest(),tokens=sorted(tokens),
        limits=dict(record_bytes=MAX_RECORD,archive_bytes=MAX_ARCHIVE,total_bytes=MAX_TOTAL),archives=reports,hits=hits,
        summary=dict(headers=sum(r['decoded_records'] for r in reports),bytes=sum(r['decoded_bytes'] for r in reports),
            hits=len(hits),errors=sum(len(r['errors']) for r in reports),routes_verified=0,navigation_ready=False),
        limitations=['UAsset headers only, not all payloads or encrypted records. Larger headers are explicitly excluded.',
                     'Exact token/class matches are candidates. Package identity, export relationship and payload still require verification.'])
    (out/'index.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(result['summary']),flush=True)
    return result

if __name__=='__main__':main()
