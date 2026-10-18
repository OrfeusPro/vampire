"""Bounded read-only search for navigation payload candidates in Nocturne archives."""
import hashlib,importlib.util,json,os,re,struct,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))
SIGNATURES={b'VAND':'Detour tile magic candidate',b'DNAV':'Detour reversed magic candidate',b'TESM':'Detour set magic candidate',b'MSET':'Detour reversed set magic candidate',b'NnRefNavMesh':'native class text',b'RecastNavMesh':'navigation class text',b'Nocturne_Nav.bin':'exact navigation filename'}

def matches(data,tokens):
    out=[]
    for value,kind in SIGNATURES.items():
        start=0
        while len(out)<100:
            offset=data.find(value,start)
            if offset<0:break
            out.append(dict(kind=kind,needle=value.decode(),offset=offset,context_hex=data[max(0,offset-8):offset+48].hex(),relation_verified=False));start=offset+len(value)
    for value in tokens:
        offset=data.find(value.encode())
        if offset>=0:out.append(dict(kind='exact external actor token',needle=value,offset=offset,relation_verified=False))
    return out

def main(root=ROOT):
    nav=json.loads((root/'maps/navigation-study/index.json').read_text('utf-8'));tokens={r['asset_file_path'].rsplit('/',1)[-1] for r in nav['decoded_header']['chunks']}
    spec=importlib.util.spec_from_file_location('payload_pak',HERE.parent/'rfnext/scan-pak.py');reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    reports=[];hits=[];out=root/'maps/navigation-study'
    for folder in sorted((root/'pak-extracted').iterdir()):
        if folder.name!='pakchunk100-Windows' and not re.fullmatch(r'pakchunk1000(?:_s[1-5])?-Windows',folder.name):continue
        source=json.loads((folder/'source.json').read_text('utf-8'));path=Path(source['path']);stat=path.stat()
        with path.open('rb') as stream:
            head=stream.read(65536);stream.seek(max(0,stat.st_size-65536));fingerprint=hashlib.sha256(head+stream.read()).hexdigest()
        if stat.st_size!=source['size'] or stat.st_mtime_ns!=source['modified_ns'] or fingerprint!=source['sample_sha256']:raise ValueError('Changed PAK '+folder.name)
        metadata=(folder/'entries.json').read_bytes();rows=json.loads(metadata);records=[r for r in rows[:-1] if not any(r.get(k) for k in ['encrypted','uasset','pixel_formats'])]
        if sum(r['uncompressed'] for r in records)>700*1024**2:raise ValueError('Archive scan budget exceeded')
        report=dict(archive=folder.name,source=source,entries_sha256=hashlib.sha256(metadata).hexdigest(),selected_records=len(records),decoded_records=0,decoded_bytes=0,skipped_large=[],errors=[]);started=time.monotonic()
        with path.open('rb') as stream:
            for row in records:
                if row['uncompressed']>128*1024**2:report['skipped_large'].append(row['entry']);continue
                try:
                    header=reader.header(stream,row['offset'],rows[-1]['index_offset'])
                    if not header or header['encrypted'] or header['usize']!=row['uncompressed']:raise ValueError('Record header changed')
                    raw=reader.decode(stream,header);report['decoded_records']+=1;report['decoded_bytes']+=len(raw)
                    found=matches(raw,tokens)
                    if found:
                        hits.append(dict(archive=folder.name,record=row,sha256=hashlib.sha256(raw).hexdigest(),matches=found,path_polygons_verified=False))
                except Exception as exc:report['errors'].append(dict(entry=row['entry'],error=str(exc)))
        report['elapsed_seconds']=round(time.monotonic()-started,2);reports.append(report);print(json.dumps({k:report[k] for k in ['archive','decoded_records','decoded_bytes','elapsed_seconds']}),flush=True)
    result=dict(schema_version=1,source_navigation_report_sha256=hashlib.sha256((out/'index.json').read_bytes()).hexdigest(),scope='Non-encrypted/non-UAsset/non-texture records in pakchunk100 and pakchunk1000 base+s1..s5; 700 MiB/archive,128 MiB/record',archives=reports,hits=hits,routes_verified=0,navigation_ready=False,limitations=['Signature matches are candidates; arbitrary binary data can contain magic by coincidence.','Absence of matches in this bounded scope is not absence from the game.','No decryption, game execution, or path traversal performed.'])
    path=out/'payload-search.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(archives=len(reports),hits=len(hits),errors=sum(len(r['errors']) for r in reports),sha256=hashlib.sha256(path.read_bytes()).hexdigest())),flush=True);return result
if __name__=='__main__':main()
