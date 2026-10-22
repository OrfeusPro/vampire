"""Build a presentation-only RU dictionary from named, hash-verified PAK CSVs.

Raw atlas data/hashes and game IDs remain unchanged. Conflicting English texts
with different translations are omitted rather than resolved arbitrarily.
"""
import csv,hashlib,importlib.util,io,json,struct
from collections import defaultdict
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
DIRECTORY=ROOT/'resource-config-snapshots/4760d94dc28b0156176d0cace6295da3ce130ea7e2f91798ff7b9a5b6976ae1c/manifest.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main(root=ROOT):
    core=load('atlas_ru_pak',HERE/'recover-pak-game-config.py');report_raw=DIRECTORY.read_bytes();report=json.loads(report_raw)
    assert sha(report_raw)==DIRECTORY.parent.name
    archive=Path(report['source_archive']['path']);assert core.sha256(archive)==report['archive_sha256']
    directory_raw=(DIRECTORY.parent/'directory.json').read_bytes();assert sha(directory_raw)==report['directory_paths_file_sha256']
    directory=json.loads(directory_raw);entries={r['path']:r for r in directory['entries']}
    snapshot=root/'release-snapshots'/report['release_manifest_sha256']
    manifests=list(snapshot.glob('record-indexes/*/*/table-snapshots/*/manifest.json'))
    matching=[p for p in manifests if json.loads(p.read_bytes())['source']['sha256']==report['archive_sha256']]
    if len(matching)!=1:raise ValueError('Ambiguous CSV snapshot')
    manifest=matching[0];manifest_raw=manifest.read_bytes();assert sha(manifest_raw)==manifest.parent.name
    tables=json.loads(manifest_raw)['tables'];by_offset={r['offset']:r for r in tables}
    key_source=root/'client-code-snapshots'/core.EXE_SHA256/'ProjectRED-Win64-Shipping.exe'
    assert core.sha256(key_source)==core.EXE_SHA256
    flow=core.load('atlas_ru_key_flow',HERE/'build-headless-cdn-json-flow.py');prep=flow.body.head.headers.uri.http.preparation;native=prep.url.settings.config.native
    exe=key_source.read_bytes();key,_=core.recover_key(exe,native.Image(exe),native,prep)
    with archive.open('rb') as stream:
        main=core.read_verified_index(stream,report['main_index'],key,archive.stat().st_size)
    metadata,encoded=core.parse_main(main)
    candidates=defaultdict(set);sources=[];pairs=0
    for ru_path,ru_entry in sorted(entries.items()):
        if not ru_path.startswith('CSV/L10N/ru/') or not ru_path.endswith('.csv'):continue
        en_path=ru_path.replace('/ru/','/en/');en_entry=entries.get(en_path)
        if not en_entry:continue
        def read(path,entry):
            # Only the position prefix is needed. Full CSV payloads were already
            # decoded and SHA-bound by extract-release-tables (including multi-block records).
            pos=entry['encoded_entry_offset'];bits=struct.unpack_from('<I',encoded,pos)[0]
            offset=struct.unpack_from('<I' if bits&(1<<31) else '<Q',encoded,pos+4)[0];meta=by_offset[offset]
            raw=Path(meta['file']).read_bytes();assert sha(raw)==meta['sha256']
            reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig')));rows=list(reader)
            assert reader.fieldnames==meta['header'] and len(rows)==meta['rows']
            sources.append(dict(path=path,entry=meta['entry'],offset=offset,file=meta['file'],sha256=meta['sha256'],rows=len(rows)))
            return reader.fieldnames,rows
        en_header,en=read(en_path,en_entry);ru_header,ru=read(ru_path,ru_entry)
        if en_header!=ru_header:raise ValueError('Language schema mismatch '+ru_path)
        key_field=en_header[0];en_ids=defaultdict(list);ru_ids=defaultdict(list)
        for row in en:en_ids[row[key_field]].append(row)
        for row in ru:ru_ids[row[key_field]].append(row)
        for identity in en_ids.keys()&ru_ids.keys():
            if len(en_ids[identity])!=1 or len(ru_ids[identity])!=1:continue
            a,b=en_ids[identity][0],ru_ids[identity][0]
            for field in en_header[1:]:
                if field.startswith('L10N') or field=='Untranslated':continue
                left,right=a[field],b[field]
                if left and right and left!=right and not left.isdecimal():candidates[left].add(right);pairs+=1
    texts={k:next(iter(v)) for k,v in candidates.items() if len(v)==1}
    out=root/'maps';payload=dict(language='ru',fallback='original',texts=texts)
    raw=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode();(out/'locale-ru.json').write_bytes(raw)
    result=dict(language='ru',file='locale-ru.json',sha256=sha(raw),dictionary_entries=len(texts),
        ambiguous_texts_omitted=sum(len(v)>1 for v in candidates.values()),paired_fields=pairs,
        source_directory_manifest=str(DIRECTORY),source_directory_manifest_sha256=sha(report_raw),source_archive_sha256=report['archive_sha256'],
        source_csv_manifest=str(manifest),source_csv_manifest_sha256=sha(manifest_raw),sources=sources,
        builder_sha256=sha(Path(__file__).read_bytes()),scope='presentation only; exact text from same table, ID and field; original retained for missing/ambiguous text')
    (out/'locale-ru-manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps({k:result[k] for k in ['dictionary_entries','ambiguous_texts_omitted','paired_fields','sha256']}));return result
if __name__=='__main__':main()
