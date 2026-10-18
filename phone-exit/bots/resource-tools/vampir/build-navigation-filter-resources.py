"""Extract exact navigation-filter packages and preserve every source variant."""
import collections,hashlib,importlib.util,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def package_imports(asset,names):
    summary=36+struct.unpack_from('<i',asset,32)[0];_,_,count,offset=struct.unpack_from('<iiii',asset,summary+28);rows=[]
    for i in range(count):
        start=offset+32*i;outer=struct.unpack_from('<i',asset,start+16)[0];name,number=struct.unpack_from('<ii',asset,start+20)
        if not 0<=name<len(names) or not -count<=outer<=0:raise ValueError('Invalid filter import')
        rows.append(dict(index=-i-1,name=names[name]+('_'+str(number-1) if number else ''),outer=outer,file_offset=start,raw_hex=asset[start:start+32].hex()))
    return rows

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    pak=load('filter_resource_pak',HERE.parent/'rfnext/scan-pak.py');package=load('filter_resource_package',HERE/'inspect-ui.py')
    inheritance=load('filter_resource_inheritance',HERE/'build-lift-blueprints.py')
    out=root/'maps/navigation-study/filter-resources';out.mkdir(exist_ok=True);archives=[];variants=[]
    for entries_path in sorted((root/'pak-extracted').glob('*/entries.json')):
        entries_bytes=entries_path.read_bytes();entries=json.loads(entries_bytes)
        selected=[r for r in entries[:-1] if r.get('uasset') and re.fullmatch(r'/Game/RED/Blueprint/Navigation/BP_NavQuery_[A-Za-z]+',(r.get('paths') or [''])[0])]
        if not selected:continue
        source=json.loads(entries_path.with_name('source.json').read_bytes());archive=Path(source['path']);stat=archive.stat()
        with archive.open('rb') as stream:
            head=stream.read(65536);stream.seek(max(0,stat.st_size-65536));sample=sha(head+stream.read())
        if (stat.st_size,stat.st_mtime_ns,sample)!=(source['size'],source['modified_ns'],source['sample_sha256']):raise ValueError('Changed filter archive')
        archive_index=len(archives);archives.append(dict(archive=entries_path.parent.name,source=source,entries_sha256=sha(entries_bytes)))
        by_id={r['entry']:r for r in entries[:-1]}
        with archive.open('rb') as stream:
            def decode(row):
                header=pak.header(stream,row['offset'],entries[-1]['index_offset'])
                if not header or header['encrypted'] or header['usize']!=row['uncompressed'] or header['usize']>1024**2:raise ValueError('Changed/unsupported filter record')
                return pak.decode(stream,header)
            for row in selected:
                asset=decode(row);path=row['paths'][0];name=path.rsplit('/',1)[-1];pairs=[]
                for body_id in [row['entry']-1,row['entry']+1]:
                    body_row=by_id.get(body_id)
                    if not body_row or body_row.get('uasset') or body_row.get('encrypted') or body_row['uncompressed']>1024**2:continue
                    body=decode(body_row)
                    try:parsed=package.exports(asset,body,max_exports=100)
                    except ValueError:continue
                    if path not in parsed['names'] or not any(e['name']==name+'_C' for e in parsed['exports']):continue
                    cdo=[e for e in parsed['exports'] if e['name']=='Default__'+name+'_C']
                    if len(cdo)!=1:continue
                    pairs.append((body_row,body,parsed,cdo[0]))
                if len(pairs)!=1:raise ValueError('Ambiguous filter body: '+path)
                body_row,body,parsed,cdo=pairs[0];tag=entries_path.parent.name+'-'+str(row['entry']);parts=[]
                for role,record,raw in [('asset',row,asset),('body',body_row,body)]:
                    file=tag+'-'+role+'.bin';(out/file).write_bytes(raw);parts.append(dict(role=role,record=record,file=file,sha256=sha(raw)))
                exported=[]
                for export in parsed['exports']:
                    raw=body[export['offset']-len(asset):export['offset']-len(asset)+export['size']]
                    if sha(raw)!=export['sha256']:raise ValueError('Changed filter export')
                    file=tag+'-export-'+str(export['index'])+'.bin';(out/file).write_bytes(raw);exported.append(dict(export=export,file=file))
                variants.append(dict(path=path,archive_index=archive_index,parts=parts,inheritance=inheritance.class_parent(asset,parsed),
                    names=parsed['names'],imports=package_imports(asset,parsed['names']),exports=exported,cdo_export_index=cdo['index'],properties_decoded=False))
    counts=collections.Counter(v['path'] for v in variants)
    report=dict(archives=archives,variants=variants,summary=dict(packages=len(variants),unique_paths=len(counts),variants_per_path=dict(counts),
        runtime_filter_selection_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['All exact package variants retained. Adjacent body candidates require unique complete export accounting and class/CDO identity.',
            'Inheritance/import references and export bytes are preserved; unversioned properties/runtime overrides are not inferred here.'])
    path=out/'index.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
