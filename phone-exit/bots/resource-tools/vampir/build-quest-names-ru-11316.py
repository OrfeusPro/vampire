"""Current Russian quest labels from two exact PAK records; no game IO."""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
PAK='15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4'
INDEX='release-snapshots/c44b60d512a5b6a07a3ca7f6242eb23a385d36c87c67a7490fb2bad3c150b4db/record-indexes/faad77301f66215958cca4d9a083ca61f09f8f54650307dab1580470dc47f913/manifest.json'
TABLES={'Quest':'f9b941f557103b79918b362aaeec0c50796631dedf1d5b6ab4d4092651ba74c2',
        'QuestNamesRu':'c0215204ed57b9eec79f527a66935392a9a493cc624ad0d7aee019f1c46b5577'}
TARGET=HERE.parents[1]/'vampir/ui-prototype/quest-names-ru.js'


def load(name,path=None):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),path or HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def collect():
    native,audit=load('build-native-entry-code'),load('audit-client-release');root=native.ROOT
    raw=(root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('Quest source changed')
    image=native.Image(raw)
    # Only the checked key-forwarding prefix is used. Full chained constructor
    # export failed in the existing decoder and is not claimed here.
    prefix=bytes.fromhex('40555641544155488d6c24b84881ec480100004c8bea488955784c8be1488d5578488d4de0e86683d6ff')
    offset=image.offset(0x145de3790-image.pe.base)
    if raw[offset:offset+len(prefix)]!=prefix:raise ValueError('Incoming quest key prefix changed')
    exports={}
    rows={}
    for run,at in (('run-d4f609a9b8e8','0x145d81aa0'),('run-22845de261d6','0x145d6f9b0')):
        path=root/'ghidra/request-exports'/SHA/run/'details.json';value=json.loads(path.read_text('utf-8'))
        if value['new_source_sha256']!=SHA:raise ValueError('Key export source differs')
        function=next(f for f in value['functions'] if f['address']==at)
        if not function['decompilation_completed'] or not function['block_coverage_complete']:raise ValueError('Incomplete key caller export')
        for row in function['instructions']:
            address=int(row['address'],16);content=bytes.fromhex(row['bytes']);off=image.offset(address-image.pe.base)
            if raw[off:off+len(content)]!=content:raise ValueError('Key export bytes differ')
            rows[address]=row
        exports[run]=audit.sha256(path)
    anchors={0x145d81b5a:'488b5308',0x145d81b6a:'e8211c0600',
             0x145d6f9d4:'488d15fd3eb903',0x145d6f9f2:'488bf8',
             0x145d6fdb0:'48897d6f',0x145d6fdb8:'e863bdddff'}
    if any(rows.get(at,{}).get('bytes')!=content for at,content in anchors.items()):raise ValueError('Incoming/named quest key binding differs')
    literal=('QuestInfoId\0').encode('utf-16le');off=image.offset(0x1499038d8-image.pe.base)
    if raw[off:off+len(literal)]!=literal:raise ValueError('QuestInfoId property changed')
    index_path=root/INDEX
    if audit.sha256(index_path)!=index_path.parent.name:raise ValueError('Record index changed')
    index=json.loads(index_path.read_text('utf-8'));archive=Path(index['source']['path']);before=archive.stat()
    if audit.sha256(archive)!=PAK or index['source']['sha256']!=PAK:raise ValueError('Current quest PAK changed')
    reader_path=HERE.parent/'rfnext/scan-pak.py';reader=load('quest_ru_reader',reader_path)
    if audit.sha256(reader_path)!=index['dependencies']['reader_sha256'] or audit.sha256(reader.ROOT/'tools/oodle-data-shared.dll')!=index['dependencies']['oodle_sha256']:
        raise ValueError('Quest PAK decoder changed')
    tables={};proof={}
    with archive.open('rb') as stream:
        for name,digest in TABLES.items():
            matches=[e for e in index['entries'] if e.get('decoded_sha256')==digest]
            if len(matches)!=1:raise ValueError('Ambiguous exact quest table')
            entry=matches[0];header=reader.header(stream,entry['offset'],index['index_offset'])
            if not header or header['end']!=entry['end']:raise ValueError('Quest record header changed')
            body=reader.decode(stream,header)
            if hashlib.sha256(body).hexdigest()!=digest:raise ValueError('Quest table body changed')
            tables[name]=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
            proof[name]=dict(sha256=digest,entry=entry['entry'],offset=entry['offset'],rows=len(tables[name]))
    after=archive.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Quest archive changed during read')
    quests={r['Id']:r for r in tables['Quest']};grouped={}
    for row in tables['QuestNamesRu']:grouped.setdefault(row['Id'],[]).append(row)
    # Some untranslated placeholder IDs occur twice with different texts.
    # Keep them unknown rather than choosing the first/last localization row.
    ambiguous=sorted(key for key,values in grouped.items() if len(values)!=1)
    names={key:values[0] for key,values in grouped.items() if len(values)==1}
    if len(quests)!=len(tables['Quest']):raise ValueError('Duplicate quest key')
    if quests['110120']['PreQuestId']!='110110' or names['110110']['Name']!='Движение вперед' or names['110120']['Name']!='Зов крови':
        raise ValueError('Reviewed quest/name anchors changed')
    catalog={};skipped=[]
    for key in sorted(quests,key=int):
        row=names.get(key)
        if not re.fullmatch(r'\d{1,20}',key):raise ValueError('Invalid quest table key')
        if row and row['Name'] and re.search('[А-Яа-яЁё]',row['Name']):
            title,objective=row['Name'],row.get('DescObjective','')
            if len(title)>256 or len(objective)>2048:raise ValueError('Quest text bounds exceeded')
            catalog[key]=dict(title=title,objective=objective)
        else:skipped.append(dict(id=key,reason='ambiguous' if key in ambiguous else 'missing' if row is None else 'untranslated'))
    metadata=dict(source_sha256=SHA,archive_sha256=PAK,tables=proof)
    data=json.dumps(catalog,ensure_ascii=False,separators=(',',':'))
    source='/* Current Russian client texts; reproduced by build-quest-names-ru-11316.py. */\n'
    source+="(function(root){'use strict';\nconst sourceSha256="+json.dumps(SHA)+";\nconst metadata=Object.freeze("+json.dumps(metadata,separators=(',',':'))+");\n"
    source+='const names='+data+';\nObject.values(names).forEach(Object.freeze);Object.freeze(names);\n'
    source+="const api={sourceSha256,metadata,count:Object.keys(names).length,get(id,source=sourceSha256){return source===sourceSha256&&typeof id==='string'&&Object.hasOwn(names,id)?names[id]:null;}};Object.freeze(api);root.VampirQuestNamesRu=api;if(typeof module!=='undefined')module.exports=api;})(typeof window==='undefined'?globalThis:window);\n"
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),installed_archive=dict(path=str(archive),sha256=PAK),
        record_index=dict(path=str(index_path),sha256=audit.sha256(index_path)),tables=proof,exports=exports,
        key_anchors={hex(k):v for k,v in anchors.items()},constructor_prefix=prefix.hex(),names=len(catalog),ambiguous_name_ids=ambiguous,skipped=skipped,
        output_sha256=hashlib.sha256(source.encode()).hexdigest(),network_used=False,
        limits=['Current key identity is a static shared-lookup binding, not active quest/task or command permission.',
            'Full145de3790 constructor export remains incomplete; only the explicit key-forwarding prefix is verified.',
            'Two exact current CSV bodies and Russian text anchors; no unknown locale is guessed by schema alone.',
            'Untranslated/non-Cyrillic or absent titles keep the Russian ID fallback; no invented translation.'])
    return source,report


def run(write=False):
    source,report=collect();audit=load('audit-client-release')
    if write:TARGET.write_text(source,encoding='utf-8',newline='\n')
    elif TARGET.read_bytes()!=source.encode('utf-8'):raise ValueError('Russian runtime catalog differs; regenerate explicitly')
    return audit.save_snapshot(load('build-native-entry-code').ROOT/'code-clues/quest-names-ru-11316',report),report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    path,report=run(args.write);print(json.dumps(dict(report=str(path),names=report['names'],output=str(TARGET))))
