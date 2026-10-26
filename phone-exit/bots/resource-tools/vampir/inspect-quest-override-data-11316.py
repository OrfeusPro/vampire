"""Bind named localization CSVs to native override inputs; static/data evidence only."""
import csv
from collections import Counter, defaultdict
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name,path=None):
    spec = importlib.util.spec_from_file_location(name.replace('-','_'),path or HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    audit = load('audit-client-release'); native = load('build-native-entry-code')
    path = HERE/'knowledge/native-contexts/quest-override-data-11316.json'
    context = json.loads(path.read_text('utf-8')); root = native.ROOT
    source = root/'client-code-snapshots'/context['source_sha256']/'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=context['source_sha256']: raise ValueError('Native source changed')
    image = native.Image(raw)
    def source_bytes(at,size):
        offset = image.offset(at-image.pe.base)
        return raw[offset:offset+size]
    def literal(at):
        return source_bytes(at,256).split(b'\0',1)[0].decode('ascii')
    if literal(0x1499f7b78)!='QuestTask_Name.csv' or literal(0x1499f7c90)!='TaskName' or literal(0x14914ed90)!='Param':
        raise ValueError('Native override column/file literals changed')
    if source_bytes(0x145a4dc20,8).hex()!='488d052921ba05c3': raise ValueError('Locale getter changed')
    locale_global = 0x145a4dc20+7+int.from_bytes(source_bytes(0x145a4dc23,4),'little',signed=True)
    exports = []
    functions = {}
    for run,sha in context['exports'].items():
        p = root/'ghidra/request-exports'/context['source_sha256']/run/'details.json'
        if audit.sha256(p)!=sha: raise ValueError('Override export changed')
        d = json.loads(p.read_text('utf-8'))
        if d['new_source_sha256']!=context['source_sha256']: raise ValueError('Override export source differs')
        functions.update({f['address']:f for f in d['functions']})
        exports.append(dict(path=str(p),sha256=sha))
    override = functions['0x145b69ca0']; transform = functions['0x14585e070']
    if not all(f.get('block_coverage_complete') for f in (override,transform)): raise ValueError('Incomplete override export')
    instructions = {int(i['address'],16):i for i in override['instructions']}
    for at,expected in {
            0x145b6a530:'498d4f78',0x145b6a537:'e824788dfb',
            0x145b6a5a7:'83bd78010000ff',0x145b6a5ae:'0f84c7010000',
            0x145b6a703:'498d8f90000000',0x145b6a70d:'e84e768dfb'}.items():
        if instructions.get(at,{}).get('bytes')!=expected or source_bytes(at,len(bytes.fromhex(expected))).hex()!=expected:
            raise ValueError('Override field/optional-column flow changed')
    directory_path = root/context['directory_manifest']; index_path = root/context['record_index']
    if audit.sha256(directory_path)!=directory_path.parent.name or audit.sha256(index_path)!=index_path.parent.name:
        raise ValueError('Directory/record manifest changed')
    directory_meta = json.loads(directory_path.read_text('utf-8')); index = json.loads(index_path.read_text('utf-8'))
    if directory_meta['archive_sha256']!=context['pak_sha256'] or index['source']['sha256']!=context['pak_sha256']:
        raise ValueError('Directory/record PAK binding differs')
    directory_raw = (directory_path.parent/'directory.json').read_bytes()
    encoded = (directory_path.parent/'encoded-entries.bin').read_bytes()
    if hashlib.sha256(directory_raw).hexdigest()!=directory_meta['directory_paths_file_sha256'] or hashlib.sha256(encoded).hexdigest()!=directory_meta['encoded_entries_file_sha256']:
        raise ValueError('Named directory metadata changed')
    if directory_meta['authoritative_directory_for_archive'] is not True: raise ValueError('Directory not authoritative')
    archive = Path(index['source']['path']); before = archive.stat()
    if audit.sha256(archive)!=context['pak_sha256']: raise ValueError('Current PAK changed')
    reader_path = HERE.parent/'rfnext/scan-pak.py'; reader = load('override_csv_reader',reader_path)
    if audit.sha256(reader_path)!=index['dependencies']['reader_sha256'] or audit.sha256(
            reader.ROOT/'tools/oodle-data-shared.dll')!=index['dependencies']['oodle_sha256']:
        raise ValueError('CSV decoder changed')
    by_offset = {e['offset']:e for e in index['entries']}
    entries = {e['path']:e for e in json.loads(directory_raw)['entries']}
    selected = {name:e for name,e in entries.items() if name.startswith('CSV/L10N/') and name.split('/')[-1].casefold()==literal(0x1499f7b78).casefold()}
    locales = sorted(name.split('/')[2] for name in selected)
    if locales!=context['locales']: raise ValueError('Locale file set changed')
    records = []; russian_catalog = None
    with archive.open('rb') as stream:
        def decode(name,meta):
            # Position is the first encoded field after flags, as in the existing atlas builder.
            position = meta['encoded_entry_offset']; bits = struct.unpack_from('<I',encoded,position)[0]
            offset = struct.unpack_from('<I' if bits&(1<<31) else '<Q',encoded,position+4)[0]
            entry = by_offset[offset]; header = reader.header(stream,offset,index['index_offset'])
            if header is None or header['end']!=entry['end']: raise ValueError('Named CSV header differs')
            payload = reader.decode(stream,header)
            sha = hashlib.sha256(payload).hexdigest()
            if sha!=entry['decoded_sha256']: raise ValueError('Named CSV hash differs')
            parsed = csv.DictReader(io.StringIO(payload.decode('utf-8-sig')))
            rows = list(parsed)
            return rows,dict(path=name,entry=entry['entry'],offset=offset,sha256=sha,columns=parsed.fieldnames,rows=len(rows))
        base_rows,base_meta = decode('CSV/QuestTask.csv',entries['CSV/QuestTask.csv'])
        if base_meta['sha256']!=context['base_csv_sha256']: raise ValueError('Named base QuestTask binding differs')
        base_ids = {row['Id'] for row in base_rows}
        if len(base_ids)!=5944 or len(base_rows)!=5944: raise ValueError('Base IDs changed/duplicated')
        for name,meta in sorted(selected.items()):
            rows,record = decode(name,meta)
            if record['columns']!=['Id','TaskName','L10NOrder','L10NRegistrationDate','Untranslated']:
                raise ValueError('Override schema changed; recheck optional Param path')
            ids = [row['Id'] for row in rows]; frequencies = Counter(ids); unique = set(ids)
            record.update(locale=name.split('/')[2],duplicate_ids=len(ids)-len(unique),matched_base_ids=len(base_ids&unique),
                          absent_base_ids=len(unique-base_ids),missing_base_ids=len(base_ids-unique),param_column_present='Param' in record['columns'],
                          selected_tasks=[dict(id=row['Id'],task_name=row['TaskName'],untranslated=row['Untranslated']) for row in rows if row['Id'] in context['task_ids']])
            # Preserve duplicate rows; do not choose an arbitrary winner for display.
            record['duplicate_id_values'] = sorted(value for value,n in frequencies.items() if n>1)
            record['missing_base_id_values'] = sorted(base_ids-unique)
            if record['locale']==context['presentation_locale']:
                by_id = defaultdict(list)
                for ordinal,row in enumerate(rows,2):
                    if row['Id'] in base_ids:
                        by_id[row['Id']].append(dict(csv_record=ordinal,task_name=row['TaskName'],untranslated=row['Untranslated']))
                # Candidate presentation data only: never pick a winner for duplicated IDs.
                russian_catalog = dict(locale='ru',source_path=name,source_sha256=record['sha256'],
                    names={key:items[0] for key,items in by_id.items() if len(items)==1},
                    duplicate_rows={key:items for key,items in by_id.items() if len(items)>1},
                    missing_ids=sorted(base_ids-unique),runtime_admitted=False)
            records.append(record)
    after = archive.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or audit.sha256(archive)!=context['pak_sha256']:
        raise ValueError('PAK changed during inspection')
    report = dict(source_sha256=context['source_sha256'],tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
                  exports=exports,directory_manifest_sha256=directory_path.parent.name,record_index_sha256=index_path.parent.name,
                  base=base_meta,locale_getter=dict(address='0x145a4dc20',target=hex(locale_global),active_value_verified=False),
                  presentation_locale=context['presentation_locale'],russian_catalog=russian_catalog,
                  records=records,network_used=False,native_execution=False,order_admitted=False,limits=context['limits'])
    target = audit.save_snapshot(root/'code-clues/quest-override-data-11316',report)
    return target,report


if __name__ == '__main__':
    target,result = run()
    print(json.dumps(dict(artifact=str(target),locales=[dict(locale=r['locale'],rows=r['rows'],matched=r['matched_base_ids'],extra=r['absent_base_ids']) for r in result['records']]),ensure_ascii=False))
