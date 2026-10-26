"""Bind current named service tables to native loader fields; no active-state inference."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name,path=None):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),path or HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def run():
    audit=load('audit-client-release'); native=load('build-native-entry-code')
    path=HERE/'knowledge/native-contexts/quest-service-data-11316.json'; context=json.loads(path.read_text('utf-8'))
    root=native.ROOT; source=root/'client-code-snapshots'/context['source_sha256']/'ProjectRED-Win64-Shipping.exe'
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=context['source_sha256']: raise ValueError('Native source changed')
    image=native.Image(raw)
    def at(address,size):
        off=image.offset(address-image.pe.base); return raw[off:off+size]
    for address,name in context['columns'].items():
        expected=(name+'\0').encode()
        if at(int(address,16),len(expected))!=expected: raise ValueError('Service column literal changed')
    export_path=root/'ghidra/request-exports'/context['source_sha256']/context['export_run']/'details.json'
    if audit.sha256(export_path)!=context['export_sha256']: raise ValueError('Service export changed')
    exported=json.loads(export_path.read_text('utf-8'))
    loader=next(f for f in exported['functions'] if f['address']=='0x145c06600')
    if not loader.get('block_coverage_complete'): raise ValueError('Service loader export incomplete')
    instructions={int(r['address'],16):r['bytes'] for r in loader['instructions']}
    for address,expected in context['stores'].items():
        address=int(address,16)
        if instructions.get(address)!=expected or at(address,len(bytes.fromhex(expected))).hex()!=expected:
            raise ValueError('Service field store changed')
    if struct.unpack('<Q',at(0x149a11990+0x38,8))[0]!=0x145c06600:
        raise ValueError('Service manager loader slot changed')
    directory_path=root/context['directory_manifest']; index_path=root/context['record_index']
    if audit.sha256(directory_path)!=directory_path.parent.name or audit.sha256(index_path)!=index_path.parent.name:
        raise ValueError('Data manifest changed')
    directory_meta=json.loads(directory_path.read_text('utf-8')); index=json.loads(index_path.read_text('utf-8'))
    if directory_meta.get('authoritative_directory_for_archive') is not True:
        raise ValueError('Service directory not authoritative')
    if directory_meta['archive_sha256']!=context['pak_sha256'] or index['source']['sha256']!=context['pak_sha256']:
        raise ValueError('Source PAK mismatch')
    directory=(directory_path.parent/'directory.json').read_bytes(); encoded=(directory_path.parent/'encoded-entries.bin').read_bytes()
    if hashlib.sha256(directory).hexdigest()!=directory_meta['directory_paths_file_sha256'] or hashlib.sha256(encoded).hexdigest()!=directory_meta['encoded_entries_file_sha256']:
        raise ValueError('Named directory changed')
    entries={e['path']:e for e in json.loads(directory)['entries']}; by_offset={e['offset']:e for e in index['entries']}
    archive=Path(index['source']['path']); before=archive.stat()
    if audit.sha256(archive)!=context['pak_sha256']: raise ValueError('Current PAK changed')
    reader_path=HERE.parent/'rfnext/scan-pak.py'; reader=load('service_csv_reader',reader_path)
    if audit.sha256(reader_path)!=index['dependencies']['reader_sha256'] or audit.sha256(reader.ROOT/'tools/oodle-data-shared.dll')!=index['dependencies']['oodle_sha256']:
        raise ValueError('CSV decoder changed')
    tables={}
    with archive.open('rb') as stream:
        for name,expected_sha in context['tables'].items():
            position=entries[name]['encoded_entry_offset']; bits=struct.unpack_from('<I',encoded,position)[0]
            offset=struct.unpack_from('<I' if bits&(1<<31) else '<Q',encoded,position+4)[0]
            entry=by_offset[offset]; header=reader.header(stream,offset,index['index_offset'])
            if header is None or header['end']!=entry['end']: raise ValueError('Service entry header changed')
            payload=reader.decode(stream,header)
            if hashlib.sha256(payload).hexdigest()!=expected_sha or entry['decoded_sha256']!=expected_sha:
                raise ValueError('Service payload changed')
            parsed=csv.DictReader(io.StringIO(payload.decode('utf-8-sig'))); rows=list(parsed)
            tables[name]=dict(entry=entry['entry'],sha256=expected_sha,columns=parsed.fieldnames,rows=rows)
    services=tables['CSV/ServerServiceGroup.csv']['rows']; servers=tables['CSV/ServerGroup.csv']['rows']
    if list(services[0])!=list(context['columns'].values()): raise ValueError('Service schema changed')
    selected=[dict(csv_record=i,row=r) for i,r in enumerate(services,2) if r['GroupId']=='10000']
    if len(selected)!=8 or len({r['row']['RegionType'] for r in selected})!=8:
        raise ValueError('Group10000 region rows changed')
    server=next(r for r in servers if r['Id']=='256')
    decisions=[]
    for r in selected:
        row=r['row']; phase=int(server['ServicePhase'])
        if row['ExcludeServerId'] or row['IncludeServerId']: raise ValueError('Group10000 lists no longer empty')
        decisions.append(dict(region_type=int(row['RegionType']),server_id=256,service_phase=phase,
            candidate_skip=not int(row['MinServicePhase'])<=phase<=int(row['MaxServicePhase']),
            active_region_verified=False))
    after=archive.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or audit.sha256(archive)!=context['pak_sha256']:
        raise ValueError('PAK changed during inspection')
    report=dict(source_sha256=context['source_sha256'],tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
        export=dict(path=str(export_path),sha256=context['export_sha256']),directory_manifest_sha256=directory_path.parent.name,
        record_index_sha256=index_path.parent.name,tables=tables,selected_group_rows=selected,server_256=server,
        candidate_decisions=decisions,native_execution=False,network_used=False,order_admitted=False,limits=context['limits'])
    target=audit.save_snapshot(root/'code-clues/quest-service-data-11316',report)
    return target,report


if __name__=='__main__':
    target,result=run(); print(json.dumps(dict(artifact=str(target),decisions=result['candidate_decisions']),ensure_ascii=False))
