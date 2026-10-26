"""Current CSV-backed dataflow through native lookup/progress/Type getter.

CSV order, row filtering and manager loading are NOT admitted as live state.
"""
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
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    audit=load('audit-client-release');context_path=HERE/'knowledge/native-contexts/quest-csv-projection-11316.json'
    context=json.loads(context_path.read_text('utf-8'))
    h=load('native-request-harness-11316').make_harness(context['exports'],{int(a,16) for a in context['functions']},
        leaves={int(a,16):b for a,b in context['leaves'].items()})
    if h.sha!=context['source_sha256'] or any(f.get('block_coverage_complete') is not True for f in h.fragments):
        raise ValueError('CSV/native source binding differs')
    loader=next(f for f in h.fragments if f['address']=='0x145b5f270')
    instructions={int(r['address'],16):r['bytes'] for r in loader['instructions']}
    for address,expected in {0x145b5f713:'48894740',0x145b5f730:'48894748',0x145b5f80a:'88878c000000',
            0x145b5fe95:'488b4350',0x145b5febf:'4c8d7308',0x145b5fee7:'4c8934d8'}.items():
        if instructions.get(address)!=expected:raise ValueError('CSV field/group store changed')
    for address,name in context['columns'].items():
        off=h.image.offset(int(address,16)-h.image.pe.base);literal=(name+'\0').encode()
        if h.raw[off:off+len(literal)]!=literal:raise ValueError('CSV column literal differs')
    literal_refs=set()
    for address,content in instructions.items():
        raw=bytes.fromhex(content)
        if len(raw)==7 and 0x48<=raw[0]<=0x4f and raw[1]==0x8d and raw[2] in (5,13,21,29,37,45,53,61):
            literal_refs.add(address+7+int.from_bytes(raw[3:],'little',signed=True))
    if not {int(a,16) for a in context['columns']}<=literal_refs:raise ValueError('CSV loader column references missing')
    manager_address=0x14b1c4bf0
    primary,secondary=struct.unpack_from('<QQ',h.raw,h.image.offset(manager_address-h.image.pe.base))
    if (primary,secondary)!=(0x1499f6948,0x1499f69e8):raise ValueError('Task manager interfaces differ')
    if struct.unpack_from('<Q',h.raw,h.image.offset(secondary-h.image.pe.base)+0x38)[0]!=0x145b5f270:
        raise ValueError('Secondary CSV loader slot differs')
    if struct.unpack_from('<Q',h.raw,h.image.offset(primary-h.image.pe.base)+0x30)[0]!=0x140bb4a10:
        raise ValueError('Post-load callback differs')
    leaf=h.image.offset(0x140bb4a10-h.image.pe.base)
    if h.raw[leaf:leaf+3]!=bytes.fromhex('b001c3'):raise ValueError('Post-load return leaf differs')
    table=int(context['data_vtable'],16)
    if struct.unpack_from('<Q',h.raw,h.image.offset(table-h.image.pe.base)+0x30)[0]!=0x145b55aa0:
        raise ValueError('Type virtual slot differs')
    index_path=h.root/context['record_index']
    if audit.sha256(index_path)!=index_path.parent.name:raise ValueError('CSV record index changed')
    index=json.loads(index_path.read_text('utf-8'));archive=Path(index['source']['path']);before=archive.stat()
    if index['source']['sha256']!=context['pak_sha256'] or audit.sha256(archive)!=context['pak_sha256']:
        raise ValueError('Current PAK changed')
    reader_path=HERE.parent/'rfnext/scan-pak.py';reader=load('quest_csv_reader',reader_path)
    if audit.sha256(reader_path)!=index['dependencies']['reader_sha256'] or audit.sha256(reader.ROOT/'tools/oodle-data-shared.dll')!=index['dependencies']['oodle_sha256']:
        raise ValueError('CSV decoder changed')
    entry=next(e for e in index['entries'] if e['entry']==context['csv_entry'])
    if entry.get('decoded_sha256')!=context['csv_sha256']:raise ValueError('Task CSV record differs')
    with archive.open('rb') as stream:
        header=reader.header(stream,entry['offset'],index['index_offset'])
        if header is None or header['end']!=entry['end']:raise ValueError('Task CSV entry header differs')
        payload=reader.decode(stream,header)
    if hashlib.sha256(payload).hexdigest()!=context['csv_sha256']:raise ValueError('Task CSV decode differs')
    parsed=csv.DictReader(io.StringIO(payload.decode('utf-8-sig')));rows=list(parsed)
    if parsed.fieldnames!=list(context['columns'].values())+['ServerServiceGroupId']:raise ValueError('Task CSV schema differs')
    groups={};seen=set()
    for ordinal,row in enumerate(rows,2):
        if row['Id'] in seen:raise ValueError('Duplicate task ID needs native merge proof')
        seen.add(row['Id'])
        for field in ('Id','QuestInfoId','Type'):
            if not row[field].isdigit() or int(row[field])>0xffffffffffffffff:raise ValueError('Invalid task scalar')
        if int(row['Type'])>255:raise ValueError('Task type needs enum conversion proof')
        groups.setdefault(row['QuestInfoId'],[]).append(dict(csv_record=ordinal,fields=row))
    uc,x,base=h.uc,h.x,h.scratch
    manager,nodes,slots,result,progress,hash_get,tasks=[base+n for n in (0x1000,0x2000,0x3000,0x5000,0x6000,0x8000,0x10000)]
    selected={};calls=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def put(at,n,size=8):uc.mem_write(at,int(n).to_bytes(size,'little',signed=n<0))
    def manager_get(machine):calls.append('manager');h.finish(manager)
    def hash_key(machine):
        if int.from_bytes(uc.mem_read(reg('RCX'),8),'little')!=selected['key'] or reg('RDX')!=8 or reg('R8')!=0:
            raise ValueError('Task lookup key/length/seed differs')
        calls.append('hash');h.finish(1)
    h.add_fixture(0x145b547a0,manager_get);h.add_fixture(hash_get,hash_key);put(0x14b0c2b00,hash_get)
    case_count=0;types=set();unprojected=[]
    for key,records in groups.items():
        if len(records)>128:
            unprojected.append(dict(quest_id=key,reason='signed_index_range'));continue
        selected['key']=int(key);uc.mem_write(manager,bytes(256));uc.mem_write(nodes,bytes(32))
        put(manager+0x68,nodes);put(manager+0x70,1,4);put(manager+0xb0,2,4);put(manager+0xa0,-1,4);put(manager+0xa4,0,4)
        put(nodes,int(key));put(nodes+8,slots);put(nodes+16,len(records),4);put(nodes+20,len(records),4);put(nodes+24,-1,4)
        uc.mem_write(tasks,bytes(len(records)*256))
        for i,item in enumerate(records):
            row=item['fields'];task=tasks+i*256;put(slots+i*8,task);put(task,table);put(task+0x40,int(row['Id']));put(task+0x48,int(row['QuestInfoId']));put(task+0x8c,int(row['Type']),1)
        immutable=[(a,bytes(uc.mem_read(a,n))) for a,n in ((manager,256),(nodes,32),(slots,len(records)*8),(tasks,len(records)*256))]
        for i,item in enumerate(records):
            row=item['fields'];calls.clear();uc.mem_write(result-16,b'A'*16+b'\xcc'*32+b'B'*16)
            uc.mem_write(progress,bytes(32));put(progress+8,i,1);put(progress+0x10,0x1234567800000001);put(progress+0x18,0x8765432100000002)
            uc.reg_write(x.UC_X86_REG_RDX,int(key));uc.reg_write(x.UC_X86_REG_R8,progress)
            if h.call(0x145de4610,result)!=result:raise ValueError('Projection result pointer differs')
            expected=bytearray(b'\xcc'*32);struct.pack_into('<QBB',expected,0,int(row['Id']),int(row['Type']),i)
            struct.pack_into('<II',expected,12,1,2);struct.pack_into('<Q',expected,24,0)
            if bytes(uc.mem_read(result,32))!=bytes(expected) or calls!=['manager','hash']:raise ValueError('CSV/native projection differs')
            if bytes(uc.mem_read(result-16,16))!=b'A'*16 or bytes(uc.mem_read(result+32,16))!=b'B'*16:raise ValueError('Projection guard changed')
            case_count+=1;types.add(row['Type'])
        if any(bytes(uc.mem_read(a,len(b)))!=b for a,b in immutable):raise ValueError('CSV model mutated')
    after=archive.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('PAK changed during CSV replay')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(context_path),
        exports=h.evidence,source_pak=index['source'],record_index=dict(path=str(index_path),sha256=audit.sha256(index_path)),
        csv=dict(entry=entry['entry'],sha256=context['csv_sha256'],columns=parsed.fieldnames,rows=len(rows)),
        static_manager=dict(address=hex(manager_address),primary=hex(primary),secondary=hex(secondary),csv_loader='0x145b5f270',post_load='0x140bb4a10'),
        native_cases=case_count,quest_groups=len(groups),types=sorted(types,key=int),catalog=groups,unprojected=unprojected,
        active_step_admitted=False,csv_order_admitted=False,network_used=False,
        fixtures=['CSV-seeded task records and quest arrays; manager population/filter/order not executed','manager getter','hash dispatch'],
        limits=['Actual lookup/progress, pointer getter and Type getter execute with current CSV values. CSV loader/clear/insert roots only source-bound static evidence.',
            'File order is a catalog candidate; no service-group filtering, sparse insertion order, data override or live selected-task permission is established.'])
    target=audit.save_snapshot(h.root/'code-clues/quest-csv-projection-11316',report);return target,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),rows=result['csv']['rows'],native_cases=result['native_cases'],groups=result['quest_groups']),ensure_ascii=False))
