"""Direct directory/header proofs for records omitted by linear discovery."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
RECIPE='directory-record-header-v1'
LIMIT=1024*1024
SHA=re.compile('[0-9a-f]{64}')
BASE=dict(schema=1,recipe=RECIPE,record_bytes=LIMIT,total_bytes=16*LIMIT,max_records=64)


def configuration(args):
    p=Path(args.knowledge)/'resource-directory-record.json'
    if not p.is_file():return None
    with p.open('rb') as stream:raw=stream.read(8193)
    d=json.loads(raw)
    if (len(raw)>8192 or not isinstance(d,dict) or set(d)!=set(BASE)|{'format_proof'}
            or any(d[k]!=v or type(d[k]) is not type(v) for k,v in BASE.items())):
        raise ValueError('Unknown direct directory record rule')
    return d


def parse_header(stream,entry,limit):
    for k in ('offset','bytes','uncompressed','method','blocks'):
        if type(entry.get(k)) is not int or entry[k]<0:raise ValueError('Invalid direct directory scalar')
    pos=entry['offset']
    if (type(limit) is not int or not 0<=pos<limit or entry['bytes']>LIMIT or entry['uncompressed']>LIMIT
            or entry['method'] not in (0,1) or entry.get('encrypted') is not False):
        raise ValueError('Unsupported direct directory record bounds')
    stream.seek(pos);pieces=[]
    def read(n):
        if n<0 or n>LIMIT or stream.tell()+n>limit:raise ValueError('Direct header exceeds entry boundary')
        raw=stream.read(n)
        if len(raw)!=n:raise ValueError('Truncated direct directory record')
        pieces.append(raw);return raw
    raw=read(48);offset,size,usize,method=struct.unpack_from('<qqqI',raw)
    if offset!=0 or (size,usize,method)!=(entry['bytes'],entry['uncompressed'],entry['method']):
        raise ValueError('Direct serialized header differs from directory')
    blocks=[]
    if method:
        count=struct.unpack('<i',read(4))[0]
        if not 1<=count<=1024 or count!=entry['blocks']:raise ValueError('Direct block count differs')
        raw_blocks=read(count*16)
        blocks=[struct.unpack_from('<qq',raw_blocks,k*16) for k in range(count)]
    elif entry['blocks']!=0:raise ValueError('Direct plain entry declares compression blocks')
    flags=read(1)[0];blocksize=struct.unpack('<I',read(4))[0];hs=stream.tell()-pos
    if flags!=0:raise ValueError('Encrypted or deleted direct record is unsupported')
    if method:
        if (not size or not usize or not 0<blocksize<=LIMIT
                or len(blocks)!=(usize+blocksize-1)//blocksize):
            raise ValueError('Direct compressed dimensions differ')
        previous=hs;total=0
        for a,b in blocks:
            if a!=previous or not a<b or pos+b>limit:raise ValueError('Direct compressed blocks escape or overlap')
            total+=b-a;previous=b
        if total!=size:raise ValueError('Direct stored block sum differs')
        end=pos+previous
    else:
        if size!=usize or blocksize!=0:raise ValueError('Direct plain dimensions differ')
        end=pos+hs+size
    if end>limit:raise ValueError('Direct payload escapes directory boundary')
    return dict(pos=pos,size=size,usize=usize,method=method,blocks=blocks,encrypted=False,
        blocksize=blocksize,hs=hs,end=end,stored_sha1=raw[28:48].hex(),
        header_sha256=hashlib.sha256(b''.join(pieces)).hexdigest())


class Scope:
    def __init__(self,index,args):
        self.index,self.args=index,args;self.owner=getattr(args,'resource_owner',None)
        if self.owner is None:raise ValueError('Direct record proof needs an open SHA owner')
        self.owner.check(index,args);self.root=Path(args.root).resolve()
        self.workflow=index.extension('research-workflow');self.csv=index.extension('resource-csv-v3')
        self.selected=index.extension('resource-selected-hashes-v1');self.indexer=index.extension('index-release-archives')
        self.rule=configuration(args)
        if self.rule is None:raise ValueError('Direct record selector missing')
        selector=Path(args.knowledge)/'resource-directory-record.json'
        with selector.open('rb') as stream:raw=stream.read(8193)
        if len(raw)>8192 or json.loads(raw)!=self.rule:raise ValueError('Direct record rule changed')
        self.rules={str(selector.resolve()):self.owner.remember(selector,raw)}
        for p in (HERE/'resource-directory-record-v1.py',HERE/'resource-selected-hashes-v1.py',HERE/'resource-csv-v3.py'):
            self.rules[str(p)]=self.owner.digest(p)
        primary=self.read(self.rule['format_proof'])
        if (primary.get('recipe')!='pak-serialized-entry-layout-v1' or type(primary.get('schema')) is not int
                or primary['schema']!=1 or primary.get('rules',{}).get('v11_plain_header_bytes')!=53
                or primary.get('rules',{}).get('v11_compressed_header_bytes')!='57 + 16 * block_count'):
            raise ValueError('Unknown direct header primary proof')
        self.rules[self.rule['format_proof']['path']]=self.rule['format_proof']['sha256']
        for p in (primary[k] for k in ('source','package','nuspec')):
            path=Path(p['path']).resolve()
            if not path.is_relative_to(self.root):raise ValueError('Direct header primary source outside library')
            self.rules[str(path)]=self.owner.expect(p['path'],p['sha256'])
        for p in (HERE.parent/'rfnext/scan-pak.py',Path(os.environ.get('PHONEEXIT_RF_RESOURCES',
                'F:/PhoneExit Resources/RF Online Next'))/'tools/oodle-data-shared.dll'):
            self.rules[str(p.resolve())]=self.owner.digest(p)
        self.runtime=self.csv._runtime(index,args);self.owner.final_checks.append(self.validate_runtime)
        self.sources={};self.memo={};self.memo_entries={};self.reader=None
        self.metrics=dict(unique_records=0,cache_hits=0,compressed_decodes=0,plain_reads=0,empty_records=0,
            decoded_bytes=0,stored_bytes=0,memo_hits=0,blocked_records=0)

    def read(self,p):
        _,d=self.csv._checked_pointer(self.index,self.args,p);return d

    def validate_runtime(self):
        if self.csv._runtime(self.owner.origin,SimpleNamespace())!=self.runtime:raise ValueError('Direct record runtime changed')

    def source(self,row,pointer):
        slot=str(Path(row['path']).resolve());sha=(row.get('current') or {}).get('sha256')
        if slot in self.sources:
            value=self.sources[slot]
            if value['pointer']!=pointer or value['source']['sha256']!=sha:raise ValueError('Direct source proof changed')
            return value
        scope=getattr(self.args,'resource_directory_v1_scope',None)
        if scope is None or scope.owner is not self.owner:raise ValueError('Direct proof needs verified directory scope')
        d=self.read(pointer);inputs=d.get('inputs',{})
        if (d.get('recipe')!='resource-directory-v1' or d.get('authoritative_directory_for_archive') is not True
                or inputs.get('source',{}).get('path')!=slot or inputs['source'].get('sha256')!=sha
                or inputs.get('rules')!=scope.rules or inputs.get('runtime')!=scope.runtime
                or d.get('path_gaps')!=[] or d.get('unmatched_csv')!=[]):
            raise ValueError('Direct directory proof differs')
        value,record,aliases=self.csv._prepare(self.index,self.args,inputs['record_index'])
        if (value['source']['path']!=slot or value['source']['sha256']!=sha
                or record['source'].get('pak_version')!=11):
            raise ValueError('Direct record source/version differs')
        self.owner.bind_aliases(aliases)
        if any(self.rules.get(str(Path(p['path']).resolve()))!=p['sha256'] for p in value['decoder'].values()):
            raise ValueError('Direct decoder identity differs from prepared scope')
        entries=d['directory_entries'];lookup={e['canonical_path']:e for e in entries}
        if len(lookup)!=len(entries):raise ValueError('Direct directory paths are ambiguous')
        offsets=sorted({e['offset'] for e in entries})
        if any(type(p) is not int or not 0<=p<record['index_offset'] for p in offsets):
            raise ValueError('Direct directory offset outside data area')
        result=dict(pointer=pointer,source=value['source'],directory=lookup,offsets=offsets,index=record,
            record_offsets={e['offset'] for e in record['entries']},decoder=value['decoder'],record_pointer=inputs['record_index'])
        self.sources[slot]=result;return result

    def resolve(self,row,pointer,entry):
        self.owner.check(self.index,self.args);source=self.source(row,pointer)
        if source['directory'].get(entry.get('canonical_path'))!=entry:
            raise ValueError('Direct entry differs from exact directory')
        if entry['offset'] in source['record_offsets']:raise ValueError('Direct proof cannot replace an indexed record')
        key=(source['source']['path'],source['source']['sha256'],entry['offset'])
        signature={k:entry[k] for k in ('offset','bytes','uncompressed','method','blocks','encrypted')}
        if key in self.memo:
            if self.memo_entries[key]!=signature:raise ValueError('Direct memo directory metadata differs')
            self.metrics['memo_hits']+=1;return copy.deepcopy(self.memo[key])
        if entry['encrypted'] or entry['method'] not in (0,1):reason='direct_record_layout_unsupported'
        elif max(entry['bytes'],entry['uncompressed'])>LIMIT:reason='direct_record_size_budget'
        elif self.metrics['unique_records']>=64:reason='direct_record_count_budget'
        elif self.metrics['decoded_bytes']+entry['uncompressed']>16*LIMIT or self.metrics['stored_bytes']+entry['bytes']>16*LIMIT:
            reason='direct_record_total_budget'
        else:reason=None
        if reason:
            self.metrics['blocked_records']+=1;return dict(state='blocked',reason=reason)
        self.metrics['unique_records']+=1
        limit=next((p for p in source['offsets'] if p>entry['offset']),source['index']['index_offset'])
        inputs=dict(recipe=RECIPE,source=source['source'],directory=pointer,entry=entry,record_index=source['record_pointer'],
            boundary=limit,decoder=source['decoder'],rules=self.rules,runtime=self.runtime,budgets=self.rule)
        cache=self.root/'knowledge/resource-comparison-cache-v3'/('directory-record-'+hashlib.sha256(self.workflow.canonical(inputs)).hexdigest()+'.json')
        cached=self.owner.cached(cache)
        if cached is not None:
            body=self.read(cached)
            if body.get('inputs')!=inputs or not isinstance(body.get('decoded_sha256'),str) or not SHA.fullmatch(body['decoded_sha256']):
                raise ValueError('Direct record cache differs')
            self.metrics['cache_hits']+=1;result=cached
        else:
            with Path(source['source']['path']).open('rb') as stream:
                header=parse_header(stream,entry,limit)
                stream.seek(entry['offset']+header['hs']);stored=stream.read(header['size'])
                if len(stored)!=header['size'] or hashlib.sha1(stored).hexdigest()!=header['stored_sha1']:
                    raise ValueError('Direct record stored SHA1 differs')
                record_sha=self.indexer.record_digest(stream,entry['offset'],header['end'])
                if not header['usize']:
                    data=b'';self.metrics['empty_records']+=1
                elif not header['method']:
                    data=stored;self.metrics['plain_reads']+=1
                else:
                    if self.reader is None:
                        decoder=source['decoder'];self.reader=self.csv._load_reader(Path(decoder['reader']['path']),decoder['reader']['sha256'])
                    bounded=self.selected.ExactRecordStream(stream,entry['offset'],header['end'])
                    data=self.reader.decode(bounded,header);self.metrics['compressed_decodes']+=1
            if not isinstance(data,bytes) or len(data)!=header['usize']:raise ValueError('Direct decoded size differs')
            body=dict(schema=1,recipe=RECIPE,inputs=inputs,header=header,stored_record_sha256=record_sha,
                decoded_sha256=hashlib.sha256(data).hexdigest(),payload_saved=False,runtime_activated=False)
            del data,stored
            p=self.workflow.snapshot(self.root,'resource-directory-record-v1',body)
            result=dict(path=str(p),sha256=self.owner.digest(p));self.owner.defer(cache,result)
            self.metrics['decoded_bytes']+=header['usize'];self.metrics['stored_bytes']+=header['size']
        outcome=dict(state='hashed',sha256=body['decoded_sha256'],proof=result,method=RECIPE)
        self.memo_entries[key]=signature;self.memo[key]=outcome;return copy.deepcopy(outcome)


def scope(index,args):
    value=getattr(args,'resource_directory_record_v1_scope',None)
    if value is None or value.owner is not getattr(args,'resource_owner',None):
        value=Scope(index,args);args.resource_directory_record_v1_scope=value
    return value
