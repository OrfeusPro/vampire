"""Bounded hashes for selected unknown PAK records; never widen index discovery."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
RECIPE='selected-record-hashes-v1'
LIMIT=32*1024*1024
SHA=re.compile('[0-9a-f]{64}')
RULE=dict(schema=1,recipe=RECIPE,record_bytes=LIMIT,total_decoded_bytes=1024*1024*1024,
    total_stored_bytes=512*1024*1024,max_records=4096)


class ExactRecordStream:
    def __init__(self,stream,start,end):
        self.stream,self.start,self.end=stream,start,end

    def seek(self,offset,whence=0):
        if whence!=0 or type(offset) is not int or not self.start<=offset<=self.end:
            raise ValueError('Selected record seek outside verified bounds')
        return self.stream.seek(offset)

    def read(self,size):
        if type(size) is not int or not 0<=size<=LIMIT or self.stream.tell()+size>self.end:
            raise ValueError('Selected record read outside verified bounds')
        raw=self.stream.read(size)
        if len(raw)!=size:raise ValueError('Selected record read truncated')
        return raw


def configuration(args):
    path=Path(args.knowledge)/'resource-selected-hashes.json'
    if not path.is_file():return None
    with path.open('rb') as stream:raw=stream.read(4097)
    value=json.loads(raw)
    if len(raw)>4096 or value!=RULE or any(type(value.get(k)) is not int for k in RULE if k not in ('recipe',)):
        raise ValueError('Unknown selected record hash rule')
    return value


def checked_header(reader,stream,entry,limit):
    try:header=reader.header(stream,entry['offset'],limit)
    except (struct.error,IndexError):raise ValueError('Selected record header truncated') from None
    fields={'pos':'offset','end':'end','size':'bytes','usize':'uncompressed','method':'method','encrypted':'encrypted'}
    if not header or any(header.get(k)!=entry[v] for k,v in fields.items()):
        raise ValueError('Selected record header differs from exact index')
    if (type(header.get('hs')) is not int or header['hs']<53 or header['pos']+header['hs']>header['end']):
        raise ValueError('Selected record header bounds differ')
    if header['method']==0:
        if (header['size']!=header['usize'] or header['blocks']!=[]
                or header['end']!=header['pos']+header['hs']+header['size']):
            raise ValueError('Selected plain record layout differs')
    else:
        blocks=header.get('blocks');blocksize=header.get('blocksize')
        if (type(blocksize) is not int or not 0<blocksize<=LIMIT or not isinstance(blocks,list)
                or len(blocks)!=(header['usize']+blocksize-1)//blocksize or not 1<=len(blocks)<=32768):
            raise ValueError('Selected compressed block count differs')
        previous=header['hs'];stored=0
        for block in blocks:
            if (not isinstance(block,(list,tuple)) or len(block)!=2 or any(type(v) is not int for v in block)
                    or block[0]!=previous or not block[0]<block[1]<=header['end']-header['pos']):
                raise ValueError('Selected compressed blocks overlap or escape')
            stored+=block[1]-block[0];previous=block[1]
        if stored!=header['size'] or previous!=header['end']-header['pos']:
            raise ValueError('Selected compressed size differs')
    return header


class Scope:
    def __init__(self,index,args):
        self.index,self.args=index,args;self.owner=getattr(args,'resource_owner',None)
        if self.owner is None:raise ValueError('Selected record hashes need a shared SHA owner')
        self.owner.check(index,args);self.rule=configuration(args)
        if self.rule is None:raise ValueError('Selected record hash selector missing')
        self.root=Path(args.root).resolve();self.workflow=index.extension('research-workflow')
        self.csv=index.extension('resource-csv-v3');self.indexer=index.extension('index-release-archives')
        selector=Path(args.knowledge)/'resource-selected-hashes.json'
        with selector.open('rb') as stream:raw=stream.read(4097)
        if len(raw)>4096 or json.loads(raw)!=self.rule:raise ValueError('Selected record rule changed')
        self.rules={str(selector.resolve()):self.owner.remember(selector,raw)}
        for p in (HERE/'resource-selected-hashes-v1.py',HERE/'resource-csv-v3.py',HERE/'index-release-archives.py'):
            self.rules[str(p)]=self.owner.digest(p)
        for p in (HERE.parent/'rfnext/scan-pak.py',Path(os.environ.get('PHONEEXIT_RF_RESOURCES',
                'F:/PhoneExit Resources/RF Online Next'))/'tools/oodle-data-shared.dll'):
            self.rules[str(p.resolve())]=self.owner.digest(p)
        self.runtime=self.csv._runtime(index,args)
        self.owner.final_checks.append(self.validate_runtime)
        self.reader=None;self.sources={};self.memo={}
        self.metrics=dict(unique_records=0,cache_hits=0,decodes=0,decoded_bytes=0,stored_bytes=0,
            memo_hits=0,blocked_records=0)

    def validate_runtime(self):
        # The owner is already validating: use fresh raw hashes, not its open-phase memo.
        if self.csv._runtime(self.owner.origin,SimpleNamespace())!=self.runtime:
            raise ValueError('Selected hash runtime changed')

    def source(self,row,directory):
        slot=str(Path(row['path']).resolve());pointer=directory['inputs']['record_index']
        if slot in self.sources:
            if (self.sources[slot]['pointer']!=pointer or self.sources[slot]['value']['source']['sha256']
                    !=(row.get('current') or {}).get('sha256')):
                raise ValueError('Selected record index/source changed')
            return self.sources[slot]
        value,record,aliases=self.csv._prepare(self.index,self.args,pointer)
        if value['source']['path']!=slot or value['source']['sha256']!=(row.get('current') or {}).get('sha256'):
            raise ValueError('Selected record source differs from directory')
        self.owner.bind_aliases(aliases)
        entries={e['offset']:e for e in record['entries']}
        if len(entries)!=len(record['entries']):raise ValueError('Selected record offsets are ambiguous')
        result=dict(pointer=pointer,record=record,value=value,entries=entries)
        self.sources[slot]=result
        return result

    def resolve(self,row,directory,entry):
        self.owner.check(self.index,self.args)
        # Only caller-selected records that lack a decoded SHA may reach this path.
        if entry.get('decoded_sha256') is not None:raise ValueError('Selected hash already known')
        source=self.source(row,directory);slot=source['value']['source']['path']
        record=source['entries'].get(entry['offset'])
        if record is not None and any(record.get(k)!=entry.get(k) for k in ('bytes','uncompressed','method','encrypted')):
            raise ValueError('Selected directory and record metadata differ')
        key=(slot,source['value']['source']['sha256'],entry['offset'])
        if key in self.memo:
            self.metrics['memo_hits']+=1;return copy.deepcopy(self.memo[key])
        if self.metrics['unique_records']>=self.rule['max_records']:
            return dict(state='blocked',reason='selected_record_count_budget')
        self.metrics['unique_records']+=1
        if record is None:reason='selected_record_missing_from_index'
        elif record['encrypted']:reason='selected_record_encrypted'
        elif record['bytes']>LIMIT or record['uncompressed']>LIMIT:reason='selected_record_size_budget'
        else:reason=None
        if reason is not None:
            result=dict(state='blocked',reason=reason);self.metrics['blocked_records']+=1
        else:result=self.hash_record(source,record)
        self.memo[key]=result
        return copy.deepcopy(result)

    def hash_record(self,source,record):
        value=source['value'];decoder=value['decoder'];slot=value['source']['path']
        stored=record.get('stored_record_sha256')
        if not isinstance(stored,str) or not SHA.fullmatch(stored):
            raise ValueError('Selected record needs its stored SHA')
        inputs=dict(recipe=RECIPE,source=value['source'],record_index=source['pointer'],
            record={k:record[k] for k in ('entry','offset','end','bytes','uncompressed','method','encrypted','stored_record_sha256')},
            decoder=decoder,rules=self.rules,runtime=self.runtime,budgets=self.rule)
        cache=self.root/'knowledge/resource-comparison-cache-v3'/('selected-hash-'+hashlib.sha256(self.workflow.canonical(inputs)).hexdigest()+'.json')
        pointer=self.owner.cached(cache)
        if pointer is not None:
            _,body=self.csv._checked_pointer(self.index,self.args,pointer,category='resource-selected-hashes-v1')
            if body.get('inputs')!=inputs or not isinstance(body.get('decoded_sha256'),str) or not SHA.fullmatch(body['decoded_sha256']):
                raise ValueError('Selected hash cache differs')
            self.metrics['cache_hits']+=1
        else:
            if (self.metrics['decoded_bytes']+record['uncompressed']>self.rule['total_decoded_bytes']
                    or self.metrics['stored_bytes']+record['bytes']>self.rule['total_stored_bytes']):
                self.metrics['blocked_records']+=1
                return dict(state='blocked',reason='selected_record_total_budget')
            if self.reader is None:
                self.reader=self.csv._load_reader(Path(decoder['reader']['path']),decoder['reader']['sha256'])
            with Path(slot).open('rb') as stream:
                stream=ExactRecordStream(stream,record['offset'],record['end'])
                header=checked_header(self.reader,stream,record,source['record']['index_offset'])
                if self.indexer.record_digest(stream,record['offset'],record['end'])!=stored:
                    raise ValueError('Selected stored record SHA differs')
                data=self.reader.decode(stream,header)
            if not isinstance(data,bytes) or len(data)!=record['uncompressed']:
                raise ValueError('Selected decoded record size differs')
            decoded=hashlib.sha256(data).hexdigest();del data
            body=dict(schema=1,recipe=RECIPE,inputs=inputs,decoded_sha256=decoded,
                payload_saved=False,compatibility='not_established',runtime_activated=False)
            path=self.workflow.snapshot(self.root,'resource-selected-hashes-v1',body)
            pointer=dict(path=str(path),sha256=self.owner.digest(path));self.owner.defer(cache,pointer)
            self.metrics['decodes']+=1;self.metrics['decoded_bytes']+=record['uncompressed'];self.metrics['stored_bytes']+=record['bytes']
        return dict(state='hashed',sha256=body['decoded_sha256'],proof=pointer)


def scope(index,args):
    value=getattr(args,'resource_selected_hashes_v1_scope',None)
    if value is None or value.owner is not getattr(args,'resource_owner',None):
        value=Scope(index,args);args.resource_selected_hashes_v1_scope=value
    return value
