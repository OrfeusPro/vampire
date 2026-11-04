"""Named CSV references, stable patch comparisons and deferred future baselines."""
import copy
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
RECIPE = 'named-table-baselines-v1'
SHA = re.compile('[0-9a-f]{64}')
LIMIT = 32*1024*1024


def exact_pointer(value):
    return (isinstance(value,dict) and set(value)=={'path','sha256'}
        and isinstance(value['path'],str) and Path(value['path']).is_absolute()
        and isinstance(value['sha256'],str) and SHA.fullmatch(value['sha256']) is not None)


def configuration(index,args):
    path=Path(args.knowledge)/'resource-named-tables-engine.json'
    if not path.is_file():return None
    with path.open('rb') as stream:raw=stream.read(16385)
    if len(raw)>16384:raise ValueError('Named table selector exceeds budget')
    value=json.loads(raw)
    if (not isinstance(value,dict) or set(value)-{'schema','recipe','legacy_references','legacy_bridge','capture_bridge'}
            or not {'schema','recipe','legacy_references','legacy_bridge'}<=set(value)
            or type(value['schema']) is not int or value['schema']!=1 or value['recipe']!=RECIPE
            or not isinstance(value['legacy_references'],list) or len(value['legacy_references'])>32
            or not isinstance(value['legacy_bridge'],dict)
            or any(not isinstance(k,str) or not isinstance(v,str) or not SHA.fullmatch(k)
                or not SHA.fullmatch(v) for k,v in value['legacy_bridge'].items())):
        raise ValueError('Unknown named table selector')
    bridge=value.get('capture_bridge',{})
    if (not isinstance(bridge,dict) or len(bridge)>32 or any(not isinstance(k,str)
            or not isinstance(v,str) or not SHA.fullmatch(k) or not SHA.fullmatch(v) for k,v in bridge.items())):
        raise ValueError('Unknown named capture bridge')
    for item in value['legacy_references']:
        if (not isinstance(item,dict) or set(item)!={'reference','rank'}
                or type(item['rank']) is not int or item['rank']<0 or not exact_pointer(item['reference'])):
            raise ValueError('Named reference needs an explicit order')
    pointers=[json.dumps(item['reference'],sort_keys=True) for item in value['legacy_references']]
    if len(pointers)!=len(set(pointers)):raise ValueError('Named reference registration is duplicated')
    return value


def enabled(index,args):
    return configuration(index,args) is not None


class Scope:
    def __init__(self,index,args):
        self.index,self.args=index,args
        self.owner=getattr(args,'resource_owner',None)
        if self.owner is None:raise ValueError('Named tables require a resource SHA owner')
        self.owner.check(index,args)
        self.root=Path(args.root).resolve()
        self.workflow=index.extension('research-workflow')
        self.reference=index.extension('resource-named-reference-v1')
        self.parser=index.extension('extract-release-tables')
        self.csv=index.extension('resource-csv-v3')
        self.rule=configuration(index,args)
        if self.rule is None:raise ValueError('Named table selector is missing')
        selector=Path(args.knowledge)/'resource-named-tables-engine.json'
        with selector.open('rb') as stream:raw=stream.read(16385)
        if len(raw)>16384 or json.loads(raw)!=self.rule:raise ValueError('Named table selector changed')
        self.rules={str(selector.resolve()):self.owner.remember(selector,raw)}
        for name in ('resource-named-tables-v1.py','resource-named-reference-v1.py',
                'extract-release-tables.py','resource-directory-v1.py',
                'resource-csv-v3.py','resource-directory-format-v1.py','resource-directory-paths-v2.py'):
            path=HERE/name;self.rules[str(path)]=self.owner.digest(path)
        self.capture_rules={p:sha for p,sha in self.rules.items() if p!=str(selector.resolve())}
        self.runtime=index.extension('resource-directory-v1')._runtime(index)
        self.owner.final_checks.append(self.validate_runtime)
        self.memo,self.inventories={},{}
        self.metrics=dict(archives=0,cache_hits=0,comparisons=0,captures=0)

    def validate_runtime(self):
        if self.index.extension('resource-directory-v1')._runtime(self.index)!=self.runtime:
            raise ValueError('Named table runtime changed')

    def read(self,pointer):
        if not exact_pointer(pointer):
            raise ValueError('Named tables require an exact pointer')
        path=Path(pointer['path']).resolve()
        if not path.is_relative_to(self.root) or path.name!='manifest.json' or path.parent.name!=pointer['sha256']:
            raise ValueError('Named table report outside immutable library')
        with path.open('rb') as stream:raw=stream.read(LIMIT+1)
        if len(raw)>LIMIT or self.owner.remember(pointer['path'],raw)!=pointer['sha256']:
            raise ValueError('Named table report changed or exceeds budget')
        return json.loads(raw.decode('utf-8-sig'))

    def snapshot(self,category,value):
        raw=self.workflow.canonical(value)
        if len(raw)>LIMIT:raise ValueError('Named table result exceeds budget')
        path=self.workflow.snapshot(self.root,category,value)
        return dict(path=str(path),sha256=self.owner.remember(path,raw))

    def payload(self,table):
        path=Path(table['file']).resolve()
        if not path.is_relative_to(self.root):raise ValueError('Named CSV outside library')
        with path.open('rb') as stream:raw=stream.read(self.csv.LIMIT+1)
        if (len(raw)>self.csv.LIMIT or len(raw)!=table['bytes']
                or self.owner.remember(table['file'],raw)!=table['sha256']):
            raise ValueError('Named CSV bytes differ')
        parsed=self.csv._parse(self.parser,raw)
        if parsed is None or parsed!=(table['header'],table['rows']):
            raise ValueError('Named CSV metadata differs')
        return raw

    def current(self,row,pointer):
        directory=getattr(self.args,'resource_directory_v1_scope',None)
        if directory is None or directory.owner is not self.owner:
            raise ValueError('Current named tables require the verified directory scope')
        value=self.read(pointer)
        source=value.get('inputs',{}).get('source',{})
        slot=str(Path(row['path']).resolve())
        if (value.get('recipe')!='resource-directory-v1' or value.get('authoritative_directory_for_archive') is not True
                or source.get('path')!=slot or source.get('sha256')!=(row.get('current') or {}).get('sha256')
                or value['inputs'].get('rules')!=directory.rules or value['inputs'].get('runtime')!=directory.runtime):
            raise ValueError('Current named tables differ from verified directory inputs')
        self.owner.expect(slot,source['sha256'])
        tables=[];seen=set()
        for table in value['csv_bindings']:
            path=table.get('canonical_path')
            if not isinstance(path,str) or path in seen or table.get('directory_identity_verified') is not True:
                raise ValueError('Current named table identities are ambiguous')
            seen.add(path)
            selected={key:table[key] for key in ('canonical_path','sha256','file','bytes','header','rows')}
            selected['state']='verified_payload';self.payload(selected);tables.append(selected)
        expected={e['canonical_path'] for e in value['directory_entries']
            if e.get('canonical_path') and e['canonical_path'].lower().endswith('.csv')}
        complete=not value['unmatched_csv'] and not value['path_gaps']
        for entry in value['directory_entries']:
            path=entry.get('canonical_path')
            if path and path in expected and path not in seen:
                tables.append(dict(canonical_path=path,sha256=entry.get('decoded_sha256'),file=None,
                    bytes=entry['uncompressed'],state='record_hash_only' if entry.get('decoded_sha256') else 'payload_hash_unknown'))
        return dict(source=dict(archive_key=slot,sha256=source['sha256']),tables=sorted(tables,key=lambda t:t['canonical_path']),
            complete_names=complete,named_report=pointer,directory_records=self.directory_records(value))

    def directory_records(self,named):
        return {e['canonical_path']:dict(canonical_path=e['canonical_path'],sha256=e.get('decoded_sha256'),
            bytes=e['uncompressed'],file=None) for e in named['directory_entries'] if e.get('canonical_path')}

    def reference_body(self,descriptor):
        key=json.dumps(descriptor,sort_keys=True)
        if key in self.memo:return copy.deepcopy(self.memo[key])
        if (not isinstance(descriptor,dict) or set(descriptor)!={'kind','reference','rank'}
                or type(descriptor['rank']) is not int or descriptor['rank']<0):
            raise ValueError('Invalid named reference descriptor')
        if descriptor['kind']=='legacy':
            value=self.reference.load_reference(self.index,self.args,self.owner,descriptor['reference'],self.rule['legacy_bridge'])
        elif descriptor['kind']=='capture':
            value=self.read(descriptor['reference'])
            producer=value.get('producer')
            own=str(HERE/'resource-named-tables-v1.py')
            if (not isinstance(producer,dict) or any(not isinstance(p,str) or not isinstance(sha,str)
                    or not SHA.fullmatch(sha) for p,sha in producer.items())):
                raise ValueError('Invalid named baseline producer metadata')
            bridged=False
            if isinstance(producer,dict) and producer!=self.capture_rules and set(producer)==set(self.capture_rules):
                bridged=(all(producer[p]==sha for p,sha in self.capture_rules.items() if p!=own)
                    and self.rule.get('capture_bridge',{}).get(producer.get(own))==self.capture_rules[own])
            if (value.get('recipe')!=RECIPE or type(value.get('schema')) is not int or value['schema']!=1
                    or (producer!=self.capture_rules and not bridged) or type(value.get('rank')) is not int
                    or value['rank']!=descriptor['rank']):
                raise ValueError('Named baseline producer/order changed')
            marker=value.get('name_inventory_rule')
            if (marker not in (None,'directory-csv-inventory-v1') or (marker is None and not bridged)):
                raise ValueError('Unknown captured name inventory rule')
            named=self.read(value['named_report'])
            if (named['inputs']['source']['sha256']!=value['source']['sha256']
                    or named['inputs']['source']['path']!=value['source']['archive_key']):
                raise ValueError('Named baseline source proof differs')
            lookup={t['canonical_path']:t for t in named['csv_bindings']}
            entries={e['canonical_path']:e for e in named['directory_entries'] if e.get('canonical_path')}
            seen=set()
            for table in value['tables']:
                path=table.get('canonical_path')
                if path in seen or path not in entries:raise ValueError('Captured named table inventory differs')
                seen.add(path)
                original=lookup.get(table['canonical_path'])
                if table.get('file'):
                    if original is None or any(table[k]!=original[k] for k in ('sha256','bytes','file','header','rows')):
                        raise ValueError('Captured named table differs from directory proof')
                    self.payload(table)
                elif table.get('sha256') is not None:
                    entry=entries[table['canonical_path']]
                    if entry is None or entry.get('decoded_sha256')!=table['sha256'] or entry['uncompressed']!=table.get('bytes'):
                        raise ValueError('Captured named table hash lacks its source record')
                elif entries[path]['uncompressed']!=table.get('bytes'):
                    raise ValueError('Captured unknown named table size differs')
            required={p for p in entries if p.lower().endswith('.csv')}|set(lookup)
            complete=not named['unmatched_csv'] and not named['path_gaps']
            recorded_complete=complete if marker is not None else complete and required<=set(lookup)
            if seen!=required or value.get('complete_names') is not recorded_complete:
                raise ValueError('Captured named table completeness differs')
            if bridged:
                value=copy.deepcopy(value)
                value['recorded_complete_names']=value['complete_names']
                value['complete_names']=complete
                value['captured_producer_revalidated']=True
            value['directory_records']=self.directory_records(named)
        else:raise ValueError('Unknown named reference origin')
        self.memo[key]=copy.deepcopy(value)
        return value

    def candidates(self,slot):
        slot_sha=hashlib.sha256(slot.encode()).hexdigest()
        folder=self.root/'knowledge/resource-comparison-cache-v3'/('named-'+slot_sha)
        paths=sorted(folder.glob('*.json'))
        if len(paths)>1024:raise ValueError('Named baseline inventory exceeds budget')
        if folder in self.inventories and paths!=self.inventories[folder]:
            raise ValueError('Named baseline inventory changed')
        if folder not in self.inventories:
            self.inventories[folder]=paths
            def unchanged(folder=folder,paths=paths):
                if sorted(folder.glob('*.json'))!=paths:raise ValueError('Named baseline inventory changed before publication')
            self.owner.final_checks.append(unchanged)
        candidates=[]
        for path in paths:
            pointer=self.owner.cached(path)
            if pointer is None:raise ValueError('Named baseline disappeared')
            value=self.read(pointer)
            descriptor=dict(kind='capture',reference=pointer,rank=value.get('rank'))
            if type(descriptor['rank']) is not int or descriptor['rank']<1:
                raise ValueError('Named baseline rank is invalid')
            value=self.reference_body(descriptor)
            if value['source']['archive_key']!=slot:raise ValueError('Named baseline archive slot differs')
            candidates.append((descriptor,value))
        for item in self.rule['legacy_references']:
            descriptor=dict(kind='legacy',reference=item['reference'],rank=item['rank'])
            value=self.reference_body(descriptor)
            if str(Path(value['source']['archive_key']).resolve())==slot:candidates.append((descriptor,value))
        return folder,candidates

    def compare(self,before,current):
        old={t['canonical_path']:t for t in before['tables']} if before else {}
        new={t['canonical_path']:t for t in current['tables']}
        if len(old)!=(len(before['tables']) if before else 0) or len(new)!=len(current['tables']):
            raise ValueError('Named comparison paths are ambiguous')
        rows=[]
        for path in sorted(old.keys()|new.keys()):
            a=old.get(path,(before or {}).get('directory_records',{}).get(path))
            b=new.get(path,current.get('directory_records',{}).get(path))
            if a is None:state='added' if (before and before['complete_names']
                and (path.lower().endswith('.csv') or 'directory_records' in before)) else 'unknown'
            elif b is None:state='removed' if current['complete_names'] else 'unknown'
            elif a.get('sha256') is None or b.get('sha256') is None:state='unknown'
            else:state='unchanged' if a['sha256']==b['sha256'] else 'changed'
            item=dict(canonical_path=path,state=state,before_sha256=a.get('sha256') if a else None,
                current_sha256=b.get('sha256') if b else None)
            if state=='changed' and a.get('file') and b.get('file'):
                raw_before,raw_after=self.payload(a),self.payload(b)
                with self.csv._CSV_LOCK:
                    previous=self.csv.csv.field_size_limit()
                    try:
                        self.csv.csv.field_size_limit(self.csv.FIELD_LIMIT)
                        item['row_diff']=self.parser.compare_unique_rows(raw_before,raw_after)
                    finally:self.csv.csv.field_size_limit(previous)
            rows.append(item)
        return rows

    def process(self,row,named):
        self.owner.check(self.index,self.args);self.metrics['archives']+=1
        current=self.current(row,named['report']);slot=current['source']['archive_key']
        folder,candidates=self.candidates(slot)
        ranks=[d['rank'] for d,v in candidates]
        newest=[(d,v) for d,v in candidates if d['rank']==max(ranks)] if ranks else []
        if len(newest)>1:raise ValueError('Newest named baseline is ambiguous')
        if newest and newest[0][1]['source']['sha256']==current['source']['sha256']:
            descriptor,captured=newest[0]
            if descriptor['kind']!='capture':raise ValueError('Current source unexpectedly aliases a legacy reference')
            selected=captured.get('previous')
            prior=self.reference_body(selected) if selected else None
            capture=descriptor['reference']
        else:
            selected,prior=newest[0] if newest else (None,None)
            rank=max(ranks,default=0)+1
            capsule=dict(schema=1,recipe=RECIPE,rank=rank,previous=selected,producer=self.capture_rules,
                name_inventory_rule='directory-csv-inventory-v1',
                **{k:v for k,v in current.items() if k!='directory_records'})
            capture=self.snapshot('resource-named-baselines-v1',capsule)
            self.owner.defer(folder/(capture['sha256']+'.json'),capture)
            self.metrics['captures']+=1
        inputs=dict(recipe=RECIPE,current_named=current['named_report'],baseline=selected,rules=self.rules,runtime=self.runtime)
        cache=self.root/'knowledge/resource-comparison-cache-v3'/('named-compare-'+hashlib.sha256(self.workflow.canonical(inputs)).hexdigest()+'.json')
        cached=self.owner.cached(cache)
        if cached is not None:
            result=self.read(cached)
            if result.get('inputs')!=inputs:raise ValueError('Named comparison cache changed')
            pointer=cached;self.metrics['cache_hits']+=1
        else:
            rows=self.compare(prior,current)
            counts={state:sum(r['state']==state for r in rows) for state in ('unchanged','changed','added','removed','unknown')}
            result=dict(schema=1,recipe=RECIPE,inputs=inputs,rows=rows,counts=counts,
                state='compared' if prior else 'baseline_missing',compatibility='not_established',runtime_activated=False)
            pointer=self.snapshot('resource-named-comparisons-v1',result)
            self.owner.defer(cache,pointer);self.metrics['comparisons']+=1
        return dict(report=pointer,baseline=selected,capture=capture,state=result['state'],counts=result['counts'],
            compatibility='not_established')


def process(index,args,row,named):
    scope=getattr(args,'resource_named_tables_v1_scope',None)
    if scope is None or scope.owner is not getattr(args,'resource_owner',None):
        scope=Scope(index,args);args.resource_named_tables_v1_scope=scope
    return scope.process(row,named)
