"""Current named table data for the reviewed Map10/11 projection; no native port."""
import copy
import csv
import fnmatch
import hashlib
import io
import json
import math
from pathlib import Path
import re
import threading
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
RECIPE='map-table-data-v1'
LIMIT=16*1024*1024
SHA=re.compile('[0-9a-f]{64}')
TABLES=dict(Map='ProjectRED/Content/RED/Data/CSV/Map.csv',World='ProjectRED/Content/RED/Data/CSV/World.csv')
CSV_LOCK=csv.__dict__.setdefault('_phone_exit_resource_csv_lock_v3',threading.RLock())


def configuration(args):
    p=Path(args.knowledge)/'resource-map-tables.json'
    if not p.is_file():return None
    with p.open('rb') as stream:raw=stream.read(8193)
    d=json.loads(raw)
    if (len(raw)>8192 or not isinstance(d,dict) or set(d)!={'schema','recipe','archive','baseline','tables'}
            or type(d['schema']) is not int or d['schema']!=1 or d['recipe']!=RECIPE
            or d['archive']!='*/Patch/Install/pakchunk1-Windows.pak' or d['tables']!=TABLES):
        raise ValueError('Unknown map table data rule')
    return d


def table_rows(raw):
    if not isinstance(raw,bytes) or len(raw)>LIMIT or not raw.startswith(b'\xef\xbb\xbf'):
        raise ValueError('Map data requires bounded UTF-8 BOM CSV')
    # The process-local CSV lock is shared with the existing extractor.
    with CSV_LOCK:
        previous=csv.field_size_limit()
        try:
            csv.field_size_limit(1024*1024)
            reader=csv.reader(io.StringIO(raw.decode('utf-8-sig'),newline=''))
            header=next(reader,None)
            if not header or len(header)!=len(set(header)) or 'Id' not in header:
                raise ValueError('Map table header is ambiguous')
            rows={}
            for values in reader:
                if len(rows)>=100000 or len(values)!=len(header):raise ValueError('Map table row shape/budget differs')
                row=dict(zip(header,values));key=row['Id']
                if not key or not key.isascii() or not key.isdecimal() or key in rows:
                    raise ValueError('Map table IDs are not unique unsigned text')
                rows[key]=row
            return header,rows
        finally:csv.field_size_limit(previous)


class Scope:
    def __init__(self,index,args,report):
        self.index,self.args=index,args;self.owner=getattr(args,'resource_owner',None)
        if self.owner is None:raise ValueError('Map table data needs the shared SHA owner')
        self.owner.check(index,args);self.root=Path(args.root).resolve()
        self.workflow=index.extension('research-workflow');self.csv=index.extension('resource-csv-v3')
        self.rule=configuration(args)
        if self.rule is None:raise ValueError('Map table rule missing')
        self.source_sha256=report.get('exe',{}).get('sha256')
        if not isinstance(self.source_sha256,str) or not SHA.fullmatch(self.source_sha256):
            raise ValueError('Map table data needs an exact client identity')
        self.owner.expect(report['exe']['path'],self.source_sha256)
        selector=Path(args.knowledge)/'resource-map-tables.json'
        with selector.open('rb') as stream:raw=stream.read(8193)
        if len(raw)>8192 or json.loads(raw)!=self.rule:raise ValueError('Map table selector changed')
        self.rules={str(selector.resolve()):self.owner.remember(selector,raw)}
        for p in (HERE/'resource-map-tables-v1.py',HERE/'resource-csv-v3.py'):
            self.rules[str(p)]=self.owner.digest(p)
        self.baseline=self.load_baseline()
        self.runtime=self.csv._runtime(index,args);self.owner.final_checks.append(self.validate_runtime)
        self.observed={};self.prepared=None;self.published=False
        self.metrics=dict(analyses=0,cache_hits=0,current_tables=0,current_rows=0)

    def validate_runtime(self):
        if self.csv._runtime(self.owner.origin,SimpleNamespace())!=self.runtime:raise ValueError('Map table runtime changed')

    def document(self,pointer):
        _,value=self.csv._checked_pointer(self.index,self.args,pointer);return value

    def bytes(self,pointer):
        if (not isinstance(pointer,dict) or set(pointer)!={'path','sha256'} or not isinstance(pointer['path'],str)
                or not Path(pointer['path']).is_absolute() or not isinstance(pointer['sha256'],str)
                or not SHA.fullmatch(pointer['sha256'])):raise ValueError('Map table input needs an exact pointer')
        path=Path(pointer['path']).resolve()
        if not path.is_relative_to(self.root):raise ValueError('Map table input outside library')
        with path.open('rb') as stream:raw=stream.read(LIMIT+1)
        if len(raw)>LIMIT or self.owner.remember(pointer['path'],raw)!=pointer['sha256']:
            raise ValueError('Map table input bytes changed')
        return raw

    def load_baseline(self):
        b=self.document(self.rule['baseline'])
        if (b.get('recipe')!='reviewed-map-table-baseline-v1' or type(b.get('schema')) is not int
                or b['schema']!=1 or b.get('map_ids')!=['10','11']):raise ValueError('Unknown reviewed map baseline')
        parent=self.document(b['parent']);tables=self.document(b['historical_table_manifest'])
        if (parent.get('source_sha256')!=b['source_sha256'] or parent.get('table_manifest')!=b['historical_table_manifest']
                or parent.get('atlas_projection_sha256')!=b['artifacts']['projection']['sha256']):
            raise ValueError('Reviewed map baseline ancestry differs')
        projection=json.loads(self.bytes(b['artifacts']['projection']))
        maps=[{k:v for k,v in row.items() if k!='provenance'} for row in projection['map_records']]
        geometry={k:projection[k] for k in ('size','center','ground_distance')}
        if maps!=b['maps'] or geometry!=b['geometry'] or projection['map_ids']!=b['map_ids']:
            raise ValueError('Reviewed map baseline projection differs')
        historical={}
        for name in ('Map','World'):
            pointer=b['artifacts'][name]
            if (parent['tables'][name]['sha256']!=pointer['sha256']
                    or not any(t.get('sha256')==pointer['sha256'] for t in tables['tables'])):
                raise ValueError('Reviewed table SHA differs from its captured audit')
            historical[name]=table_rows(self.bytes(pointer))[1]
        if [historical['Map'].get(key) for key in b['map_ids']]!=maps:
            raise ValueError('Reviewed Map rows differ from historical payload')
        worlds={key:dict(MapId=row['MapId'],LevelPath=row['LevelPath']) for key,row in historical['World'].items()
            if row['MapId'] in b['map_ids']}
        if worlds!=b['worlds'] or {key:v['MapId'] for key,v in worlds.items()}!=parent['worlds']:
            raise ValueError('Reviewed World bindings differ from historical payload')
        size,center,ground=geometry['size'],geometry['center'],geometry['ground_distance']
        if (len(size)!=2 or len(center)!=2 or any(type(v) not in (int,float) or not math.isfinite(v)
                for v in (*size,*center,ground)) or min(*size,ground)<=0):
            raise ValueError('Reviewed map geometry is not finite and positive')
        if any(float(row['GroundDistance'])!=ground or [float(row['CenterX']),float(row['CenterY'])]!=center for row in maps):
            raise ValueError('Reviewed map parameters differ from geometry')
        return b

    def observe(self,row,outcome):
        self.owner.check(self.index,self.args)
        if self.prepared is not None:raise ValueError('Map table analysis already prepared')
        slot=str(Path(row['path']).resolve())
        if not fnmatch.fnmatchcase(slot.replace('\\','/'),self.rule['archive']):return
        selected=dict(row=copy.deepcopy(row),directory=(outcome.get('directory') or {}).get('report'))
        if slot in self.observed and self.observed[slot]!=selected:raise ValueError('Map table source observation differs')
        self.observed[slot]=selected

    def current(self):
        if not self.observed:return None,['map_table_archive_not_observed']
        if len(self.observed)!=1:return None,['map_table_archive_ambiguous']
        slot,value=next(iter(self.observed.items()));pointer=value['directory']
        if pointer is None:return None,['map_table_directory_missing']
        scope=getattr(self.args,'resource_directory_v1_scope',None)
        if scope is None or scope.owner is not self.owner:raise ValueError('Map data needs the same verified directory owner')
        d=self.document(pointer);source=d.get('inputs',{}).get('source',{})
        if (d.get('recipe')!='resource-directory-v1' or d.get('authoritative_directory_for_archive') is not True
                or d['inputs'].get('rules')!=scope.rules or d['inputs'].get('runtime')!=scope.runtime
                or source.get('path')!=slot or source.get('sha256')!=(value['row'].get('current') or {}).get('sha256')):
            raise ValueError('Map data current directory provenance differs')
        self.owner.expect(value['row']['path'],source['sha256'])
        if d.get('path_gaps')!=[] or d.get('unmatched_csv')!=[]:return None,['map_table_directory_incomplete']
        data={};pointers={}
        for name,path in self.rule['tables'].items():
            matches=[r for r in d['csv_bindings'] if r.get('canonical_path')==path]
            if len(matches)!=1:return None,['map_table_payload_missing_or_ambiguous:'+name]
            table=matches[0]
            if table.get('directory_identity_verified') is not True:raise ValueError('Map table filename is not verified')
            raw=self.bytes(dict(path=table['file'],sha256=table['sha256']));header,rows=table_rows(raw)
            if len(raw)!=table['bytes'] or header!=table['header'] or len(rows)!=table['rows']:
                raise ValueError('Map table CSV metadata differs')
            data[name]=dict(header=header,rows=rows);pointers[name]={k:table[k] for k in ('canonical_path','sha256','file','bytes','rows')}
        self.metrics['current_tables']=2;self.metrics['current_rows']=sum(len(v['rows']) for v in data.values())
        return dict(directory=pointer,source=source,tables=pointers,data=data),[]

    def compare(self,current,reasons):
        if current is None:return dict(state='requires_review',reasons=reasons,matched_maps=0,matched_worlds=0)
        maps=current['data']['Map'];world=current['data']['World'];b=self.baseline;reasons=[]
        if set(maps['header'])!=set(b['maps'][0]):reasons.append('map_table_columns_changed')
        if not {'Id','MapId','LevelPath'}<=set(world['header']):reasons.append('world_projection_columns_missing')
        changed_maps=[r['Id'] for r in b['maps'] if maps['rows'].get(r['Id'])!=r]
        if changed_maps:reasons.append('reviewed_map_rows_changed')
        current_worlds={key:dict(MapId=row.get('MapId'),LevelPath=row.get('LevelPath')) for key,row in world['rows'].items()
            if row.get('MapId') in b['map_ids']}
        if current_worlds!=b['worlds']:reasons.append('reviewed_world_membership_or_binding_changed')
        return dict(state='data_matched' if not reasons else 'requires_review',reasons=reasons,
            matched_maps=sum(maps['rows'].get(r['Id'])==r for r in b['maps']),
            matched_worlds=sum(current_worlds.get(k)==v for k,v in b['worlds'].items()),
            changed_map_ids=changed_maps,world_ids_added=sorted(set(current_worlds)-set(b['worlds'])),
            world_ids_missing=sorted(set(b['worlds'])-set(current_worlds)))

    def prepare(self):
        self.owner.check(self.index,self.args)
        if self.prepared is not None:raise ValueError('Map table analysis already prepared')
        current,reasons=self.current()
        inputs=dict(recipe=RECIPE,source_sha256=self.source_sha256,baseline=self.rule['baseline'],rules=self.rules,runtime=self.runtime,
            current={k:v for k,v in current.items() if k!='data'} if current else None,missing=reasons,
            observed={slot:dict(source=(v['row'].get('current') or {}).get('sha256'),directory=v['directory'])
                for slot,v in sorted(self.observed.items())})
        cache=self.root/'knowledge/resource-comparison-cache-v3'/('map-tables-'+hashlib.sha256(self.workflow.canonical(inputs)).hexdigest()+'.json')
        pointer=self.owner.cached(cache)
        if pointer is not None:
            body=self.document(pointer)
            if body.get('inputs')!=inputs:raise ValueError('Map table cache inputs differ')
            self.metrics['cache_hits']+=1
        else:
            body=dict(schema=1,recipe=RECIPE,inputs=inputs,**self.compare(current,reasons),
                scope='reviewed_Map10_11_table_data',historical_archive_freshly_hashed=False,
                target_native_projection_verified=False,runtime_activated=False,profile_activated=False,
                geometry=self.baseline['geometry'],map_ids=self.baseline['map_ids'])
            path=self.workflow.snapshot(self.root,'resource-map-table-results-v1',body)
            pointer=dict(path=str(path),sha256=self.owner.digest(path));self.owner.defer(cache,pointer)
            self.metrics['analyses']+=1
        self.prepared=dict(pointer=pointer,state=body['state'],reasons=body['reasons'])
        return copy.deepcopy(pointer)

    def publish(self,barrier):
        if self.prepared is None or self.published or self.owner.state!='completed':
            raise ValueError('Map data publication needs completed owner')
        path=Path(barrier['report']).resolve();sha=barrier['sha256']
        if (not isinstance(sha,str) or not SHA.fullmatch(sha) or path.name!='manifest.json' or path.parent.name!=sha
                or not path.is_relative_to(self.root/'knowledge/resource-owner-barriers-v4')):
            raise ValueError('Map data owner pointer differs')
        with path.open('rb') as stream:raw=stream.read(32*1024*1024+1)
        if len(raw)>32*1024*1024 or hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Map data owner proof changed')
        proof=json.loads(raw);pointer=self.prepared['pointer']
        if (barrier.get('barrier_completed') is not True or proof.get('barrier_completed') is not True
                or proof.get('recipe')!='resource-owner-sha-v4' or proof.get('epoch')!=self.owner.epoch
                or any(proof['inputs'].get(str(p))!=s for p,s in self.owner.files.items())
                or self.index.digest(pointer['path'])!=pointer['sha256']):raise ValueError('Map data final proof differs')
        body=dict(schema=1,recipe=RECIPE,data=pointer,owner_barrier=dict(path=str(path),sha256=sha),
            state=self.prepared['state'],target_native_projection_verified=False,runtime_activated=False,profile_activated=False)
        target=self.workflow.snapshot(self.root,'resource-map-table-receipts-v1',body);self.published=True
        return dict(report=str(target),sha256=self.index.digest(target),data=copy.deepcopy(pointer),state=self.prepared['state'],
            reasons=self.prepared['reasons'],metrics=copy.deepcopy(self.metrics),target_native_projection_verified=False)
