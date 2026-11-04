"""Независимые текущие ресурсы, reference hashes и сравнения одного обновления."""
import copy
import fnmatch
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
RECIPE = 'resource-pipeline-v3'


def enabled(index, args):
    path = Path(args.knowledge)/'resource-pipeline-engine.json'
    if not path.is_file():
        return False
    if index.read_json(path) != dict(schema=3, recipe=RECIPE,
            reference='immutable-hash-reference-v3', current_csv='current-resource-csv-v3'):
        raise ValueError('Неизвестный recipe ресурсов')
    return True


def plan(report, contracts, changed):
    """A plan is an inventory of consumers, never an extraction admission."""
    selected={row['path']:row for row in changed}
    for row in report['files']:
        if ((row.get('current') or {}).get('pak_version')==11 and any(
                fnmatch.fnmatchcase(row['path'].replace('\\','/'), dep['archive'])
                for contract in contracts['contracts'] for dep in contract.get('resources',[]))):
            selected[row['path']]=row
    return list(selected.values())


class Pipeline:
    def __init__(self,index,args,workflow,update,journal,manifest,report,rows,resource_tools):
        self.index,self.args,self.workflow,self.update=index,args,workflow,update
        self.journal,self.manifest,self.report=journal,Path(manifest),report
        self.rows,self.resource_tools=rows,copy.deepcopy(resource_tools)
        self.root=Path(args.root).resolve()
        owner_api=index.extension('resource-owner-v4')
        self.owner=owner_api.begin(index,args) if owner_api.enabled(index,args) else None
        self.engine=index.extension('update-run')
        self.reference_api=index.extension('resource-reference-v3')
        self.index_api=index.extension('resource-index-v3')
        self.csv_api=index.extension('resource-csv-v3')
        self.assets=index.extension('compare-release-assets')
        self.tables=index.extension('extract-release-tables')
        self.reference,self.reference_error=None,None
        self.files,self.aliases={},{}
        self.optional_files,self.pending={},{}
        self.rules={str(HERE/name):self.pin(HERE/name) for name in (
            'resource-pipeline-v3.py','resource-reference-v3.py','resource-index-v3.py',
            'resource-csv-v3.py','compare-release-assets.py','extract-release-tables.py')}
        self.metrics=dict(archives=0,reference_import_seconds=0,reference_open_seconds=0,
            record_index_seconds=0,current_csv_seconds=0,comparison_input_seconds=0,
            asset_comparison_seconds=0,table_comparison_seconds=0,report_validation_seconds=0,
            comparison_cache_hits=0,comparison_executions=0,final_barrier_seconds=0,
            current_csv_tables=0,current_csv_errors=0,common_table_baseline_missing=0)
        self.finished=False

    def pin(self,path,expected=None):
        lexical=str(Path(path).absolute());canonical=Path(path).resolve()
        if lexical in self.aliases and self.aliases[lexical]!=canonical:
            raise ValueError('Resource pipeline path alias changed')
        self.aliases[lexical]=canonical
        name=str(canonical)
        if name not in self.files:
            self.files[name]=self.owner.digest(path) if self.owner is not None else self.index.digest(canonical)
        actual=self.files[name]
        if expected is not None and actual!=expected:
            raise ValueError('Resource pipeline input SHA differs: '+name)
        if self.owner is not None:
            self.owner.expect(path, actual if expected is None else expected)
        return actual

    def read(self,pointer):
        if not isinstance(pointer,dict) or set(pointer)!={'path','sha256'}:
            raise ValueError('Resource pipeline needs an exact pointer')
        path=Path(pointer['path']).resolve()
        if not path.is_relative_to(self.root):raise ValueError('Resource report outside library')
        self.pin(pointer['path'],pointer['sha256'])
        with path.open('rb') as stream:raw=stream.read(32*1024*1024+1)
        if len(raw)>32*1024*1024 or hashlib.sha256(raw).hexdigest()!=pointer['sha256']:
            raise ValueError('Resource report changed or exceeds budget')
        return json.loads(raw.decode('utf-8-sig'))

    def receipt(self,category,value):
        path=self.workflow.snapshot(self.root,category,value)
        pointer=dict(path=str(path),sha256=self.pin(path))
        return pointer

    def _reference(self,row):
        if self.reference_error is not None:
            return dict(state='blocked',reason=self.reference_error,blobs=[],projection_sha256=None)
        if self.reference is None:
            started=time.perf_counter()
            try:
                self.reference=self.reference_api.open_active(self.index,self.args)
                if self.reference is None:
                    import_started=time.perf_counter()
                    pointer=self.reference_api.import_legacy(self.index,self.args,
                        [item for item in self.rows if (item.get('current') or {}).get('pak_version')==11])
                    self.metrics['reference_import_seconds']+=time.perf_counter()-import_started
                    self.reference=self.reference_api.open_snapshot(self.index,self.args,pointer)
            except (ValueError,OSError) as error:
                self.reference_error=str(error)
                return dict(state='blocked',reason=str(error),blobs=[],projection_sha256=None)
            finally:self.metrics['reference_open_seconds']+=time.perf_counter()-started
        return self.reference.select(row)

    def _comparison(self,kind,inputs,action):
        started=time.perf_counter()
        inputs=dict(inputs,recipe_guard=dict(self.rules))
        key=self.engine.fingerprint(self.workflow,dict(recipe=RECIPE,kind=kind,inputs=inputs))
        cache=self.root/'knowledge/resource-comparison-cache-v3'/(key+'.json')
        if cache in self.pending:
            pointer=self.pending[cache]
            value=self.read(pointer)
            self.metrics['comparison_cache_hits']+=1
        elif cache.is_file():
            self.pin(cache)
            pointer=self.index.read_json(cache);value=self.read(pointer)
            if value.get('recipe')!=RECIPE or value.get('kind')!=kind or value.get('inputs')!=inputs:
                raise ValueError('Resource comparison cache inputs differ')
            self.metrics['comparison_cache_hits']+=1
        else:
            value=dict(schema=3,recipe=RECIPE,kind=kind,inputs=copy.deepcopy(inputs),
                compatibility='not_established',resource_identity_proven=False,**action())
            pointer=self.receipt('resource-comparisons-v3',value)
            # Unassigned immutable reports may survive an interruption. A
            # reusable cache pointer is earned only by the final owner barrier.
            self.pending[cache]=pointer
            self.metrics['comparison_executions']+=1
        self.metrics['report_validation_seconds']+=time.perf_counter()-started
        return pointer,value

    def _asset_comparison(self,record_pointer,record,reference):
        before=time.perf_counter()
        projection={key:copy.deepcopy(value) for key,value in reference.items() if key!='projection_sha256'}
        inputs=dict(record_index=record_pointer,reference_projection=projection,
            rule_sha256=self.rules[str(HERE/'compare-release-assets.py')])
        self.metrics['comparison_input_seconds']+=time.perf_counter()-before
        def compare():
            if reference['state']!='available':
                return dict(state='requires_review',reason='historical_blob_reference_missing',blobs=[])
            rows=self.assets.match_blobs(reference['blobs'],record['entries'])
            return dict(state='compared',scope='Immutable legacy blob hashes against current decoded record hashes; observed paths are references only',
                exact_content_matches=sum(row['status']=='exact_content_match' for row in rows),
                not_observed=sum(row['status']=='not_observed' for row in rows),blobs=rows)
        started=time.perf_counter();result=self._comparison('asset-hashes',inputs,compare)
        self.metrics['asset_comparison_seconds']+=time.perf_counter()-started
        return result

    def _read_csv(self,path,expected):
        self.pin(path,expected)
        with Path(path).open('rb') as stream:raw=stream.read(self.csv_api.LIMIT+1)
        if len(raw)>self.csv_api.LIMIT or hashlib.sha256(raw).hexdigest()!=expected:
            raise ValueError('CSV comparison bytes changed or exceed budget')
        return raw

    def _table_comparison(self,row,csv_pointer,current):
        started=time.perf_counter()
        metadata=self.root/'table-study/index.json'
        lexical=str(metadata.absolute());canonical=metadata.resolve()
        self.aliases[lexical]=canonical
        exists=canonical.is_file()
        if canonical in self.optional_files and self.optional_files[canonical]!=exists:
            raise ValueError('Resource table catalogue appeared or disappeared')
        self.optional_files[canonical]=exists
        if self.owner is not None:self.owner.watch(metadata, exists)
        if exists:self.pin(metadata)
        baseline=self.engine.table_baseline(self.index,self.args,row)
        previous=copy.deepcopy(baseline['tables'])
        for item in previous:
            raw=self._read_csv(item['file'],item['sha256'])
            parsed=self.tables.parse_csv(raw)
            if parsed is None or parsed[0]!=item['header']:
                raise ValueError('Historical CSV metadata differs from its actual bytes')
        inputs=dict(current_csv=csv_pointer,previous_tables=previous,baseline_state=baseline['state'],
            rule_sha256=self.rules[str(HERE/'extract-release-tables.py')])
        self.metrics['comparison_input_seconds']+=time.perf_counter()-started
        def compare():
            tables=copy.deepcopy(current['tables'])
            if baseline['state']!='selected' or not previous:
                return dict(state='requires_review',reason='matching_table_baseline_missing',
                    baseline_state=baseline['state'],tables=tables,table_identity_by_entry_assumed=False)
            result=self.tables.compare_tables(previous,tables)
            lookup={item['file']:item for item in previous}
            for table in tables:
                candidate=table['unique_schema_candidate']
                if candidate and not table['identical_previous_files']:
                    old=self._read_csv(candidate,lookup[candidate]['sha256'])
                    new=self._read_csv(table['file'],table['sha256'])
                    table['candidate_row_diff']=self.tables.compare_unique_rows(old,new)
            return dict(state='compared',tables=tables,comparison=result)
        started=time.perf_counter();result=self._comparison('csv-tables',inputs,compare)
        self.metrics['table_comparison_seconds']+=time.perf_counter()-started
        return result

    def process(self,row):
        if self.finished:raise ValueError('Resource pipeline already finished')
        self.metrics['archives']+=1
        current=row.get('current')
        if not current or current.get('pak_version')!=11:
            return dict(state='requires_review',reason='Removed archive or unsupported archive format',steps=[],recipe=RECIPE)
        try:
            # Config extraction is an independent EXE/data dependency, even
            # when this archive has no matching historical table catalogue.
            config=None
            if Path(row['path']).name in ('ProjectRED-Windows.pak','pakchunk0-Windows.pak'):
                core=self.index.extension('recover-pak-game-config')
                config_material=[self.root/'resource-config-snapshots/393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db/manifest.json',
                    self.root/'client-code-snapshots'/core.EXE_SHA256/'ProjectRED-Win64-Shipping.exe']
                historical={str(path.resolve()):self.pin(path) for path in config_material}
                config=self.journal.stage('resource-config-v3-'+hashlib.sha256(row['path'].encode()).hexdigest()[:16],
                    dict(source_sha256=self.report['exe']['sha256'],archive=current['sha256'],
                        historical=historical,tools=self.resource_tools,rules=self.rules),
                    lambda:self.update.execute_adapter(self.index,self.args,'recover-release-game-config.py',
                        [self.manifest,'--archive',row['path']]))
                for artifact in self.engine.resource_artifacts(self.index,self.root,config):
                    self.pin(artifact['path'],artifact['sha256'])
            started=time.perf_counter()
            record_pointer=self.index_api.find(self.index,self.args,self.manifest,row,self.resource_tools)
            if record_pointer is None:
                record_pointer=self.index_api.build(self.index,self.update,self.workflow,self.args,self.manifest,row)
            self.metrics['record_index_seconds']+=time.perf_counter()-started
            record=self.read(record_pointer)
            started=time.perf_counter()
            csv_pointer=self.csv_api.extract(self.index,self.args,record_pointer,source_sha256=current['sha256'])
            csv_report=self.read(csv_pointer)
            for table in csv_report['tables']:self.pin(table['file'],table['sha256'])
            self.metrics['current_csv_seconds']+=time.perf_counter()-started
            self.metrics['current_csv_tables']+=len(csv_report['tables'])
            self.metrics['current_csv_errors']+=len(csv_report['errors'])
            reference=self._reference(row)
            asset_pointer,asset_report=self._asset_comparison(record_pointer,record,reference)
            table_pointer,table_report=self._table_comparison(row,csv_pointer,csv_report)
            reasons=[]
            if config is not None and config.get('state')!='passed':reasons.append('current_game_config_extraction_incomplete')
            if csv_report['state']!='extracted':reasons.append('current_csv_extraction_errors')
            if asset_report['state']!='compared':reasons.append(asset_report['reason'])
            if table_report['state']!='compared':
                reasons.append(table_report['reason'])
                self.metrics['common_table_baseline_missing']+=1
            outcome=dict(schema=3,recipe=RECIPE,state='requires_review' if reasons else 'passed',
                reason='; '.join(reasons) if reasons else 'Bounded resource processing completed; logical identity remains unproven',
                reasons=reasons,record_index=record_pointer,current_csv=csv_pointer,
                asset_comparison=asset_pointer,table_comparison=table_pointer,
                directory_index_parsed=record['directory_index_parsed'],compatibility='not_established',
                resource_identity_proven=False,owner_barrier_pending=True)
            if config is not None:outcome['config']=config
            pointer=self.receipt('resource-processing-v3',outcome)
            inputs=dict(record_index=record_pointer,current_csv=csv_pointer,asset_comparison=asset_pointer,
                table_comparison=table_pointer,rules=self.rules)
            if config is not None:
                inputs['config_outcome']=copy.deepcopy(config)
                inputs['config_source_sha256']=self.report['exe']['sha256']
            result=self.journal.stage('resource-v3-'+hashlib.sha256(row['path'].encode()).hexdigest()[:16],inputs,
                lambda:dict(outcome,report=pointer['path'],sha256=pointer['sha256']))
            print(json.dumps(dict(event='update_resource_v3',archive=Path(row['path']).name,
                state=result['state'],tables=len(csv_report['tables']),errors=len(csv_report['errors']),
                reasons=reasons)),flush=True)
            return result
        except (ValueError,OSError,KeyError) as error:
            return dict(state='requires_review',recipe=RECIPE,reason='Resource v3 rejected: '+str(error),
                reasons=['resource_processing_rejected'],compatibility='not_established',resource_identity_proven=False)

    def finish(self):
        if self.finished:raise ValueError('Resource pipeline already finished')
        try:
            return self._finish()
        except BaseException:
            self.finished=True
            if self.owner is not None and not self.owner.closed:self.owner.abort()
            raise

    def _finish(self):
        started=time.perf_counter()
        if self.owner is not None and self.reference is not None:
            inputs=self.reference.consumed_inputs()
            self.owner.bind_aliases(inputs['aliases'])
            for path,sha in inputs['files'].items():self.owner.expect(path,sha)
        reference=self.reference.finish_barrier() if self.reference is not None else dict(state='not_consumed',reason=self.reference_error)
        indexes=self.index_api.finish(self.index,self.args)
        for path,exists in self.optional_files.items():
            if path.is_file()!=exists:raise ValueError('Resource table catalogue appeared or disappeared before final barrier')
        for lexical,expected in self.aliases.items():
            if Path(lexical).resolve()!=expected:raise ValueError('Resource pipeline alias changed before publication')
        for path,expected in self.files.items():
            digest=self.owner.expect(path,expected) if self.owner is not None else self.index.digest(path)
            if digest!=expected:raise ValueError('Resource pipeline bytes changed before publication: '+path)
        for lexical,expected in self.aliases.items():
            if Path(lexical).resolve()!=expected:raise ValueError('Resource pipeline alias changed during final barrier')
        if self.owner is not None:
            for cache,pointer in self.pending.items():self.owner.defer(cache,pointer)
            owner=self.owner.finish()
            indexes=dict(indexes,source_barrier_completed=True,source_barrier_pending=False,
                source_barrier_owner=dict(path=owner['report'],sha256=owner['sha256']))
        else:
            owner=None
            for cache,pointer in self.pending.items():
                if cache.exists():
                    if self.index.read_json(cache)!=pointer:
                        raise ValueError('Resource comparison cache changed before activation')
                else:self.workflow.atomic(cache,self.workflow.canonical(pointer))
        self.metrics['final_barrier_seconds']=round(time.perf_counter()-started,6)
        self.finished=True
        return dict(recipe=RECIPE,reference=reference,record_indexes=indexes,owner=owner,
            metrics=copy.deepcopy(self.metrics),validation_scope='bounded_resource_processing_only',
            compatibility='not_established',resource_identity_proven=False)
