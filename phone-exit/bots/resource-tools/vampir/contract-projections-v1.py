"""Проверенные contract projections поверх опубликованных native семейств.

Старые native suites не исполняются. Static inheritance сохраняет их fixture
границы; непроверенная связь wrapper остаётся отдельным блокером.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import time

HERE=Path(__file__).resolve().parent
RECIPE='contract-projections-v1'
FAMILIES=('archive-wire','string-writer','version-prepare','login-prepare')
LIMIT=32*1024*1024
SHA=re.compile('[0-9a-f]{64}')


def canonical(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode('utf-8')


def fingerprint(value):return hashlib.sha256(canonical(value)).hexdigest()


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate contract projection JSON key')
        result[key]=value
    return result


def enabled(index,args):
    path=Path(args.knowledge)/'contract-projections.json'
    if not path.is_file():return False
    value=index.read_json(path)
    if not isinstance(value,dict) or type(value.get('schema')) is not int or value['schema']!=1 or value.get('recipe')!=RECIPE:
        raise ValueError('Unknown contract projection recipe')
    return True


def begin(index,args,sha):return Session(index,args,sha)


def _merge(target,values,kind):
    for key,value in values.items():
        if key in target and target[key]!=value:
            raise ValueError('Conflicting contract projection '+kind+': '+key)
        target[key]=copy.deepcopy(value)


class Session:
    def __init__(self,index,args,sha):
        if not SHA.fullmatch(str(sha)):raise ValueError('Full projection source SHA required')
        self.index,self.args,self.sha=index,args,sha
        self.root,self.knowledge=Path(args.root).resolve(),Path(args.knowledge).resolve()
        self.store=args.source_store
        if Path(self.store.root).resolve()!=self.root:raise ValueError('Projection SourceStore belongs to another root')
        if getattr(index.digest,'__self__',None) is self.store:raise ValueError('Projection barrier needs the original digest')
        self.workflow=index.extension('research-workflow')
        self.files,self.aliases={},{}
        self.contexts,self.publications,self.preparations={},{},{}
        self.results={};self.executed=set();self.ready=False;self.error=None;self.closed=False;self.input_files={}
        self.metrics=dict(projected=0,static_checks=0,cached_checks=0,publication_seconds=0,barrier_seconds=0,
            inherited_writer_cases=0,inherited_tag_cases=0,target_native_cases=0)
        self.registry=self.read_path(self.knowledge/'contract-projections.json')
        if (set(self.registry)!={'schema','recipe','baseline','contracts'} or type(self.registry['schema']) is not int or self.registry['schema']!=1
                or self.registry['recipe']!=RECIPE or set(self.registry['contracts'])!={'game-version','game-login'}):
            raise ValueError('Contract projection registry structure differs')
        self.rule={str(HERE/name):self.pin(HERE/name) for name in (
            'contract-projections-v1.py','contract-writer-inheritance-v1.py',
            'build-native-entry-code.py','update-bindings.py')}
        self.baseline=self.registry['baseline']
        self.baseline_archive=self.config_pointer(self.baseline['archive'])
        self.writer_report=self.config_pointer(self.baseline['writers'])
        self.tag_report=self.config_pointer(self.baseline['tags'])
        self._historical('writer_check','writers','packet-writer-context')
        self._historical('tag_check','tags','compiled-tag-native-11316')
        self.baseline_prepare={name:self.config_pointer(spec['prepare']) for name,spec in self.registry['contracts'].items()}
        for name,spec in self.registry['contracts'].items():
            if (set(spec)!={'family','prepare','tag'} or spec['family']!=('version-prepare' if name=='game-version' else 'login-prepare')
                    or spec['tag']['object_size']!=self.baseline_archive['packets'][name]['object_size']):
                raise ValueError('Projection preparation recipe differs')
        for value in (self.writer_report,self.tag_report):
            if (value.get('source_sha256')!=self.baseline_archive['source_sha256']
                    or any(value.get(k) is not False for k in ('network_used','profile_activated','runtime_activated'))):
                raise ValueError('Historical contract report source or scope differs')
            for report in value['reports'].values():
                for pointer in report['evidence']:self.pin(pointer['path'],pointer['sha256'])
        for name,expected in self.baseline['fixture_tools'].items():
            if Path(name).name!=name or self.pin(HERE/name)!=expected:
                raise ValueError('Historical fixture implementation changed')
        self.native=index.extension('build-native-entry-code')
        self.bindings=index.extension('update-bindings')
        self.source=self.store.image(self.native,sha)
        self.before=self.store.image(self.native,self.baseline_archive['source_sha256'])

    def _open(self):
        if self.closed:raise ValueError('Projection session is closed')
        if (Path(self.args.root).resolve()!=self.root or Path(self.args.knowledge).resolve()!=self.knowledge
                or self.args.source_store is not self.store):raise ValueError('Projection owner changed')

    def pin(self,path,expected=None):
        self._open()
        lexical=str(Path(path).absolute());resolved=Path(path).resolve()
        if lexical in self.aliases and self.aliases[lexical]!=resolved:raise ValueError('Projection alias changed')
        self.aliases[lexical]=resolved
        value=self.files.setdefault(str(resolved),self.index.digest(resolved)) if str(resolved) not in self.files else self.files[str(resolved)]
        if expected is not None and value!=expected:raise ValueError('Projection artifact SHA differs: '+str(path))
        return value

    def read_path(self,path,expected=None):
        value=self.pin(path,expected)
        with Path(path).open('rb') as stream:raw=stream.read(LIMIT+1)
        if len(raw)>LIMIT or hashlib.sha256(raw).hexdigest()!=value:raise ValueError('Projection JSON changed or exceeds budget')
        return json.loads(raw,object_pairs_hook=_unique)

    def read(self,pointer):
        if (not isinstance(pointer,dict) or set(pointer)!={'path','sha256'}
                or not isinstance(pointer['path'],str) or not SHA.fullmatch(str(pointer['sha256']))):
            raise ValueError('Projection requires an exact pointer')
        path=Path(pointer['path'])
        if not path.is_absolute() or not any(path.resolve().is_relative_to(folder) for folder in (self.root,self.knowledge)):
            raise ValueError('Projection pointer outside knowledge')
        return self.read_path(path,pointer['sha256'])

    def pointer(self,path):return dict(path=str(Path(path).resolve()),sha256=self.pin(path))

    def configured(self,pointer):
        if (not isinstance(pointer,dict) or set(pointer)!={'base','path','sha256'}
                or pointer['base'] not in ('library','repository') or not isinstance(pointer['path'],str)):
            raise ValueError('Invalid configured projection pointer')
        base=self.root if pointer['base']=='library' else self.knowledge
        path=base/pointer['path']
        if Path(pointer['path']).is_absolute() or not path.resolve().is_relative_to(base):
            raise ValueError('Configured projection pointer escapes base')
        return dict(path=str(path.absolute()),sha256=pointer['sha256'])

    def config_pointer(self,pointer):return self.read(self.configured(pointer))

    def _historical(self,check_name,report_name,check_id):
        check=self.config_pointer(self.baseline[check_name])
        report=self.config_pointer(self.baseline[report_name])
        fact_doc=self.config_pointer(self.baseline['facts'])
        facts=[f for f in fact_doc['facts'] if f['id']==self.baseline['fact_id']]
        if len(facts)!=1:raise ValueError('Historical projection fact is missing or ambiguous')
        checked=self.configured(self.baseline[check_name])
        if (check.get('state')!='passed' or check['definition']['source_sha256']!=self.baseline_archive['source_sha256']
                or check['definition']['check']['id']!=check_id
                or not any(c.get('id')==check_id and c.get('state')=='passed'
                    and c.get('report')==checked['path'] and c.get('sha256')==checked['sha256'] for c in facts[0]['checks'])
                or report.get('kind')!=report_name
                or any(check['definition'].get('artifacts',{}).get(item['path'])!=item['sha256']
                    for value in report['reports'].values() for item in value['evidence'])):
            raise ValueError('Historical projection check/report/fact provenance differs')
        for name,expected in self.baseline['fixture_tools'].items():
            recorded=check['definition']['inputs'].get(str(HERE/name))
            if recorded is not None and recorded!=expected:raise ValueError('Historical fixture tool provenance differs')
        required=('verify-entry-contracts-11320.py',
            'verify-packet-writer-context.py' if report_name=='writers' else 'verify-version-login-context.py')
        if any(check['definition']['inputs'].get(str(HERE/name))!=self.baseline['fixture_tools'].get(name) for name in required):
            raise ValueError('Historical fixture producer is not explicit')

    def prepare(self,native,checks):
        self._open()
        if self.ready or self.error is not None:raise ValueError('Projection publications already selected')
        started=time.perf_counter()
        publication=self.index.extension('native-publication-v3').begin(self.index,self.args,self.sha)
        try:
            descriptors=self.index.extension('update-native-drivers-v2')
            specs={row['family']:row for row in descriptors.registry(self.index,self.knowledge)}
            declarations=native.get('checks',native.get('declarations',[]))
            for family in FAMILIES:
                descriptor=specs[family];spec=descriptors.spec(descriptor)
                candidates=[d for d in declarations if d.get('id')==spec['id']]
                outcomes=[c for c in checks if c.get('id')==spec['id']]
                if len(candidates)!=1 or len(outcomes)!=1:raise ValueError('Missing or ambiguous projection provider: '+family)
                declaration,outcome=candidates[0],outcomes[0]
                publication.publish(spec,descriptors.tool(self.index,descriptor),declaration,outcome)
                self.publications[family]=dict(context=declaration['context'],
                    check=dict(path=outcome['report'],sha256=outcome['sha256']))
                self.contexts[family]=self.read(declaration['context'])
            self.publication_metrics=publication.finish()
            for name,expected in {**publication.files,**publication.mutable_files}.items():
                if expected is None:raise ValueError('Projection publication input unexpectedly absent')
                self.pin(name,expected)
            for lexical,expected in publication._aliases.items():
                if Path(lexical).resolve()!=expected:raise ValueError('Projection publication alias changed')
                if lexical in self.aliases and self.aliases[lexical]!=expected:raise ValueError('Projection alias conflicts')
                self.aliases[lexical]=expected
            self.ready=True
        except (ValueError,OSError,KeyError,StopIteration) as error:
            self.error=str(error)
        self.input_files=dict(self.files)
        self.metrics['publication_seconds']=round(time.perf_counter()-started,6)
        return dict(state='ready' if self.ready else 'requires_review',reason=self.error,publications=copy.deepcopy(self.publications))

    def _chain(self,current,baseline):
        chain=[];seen=set()
        expected=fingerprint(baseline)
        while fingerprint(current)!=expected:
            pointer=current.get('transfer_proof')
            if pointer is None or pointer['sha256'] in seen or len(seen)>=32:
                raise ValueError('Projection transfer chain does not reach declared baseline')
            seen.add(pointer['sha256']);proof=self.read(pointer)
            chain.append(proof)
            current=self.read(proof['baseline'])
        return list(reversed(chain))

    def _mapping(self,current,baseline,addresses):
        mapped={hex(at):hex(at) for at in addresses}
        for proof in self._chain(current,baseline):
            mapping=proof['relocation']['mapping']
            for key,previous in mapped.items():
                if previous not in mapping:raise ValueError('Projection transfer lacks an exact instruction/dependency mapping')
                mapped[key]=mapping[previous]
        return mapped

    def bytes(self,image,address,count):
        if not 1<=count<=4096:raise ValueError('Projection data budget differs')
        offset=image.offset(address-image.pe.base)
        value=bytes(image.data[offset:offset+count])
        if len(value)!=count:raise ValueError('Projection source data is truncated')
        return value

    def providers(self,name):
        archive=self.contexts['archive-wire'];packet=archive['packets'][name]
        prepare=self.contexts[self.registry['contracts'][name]['family']]
        if (prepare['packet_table']!=packet['table'] or prepare['layout']['packet_bytes']!=packet['object_size']
                or self.contexts['string-writer']['bindings']['string-writer']!=archive['bindings']['string-writer']
                or struct.unpack('<Q',self.bytes(self.source,int(packet['table'],16)+16,8))[0]!=int(packet['writer'],16)):
            raise ValueError('Projection constructor/table/writer providers conflict')
        rows=self.bindings.rows(self.native,self.source,int(prepare['constructor'],16))
        references=[r for r in rows if r['mnemonic']=='lea' and r['operands'].startswith('rax, [rip')
            and r['rip_references']==[int(packet['table'],16)]]
        if len(references)!=1:raise ValueError('Projection constructor has no unique packet table source link')
        return prepare,archive,packet

    def project(self,context):
        self._open();name=context['contract']['id']
        if name not in self.registry['contracts']:return copy.deepcopy(context)
        if not self.ready:return copy.deepcopy(context)
        result=copy.deepcopy(context);prepare,archive,packet=self.providers(name)
        values=dict(constructor=prepare['constructor'],prepare=prepare['prepare'],writer=packet['writer'],
            **{'string-writer':archive['bindings']['string-writer']})
        _merge(result['bindings']['bindings'],values,'binding')
        gaps=result['bindings'].get('queue',[])
        result['bindings']['queue']=[gap for gap in gaps if not any(gap.startswith(key+':') for key in values)]
        data={'tag-pointer':dict(kind='pointer',address=prepare['globals']['tag_pointer']),
            'tag-literal':dict(kind='ascii',address=prepare['compiled_tag_source']['literal']),
            'packet-table':dict(kind='vtable',address=packet['table'])}
        target=result['contract'].setdefault('data_dependencies',{}).setdefault(self.sha,{})
        _merge(target,data,'data')
        spec=self.registry['contracts'][name]
        target=result['contract'].setdefault('tag_check_by_source',{})
        _merge(target,{self.sha:dict(spec['tag'],verify_whole_exports=True)},'tag spec')
        target=result['contract'].setdefault('writer_check_by_source',{})
        _merge(target,{self.sha:dict(object_size=packet['object_size'],fields=packet['fields'],
            memcpy=archive['helpers']['memcpy'],verify_whole_exports=True)},'writer spec')
        result['projection']=dict(recipe=RECIPE,rule=self.rule,publications=self.publications,
            baseline_sha256=self.baseline_archive['source_sha256'],contract_coverage_unchanged=True)
        self.metrics['projected']+=1
        return result

    def inputs(self,context,adapter):
        return dict(recipe=RECIPE,context=fingerprint(context),adapter=adapter,source_sha256=self.sha,
            registry_sha256=self.pin(self.knowledge/'contract-projections.json'),rule=self.rule,
            publications=self.publications,publication_error=self.error,files=self.input_files)

    def _writer(self,context):
        name=context['contract']['id'];prepare,archive,packet=self.providers(name)
        old=self.baseline_archive['packets'][name]
        before_rows=self.bindings.rows(self.native,self.before,int(old['writer'],16))
        after_rows=self.bindings.rows(self.native,self.source,int(packet['writer'],16))
        wanted={r['address'] for r in before_rows}|{int(old['writer'],16),int(old['table'],16),
            int(self.baseline_archive['bindings']['string-writer'],16)}
        wanted.update(r['direct_target'] for r in before_rows if r['direct_target'] is not None)
        mapping=self._mapping(archive,self.baseline_archive,wanted)
        report=self.writer_report['reports'][name]
        for pointer in report['evidence']:self.pin(pointer['path'],pointer['sha256'])
        result=self.index.extension('contract-writer-inheritance-v1').verify(report,self.baseline_archive,
            archive,name,before_rows,after_rows,mapping)
        if report['binding']['constructor']!=self.baseline_prepare[name]['constructor']:
            raise ValueError('Writer historical constructor provider differs')
        self._chain(prepare,self.baseline_prepare[name])
        return dict(result,state='passed',constructor=prepare['constructor'])

    def _wrapper_store(self,image,table,prepare):
        if struct.unpack('<Q',self.bytes(image,table+0x48,8))[0]!=prepare:
            raise ValueError('Version wrapper table slot does not point to prepare')
        matches=[]
        for site,_ in self.native.rip_candidates(image,{table}):
            fragment=image.containing(site)
            if fragment is None:continue
            root=image.pe.base+image.roots[fragment][0]
            rows=self.bindings.rows(self.native,image,root)
            for load,store in zip(rows,rows[1:]):
                if (load['address']==site and load['mnemonic']=='lea'
                        and load['operands'].startswith('rax, [rip') and load['rip_references']==[table]
                        and store['address']==site+len(bytes.fromhex(load['bytes']))
                        and store['mnemonic']=='mov' and store['operands']=='qword ptr [rbx], rax'):
                    matches.append((root,site))
        if len(matches)!=1:
            raise ValueError('Version wrapper table requires exactly one constructor store')
        return matches[0]

    def _wrapper_link(self,context,old,prepare,links):
        old_table=int(old['wrapper_table'],16)
        if links.get('wrapper_table')!=old['wrapper_table'] or links.get('version_slot')!=0x48:
            raise ValueError('Historical Version wrapper table link differs')
        old_root,old_site=self._wrapper_store(self.before,old_table,int(old['prepare'],16))
        baseline=self.baseline_archive['source_sha256']
        recorded=context['contract']['bindings'][baseline]['wrapper-constructor']
        if hex(old_root)!=recorded:
            raise ValueError('Historical Version wrapper constructor differs')
        table=int(prepare['wrapper_table'],16)
        root,site=self._wrapper_store(self.source,table,int(prepare['prepare'],16))
        if site-root!=old_site-old_root:
            raise ValueError('Version wrapper constructor store offset differs')
        return dict(constructor=hex(root),store_site=hex(site),table=hex(table),
            version_slot=0x48,prepare=prepare['prepare'])

    def _tag(self,context):
        name=context['contract']['id'];prepare,archive,packet=self.providers(name)
        old=self.baseline_prepare[name];report=self.tag_report['reports'][name]
        spec=self.registry['contracts'][name]['tag'];binding=report['binding']
        if (type(report.get('schema')) is not int or report['schema']!=1 or report.get('contract')!=name
                or report.get('source_sha256')!=self.baseline_archive['source_sha256']
                or any(report.get(key) is not False for key in ('network_used','profile_activated'))):
            raise ValueError('Historical tag fixture scope differs')
        if (binding['constructor']!=old['constructor'] or binding['prepare']!=old['prepare']
                or binding['table']!=old['packet_table'] or type(binding['packet_id']) is not int or binding['packet_id']!=spec['packet_id']
                or binding['pointer']!=old['globals']['tag_pointer'] or binding['literal']!=old['compiled_tag_source']['literal']
                or binding['packet_name']!=spec['packet_name'] or binding['tag']!=old['compiled_tag_source']['value']):
            raise ValueError('Historical tag provider/spec differs')
        cases=report['cases']
        if (len(cases)!=4 or {c['poison'] for c in cases}!={0,85,170,255}
                or any(type(c['poison']) is not int or type(c['packet_id']) is not int or c['guards'] is not True
                    or c!=dict(poison=c['poison'],packet_id=spec['packet_id'],events=['ascii','allocate','copy'],guards=True) for c in cases)):
            raise ValueError('Historical tag fixture matrix differs')
        addresses={int(old[key],16) for key in ('constructor','prepare')}
        addresses.update(int(old['prepare'],16)+spec[key] for key in ('start_offset','stop_offset'))
        mapping=self._mapping(prepare,old,addresses)
        if any(mapping[hex(int(old['prepare'],16)+spec[key])]!=hex(int(prepare['prepare'],16)+spec[key]) for key in ('start_offset','stop_offset')):
            raise ValueError('Target tag fixture slice geometry differs')
        if any(mapping[old[key]]!=prepare[key] for key in ('constructor','prepare')):
            raise ValueError('Target tag fixture roots differ')
        for pointer in report['evidence']:self.pin(pointer['path'],pointer['sha256'])
        pointer=int(prepare['globals']['tag_pointer'],16);literal=int(prepare['compiled_tag_source']['literal'],16)
        if (struct.unpack('<Q',self.bytes(self.source,pointer,8))[0]!=literal
                or self.bytes(self.source,literal,33)!=prepare['compiled_tag_source']['value'].encode('ascii')+b'\0'):
            raise ValueError('Target compiled tag source differs')
        table=int(packet['table'],16)
        getter,name_getter=[struct.unpack('<Q',self.bytes(self.source,table+offset,8))[0] for offset in (40,56)]
        if self.bytes(self.source,getter,6)!=b'\xb8'+struct.pack('<I',spec['packet_id'])+b'\xc3':
            raise ValueError('Target packet ID leaf differs')
        name_rows=self.bindings.rows(self.native,self.source,name_getter)
        refs=[r['rip_references'][0] for r in name_rows if r['mnemonic']=='lea' and r['operands'].startswith('rdx, [rip') and len(r['rip_references'])==1]
        expected=(spec['packet_name']+'\0').encode('ascii')
        if len(refs)!=1 or self.bytes(self.source,refs[0],len(expected))!=expected:
            raise ValueError('Target packet name source differs')
        wrapper=self._wrapper_link(context,old,prepare,report['links']) if name=='game-version' else None
        if name!='game-version' and report['links'].get('wrapper_table'):
            raise ValueError('Unexpected wrapper link in Login tag fixture')
        return dict(state='passed',wrapper_link=wrapper,
            method='static_inheritance',inherited_cases=4,target_native_cases=0,
            packet_id=spec['packet_id'],packet_name=spec['packet_name'],id_leaf=hex(getter),name_getter=hex(name_getter),
            runtime_activated=False,network_used=False,profile_activated=False,
            limits=['Inherited constructor/tag fixture matrix and explicit target ID/name source checks.',
                'Version wrapper proof covers the vptr store and Version slot only.'])

    def check(self,context,adapter):
        self._open()
        if adapter not in ('version-login-tag','packet-writer-projection'):raise ValueError('Unknown projected context check')
        inputs=self.inputs(context,adapter)
        try:
            if not self.ready:raise ValueError('Projection publication admission failed: '+str(self.error))
            result=self._writer(context) if adapter=='packet-writer-projection' else self._tag(context)
        except (ValueError,OSError,KeyError,StopIteration) as error:
            result=dict(state='requires_review',reason=str(error),target_native_cases=0)
        value=dict(result,schema=1,recipe=RECIPE,source_sha256=self.sha,contract=context['contract']['id'],
            adapter=adapter,inputs=inputs,owner_barrier_pending=True,contract_coverage='unchanged',
            runtime_activated=False,profile_activated=False,network_used=False)
        if 'recipe' in result:value['inheritance_recipe']=result['recipe']
        path=self.workflow.snapshot(self.root,'contract-projection-checks-v1',value)
        self.metrics['static_checks']+=1
        self.executed.add((context['contract']['id'],adapter))
        return dict(id=adapter,state=value['state'],reason=value.get('reason',''),report=str(path),sha256=self.pin(path))

    def observe(self,context,adapter,result):
        self._open()
        value=self.read(dict(path=result['report'],sha256=result['sha256']))
        inputs=value.get('inputs',{})
        current=self.inputs(context,adapter)
        if (value.get('recipe')!=RECIPE or value.get('source_sha256')!=self.sha
                or value.get('contract')!=context['contract']['id'] or value.get('adapter')!=adapter
                or inputs!=current
                or type(value.get('schema')) is not int or value['schema']!=1
                or value.get('state')!=result['state'] or result.get('id')!=adapter
                or value.get('reason','')!=result.get('reason','')
                or value.get('state') not in ('passed','requires_review')
                or any(value.get(k) is not False for k in ('runtime_activated','profile_activated','network_used'))
                or value.get('owner_barrier_pending') is not True or value.get('contract_coverage')!='unchanged'
                or type(value.get('target_native_cases')) is not int or value['target_native_cases']!=0):
            raise ValueError('Cached contract projection provenance differs')
        name=context['contract']['id']
        cases=value.get('inherited_cases')
        if value['state']=='passed':
            expected=4 if adapter=='version-login-tag' else {'game-version':56,'game-login':104}[name]
            if (value.get('method')!='static_inheritance' or type(cases) is not int or cases!=expected):
                raise ValueError('Cached contract projection case coverage differs')
            if adapter=='version-login-tag' and name=='game-version':
                link=value.get('wrapper_link')
                prepare=self.contexts['version-prepare']
                if (not isinstance(link,dict) or link.get('table')!=prepare['wrapper_table']
                        or link.get('prepare')!=prepare['prepare'] or link.get('version_slot')!=0x48
                        or any(not re.fullmatch('0x[0-9a-f]+',str(link.get(key))) for key in ('constructor','store_site'))):
                    raise ValueError('Cached contract projection wrapper link differs')
        self.results[(context['contract']['id'],adapter)]=copy.deepcopy(result)
        if (context['contract']['id'],adapter) not in self.executed:self.metrics['cached_checks']+=1
        if value['state']=='passed':
            metric='inherited_writer_cases' if adapter=='packet-writer-projection' else 'inherited_tag_cases'
            self.metrics[metric]+=cases

    def finish(self):
        self._open();started=time.perf_counter()
        for lexical,expected in self.aliases.items():
            if Path(lexical).resolve()!=expected:raise ValueError('Projection alias changed before final barrier')
        for name,expected in self.files.items():
            if self.index.digest(name)!=expected:raise ValueError('Projection input changed before final barrier: '+name)
        source_metrics=self.store.validate()
        for lexical,expected in self.aliases.items():
            if Path(lexical).resolve()!=expected:raise ValueError('Projection alias changed during final barrier')
        self.metrics['barrier_seconds']=round(time.perf_counter()-started,6);self.closed=True
        return dict(recipe=RECIPE,owner_barrier_completed=True,source_store=source_metrics,metrics=self.metrics,
            source_sha256=self.sha,profile_activated=False,live_verified=False)
