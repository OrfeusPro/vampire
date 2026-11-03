"""Общие проекции на изолированных metadata и bytes; без native / JVM / игры."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('contract_projection_fixture',TOOLS/'contract-projections-v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
TARGET='a'*64
BASELINE='b'*64


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Store:
    def __init__(self,root):
        self.root=root;self.validations=0
        self.target=SimpleNamespace(pe=SimpleNamespace(base=0x1000),data=bytearray(8192),offset=lambda rva:rva)
        self.before=SimpleNamespace(pe=SimpleNamespace(base=0x7000),data=bytearray(8192),offset=lambda rva:rva)
    def image(self,native,sha):return self.target if sha==TARGET else self.before
    def validate(self):
        self.validations+=1
        return dict(validation_reads=self.validations,fixture_only=True)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()/'library';self.root.mkdir()
        self.knowledge=Path(self.temp.name).resolve()/'knowledge';self.knowledge.mkdir()
        self.here=Path(self.temp.name).resolve()/'tools';self.here.mkdir()
        self.here_patch=patch.object(P,'HERE',self.here);self.here_patch.start();self.addCleanup(self.here_patch.stop)
        self.store=Store(self.root);self.args=SimpleNamespace(root=self.root,knowledge=self.knowledge,source_store=self.store)
        self.rows={};self.publication_calls=[]
        self.workflow=SimpleNamespace(snapshot=self.snapshot)
        self.index=SimpleNamespace(digest=digest,read_json=lambda path:json.loads(Path(path).read_bytes()),extension=self.extension)
        tools=('contract-projections-v1.py','contract-writer-inheritance-v1.py',
            'verify-entry-contracts-11320.py','verify-packet-writer-context.py','verify-version-login-context.py')
        for name in tools:(self.here/name).write_text('# fixture '+name+'\n',encoding='utf-8')
        for name in ('build-native-entry-code.py','update-bindings.py'):
            (self.here/name).write_text('# fixture '+name+'\n',encoding='utf-8')
        self.fixture_tools={name:digest(self.here/name) for name in tools[2:]}
        self.artifact=self.put(self.root/'exports/details.json',dict(fixture='source export'))
        self.old_archive=dict(source_sha256=BASELINE,packets={
            'game-version':dict(object_size=208),'game-login':dict(object_size=320)})
        self.old_prepares={name:dict(source_sha256=BASELINE,constructor=ctor,prepare=prep,packet_table=table,
            globals=dict(tag_pointer='0x7100'),compiled_tag_source=dict(literal='0x7600',value='A'*32))
            for name,ctor,prep,table in (
                ('game-version','0x7300','0x7400','0x7200'),('game-login','0x8300','0x8400','0x8200'))}
        self.tags={name:dict(packet_id=packet_id,packet_name=packet_name,tag_field=field,object_size=size,
            start_offset=16,stop_offset=32,destination_offset=80,temporary_offset=64)
            for name,packet_id,packet_name,field,size in (
                ('game-version',1,'PktVersion',176,208),('game-login',3,'PktLogin',272,320))}
        writer_reports={name:dict(evidence=[self.artifact]) for name in self.tags}
        tag_reports={}
        for name,old in self.old_prepares.items():
            tag=self.tags[name]
            tag_reports[name]=dict(schema=1,contract=name,source_sha256=BASELINE,network_used=False,profile_activated=False,
                binding=dict(constructor=old['constructor'],prepare=old['prepare'],table=old['packet_table'],
                packet_id=tag['packet_id'],packet_name=tag['packet_name'],pointer=old['globals']['tag_pointer'],
                literal=old['compiled_tag_source']['literal'],tag='A'*32),
                cases=[dict(poison=value,packet_id=tag['packet_id'],events=['ascii','allocate','copy'],guards=True)
                    for value in (0,85,170,255)],
                links=dict(wrapper_table='0x7900',version_slot=72) if name=='game-version' else dict(login_constructor_call='0x8405',login_tag_field=272),
                evidence=[self.artifact])
        self.writer_report=dict(source_sha256=BASELINE,kind='writers',reports=writer_reports,
            network_used=False,profile_activated=False,runtime_activated=False)
        self.tag_report=dict(source_sha256=BASELINE,kind='tags',reports=tag_reports,
            network_used=False,profile_activated=False,runtime_activated=False)
        archive=self.config(self.put(self.knowledge/'baseline/archive.json',self.old_archive),'repository')
        writers=self.config(self.put(self.root/'baseline/writers.json',self.writer_report),'library')
        tags=self.config(self.put(self.root/'baseline/tags.json',self.tag_report),'library')
        check_pointers={}
        for kind,identifier in (('writer','packet-writer-context'),('tag','compiled-tag-native-11316')):
            check=dict(state='passed',definition=dict(source_sha256=BASELINE,check=dict(id=identifier),
                inputs={str(self.here/name):sha for name,sha in self.fixture_tools.items()},
                artifacts={self.artifact['path']:self.artifact['sha256']}))
            check_pointers[kind]=self.put(self.root/('baseline/'+kind+'-check.json'),check)
        fact=dict(id='f'*64,checks=[dict(id=identifier,state='passed',report=check_pointers[kind]['path'],
            sha256=check_pointers[kind]['sha256']) for kind,identifier in
            (('writer','packet-writer-context'),('tag','compiled-tag-native-11316'))])
        self.facts=self.put(self.knowledge/'baseline/facts.json',dict(facts=[fact]))
        contracts={name:dict(family='version-prepare' if name=='game-version' else 'login-prepare',
            prepare=self.config(self.put(self.knowledge/('baseline/'+name+'.json'),old),'repository'),tag=self.tags[name])
            for name,old in self.old_prepares.items()}
        self.registry=dict(schema=1,recipe=P.RECIPE,baseline=dict(archive=archive,writers=writers,tags=tags,
            writer_check=self.config(check_pointers['writer'],'library'),tag_check=self.config(check_pointers['tag'],'library'),
            facts=self.config(self.facts,'repository'),fact_id='f'*64,fixture_tools=self.fixture_tools),contracts=contracts)
        self.put(self.knowledge/'contract-projections.json',self.registry)

    def put(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(P.canonical(value))
        return dict(path=str(path),sha256=digest(path))

    def config(self,pointer,base):
        root=self.root if base=='library' else self.knowledge
        return dict(base=base,path=str(Path(pointer['path']).relative_to(root)),sha256=pointer['sha256'])

    def snapshot(self,root,category,value):
        raw=P.canonical(value);path=Path(root)/'knowledge'/category/hashlib.sha256(raw).hexdigest()/'manifest.json'
        path.parent.mkdir(parents=True,exist_ok=True)
        if path.exists():self.assertEqual(path.read_bytes(),raw)
        else:path.write_bytes(raw)
        return path

    def extension(self,name):
        if name=='research-workflow':return self.workflow
        if name=='build-native-entry-code':return SimpleNamespace()
        if name=='update-bindings':return SimpleNamespace(rows=lambda native,image,address:self.rows[address])
        if name=='native-publication-v3':return SimpleNamespace(begin=lambda *_:self.publication)
        if name=='update-native-drivers-v2':return SimpleNamespace(
            registry=lambda *_:[dict(family=family) for family in P.FAMILIES],
            spec=lambda row:dict(id=row['family']),tool=lambda *_:SimpleNamespace())
        raise AssertionError('Unexpected fixture extension: '+name)

    def session(self):return P.begin(self.index,self.args,TARGET)

    def ready(self):
        s=self.session();s.ready=True
        s.contexts={'archive-wire':dict(source_sha256=TARGET,packets={
            name:dict(table=table,writer=writer,object_size=self.tags[name]['object_size'],fields=[['u32',16]])
            for name,table,writer in (('game-login','0x1200','0x1500'),('game-version','0x2200','0x2500'))},
            bindings={'string-writer':'0x1a00'},helpers=dict(memcpy='0x1b00')),
            'string-writer':dict(bindings={'string-writer':'0x1a00'})}
        for name,ctor,prep,table in (('game-login','0x1300','0x1400','0x1200'),
                ('game-version','0x2300','0x2400','0x2200')):
            current=dict(source_sha256=TARGET,constructor=ctor,prepare=prep,packet_table=table,
                layout=dict(packet_bytes=self.tags[name]['object_size']),globals=dict(tag_pointer='0x1100'),
                compiled_tag_source=dict(literal='0x1600',value='A'*32))
            s.contexts[self.registry['contracts'][name]['family']]=current
            self.rows[int(ctor,16)]=[dict(mnemonic='lea',operands='rax, [rip + 12]',rip_references=[int(table,16)])]
            struct.pack_into('<Q',self.store.target.data,int(table,16)-0x1000+16,
                int(s.contexts['archive-wire']['packets'][name]['writer'],16))
        s.input_files=dict(s.files)
        s.publications={name:dict(context='fixture '+name) for name in P.FAMILIES}
        return s

    def context(self,name='game-login'):
        return dict(source_sha256=TARGET,contract=dict(id=name,coverage='partial'),
            bindings=dict(bindings={'already':'0x1000'},queue=['constructor:missing','writer:missing','other:pending']))

    def check_report(self,s,context=None,adapter='packet-writer-projection'):
        context=context or self.context()
        value=dict(schema=1,recipe=P.RECIPE,source_sha256=TARGET,contract=context['contract']['id'],adapter=adapter,
            inputs=s.inputs(context,adapter),state='passed',method='static_inheritance',inherited_cases=104,target_native_cases=0,
            runtime_activated=False,profile_activated=False,network_used=False,
            owner_barrier_pending=True,contract_coverage='unchanged')
        ptr=self.put(self.root/'cached/manifest.json',value)
        return context,value,dict(id=adapter,state='passed',report=ptr['path'],sha256=ptr['sha256'])

    def test_constructor_checks_full_historical_provenance_and_records_no_native_cases(self):
        s=self.session()
        self.assertFalse(s.ready);self.assertEqual(s.metrics['target_native_cases'],0)
        self.assertEqual(s.tag_report['kind'],'tags');self.assertGreaterEqual(len(s.files),9)

    def test_selector_absent_or_unknown_recipe(self):
        self.assertTrue(P.enabled(self.index,self.args))
        self.put(self.knowledge/'contract-projections.json',dict(schema=2,recipe=P.RECIPE))
        with self.assertRaises(ValueError):P.enabled(self.index,self.args)
        (self.knowledge/'contract-projections.json').unlink()
        self.assertFalse(P.enabled(self.index,self.args))

    def test_constructor_rejects_short_source_sha_foreign_store_and_memo_digest(self):
        with self.assertRaises(ValueError):P.begin(self.index,self.args,'short')
        self.store.root=self.root.parent
        with self.assertRaisesRegex(ValueError,'another root'):self.session()
        self.store.root=self.root
        self.store.memo=lambda path:digest(path)
        class BoundStore(Store):
            def digest(self,path):return digest(path)
        other=BoundStore(self.root);self.args.source_store=other
        self.index.digest=other.digest
        with self.assertRaisesRegex(ValueError,'original digest'):self.session()

    def test_missing_or_ambiguous_baseline_fact_does_not_admit(self):
        for facts in ([],[dict(id='f'*64),dict(id='f'*64)]):
            ptr=self.put(Path(self.facts['path']),dict(facts=facts))
            self.registry['baseline']['facts']=self.config(ptr,'repository');self.put(self.knowledge/'contract-projections.json',self.registry)
            with self.assertRaisesRegex(ValueError,'missing or ambiguous'):self.session()

    def test_wrong_historical_check_artifact_is_rejected(self):
        pointer=self.registry['baseline']['writer_check'];path=self.root/pointer['path']
        value=json.loads(path.read_bytes());value['definition']['artifacts'][self.artifact['path']]='0'*64
        ptr=self.put(path,value);self.registry['baseline']['writer_check']=self.config(ptr,'library')
        fact=json.loads(Path(self.facts['path']).read_bytes())
        fact['facts'][0]['checks'][0]['sha256']=ptr['sha256']
        self.registry['baseline']['facts']=self.config(self.put(Path(self.facts['path']),fact),'repository')
        self.put(self.knowledge/'contract-projections.json',self.registry)
        with self.assertRaisesRegex(ValueError,'provenance'):self.session()

    def test_historical_fixture_tools_must_match_registered_check_and_current_bytes(self):
        path=self.here/'verify-version-login-context.py';path.write_text('# changed\n')
        with self.assertRaisesRegex(ValueError,'fixture implementation changed'):self.session()

    def test_configured_paths_cannot_escape_or_claim_unknown_base(self):
        s=self.session()
        for pointer in (dict(base='library',path='../outside.json',sha256='0'*64),
                dict(base='unknown',path='x.json',sha256='0'*64),
                dict(base='repository',path=str(self.root/'absolute.json'),sha256='0'*64)):
            with self.subTest(pointer=pointer),self.assertRaises(ValueError):s.configured(pointer)

    def test_pointer_schema_sha_and_library_boundaries_are_enforced(self):
        s=self.session();outside=Path(self.temp.name).resolve()/'outside.json';self.put(outside,dict(x=1))
        for pointer in ({'path':str(outside),'sha256':digest(outside)},dict(self.artifact,sha256='0'*64),
                dict(self.artifact,extra=True),dict(self.artifact,sha256='bad')):
            with self.subTest(pointer=pointer),self.assertRaises(ValueError):s.read(pointer)

    def test_duplicate_json_keys_and_json_budget_are_rejected(self):
        s=self.session();path=self.root/'duplicate.json';path.write_bytes(b'{"x":1,"x":2}')
        with self.assertRaisesRegex(ValueError,'Duplicate'):s.read_path(path)
        budget=self.root/'large.json';budget.write_bytes(b' '*65)
        with patch.object(P,'LIMIT',64),self.assertRaisesRegex(ValueError,'exceeds budget'):s.read_path(budget)

    def test_read_detects_changed_bytes_after_first_pin_even_without_restat(self):
        s=self.session();path=self.root/'mutable.json';self.put(path,dict(value=1))
        s.read_path(path);self.put(path,dict(value=2))
        with self.assertRaisesRegex(ValueError,'JSON changed'):s.read_path(path)

    def test_owner_changes_and_closed_sessions_are_not_reused(self):
        s=self.session();self.args.source_store=Store(self.root)
        with self.assertRaisesRegex(ValueError,'owner changed'):s.project(self.context())
        self.args.source_store=self.store;s.closed=True
        with self.assertRaisesRegex(ValueError,'closed'):s.project(self.context())

    def test_project_keeps_partial_coverage_and_removes_only_filled_binding_gaps(self):
        s=self.ready();original=self.context();projected=s.project(original)
        self.assertEqual(projected['contract']['coverage'],'partial');self.assertEqual(original['bindings']['queue'],['constructor:missing','writer:missing','other:pending'])
        self.assertEqual(projected['bindings']['queue'],['other:pending'])
        self.assertEqual(projected['bindings']['bindings']['constructor'],'0x1300')
        self.assertTrue(projected['projection']['contract_coverage_unchanged'])
        self.assertEqual(projected['contract']['tag_check_by_source'][TARGET]['packet_id'],3)
        self.assertNotIn('wrapper-constructor',projected['bindings']['bindings'])

    def test_not_ready_or_unrelated_contract_is_copied_without_guessing(self):
        s=self.session();context=self.context()
        self.assertEqual(s.project(context),context);self.assertIsNot(s.project(context),context)
        s.ready=True;context['contract']['id']='quests'
        self.assertEqual(s.project(context),context)

    def publication_fixture(self):
        s=self.session();contexts=self.ready().contexts
        declarations=[];checks=[]
        for family in P.FAMILIES:
            pointer=self.put(self.root/('published/'+family+'.json'),contexts[family])
            report=self.put(self.root/('published/'+family+'-check.json'),dict(state='passed'))
            declarations.append(dict(id=family,context=pointer))
            checks.append(dict(id=family,state='passed',report=report['path'],sha256=report['sha256']))
        parent=self
        class Publication:
            files={parent.artifact['path']:parent.artifact['sha256']}
            mutable_files={}
            _aliases={}
            def publish(self,spec,tool,declaration,outcome):
                parent.publication_calls.append(spec['id'])
            def finish(self):return dict(reused=4)
        self.publication=Publication()
        return s,declarations,checks

    def test_prepare_requires_one_admitted_provider_per_family_then_finishes_publication(self):
        s,declarations,checks=self.publication_fixture()
        result=s.prepare(dict(checks=declarations),checks)
        self.assertEqual(result['state'],'ready');self.assertEqual(self.publication_calls,list(P.FAMILIES))
        self.assertEqual(set(s.contexts),set(P.FAMILIES));self.assertEqual(s.input_files,s.files)
        self.assertEqual(s.publication_metrics,dict(reused=4))
        with self.assertRaisesRegex(ValueError,'already selected'):s.prepare(dict(checks=declarations),checks)

    def test_prepare_missing_ambiguous_or_failed_publication_is_explicit_blocker(self):
        for kind in ('missing','ambiguous','admission','absent-file'):
            s,declarations,checks=self.publication_fixture()
            if kind=='missing':declarations.pop()
            elif kind=='ambiguous':checks.append(copy.deepcopy(checks[0]))
            elif kind=='admission':self.publication.publish=lambda *_:(_ for _ in ()).throw(ValueError('proof rejected'))
            else:self.publication.mutable_files={str(self.root/'absent'):None}
            result=s.prepare(dict(checks=declarations),checks)
            self.assertEqual(result['state'],'requires_review');self.assertFalse(s.ready)
            self.assertTrue(result['reason'])

    def test_conflicting_existing_binding_data_and_spec_block_project(self):
        s=self.ready()
        for kind in ('binding','data','spec'):
            context=self.context()
            if kind=='binding':context['bindings']['bindings']['writer']='0xdead'
            elif kind=='data':context['contract']['data_dependencies']={TARGET:{'packet-table':dict(kind='vtable',address='0xdead')}}
            else:context['contract']['tag_check_by_source']={TARGET:dict(packet_id=99)}
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'Conflicting'):s.project(context)

    def test_provider_table_layout_string_and_constructor_links_must_agree(self):
        for mutate in ('table','layout','string','vptr','constructor'):
            s=self.ready()
            if mutate=='table':s.contexts['login-prepare']['packet_table']='0xdead'
            elif mutate=='layout':s.contexts['login-prepare']['layout']['packet_bytes']=1
            elif mutate=='string':s.contexts['string-writer']['bindings']['string-writer']='0xdead'
            elif mutate=='vptr':struct.pack_into('<Q',self.store.target.data,0x210,0xdead)
            else:self.rows[0x1300]=[]
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):s.providers('game-login')

    def test_observe_exact_cached_inputs_counts_inherited_cases_without_native(self):
        s=self.ready();context,_,result=self.check_report(s)
        s.observe(context,'packet-writer-projection',result)
        self.assertEqual(s.metrics['cached_checks'],1);self.assertEqual(s.metrics['inherited_writer_cases'],104)
        self.assertEqual(s.metrics['target_native_cases'],0)
        final=s.finish();self.assertTrue(final['owner_barrier_completed']);self.assertFalse(final['profile_activated']);self.assertFalse(final['live_verified'])
        self.assertEqual(self.store.validations,1)

    def test_cached_provenance_mutations_are_rejected(self):
        for field,mutated in (('source_sha256','c'*64),('contract','game-version'),('adapter','version-login-tag'),
                ('recipe','legacy'),('state','requires_review'),('runtime_activated',True),('profile_activated',True),
                ('network_used',True),('owner_barrier_pending',False),('contract_coverage','complete'),('target_native_cases',1),
                ('target_native_cases',True),('schema',2)):
            s=self.ready();context,value,result=self.check_report(s);value[field]=mutated
            ptr=self.put(Path(result['report']),value);result['sha256']=ptr['sha256']
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'provenance'):s.observe(context,'packet-writer-projection',result)

    def test_cached_inputs_change_in_context_rule_or_publications_is_rejected(self):
        for field in ('context','rule','publications'):
            s=self.ready();context,value,result=self.check_report(s)
            if field=='context':context['contract']['coverage']='complete'
            elif field=='rule':s.rule=dict(s.rule,changed='0'*64)
            else:s.publications['archive-wire']=dict(context='changed')
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'provenance'):s.observe(context,'packet-writer-projection',result)

    def test_cached_result_id_and_unknown_terminal_state_are_rejected(self):
        s=self.ready();context,value,result=self.check_report(s)
        result['id']='version-login-tag'
        with self.assertRaisesRegex(ValueError,'provenance'):s.observe(context,'packet-writer-projection',result)
        s=self.ready();context,value,result=self.check_report(s)
        result['state']=value['state']='unreviewed'
        pointer=self.put(self.root/'cached/unknown.json',value)
        result.update(report=pointer['path'],sha256=pointer['sha256'])
        with self.assertRaisesRegex(ValueError,'provenance'):s.observe(context,'packet-writer-projection',result)

    def test_cached_pass_requires_verified_method_case_count_and_tag_scope(self):
        for name,adapter,method,cases in (
                ('game-login','packet-writer-projection','native',104),
                ('game-login','packet-writer-projection','static_inheritance',56),
                ('game-version','version-login-tag','static_inheritance',4)):
            s=self.ready();context,value,result=self.check_report(s,self.context(name),adapter)
            value.update(method=method,inherited_cases=cases)
            pointer=self.put(Path(result['report']),value);result['sha256']=pointer['sha256']
            with self.subTest(name=name,method=method,cases=cases),self.assertRaisesRegex(ValueError,'case coverage|wrapper link'):
                if name=='game-version':s.contexts['version-prepare']['wrapper_table']='0x2600'
                s.observe(context,adapter,result)

    def test_finish_rehashes_used_files_and_rejects_mutation(self):
        s=self.session();path=Path(self.artifact['path']);path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'input changed'):s.finish()

    def test_finish_rejects_alias_retarget_and_validates_source_store(self):
        s=self.session();lexical=str(self.root/'alias.json');s.aliases[lexical]=self.root/'old.json'
        with self.assertRaisesRegex(ValueError,'alias changed'):s.finish()
        s.aliases.pop(lexical)
        with patch.object(self.store,'validate',side_effect=ValueError('source changed')):
            with self.assertRaisesRegex(ValueError,'source changed'):s.finish()

    def test_transfer_chain_missing_cycle_and_mapping_gaps_are_blockers(self):
        s=self.session();baseline=dict(source_sha256=BASELINE,role='before')
        with self.assertRaisesRegex(ValueError,'does not reach'):s._chain(dict(source_sha256=TARGET),baseline)
        proof=self.put(self.root/'chain.json',dict(baseline=self.artifact,relocation=dict(mapping={})))
        with self.assertRaises(ValueError):s._mapping(dict(source_sha256=TARGET,transfer_proof=proof),baseline,{0x1000})

    def test_transfer_chain_reaches_exact_baseline_and_maps_every_requested_address(self):
        s=self.session();baseline=dict(source_sha256=BASELINE,role='before');ptr=self.put(self.root/'baseline-chain.json',baseline)
        proof=self.put(self.root/'good-chain.json',dict(baseline=ptr,relocation=dict(mapping={'0x1000':'0x2000'})))
        target=dict(source_sha256=TARGET,transfer_proof=proof)
        self.assertEqual(s._mapping(target,baseline,{0x1000}),{'0x1000':'0x2000'})
        with self.assertRaisesRegex(ValueError,'exact instruction'):s._mapping(target,baseline,{0x1001})
        with patch.object(s,'read',side_effect=[dict(baseline=ptr),target]),\
                self.assertRaisesRegex(ValueError,'does not reach'):
            s._chain(target,baseline)

    def tag_ready(self,name):
        s=self.ready();prepare,archive,packet=s.providers(name);old=s.baseline_prepare[name];tag=self.tags[name]
        mapping={old['constructor']:prepare['constructor'],old['prepare']:prepare['prepare']}
        mapping.update({hex(int(old['prepare'],16)+tag[key]):hex(int(prepare['prepare'],16)+tag[key]) for key in ('start_offset','stop_offset')})
        s._mapping=lambda *_:mapping
        data=self.store.target.data
        struct.pack_into('<Q',data,0x100,0x1600);data[0x600:0x621]=b'A'*32+b'\0'
        table=int(packet['table'],16)-0x1000
        struct.pack_into('<Q',data,table+40,0x1700);struct.pack_into('<Q',data,table+56,0x1800)
        data[0x700:0x706]=b'\xb8'+struct.pack('<I',tag['packet_id'])+b'\xc3'
        expected=tag['packet_name'].encode()+b'\0';data[0x900:0x900+len(expected)]=expected
        self.rows[0x1800]=[dict(mnemonic='lea',operands='rdx, [rip + 12]',rip_references=[0x1900])]
        return s

    def test_login_tag_inherits_four_cases_only_after_explicit_source_leaf_and_name_checks(self):
        s=self.tag_ready('game-login');result=s._tag(self.context())
        self.assertEqual(result['state'],'passed');self.assertEqual(result['inherited_cases'],4)
        self.assertEqual(result['target_native_cases'],0);self.assertFalse(result['network_used'])

    def wrapper_ready(self):
        s=self.tag_ready('game-version');context=self.context('game-version')
        context['contract']['bindings']={BASELINE:{'wrapper-constructor':'0x7a00'}}
        old=s.baseline_prepare['game-version'];prepare=s.contexts['version-prepare']
        old['wrapper_table']='0x7900';prepare['wrapper_table']='0x2600'
        candidates={}
        for image,table,root,entry in ((s.before,0x7900,0x7a00,0x7400),(s.source,0x2600,0x2700,0x2400)):
            site=root+0x10;base=image.pe.base
            struct.pack_into('<Q',image.data,table-base+0x48,entry)
            fragment=(root-base,root-base+0x40,1)
            image.containing=lambda at,fragment=fragment:fragment
            image.roots={fragment:fragment}
            candidates[base]=[(site,table)]
            self.rows[root]=[dict(address=site,mnemonic='lea',operands='rax, [rip + 2]',
                bytes='488d0502000000',rip_references=[table]),
                dict(address=site+7,mnemonic='mov',operands='qword ptr [rbx], rax')]
        s.native.rip_candidates=lambda image,_:candidates[image.pe.base]
        return s,context,candidates

    def test_version_wrapper_store_and_slot_allow_static_inheritance(self):
        s,context,_=self.wrapper_ready();result=s._tag(context)
        self.assertEqual(result['state'],'passed')
        self.assertEqual(result['wrapper_link']['constructor'],'0x2700')
        pointer=s.check(context,'version-login-tag');s.observe(context,'version-login-tag',pointer)
        self.assertEqual(s.metrics['inherited_tag_cases'],4)

    def test_version_wrapper_rejects_wrong_store_wrong_slot_and_ambiguity(self):
        for changed in ('store','slot','ambiguous','baseline'):
            s,context,candidates=self.wrapper_ready()
            if changed=='store':self.rows[0x2700][-1]['operands']='qword ptr [rcx], rax'
            elif changed=='slot':struct.pack_into('<Q',s.source.data,0x1648,0x2500)
            elif changed=='ambiguous':
                candidates[0x1000].append((0x2720,0x2600))
                self.rows[0x2700].extend(dict(row,address=row['address']+0x10) for row in self.rows[0x2700][:])
            else:context['contract']['bindings'][BASELINE]['wrapper-constructor']='0x7b00'
            with self.subTest(changed=changed):
                pointer=s.check(context,'version-login-tag')
                self.assertEqual(pointer['state'],'requires_review')
                self.assertIn('wrapper',pointer['reason'])

    def test_tag_failure_matrix_source_data_id_or_name_changes_block_inheritance(self):
        for changed in ('matrix','pointer','id','name'):
            s=self.tag_ready('game-login')
            if changed=='matrix':s.tag_report['reports']['game-login']['cases'][0]['guards']=False
            elif changed=='pointer':struct.pack_into('<Q',self.store.target.data,0x100,0x1601)
            elif changed=='id':self.store.target.data[0x701]=99
            else:self.store.target.data[0x900]=ord('X')
            with self.subTest(changed=changed),self.assertRaises(ValueError):s._tag(self.context())

    def test_check_returns_explicit_blocker_for_unready_publication_and_unknown_adapter(self):
        s=self.session();s.error='missing family'
        result=s.check(self.context(),'packet-writer-projection')
        self.assertEqual(result['state'],'requires_review');self.assertIn('missing family',result['reason'])
        with self.assertRaises(ValueError):s.check(self.context(),'unknown')


if __name__=='__main__':unittest.main()
