"""Synthetic negative admission tests; no Ghidra, native replay or game IO."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


WRITER=load('update-native-string-writer');DRIVERS=load('update-native-drivers')
BASE=0x140000000


class WriterDescribeTests(unittest.TestCase):
    def setUp(self):
        raw=bytearray(4096);struct.pack_into('<I',raw,60,0x80)
        opt=0x80+24;struct.pack_into('<H',raw,opt,0x20b);struct.pack_into('<I',raw,opt+108,16)
        struct.pack_into('<II',raw,opt+112+10*8,0x300,96)
        struct.pack_into('<I',raw,0x300,96);struct.pack_into('<Q',raw,0x300+88,BASE+0x700)
        raw[0x700:0x708]=bytes.fromhex('1122334455667788')
        self.image=SimpleNamespace(data=bytes(raw),pe=SimpleNamespace(base=BASE),offset=lambda rva:rva)
        self.utf8=dict(bindings=dict(length=hex(BASE+0x100),convert=hex(BASE+0x200),encoder=hex(BASE+0x300)),
            helpers=dict(memcpy=hex(BASE+0x1000)))
        self.writer=BASE+0x500
        self.roles=dict(length=BASE+0x100,convert=BASE+0x200,memcpy=BASE+0x1000,
            utf8_allocate=BASE+0x1100,utf8_free=BASE+0x1200,cpp_allocate=BASE+0x1300,
            cpp_free=BASE+0x1400,security_check=BASE+0x1500,exception_0=BASE+0x1600,exception_1=BASE+0x1700)
        self.rows=[]
        for number,role in enumerate(WRITER.CALL_ROLES):
            self.rows.append(dict(address=self.writer+number*8,call=True,branch=False,
                direct_target=self.roles[role],rip_references=[],operands=hex(self.roles[role]),mnemonic='call'))
        self.rows+= [dict(address=self.writer+0x100+number*8,call=True,branch=False,direct_target=None,
            rip_references=[] if number==1 else [BASE+0x900],operands=operand,mnemonic='call')
            for number,operand in enumerate(('qword ptr [rip + 1]','qword ptr [rax + 0x28]','qword ptr [rip + 2]'))]
        self.rows += [dict(address=self.writer+0x180+number*8,call=False,branch=False,direct_target=None,
            rip_references=[address],operands='',mnemonic=mnemonic)
            for number,(address,mnemonic) in enumerate(((BASE+0x700,'mov'),(BASE+0x780,'lea')))]
        fixtures=sorted({value for key,value in self.roles.items() if key not in ('length','convert','memcpy')})
        self.image.roots=[(at-BASE,at-BASE+8) for at in fixtures]
        self.image.containing=lambda at:next((i for i,(start,end) in enumerate(self.image.roots) if BASE+start<=at<BASE+end),None)
        self.bindings=SimpleNamespace(rows=lambda *args:self.rows)
        self.common=SimpleNamespace(memcpy_identity=Mock(),image_bytes=lambda image,at,size:image.data[at-BASE:at-BASE+size])
        self.imports=SimpleNamespace(import_at=Mock(return_value=dict(dll='api-ms-win-crt-runtime-l1-1-0.dll',name='_invalid_parameter_noinfo_noreturn')))
        real=WRITER.load
        def modules(name):
            if name=='update-native-contexts':return self.common
            if name=='build-object-zero-init-code':return self.imports
            return real(name)
        mocked=patch.object(WRITER,'load',side_effect=modules);mocked.start();self.addCleanup(mocked.stop)

    def describe(self):return WRITER.describe(None,self.bindings,self.image,self.writer,self.utf8)

    def test_exact_roles_load_config_cookie_and_import_inputs(self):
        fields=self.describe()
        self.assertEqual(fields['writer_metadata']['cookie'],hex(BASE+0x700))
        self.assertEqual(fields['inputs']['cookie']['bytes'],'1122334455667788')
        self.assertEqual(fields['fixtures']['archive_slot'],40)
        self.assertEqual([row['role'] for row in fields['calls']],list(WRITER.CALL_ROLES))
        self.common.memcpy_identity.assert_called_once()

    def test_repeated_call_target_change_and_fixture_alias_are_rejected(self):
        self.rows[5]['direct_target']=BASE+0x1800
        with self.assertRaisesRegex(ValueError,'repeated'):self.describe()
        self.rows[5]['direct_target']=self.roles['cpp_allocate']
        self.rows[1]['direct_target']=self.roles['cpp_allocate']
        with self.assertRaisesRegex(ValueError,'alias'):self.describe()

    def test_fixture_cannot_overlap_executed_root_or_name_function_interior(self):
        self.rows[1]['direct_target']=self.writer
        with self.assertRaisesRegex(ValueError,'overlap'):self.describe()
        self.rows[1]['direct_target']=self.roles['utf8_allocate']+1
        with self.assertRaisesRegex(ValueError,'unwind root'):self.describe()

    def test_utf8_and_memcpy_links_cannot_be_substituted(self):
        self.rows[0]['direct_target']+=1
        with self.assertRaisesRegex(ValueError,'UTF-8 callee'):self.describe()
        self.rows[0]['direct_target']-=1
        self.rows[3]['direct_target']=self.rows[6]['direct_target']=BASE+0x1800
        with self.assertRaisesRegex(ValueError,'memcpy link'):self.describe()

    def test_archive_slot_and_duplicate_iat_must_match(self):
        self.rows[13]['operands']='qword ptr [rax + 0x30]'
        with self.assertRaisesRegex(ValueError,'archive slot'):self.describe()
        self.rows[13]['operands']='qword ptr [rax + 0x28]'
        self.rows[14]['rip_references']=[BASE+0x908]
        with self.assertRaisesRegex(ValueError,'IAT slots'):self.describe()

    def test_iat_dll_and_symbol_are_both_required(self):
        for value in (dict(dll='other.dll',name='_invalid_parameter_noinfo_noreturn'),
                dict(dll='api-ms-win-crt-runtime-l1-1-0.dll',name='_invalid_parameter')):
            self.imports.import_at.return_value=value
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'IAT identity'):self.describe()

    def test_cookie_must_be_referenced_from_pe_load_config(self):
        self.rows[15]['rip_references']=[BASE+0x708]
        with self.assertRaisesRegex(ValueError,'cookie/literal'):self.describe()

    def test_empty_literal_is_checked_from_target_bytes(self):
        raw=bytearray(self.image.data);raw[0x780]=1;self.image.data=bytes(raw)
        with self.assertRaisesRegex(ValueError,'empty UTF-16'):self.describe()

    def test_external_or_indirect_branch_cannot_enter_unreviewed_code(self):
        self.rows.append(dict(address=self.writer+0x200,call=False,branch=True,direct_target=BASE+0x1900,
            rip_references=[],operands=hex(BASE+0x1900),mnemonic='jmp'))
        with self.assertRaisesRegex(ValueError,'external branch'):self.describe()
        self.rows[-1]['direct_target']=None
        with self.assertRaisesRegex(ValueError,'external branch'):self.describe()

    def test_pe32_or_missing_load_config_cookie_rejected(self):
        raw=bytearray(self.image.data);opt=0x80+24
        for offset,encoding,value in ((opt,'<H',0x10b),(opt+108,'<I',10),(opt+112+10*8+4,'<I',95),(0x300,'<I',95)):
            candidate=bytearray(raw);struct.pack_into(encoding,candidate,offset,value)
            image=SimpleNamespace(data=bytes(candidate),offset=lambda rva:rva)
            with self.subTest(offset=offset),self.assertRaises(ValueError):WRITER.cookie_address(image)


class WriterProofValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve();self.path=self.root/'knowledge/generated-native-contexts/baseline.json'
        self.path.parent.mkdir(parents=True)
        self.sha='a'*64;self.old='b'*64
        self.fields=dict(fixtures=dict(archive_slot=40),writer_metadata=dict(cookie='0x1700'),
            calls=[dict(offset=3,role='length')],inputs=dict(cookie=dict(address='0x1700',bytes='0000000000000000')))
        self.utf8=dict(source_sha256=self.sha,source='target.exe',bindings=dict(length='0x1100',convert='0x1200',encoder='0x1300',**{'string-writer':'0x1400'}),
            helpers=dict(memcpy='0x1500'),encoder_leaf=dict(bytes='c3'))
        self.baseline={**self.utf8,'source_sha256':self.old,**{key:self.fields[key] for key in ('fixtures','writer_metadata')}}
        self.path.write_text(json.dumps(self.baseline))
        self.context=dict(schema=1,source_sha256=self.sha,source='target.exe',family='string-writer',
            bindings=self.utf8['bindings'],encoder_leaf=self.utf8['encoder_leaf'],helpers=self.utf8['helpers'],
            fixtures=self.fields['fixtures'],writer_metadata=self.fields['writer_metadata'],
            verify_whole_exports=True,layout=WRITER.LAYOUT,exports={},transfer_proof=dict(path='proof',sha256='c'*64))
        self.tools={'tool':'d'*64}
        self.proof=dict(schema=1,adapter=WRITER.ADAPTER,scope=WRITER.SCOPE,tools=self.tools,runtime_activated=False,
            target={k:v for k,v in self.context.items() if k not in ('exports','transfer_proof','release_id')},
            baseline=dict(path=str(self.path),sha256='e'*64),utf8=dict(path='utf8',sha256='f'*64),
            calls=self.fields['calls'],relocated_inputs=self.fields['inputs'])
        common=SimpleNamespace(digest=lambda _: 'e'*64,admitted_instructions=Mock(),signature=lambda *_:'shape')
        self.args=SimpleNamespace(root=self.root,source_store=SimpleNamespace(image=lambda *args:object()))
        modules={'update-native-contexts':common,'build-native-entry-code':object(),'update-bindings':SimpleNamespace(rows=lambda *_:[])}
        for name,mock in (('load',patch.object(WRITER,'load',side_effect=lambda name:modules[name])),
                ('tools',patch.object(WRITER,'tools',return_value=self.tools)),
                ('checked',patch.object(WRITER,'checked',side_effect=lambda root,item,category:self.proof if category=='native-string-writer-proofs' else self.utf8)),
                ('coverage',patch.object(WRITER,'export_coverage')),
                ('describe',patch.object(WRITER,'describe',side_effect=lambda *_:copy.deepcopy(self.fields)))):
            mock.start();self.addCleanup(mock.stop)

    def test_valid_source_bound_proof_reaches_only_mocked_static_validation(self):
        self.assertIs(WRITER.validate(None,self.args,self.context),self.context)

    def test_edited_context_scope_layout_or_tools_are_rejected(self):
        for field,value in (('source','substituted.exe'),('layout',{})):
            changed=copy.deepcopy(self.context);changed[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'fields, tools or layout'):
                WRITER.validate(None,self.args,changed)
        self.proof['tools']={'tool':'0'*64}
        with self.assertRaisesRegex(ValueError,'tools'):WRITER.validate(None,self.args,self.context)

    def test_target_utf8_source_call_metadata_and_data_are_rejected(self):
        self.utf8['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'UTF-8 source'):WRITER.validate(None,self.args,self.context)
        self.utf8['source_sha256']=self.sha
        for key in ('calls','relocated_inputs'):
            saved=self.proof[key];self.proof[key]={}
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'relocated data, calls'):
                WRITER.validate(None,self.args,self.context)
            self.proof[key]=saved

    def test_baseline_fixture_metadata_cannot_be_redeclared(self):
        baseline=copy.deepcopy(self.baseline);baseline['writer_metadata']['cookie']='0xdeadbeef'
        self.path.write_text(json.dumps(baseline))
        with self.assertRaisesRegex(ValueError,'baseline layout/call roles'):WRITER.validate(None,self.args,self.context)

    def test_baseline_path_scope_and_proof_cycle_are_rejected(self):
        self.proof['baseline']['path']=str(self.root/'outside.json')
        with self.assertRaisesRegex(ValueError,'outside reviewed'):WRITER.validate(None,self.args,self.context)
        self.proof['baseline']['path']=str(self.path)
        with self.assertRaisesRegex(ValueError,'cycle/depth'):WRITER.validate(None,self.args,self.context,seen={'c'*64})

    def test_same_target_discovery_reuses_context_without_new_receipt_chain(self):
        registry=dict(releases=[])
        module=SimpleNamespace(read=lambda _:registry)
        common=SimpleNamespace()
        def load(name):return common if name=='update-native-contexts' else module
        args=SimpleNamespace(root=self.root,knowledge=self.root/'knowledge')
        with patch.object(WRITER,'load',side_effect=load),\
                patch.object(WRITER,'published_contexts',return_value=[(self.path,self.context,1)]),\
                patch.object(WRITER,'validate',return_value=self.context) as validate:
            first=WRITER.discover(None,args,self.sha)
            second=WRITER.discover(None,args,self.sha)
        self.assertEqual(first,second)
        self.assertEqual(first['context']['transfer_proof'],self.context['transfer_proof'])
        self.assertEqual(validate.call_count,2)


class WriterFixtureBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.address=BASE+0x100;self.target=BASE+0x300
        self.prefix=bytes.fromhex('4885c9b801000000ba10000000480f45c1488bc8')
        self.raw=bytearray(4096)
        self.image=SimpleNamespace(data=self.raw,pe=SimpleNamespace(base=BASE),roots=[(0x300,0x320)],
            containing=lambda at:0 if BASE+0x300<=at<BASE+0x320 else None)
        common=SimpleNamespace(image_bytes=lambda image,at,size:bytes(image.data[at-BASE:at-BASE+size]))
        mocked=patch.object(WRITER,'load',return_value=common);mocked.start();self.addCleanup(mocked.stop)

    def allocation(self,target=None):
        target=self.target if target is None else target
        self.raw[0x100:0x119]=self.prefix+b'\xe9'+struct.pack('<i',target-self.address-25)

    def test_exact_allocation_tail_names_unwind_root_without_executing_it(self):
        self.allocation()
        self.assertEqual(WRITER.fixture_boundary(self.image,'cpp_allocate',self.address,{}),
            dict(kind='allocate-tail',target=hex(self.target),size=25,alignment=16,minimum=1))

    def test_changed_minimum_prefix_or_alignment_are_not_generalized(self):
        for offset,value in ((4,2),(9,32),(13,0x49)):
            self.allocation();self.raw[0x100+offset]=value
            with self.subTest(offset=offset),self.assertRaisesRegex(ValueError,'reviewed tail'):
                WRITER.fixture_boundary(self.image,'cpp_allocate',self.address,{})

    def test_free_tail_requires_exact_utf8_free_role(self):
        self.raw[0x100:0x105]=b'\xe9'+struct.pack('<i',self.target-self.address-5)
        self.assertEqual(WRITER.fixture_boundary(self.image,'cpp_free',self.address,dict(utf8_free=self.target)),
            dict(kind='free-tail',target=hex(self.target),size=5))
        with self.assertRaisesRegex(ValueError,'reviewed tail'):
            WRITER.fixture_boundary(self.image,'cpp_free',self.address,dict(utf8_free=self.target+16))
        self.raw[0x100]=0xe8
        with self.assertRaisesRegex(ValueError,'reviewed tail'):
            WRITER.fixture_boundary(self.image,'cpp_free',self.address,dict(utf8_free=self.target))

    def test_allocation_tail_must_not_target_function_interior(self):
        self.allocation(self.target+1)
        with self.assertRaisesRegex(ValueError,'reviewed tail'):
            WRITER.fixture_boundary(self.image,'cpp_allocate',self.address,{})
        self.assertEqual(WRITER.fixture_boundary(self.image,'cpp_allocate',self.target,{}),dict(kind='unwind-root'))


class WriterDriverTests(unittest.TestCase):
    def test_plan_key_tracks_baseline_registry_and_export_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);knowledge=root/'definitions';contexts=knowledge/'native-contexts';contexts.mkdir(parents=True)
            baseline=contexts/'string-writer-fixture.json';baseline.write_text('{"revision":1}')
            registry_path=knowledge/'native-release-registry.json';registry_path.write_text('{"schema":1}')
            sha='a'*64;before='b'*64
            export=root/'ghidra/request-exports'/before/'run-fixture/details.json';export.parent.mkdir(parents=True);export.write_text('{}')
            value=dict(source_sha256=before,exports={'run-fixture':'c'*64})
            args=SimpleNamespace(root=root,knowledge=knowledge)
            index=SimpleNamespace(digest=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest())
            modules={'native-release-registry':SimpleNamespace(read=lambda _:dict(releases=[])),
                'update-native-contexts':SimpleNamespace()}
            with patch.object(WRITER,'load',side_effect=lambda name:modules[name]),\
                    patch.object(WRITER,'baseline_context',return_value=(baseline,value)),patch.object(WRITER,'tools',return_value={'tool':'d'*64}):
                first=WRITER.plan_inputs(index,args,sha)
                self.assertEqual(first,WRITER.plan_inputs(index,args,sha))
                baseline.write_text('{"revision":2}');second=WRITER.plan_inputs(index,args,sha)
                self.assertNotEqual(first,second)
                registry_path.write_text('{"schema":1,"new_release":true}');third=WRITER.plan_inputs(index,args,sha)
                self.assertNotEqual(second,third)
                export.write_text('{"updated":true}');fourth=WRITER.plan_inputs(index,args,sha)
                self.assertNotEqual(third,fourth)

    def test_plan_key_ignores_unrelated_generated_index_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);knowledge=root/'definitions';contexts=knowledge/'native-contexts';contexts.mkdir(parents=True)
            baseline=contexts/'string-writer-fixture.json';baseline.write_text('{}')
            (knowledge/'native-release-registry.json').write_text('{}')
            value=dict(source_sha256='b'*64,exports={});sha='a'*64
            folder=root/'knowledge/generated-native';folder.mkdir(parents=True)
            selected=dict(context=dict(path='selected',sha256='c'*64),check=dict(path='selected-check',sha256='d'*64),order=1)
            unrelated=dict(context=dict(path='unrelated',sha256='e'*64),check=dict(path='unrelated-check',sha256='f'*64),order=2)
            path=folder/'index.json';path.write_text(json.dumps(dict(schema=1,contexts=[selected])))
            args=SimpleNamespace(root=root,knowledge=knowledge)
            index=SimpleNamespace(digest=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest())
            modules={'native-release-registry':SimpleNamespace(read=lambda _:dict(releases=[])),
                'update-native-contexts':SimpleNamespace()}
            def checked(root,item,category):return dict(source_sha256=sha if item['path']=='selected' else '0'*64)
            with patch.object(WRITER,'load',side_effect=lambda name:modules[name]),\
                    patch.object(WRITER,'baseline_context',return_value=(baseline,value)),\
                    patch.object(WRITER,'checked',side_effect=checked),patch.object(WRITER,'tools',return_value={}):
                first=WRITER.plan_inputs(index,args,sha)
                path.write_text(json.dumps(dict(schema=1,contexts=[selected,unrelated])))
                self.assertEqual(first,WRITER.plan_inputs(index,args,sha))

    def test_publication_rejects_bad_semantic_report_before_atomic_index_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);sha='a'*64
            context=dict(family='string-writer',source_sha256=sha,bindings={'string-writer':'0x1400'},
                transfer_proof=dict(path='proof',sha256='c'*64))
            declaration=dict(context=dict(path='context',sha256='d'*64))
            outcome=dict(state='passed',report='check',sha256='e'*64)
            valid=dict(source_sha256=sha,scope=WRITER.SCOPE,method='bounded_native',runtime_activated=False,
                network_used=False,profile_activated=False,proof=context['transfer_proof'],bindings=context['bindings'],
                context_sha256='d'*64,cases=[dict(guards=True)]*228)
            workflow=SimpleNamespace(atomic=Mock(),canonical=lambda value:json.dumps(value).encode())
            registry=SimpleNamespace(read=lambda _:dict(releases=[dict(source_sha256=sha,order=1)]))
            modules={'native-release-registry':registry,'research-workflow':workflow}
            args=SimpleNamespace(root=root,knowledge=root/'knowledge')
            index=SimpleNamespace(digest=lambda _:'f'*64)
            for changes in (dict(scope='function_only'),dict(cases=[dict(guards=True)]),dict(cases=[dict(guards=False)]*228)):
                report={**valid,**changes}
                def checked(root,item,category):return context if category=='generated-native-contexts' else report
                with self.subTest(changes=tuple(changes)),patch.object(WRITER,'checked',side_effect=checked),\
                        patch.object(WRITER,'validate',return_value=context),patch.object(WRITER,'load',side_effect=lambda name:modules[name]):
                    with self.assertRaisesRegex(ValueError,'reviewed native proof'):
                        WRITER.publish(index,args,sha,declaration,outcome)
                workflow.atomic.assert_not_called()

    def test_registry_is_explicit_and_rejects_unknown_adapter_or_extra_entry(self):
        expected=[dict(id='native-auto-string-writer',family='string-writer',adapter='string-writer-v1')]
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary);index=SimpleNamespace(read_json=lambda p:json.loads(p.read_text()))
            self.assertEqual(DRIVERS.registry(index,folder),[])
            path=folder/'native-check-adapters.json';path.write_text(json.dumps(dict(schema=1,adapters=expected)))
            self.assertEqual(DRIVERS.registry(index,folder),expected)
            for value in (dict(schema=2,adapters=expected),dict(schema=1,adapters=expected+expected),
                    dict(schema=1,adapters=[{**expected[0],'adapter':'arbitrary-command'}])):
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError,'Unreviewed'):DRIVERS.registry(index,folder)

    def test_merge_replaces_only_covered_family_marker_and_keeps_failed_adapter(self):
        native=dict(queue=[dict(family='string-writer',reason='unsupported_native_adapter'),
            dict(family='world',reason='unsupported_native_adapter'),
            dict(reason='unregistered_native_suite_families',families=['string-writer','archive-wire'])],
            checks=[],family_coverage=[dict(family='string-writer',adapter='unsupported'),dict(family='world',adapter='unsupported')])
        extra=dict(families=['string-writer'],queue=[dict(family='string-writer',reason='ambiguous_candidate')],
            declarations=[dict(id='writer')],checks=[dict(id='writer',state='failed')]);checks=[]
        DRIVERS.merge(native,checks,extra)
        self.assertIn(dict(family='world',reason='unsupported_native_adapter'),native['queue'])
        self.assertIn(dict(reason='unregistered_native_suite_families',families=['archive-wire']),native['queue'])
        self.assertIn(extra['queue'][0],native['queue']);self.assertEqual(checks,extra['checks'])
        self.assertEqual(native['family_coverage'][1]['adapter'],'unsupported')


if __name__=='__main__':unittest.main()
