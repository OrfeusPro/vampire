"""Reviewed-context catalog selection, provenance and real bounded resolver fixtures."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_bindings import BindingTests
from test_vampir_update_contracts import load

class FunctionReusePlanTests(unittest.TestCase):
    setUp=BindingTests.setUp
    image=BindingTests.image

    def setup_catalog(self):
        old=self.image(0x1000);new=self.image(0x1020)
        module=load('function-reuse-plan')
        module.SOURCES={'11316':old,'11318':new}
        knowledge=self.root/'knowledge-src';(knowledge/'native-contexts').mkdir(parents=True)
        self.addCleanup(lambda:None)
        return module,knowledge,old,new

    def context(self,module,knowledge,source,family,version,functions):
        native=load('build-native-entry-code');bindings=load('update-bindings')
        raw=(self.root/'client-code-snapshots'/source/'ProjectRED-Win64-Shipping.exe').read_bytes()
        image=native.Image(raw)
        addresses=sorted(set(functions.values() if isinstance(functions,dict) else functions))
        rows=[]
        for address in addresses:
            try:instructions=bindings.rows(native,image,int(address,16))
            except ValueError:continue
            rows.append(dict(address=address,instructions=[dict(address=hex(r['address']),bytes=r['bytes']) for r in instructions]))
        report=dict(new_source_sha256=source,functions=rows)
        export=self.root/'ghidra/request-exports'/source/('run-'+family+version)/'details.json'
        export.parent.mkdir(parents=True,exist_ok=True)
        export.write_text(json.dumps(report),encoding='utf-8')
        value=dict(source_sha256=source,functions=functions,exports={export.parent.name:hashlib.sha256(export.read_bytes()).hexdigest()})
        path=knowledge/'native-contexts'/(family+'-'+version+'.json')
        path.write_text(json.dumps(value),encoding='utf-8');return path,export

    def test_latest_role_selection_deduplicates_and_keeps_old_dependency_direct(self):
        module,knowledge,old,new=self.setup_catalog()
        self.context(module,knowledge,old,'packet','11316',dict(main='0x140001000',helper='0x140001040'))
        self.context(module,knowledge,new,'packet','11318',dict(helper='0x140001040'))
        result=module.build(self.root,knowledge,new)
        self.assertEqual(result['summary']['functions'],3)
        self.assertEqual(result['summary']['verified'],3)
        self.assertEqual(result['summary']['baseline_counts'],{old:2,new:1})
        oldhelper=next(r for r in result['inventory'] if r['source_sha256']==old and r['address']=='0x140001040')
        self.assertTrue(oldhelper['dependency_added'])
        self.assertTrue(all(r['search_window']==65536 for c in result['contracts'] for r in c['recipes']))
        self.assertFalse(result['runtime_activated']);self.assertFalse(result['profile_activated'])

    def test_real_planner_receipt_is_accepted_by_update_adoption(self):
        module,knowledge,old,new=self.setup_catalog()
        self.context(module,knowledge,old,'packet','11316',dict(helper='0x140001040'))
        report=module.build(self.root,knowledge,new)
        index=load('knowledge-index').api();engine=load('update-run');workflow=load('research-workflow')
        path=workflow.snapshot(self.root,'function-reuse-catalog',report)
        result=dict(report=str(path),sha256=index.digest(path))
        model=dict(contracts=[dict(id='fixture',recipes=[dict(key='helper',method='reviewed')],
            bindings={old:dict(helper='0x140001040')})])
        contexts=dict(contracts={'fixture':dict(bindings={},queue=['helper: missing or ambiguous reviewed candidate'])})
        with patch.object(index,'extension',return_value=module):
            revised=engine.apply_function_reuse(index,self.root,model,contexts,new,result)
        self.assertEqual(revised['contracts']['fixture']['bindings'],dict(helper='0x140001040'))
        # Newer unresolved declaration must block the older verified function.
        model['contracts'][0]['bindings'][new]=dict(helper='0x140001060')
        with patch.object(index,'extension',return_value=module):
            self.assertEqual(engine.apply_function_reuse(index,self.root,model,contexts,new,result),contexts)

    def test_context_change_between_inventory_reads_cannot_prove_old_body(self):
        module,knowledge,old,new=self.setup_catalog()
        path,_=self.context(module,knowledge,old,'packet','11316',dict(helper='0x140001040'))
        original=module.inventory;calls=[]
        def changed(*args):
            value=original(*args);calls.append(1)
            if len(calls)==1:
                data=json.loads(path.read_text());data['functions']['helper']='0x140001060'
                path.write_text(json.dumps(data),encoding='utf-8')
            return value
        with patch.object(module,'inventory',side_effect=changed):
            try:report=module.build(self.root,knowledge,new)
            except ValueError:return
        self.assertEqual(report['summary']['verified'],0)

    def test_same_address_work_is_deduplicated_but_alias_provenance_preserved(self):
        module,knowledge,old,new=self.setup_catalog()
        self.context(module,knowledge,old,'one','11316',dict(helper='0x140001040'))
        self.context(module,knowledge,old,'two','11316',['0x140001040'])
        value=module.build(self.root,knowledge,new)
        self.assertEqual(value['summary']['roles'],2);self.assertEqual(value['summary']['functions'],1)
        self.assertEqual(len(value['inventory'][0]['aliases']),2)
        self.assertIn('covering_export',value['inventory'][0])
        self.assertEqual(value['summary']['verified'],1)

    def dependency_context(self,module,knowledge,source,functions):
        path,export=self.context(module,knowledge,source,'dependencies','11316',functions)
        value=json.loads(path.read_text());value['dependency_only']=True
        path.write_text(json.dumps(value),encoding='utf-8');return path

    def test_dependency_only_is_reached_by_call_without_becoming_a_primary_role(self):
        module,knowledge,old,new=self.setup_catalog()
        self.context(module,knowledge,old,'packet','11316',dict(main='0x140001000'))
        self.dependency_context(module,knowledge,old,dict(helper='0x140001040'))
        value=module.build(self.root,knowledge,new);summary=value['summary']
        self.assertEqual(summary['roles'],1);self.assertEqual(summary['primary_functions'],1)
        self.assertEqual(summary['primary_verified'],1);self.assertEqual(summary['dependency_declarations'],1)
        self.assertEqual(summary['dependency_functions'],1);self.assertEqual(summary['dependency_verified'],1)
        self.assertEqual(summary['verified'],2)
        helper=next(r for r in value['inventory'] if r['address']=='0x140001040')
        self.assertTrue(helper['dependency_added'])

    def test_unused_dependency_is_not_analysed_or_counted_as_a_role(self):
        module,knowledge,old,new=self.setup_catalog()
        path=self.dependency_context(module,knowledge,old,dict(helper='0x140001040'))
        value=module.build(self.root,knowledge,new)
        self.assertEqual(value['summary']['functions'],0);self.assertEqual(value['summary']['roles'],0)
        self.assertEqual(value['contracts'],[]);self.assertEqual(value['inventory'],[])
        data=json.loads(path.read_text());data['dependency_only']='true';path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'must be boolean'):module.build(self.root,knowledge,new)

    def test_undeclared_callee_stays_queued_without_partial_equivalence_admission(self):
        module,knowledge,old,new=self.setup_catalog()
        self.context(module,knowledge,old,'packet','11316',dict(main='0x140001000'))
        value=module.build(self.root,knowledge,new)
        self.assertEqual(value['summary']['verified'],0)
        self.assertEqual(value['contracts'],[])
        self.assertTrue(any('undeclared_callee' in reason for q in value['queue'] for reason in q.get('reasons',[])))
        frontier=value['dependency_frontier']
        self.assertEqual(len(frontier),1);self.assertFalse(frontier[0]['declared'])
        self.assertEqual(frontier[0]['address'],'0x140001040');self.assertEqual(frontier[0]['direct_consumers'],1)
        self.assertEqual(frontier[0]['reasons'],['dependency_not_declared'])

    def test_frontier_counts_functions_once_and_distinguishes_unverified_target(self):
        module,knowledge,old,new=self.setup_catalog();changed=self.image(0x1020,callee_value=8)
        self.context(module,knowledge,old,'one','11316',dict(main='0x140001000'))
        self.context(module,knowledge,old,'two','11316',dict(main='0x140001000'))
        self.dependency_context(module,knowledge,old,dict(helper='0x140001040'))
        value=module.build(self.root,knowledge,changed)
        frontier=value['dependency_frontier'];self.assertEqual(len(frontier),1)
        self.assertEqual(frontier[0]['direct_consumers'],1);self.assertTrue(frontier[0]['declared'])
        self.assertEqual(frontier[0]['reasons'],['target_shape_not_verified'])
        self.assertEqual(value['summary']['primary_requires_review'],1)

    def test_missing_unwind_root_is_a_named_queue_not_guessed_leaf(self):
        module,knowledge,old,new=self.setup_catalog()
        self.context(module,knowledge,old,'packet','11316',dict(leaf='0x140001060'))
        value=module.build(self.root,knowledge,new)
        self.assertEqual(value['summary']['verified'],0)
        self.assertEqual(value['summary']['requires_review'],1)
        self.assertTrue(any('unwind root' in reason for q in value['queue'] for reason in q.get('reasons',[])))

    def test_source_or_export_mutation_rejects_catalog_before_cache(self):
        module,knowledge,old,new=self.setup_catalog()
        path,export=self.context(module,knowledge,old,'packet','11316',dict(helper='0x140001040'))
        first=module.inputs(self.root,knowledge)
        self.assertTrue(first['present']);self.assertTrue(first['exports'])
        export.write_bytes(export.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'export changed'):module.inputs(self.root,knowledge)

    def test_plan_only_never_calls_target_resolver(self):
        module,knowledge,old,new=self.setup_catalog()
        self.context(module,knowledge,old,'packet','11316',dict(helper='0x140001040'))
        original=module.load;bindings=original('update-bindings')
        with patch.object(bindings,'resolve',side_effect=AssertionError('Plan-only must not resolve')),patch.object(module,'load',side_effect=lambda n:bindings if n=='update-bindings' else original(n)):
            value=module.build(self.root,knowledge,new,execute=False)
        self.assertEqual(value['summary']['planned'],1);self.assertEqual(value['summary']['verified'],0)
        self.assertFalse(value['summary']['executed'])

    def test_unknown_source_declaration_does_not_mask_gap(self):
        module,knowledge,old,new=self.setup_catalog()
        path,_=self.context(module,knowledge,old,'packet','11316',dict(helper='0x140001040'))
        data=json.loads(path.read_text());data['source_sha256']='f'*64;path.write_text(json.dumps(data))
        value=module.build(self.root,knowledge,new)
        self.assertEqual(value['summary']['functions'],0)
        self.assertTrue(any(q.get('reason')=='context_source_not_verified' for q in value['queue']))

    def test_latest_11320_alias_replaces_18_and_16_role(self):
        module,knowledge,old,middle=self.setup_catalog();new=self.image(0x1060)
        module.SOURCES['11320']=new
        self.context(module,knowledge,old,'login-result','11316',dict(reader='0x140001000',helper='0x140001040'))
        self.context(module,knowledge,middle,'login-result','11318',dict(reader='0x140001020',helper='0x140001040'))
        self.context(module,knowledge,new,'login-nested','11320',dict(reader='0x140001060',helper='0x140001040'))
        value=module.build(self.root,knowledge,new)
        self.assertEqual(value['summary']['baseline_counts'],{old:0,middle:0,new:2})
        self.assertEqual(value['summary']['primary_verified'],2)
        aliases=[a for row in value['inventory'] for a in row['aliases'] if a['version']=='11320']
        self.assertTrue(all(a['family']=='login-result' and a['declared_family']=='login-nested' for a in aliases))

    def test_input_and_native_input_roles_share_explicit_latest_identity(self):
        module,knowledge,old,middle=self.setup_catalog();new=self.image(0x1060)
        module.SOURCES['11320']=new
        for source,family,version,group in ((middle,'login-result-input','11318','native_input'),(new,'login-input','11320','input')):
            path,_=self.context(module,knowledge,source,family,version,dict(scalar='0x140001040'))
            data=json.loads(path.read_text());data['functions']={}
            data[group]=dict(functions=dict(scalar='0x140001040'))
            if version=='11318':data[group]['source_sha256']=source
            path.write_text(json.dumps(data))
        value=module.build(self.root,knowledge,new)
        self.assertEqual(value['summary']['primary_functions'],1)
        self.assertEqual(value['inventory'][0]['source_sha256'],new)
        self.assertTrue(any(a['role']=='input:functions:scalar' for a in value['inventory'][0]['aliases']))
        self.assertNotIn('login-strings-buffer',module.FAMILY_ALIASES.get('11318',{}))
        self.assertNotEqual(module.FAMILY_ALIASES['11320']['login-strings-buffer'],'login-result-string')

    def test_nested_source_and_invalid_export_are_rejected(self):
        module,knowledge,old,new=self.setup_catalog()
        path,_=self.context(module,knowledge,old,'packet','11316',dict(helper='0x140001040'))
        data=json.loads(path.read_text())
        data['native_input']=dict(source_sha256='f'*64,functions=dict(helper='0x140001040'))
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'Nested input source differs'):module.inventory(self.root,knowledge)
        data['native_input']['source_sha256']=old
        data['native_input']['exports']={'run-unknown':'not-a-sha'}
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'Invalid explicit context export'):module.inventory(self.root,knowledge)
        data['native_input']['exports']={next(iter(data['exports'])):'e'*64}
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'Conflicting nested input export'):module.inventory(self.root,knowledge)

    def test_nested_exports_cover_roots_and_dependency_only_stays_non_primary(self):
        module,knowledge,old,new=self.setup_catalog()
        path,_=self.context(module,knowledge,old,'packet','11316',dict(main='0x140001000'))
        material,_=self.context(module,knowledge,old,'nested-material','11316',dict(helper='0x140001040'))
        helper=json.loads(material.read_text());material.unlink()
        value=json.loads(path.read_text());value['native_input']=dict(source_sha256=old,
            functions=dict(helper='0x140001040'),exports=helper['exports']);value['dependency_only']=True
        path.write_text(json.dumps(value))
        report=module.build(self.root,knowledge,new)
        self.assertEqual(report['summary']['roles'],0)
        self.assertEqual(report['summary']['dependency_declarations'],2)
        self.assertEqual(report['summary']['primary_functions'],0)
        contexts,exports,_,_=module.inventory(self.root,knowledge)
        self.assertEqual(len(contexts[0]['exports']),2)
        self.assertEqual(len(exports),2)

    def test_conflicting_nested_aliases_cannot_silently_replace_a_role(self):
        module,knowledge,old,new=self.setup_catalog()
        path,_=self.context(module,knowledge,old,'packet','11316',dict(helper='0x140001040'))
        data=json.loads(path.read_text());data['input']=dict(functions=dict(scalar='0x140001000'))
        data['native_input']=dict(functions=dict(scalar='0x140001040'))
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'Conflicting normalized nested input role'):module.inventory(self.root,knowledge)

    def test_reviewed_11322_role_blocks_20_fallback_without_22_proof(self):
        module,knowledge,_,_=self.setup_catalog()
        self.assertIn('11322',load('function-reuse-plan').SOURCES)
        twenty=self.image(0x1060);twentytwo=self.image(0x1080);target=self.image(0x10a0)
        module.SOURCES={'11320':twenty,'11322':twentytwo}
        self.context(module,knowledge,twenty,'packet','11320',dict(helper='0x140001040'))
        report=module.build(self.root,knowledge,target)
        self.assertEqual(report['summary']['verified'],1)
        index=load('knowledge-index').api();engine=load('update-run');workflow=load('research-workflow')
        path=workflow.snapshot(self.root,'function-reuse-catalog',report)
        result=dict(report=str(path),sha256=index.digest(path))
        model=dict(contracts=[dict(id='fixture',recipes=[dict(key='helper',method='reviewed')],
            bindings={twenty:dict(helper='0x140001040'),twentytwo:dict(helper='0x140001040')})])
        contexts=dict(contracts={'fixture':dict(bindings={},queue=['helper: missing or ambiguous reviewed candidate'])})
        with patch.object(index,'extension',return_value=module):
            self.assertEqual(engine.apply_function_reuse(index,self.root,model,contexts,target,result),contexts)
            # The old proof exists and is usable only when no newer role is declared.
            del model['contracts'][0]['bindings'][twentytwo]
            revised=engine.apply_function_reuse(index,self.root,model,contexts,target,result)
            self.assertEqual(revised['contracts']['fixture']['bindings'],dict(helper='0x140001040'))

def load_tests(loader,tests,pattern):
    return loader.loadTestsFromTestCase(FunctionReusePlanTests)

if __name__=='__main__':unittest.main()
