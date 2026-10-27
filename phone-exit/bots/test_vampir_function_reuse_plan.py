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

    def test_undeclared_callee_stays_queued_without_partial_equivalence_admission(self):
        module,knowledge,old,new=self.setup_catalog()
        self.context(module,knowledge,old,'packet','11316',dict(main='0x140001000'))
        value=module.build(self.root,knowledge,new)
        self.assertEqual(value['summary']['verified'],0)
        self.assertEqual(value['contracts'],[])
        self.assertTrue(any('undeclared_callee' in reason for q in value['queue'] for reason in q.get('reasons',[])))

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

def load_tests(loader,tests,pattern):
    return loader.loadTestsFromTestCase(FunctionReusePlanTests)

if __name__=='__main__':unittest.main()
