"""Function-only equivalence skips duplicate Ghidra work, never semantic checks."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from test_vampir_update_contracts import load
from test_vampir_update_run import UpdateRunTests

ADDRESS='0x140001000'
SHAPE='a'*64

def context(sha):
 return dict(bindings={'helper':ADDRESS},queue=[],closed_shapes={'helper':SHAPE},verification={
  'helper':dict(state='unchanged',baseline_sha256=sha,baseline_address=ADDRESS,address=ADDRESS,
   closed_shape_sha256=SHAPE,scope='declared_instruction_callee_data_closure',runtime_activated=False)})

class FunctionReuseExportTests(unittest.TestCase):
 def setUp(self):
  self.fixture=UpdateRunTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.engine=self.fixture.engine;self.index=self.fixture.api;self.workflow=self.fixture.workflow
  self.root=self.fixture.root;self.sha=self.fixture.sha;self.args=self.fixture.args
  self.value=context(self.sha)
 def collect(self,contexts):
  db=SimpleNamespace(close=Mock())
  with patch.object(self.index,'open_index',return_value=db),patch.object(self.index,'build') as build, \
    patch.object(self.workflow,'function_state',return_value=dict(state='ready',variants=[])) as state, \
    patch.object(self.workflow,'collector',side_effect=AssertionError('No Ghidra')):
   result=self.engine.collect_batches(self.index,self.workflow,SimpleNamespace(),self.args,
    self.root/'unused.sqlite3',dict(source_sha256=self.sha,contracts=contexts),self.sha)
  return result,state,build
 def test_verified_equivalence_skips_export_and_keeps_separate_receipt(self):
  result,state,build=self.collect({'fixture':self.value})
  self.assertEqual(len(result),1);self.assertEqual(result[0]['state'],'equivalent')
  self.assertEqual(result[0]['artifacts'],[]);state.assert_not_called();build.assert_not_called()
  receipt=self.index.read_json(Path(result[0]['report']))
  self.assertEqual(receipt['scope'],'function_only');self.assertFalse(receipt['runtime_activated'])
  self.assertFalse(receipt['semantic_checks_bypassed']);self.assertEqual(receipt['source_identities'],[self.sha])
  self.assertTrue(self.engine.export_satisfies(self.index,self.root,self.sha,'fixture',self.value,result[0]))
 def test_missing_or_malformed_closure_never_skips_export(self):
  for changes in ({'state':'candidate'},{'closed_shape_sha256':'b'*64},{'runtime_activated':True},
      {'address':'0x140002000'},{'baseline_sha256':'short'},{'scope':'name_only'},{'baseline_address':'0x140002000'}):
   value=copy.deepcopy(self.value);value['verification']['helper'].update(changes)
   with self.subTest(changes=changes):
    result,state,build=self.collect({'fixture':value})
    self.assertEqual(result[0]['state'],'ready');self.assertEqual(state.call_count,2)
  value=copy.deepcopy(self.value);value['closed_shapes']={}
  self.assertEqual(self.engine.function_equivalences(dict(contracts={'fixture':value}),self.sha),{})
 def test_shared_address_unknown_consumer_requires_actual_export(self):
  other=dict(bindings={'unknown':ADDRESS},queue=[],closed_shapes={},verification={})
  result,state,build=self.collect({'fixture':self.value,'other':other})
  self.assertEqual(result[0]['state'],'ready');self.assertEqual(state.call_count,2)
 def test_changed_receipt_or_wrong_scope_cannot_satisfy_contract(self):
  result,_,_=self.collect({'fixture':self.value});export=result[0]
  other=copy.deepcopy(self.value);other['verification']['helper']['state']='requires_review'
  self.assertFalse(self.engine.export_satisfies(self.index,self.root,self.sha,'fixture',other,export))
  self.assertFalse(self.engine.export_satisfies(self.index,self.root,'b'*64,'fixture',self.value,export))
  path=Path(export['report']);path.write_bytes(path.read_bytes()+b' ')
  self.assertFalse(self.engine.export_satisfies(self.index,self.root,self.sha,'fixture',self.value,export))
 def test_changed_full_snapshot_rejects_receipt_before_export(self):
  source=self.root/'client-code-snapshots'/self.sha/'ProjectRED-Win64-Shipping.exe'
  source.write_bytes(source.read_bytes()+b'changed')
  with self.assertRaisesRegex(ValueError,'snapshot changed'):self.collect({'fixture':self.value})
 def test_semantic_requires_port_is_preserved_despite_equivalent_function(self):
  f=self.fixture
  f.contracts['contracts'][0]['bindings']={self.sha:{'helper':ADDRESS}}
  f.contracts['contracts'][0]['recipes']=[dict(key='helper',method='reviewed')]
  (f.knowledge/'update-contracts.json').write_text(json.dumps(f.contracts),encoding='utf-8')
  with patch.object(f.bindings,'resolve',return_value=dict(source_sha256=self.sha,contracts={'fixture':self.value})), \
      patch.object(f.workflow,'run_checks',return_value=[dict(id='fixture-check',state='requires_port')]), \
      patch.object(f.update,'execute_adapter',return_value=dict(state='passed',result=dict(candidates=[]))), \
      patch.object(f.workflow,'collector',side_effect=AssertionError('No duplicate Ghidra')):
   result=self.engine.run(self.index,self.args,self.root/'knowledge/search.sqlite3')
  self.assertEqual(result['state'],'needs_review');self.assertFalse(result['profile_activation'])
  self.assertEqual(result['capabilities']['fixture']['state'],'incomplete')
  saved=self.engine.read(self.index,self.workflow,Path(result['run']),self.root)
  self.assertTrue(any(row['reason']=='fixture-check: requires_port' for row in saved['queue']))
  self.assertFalse(any(row['reason'].startswith('Export is not ready') for row in saved['queue']))
 def catalog_receipt(self,batches):
  tools={name:self.index.digest(self.index.HERE/name) for name in ('function-reuse-plan.py','update-bindings.py',
   'build-native-entry-code.py','extract-native-enums.py','research-workflow.py','update-contracts.py')}
  declared=[dict(id=batch['id'],bindings={self.sha:{key:proof['baseline_address'] for key,proof in batch['verification'].items()}})
   for batch in batches]
  return self.workflow.snapshot(self.root,'function-reuse-catalog',dict(target_sha256=self.sha,
   identity=dict(target_sha256=self.sha,tools=tools,sources={self.sha:self.sha}),scope='function_only',
   runtime_activated=False,profile_activated=False,contracts=declared,verification=batches))
 def test_catalog_address_proof_adopts_only_missing_reviewed_binding(self):
  batch=dict(self.value,id='batch')
  path=self.catalog_receipt([batch]);result=dict(report=str(path),sha256=self.index.digest(path))
  model=dict(contracts=[dict(id='fixture',recipes=[dict(key='renamed-role',method='reviewed')],
   bindings={self.sha:{'renamed-role':ADDRESS}})])
  old=dict(contracts={'fixture':dict(bindings={},queue=['renamed-role: missing or ambiguous reviewed candidate','Other limit'])})
  revised=self.engine.apply_function_reuse(self.index,self.root,model,old,self.sha,result)
  value=revised['contracts']['fixture']
  self.assertEqual(value['bindings'],{'renamed-role':ADDRESS})
  self.assertEqual(value['queue'],['Other limit']);self.assertEqual(old['contracts']['fixture']['bindings'],{})
  self.assertEqual(value['verification']['renamed-role']['function_reuse_receipt']['sha256'],result['sha256'])
  self.assertEqual(value['closed_shapes']['renamed-role'],SHAPE)
  # An analytical name match without the exact baseline address proves nothing.
  model['contracts'][0]['bindings'][self.sha]['renamed-role']='0x140009999'
  self.assertEqual(self.engine.apply_function_reuse(self.index,self.root,model,old,self.sha,result),old)
 def test_catalog_conflict_never_overrides_known_or_ambiguous_binding(self):
  first=dict(copy.deepcopy(self.value),id='first');second=dict(copy.deepcopy(self.value),id='second')
  second['bindings']['helper']='0x140002000';second['verification']['helper'].update(state='moved_verified',address='0x140002000')
  path=self.catalog_receipt([first,second]);result=dict(report=str(path),sha256=self.index.digest(path))
  model=dict(contracts=[dict(id='fixture',recipes=[dict(key='helper',method='reviewed')],bindings={self.sha:{'helper':ADDRESS}})])
  old=dict(contracts={'fixture':dict(bindings={},queue=['helper: missing or ambiguous reviewed candidate'])})
  self.assertEqual(self.engine.apply_function_reuse(self.index,self.root,model,old,self.sha,result),old)
  path=self.catalog_receipt([first]);result=dict(report=str(path),sha256=self.index.digest(path))
  old['contracts']['fixture']['bindings']['helper']='0x140003000'
  self.assertEqual(self.engine.apply_function_reuse(self.index,self.root,model,old,self.sha,result),old)
 def test_catalog_scope_source_and_tools_are_verified_before_adoption(self):
  path=self.catalog_receipt([dict(self.value,id='batch')]);result=dict(report=str(path),sha256=self.index.digest(path))
  model=dict(contracts=[]);contexts=dict(contracts={})
  with self.assertRaisesRegex(ValueError,'source or scope'):
   self.engine.apply_function_reuse(self.index,self.root,model,contexts,'b'*64,result)
  data=self.index.read_json(path);data['identity']['tools']['update-bindings.py']='0'*64
  changed=self.workflow.snapshot(self.root,'function-reuse-catalog',data)
  with self.assertRaisesRegex(ValueError,'tools changed'):
   self.engine.apply_function_reuse(self.index,self.root,model,contexts,self.sha,
    dict(report=str(changed),sha256=self.index.digest(changed)))
 def test_catalog_stage_is_cached_and_never_promotes_capabilities(self):
  f=self.fixture;(f.knowledge/'native-contexts').mkdir()
  proof=self.catalog_receipt([])
  catalog=SimpleNamespace(SOURCES={'11316':self.sha},inputs=Mock(return_value=dict(present=True,contexts={'source':'a'*64})),
   run=Mock(return_value=dict(report=str(proof),sha256=self.index.digest(proof),
    summary=dict(verified=1,requires_review=2),runtime_activated=False,profile_activated=False)))
  f.modules['function-reuse-plan']=catalog
  first,_=f.run_fixture();f.args.resume=Path(first['run']);second,_=f.run_fixture()
  self.assertEqual(catalog.inputs.call_count,2);catalog.run.assert_called_once()
  self.assertEqual(second['function_reuse'],dict(verified=1,requires_review=2))
  saved=self.engine.read(self.index,self.workflow,Path(second['run']),self.root)
  self.assertEqual(saved['function_reuse']['report'],str(proof))
  self.assertFalse(second['profile_activation']);self.assertFalse(second['baseline_promoted'])
  self.assertTrue(any(name=='function-reuse' for name in saved['stages']))
  catalog.inputs.return_value=dict(present=True,contexts={'source':'b'*64})
  f.run_fixture();self.assertEqual(catalog.run.call_count,2)

def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(FunctionReuseExportTests)

if __name__=='__main__':unittest.main()
