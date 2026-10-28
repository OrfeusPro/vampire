"""Real native scenarios on a synthetic, unregistered client SHA; no live game."""
import copy
import hashlib
import json
import shutil
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from test_vampir_update_contracts import load,HERE


class NativeContextAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temporary.name);cls.index=load('knowledge-index').api()
        cls.tool=load('update-native-contexts');cls.api=load('native-release-registry')
        cls.baseline_path=HERE/'knowledge/native-contexts/utf8-11320.json'
        cls.baseline=json.loads(cls.baseline_path.read_text('utf-8'))
        source=Path('F:/PhoneExit Resources/Vampir/client-code-snapshots')/cls.baseline['source_sha256']/'ProjectRED-Win64-Shipping.exe'
        if not source.is_file():
            cls.temporary.cleanup();raise unittest.SkipTest('Pinned native artifact is not installed')
        # Only the test-owned copy changes. The original PE and its capabilities
        # are not modified or executed; appended bytes give a genuinely new SHA.
        raw=source.read_bytes()+b'PhoneExit offline synthetic release adapter test\0'
        cls.sha=hashlib.sha256(raw).hexdigest()
        if cls.sha in cls.api.sources().values():raise AssertionError('Synthetic source unexpectedly registered')
        target=cls.root/'client-code-snapshots'/cls.sha/source.name;target.parent.mkdir(parents=True);target.write_bytes(raw)
        old=cls.root/'client-code-snapshots'/cls.baseline['source_sha256']/source.name;old.parent.mkdir(parents=True);shutil.copyfile(source,old)
        for run in cls.baseline['exports']:
            original=Path('F:/PhoneExit Resources/Vampir/ghidra/request-exports')/cls.baseline['source_sha256']/run/'details.json'
            target=cls.root/'ghidra/request-exports'/cls.baseline['source_sha256']/run/'details.json'
            target.parent.mkdir(parents=True);shutil.copyfile(original,target)
        cls.knowledge=cls.root/'knowledge-src';cls.knowledge.mkdir()
        cls.registry=dict(schema=1,releases=[dict(id='reviewed',order=1,source_sha256=cls.baseline['source_sha256'])],
            family_aliases={},projections=[],suite_adapters=[dict(id='utf8',family='utf8',adapter='utf8-v1')])
        (cls.knowledge/'native-release-registry.json').write_text(json.dumps(cls.registry))
        cls.store=load('update-bindings').SourceStore(cls.index,cls.root)
        cls.args=SimpleNamespace(root=cls.root,knowledge=cls.knowledge,source_store=cls.store)
        cls.context,cls.proof=cls.tool.discover_utf8(cls.index,cls.args,cls.sha,cls.baseline_path,cls.baseline)
        cls.context_receipt=cls.tool.receipt(cls.root,'generated-native-contexts',cls.context)
        cls.declaration=dict(id='native-auto-utf8',adapter='utf8-v1',context=cls.context_receipt,proof=cls.proof,
            scope='bounded_native_utf8',contracts=[],dependencies={str(HERE/name):cls.tool.digest(HERE/name) for name in cls.tool.TOOLS},
            artifacts={str(cls.baseline_path):cls.tool.digest(cls.baseline_path),cls.proof['path']:cls.proof['sha256'],
                cls.context_receipt['path']:cls.context_receipt['sha256']})
        cls.outcome=cls.tool.execute(cls.index,cls.args,cls.sha,cls.declaration)

    @classmethod
    def tearDownClass(cls):
        cls.store.validate();cls.temporary.cleanup()

    def admission(self,context):
        functions={int(context['bindings'][key],16) for key in ('length','convert')}
        leaves={int(context['bindings']['encoder'],16):context['encoder_leaf']['bytes']}
        return self.tool.admitted_instructions(context,self.root,functions,leaves,source_store=self.store)

    def test_native_scenarios_run_on_a_sha_absent_from_legacy_allowlists(self):
        report=json.loads(Path(self.outcome['report']).read_text('utf-8'))
        self.assertEqual(self.outcome['state'],'passed')
        self.assertEqual(report['source_sha256'],self.sha)
        self.assertEqual((len(report['cases']),len(report['scalar_cases'])),(142,80))
        self.assertTrue(all(row['guards'] for row in report['cases']+report['scalar_cases']))
        self.assertFalse(report['network_used']);self.assertFalse(report['runtime_activated'])
        self.assertFalse(report['profile_activated'])

    def test_layout_field_and_target_scope_cannot_be_changed(self):
        for mutate in (
            lambda value:value['layout'].update(max_output_bytes=2048),
            lambda value:value['bindings'].update(encoder='0x140001060'),
            lambda value:value.update(source_sha256='0'*64),
            lambda value:value['helpers'].update(memcpy='0x140001000')):
            context=copy.deepcopy(self.context);mutate(context)
            with self.assertRaisesRegex(ValueError,'fields/layout'):self.admission(context)

    def test_closed_recipe_and_leaf_are_verified_instead_of_trusting_receipt_claims(self):
        proof=json.loads(Path(self.proof['path']).read_text('utf-8'))
        proof['recipes'][0]['calls']={'0':'encoder'}
        context=copy.deepcopy(self.context)
        context['native_admission']=self.tool.receipt(self.root,'native-context-proofs',proof)
        with self.assertRaisesRegex(ValueError,'closure recipe changed'):self.admission(context)
        proof=json.loads(Path(self.proof['path']).read_text('utf-8'))
        proof['target_context']['encoder_leaf']['bytes']='c3'
        proof['target_context']['encoder_leaf'].update(size=1,sha256=hashlib.sha256(b'\xc3').hexdigest())
        context=copy.deepcopy(proof['target_context'])
        context['native_admission']=self.tool.receipt(self.root,'native-context-proofs',proof)
        with self.assertRaisesRegex(ValueError,'leaf bytes or layout differ'):self.admission(context)

    def test_publication_and_cached_republication_keep_target_as_latest_baseline(self):
        pointer=self.tool.publish(self.index,self.args,self.sha,self.declaration,self.outcome)
        first=Path(pointer['path']).read_bytes()
        self.tool.publish(self.index,self.args,self.sha,self.declaration,self.outcome)
        self.assertEqual(Path(pointer['path']).read_bytes(),first)
        warm=self.tool.materialize(self.index,self.args,self.sha,{}, {})
        self.assertEqual(warm['checks'],[self.declaration])
        planner=load('function-reuse-plan')
        self.assertEqual(planner.ordered_sources(self.knowledge,self.root)[0],self.sha)
        contexts,_,_,_=planner.inventory(self.root,self.knowledge,source_store=self.store)
        self.assertEqual(len(contexts),1);self.assertEqual(contexts[0]['source_sha256'],self.sha)
        Path(pointer['path']).unlink()
        self.tool.publish(self.index,self.args,self.sha,self.declaration,self.outcome)
        self.assertTrue(Path(pointer['path']).is_file())

    def test_published_helper_is_next_operational_baseline_without_writer_promotion(self):
        self.tool.publish(self.index,self.args,self.sha,self.declaration,self.outcome)
        model=dict(contracts=[dict(id='game-version',recipes=[dict(key='utf8-length',method='closed_shape',
            baseline_sha256=self.baseline['source_sha256'],baseline_address=self.baseline['bindings']['length'],calls={},data={})],
            bindings={self.baseline['source_sha256']:{'utf8-length':self.baseline['bindings']['length']}})])
        revised=self.tool.operational_model(self.index,self.args,model)
        self.assertEqual(revised['contracts'][0]['recipes'][0]['baseline_sha256'],self.sha)
        self.assertEqual(set(revised['contracts'][0]['bindings'][self.sha]),{'utf8-length'})
        self.assertNotIn(self.sha,model['contracts'][0]['bindings'])


if __name__=='__main__':unittest.main()
