"""Synthetic end-to-end updater regressions for scoped context/profile keys."""

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_run import UpdateRunTests


class ProfileStageKeyTests(UpdateRunTests):
    def setUp(self):
        super().setUp()
        # TemporaryDirectory may return a Windows short-name alias; resume restores
        # the canonical journal path. Keep this fixture's spelling stable throughout.
        self.args.install=self.install.resolve()
        self.tools.update({name:dict(fixture=name+'-v1') for name in
            ('context-tag','context-writer','profile-builder')})
        self.check_revisions={'fixture-check':'v1'}
        self.binding_metadata={}
        self.profile_inputs=Mock(return_value=dict(selected='unchanged-fixture'))
        self.modules['update-profile']=SimpleNamespace(inputs=self.profile_inputs)
        self.profile_builder=Mock(side_effect=self.build_fixture_profile)
        self.tag=Mock(return_value=dict(proof='tag'))
        self.writer=Mock(return_value=dict(proof='writer'))
        self.modules['verify-version-login-context']=SimpleNamespace(verify=self.tag)
        self.modules['verify-packet-writer-context']=SimpleNamespace(verify=self.writer)

    def write_contracts(self):
        self.contracts['order']=[contract['id'] for contract in self.contracts['contracts']]
        (self.knowledge/'update-contracts.json').write_text(json.dumps(self.contracts),encoding='utf-8')
        checks=[dict(id=check) for contract in self.contracts['contracts'] for check in contract['checks']]
        (self.knowledge/'research-checks.json').write_text(json.dumps(dict(checks=checks)),encoding='utf-8')

    def add_other_contract(self):
        self.contracts['contracts'].append(dict(id='other',purpose='Other fixture',depends_on=[],
            checks=['other-check'],recipes=[],bindings={},resources=[],coverage='source_checks',
            builder=None,limits=['Synthetic check'],next_check='Inspect other fixture'))
        self.contracts['capabilities']['other']=dict(requires=['other'])
        self.check_revisions['other-check']='v1'

    def fixture_bindings(self,index,args,selected,sha,discoveries):
        return dict(source_sha256=sha,contracts={contract['id']:dict(bindings={},queue=[],
            **self.binding_metadata.get(contract['id'],{})) for contract in selected['contracts']})

    def fixture_checks(self,index,args,sha,question,*,check_ids):
        results=[]
        for check_id in check_ids:
            report=self.workflow.snapshot(self.root,'profile-stage-check-fixtures',
                dict(id=check_id,source_sha256=sha,revision=self.check_revisions[check_id]))
            results.append(dict(id=check_id,state='passed',report=str(report),sha256=index.digest(report)))
        return results

    def build_fixture_profile(self,index,workflow,args,contract,outcomes,sha,contexts):
        profile=workflow.snapshot(self.root,'prepared-profiles',dict(schema=1,contract=contract['id'],
            source_sha256=sha,installed_source=str(args.install.resolve()),contexts=contexts,
            passed_checks={name:row['checks'] for name,row in outcomes.items() if row['state']=='passed'},
            activated=False))
        return dict(profile=str(profile),activated=False)

    def run_profile_fixture(self):
        self.write_contracts()
        # These contracts intentionally have no real profile reports or native addresses.
        # Exercise the controller and immutable journal, not profile admission or native execution.
        with patch.object(self.model,'load',return_value=self.contracts), \
             patch.object(self.bindings,'resolve',side_effect=self.fixture_bindings), \
             patch.object(self.workflow,'run_checks',side_effect=self.fixture_checks), \
             patch.object(self.update,'execute_adapter',return_value=dict(state='passed',result=dict(candidates=[]))), \
             patch.object(self.engine,'build_profile',self.profile_builder):
            result=self.engine.run(self.api,self.args,self.root/'knowledge/search.sqlite3')
        self.assertEqual(result['metrics']['completed_ghidra_launches_this_run'],0)
        self.assertEqual(result['metrics']['native_replays_this_run'],0)
        self.assertEqual(result['capabilities']['fixture']['state'],'prepared_offline')
        saved=self.engine.read(self.api,self.workflow,Path(result['run']),self.root)
        return result,saved

    def test_legacy_context_adapters_reuse_common_change_and_invalidate_own_scope(self):
        self.contracts['contracts'][0]['context_checks']=['version-login-tag','packet-writer-projection']
        first,initial=self.run_profile_fixture()
        self.assertEqual((self.tag.call_count,self.writer.call_count),(1,1))
        self.assertEqual(first['metrics']['context_replays_this_run'],2)
        self.args.resume=Path(first['run'])
        self.tools['context']['unrelated-native-suite']='v2'
        reused,common_changed=self.run_profile_fixture()
        self.assertEqual((self.tag.call_count,self.writer.call_count),(1,1))
        self.assertEqual(reused['metrics']['context_replays_this_run'],0)
        self.assertEqual(initial['stages']['context-check-fixture']['key'],
            common_changed['stages']['context-check-fixture']['key'])
        self.assertEqual(initial['stages']['context-check-fixture-packet-writer-projection']['key'],
            common_changed['stages']['context-check-fixture-packet-writer-projection']['key'])
        self.tools['context-tag']['fixture']='context-tag-v2'
        changed,tag_changed=self.run_profile_fixture()
        self.assertEqual((self.tag.call_count,self.writer.call_count),(2,1))
        self.assertEqual(changed['metrics']['context_replays_this_run'],1)
        self.assertNotEqual(common_changed['stages']['context-check-fixture']['key'],
            tag_changed['stages']['context-check-fixture']['key'])
        self.assertEqual(common_changed['stages']['context-check-fixture-packet-writer-projection']['key'],
            tag_changed['stages']['context-check-fixture-packet-writer-projection']['key'])

    def test_profile_builder_reuses_unrelated_tools_and_invalidates_own_scope(self):
        self.contracts['contracts'][0]['builder']='sdk-launcher'
        first,initial=self.run_profile_fixture()
        self.assertEqual(self.profile_builder.call_count,1)
        self.args.resume=Path(first['run'])
        self.tools['profile']['unrelated-profile-check']='v2'
        _,common_changed=self.run_profile_fixture()
        self.assertEqual(self.profile_builder.call_count,1)
        self.assertEqual(initial['stages']['profile-fixture']['key'],common_changed['stages']['profile-fixture']['key'])
        self.tools['profile-builder']['fixture']='profile-builder-v2'
        _,builder_changed=self.run_profile_fixture()
        self.assertEqual(self.profile_builder.call_count,2)
        self.assertNotEqual(common_changed['stages']['profile-fixture']['key'],builder_changed['stages']['profile-fixture']['key'])
        self.assertEqual(self.profile_inputs.call_count,3)

    def test_profile_rebuilds_for_another_passed_contract_report(self):
        self.contracts['contracts'][0]['builder']='sdk-launcher'
        self.add_other_contract()
        first,initial=self.run_profile_fixture()
        self.args.resume=Path(first['run'])
        self.run_profile_fixture()
        self.assertEqual(self.profile_builder.call_count,1)
        self.check_revisions['other-check']='v2'
        changed,revised=self.run_profile_fixture()
        old_inputs=initial['stages']['profile-fixture']['inputs']
        new_inputs=revised['stages']['profile-fixture']['inputs']
        self.assertEqual(self.profile_builder.call_count,2)
        self.assertEqual(old_inputs['context'],new_inputs['context'])
        self.assertEqual(old_inputs['inputs'],new_inputs['inputs'])
        self.assertEqual(old_inputs['contexts'],new_inputs['contexts'])
        self.assertNotEqual(old_inputs['passed_checks']['other'],new_inputs['passed_checks']['other'])
        self.assertNotEqual(first['profiles'][0]['profile'],changed['profiles'][0]['profile'])

    def test_profile_rebuilds_for_other_binding_metadata_with_unchanged_checks(self):
        self.contracts['contracts'][0]['builder']='sdk-launcher'
        self.add_other_contract()
        self.binding_metadata['other']=dict(marker='v1')
        first,initial=self.run_profile_fixture()
        self.args.resume=Path(first['run'])
        self.run_profile_fixture()
        self.assertEqual(self.profile_builder.call_count,1)
        # Alter only the other resolver input, retaining empty actual bindings.
        self.contracts['contracts'][1]['bindings']={self.sha:{}}
        self.binding_metadata['other']=dict(marker='v2')
        _,revised=self.run_profile_fixture()
        old_inputs=initial['stages']['profile-fixture']['inputs']
        new_inputs=revised['stages']['profile-fixture']['inputs']
        self.assertEqual(self.profile_builder.call_count,2)
        self.assertEqual(old_inputs['context'],new_inputs['context'])
        self.assertEqual(old_inputs['inputs'],new_inputs['inputs'])
        self.assertEqual(old_inputs['passed_checks'],new_inputs['passed_checks'])
        self.assertEqual(old_inputs['contexts']['contracts']['other']['marker'],'v1')
        self.assertEqual(new_inputs['contexts']['contracts']['other']['marker'],'v2')
        self.assertEqual(new_inputs['contexts']['contracts']['other']['bindings'],{})

    def test_same_exe_sha_at_another_installation_rebuilds_profile(self):
        self.contracts['contracts'][0]['builder']='sdk-launcher'
        first,initial=self.run_profile_fixture()
        self.run_profile_fixture()
        self.assertEqual(self.profile_builder.call_count,1)
        second_install=self.root.parent/'other-install'
        for source in (self.exe,self.pak):
            destination=second_install/source.relative_to(self.install)
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(source.read_bytes())
        # A resume intentionally restores its saved install. A new run selects the new path.
        self.args.resume=None
        self.args.install=second_install
        baseline=self.workflow.checked_manifest(self.api,self.args.baseline)
        baseline['source']=str(second_install.resolve())
        baseline['exe']['path']=str((second_install/self.exe.relative_to(self.install)).resolve())
        for row in baseline['files']:
            relative=Path(row['path']).resolve().relative_to(self.install.resolve())
            row['path']=str((second_install/relative).resolve())
        self.args.baseline=self.workflow.snapshot(self.root,'fixture-baselines',baseline)
        changed,revised=self.run_profile_fixture()
        old_inputs=initial['stages']['profile-fixture']['inputs']
        new_inputs=revised['stages']['profile-fixture']['inputs']
        self.assertEqual(first['source_sha256'],changed['source_sha256'])
        self.assertEqual(self.profile_builder.call_count,2)
        for field in ('context','inputs','contexts','passed_checks','tools'):
            self.assertEqual(old_inputs[field],new_inputs[field])
        target=second_install/'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
        self.assertEqual(new_inputs['installed_source'],dict(path=str(target),resolved=str(target.resolve())))
        self.assertNotEqual(old_inputs['installed_source'],new_inputs['installed_source'])
        self.assertNotEqual(first['profiles'][0]['profile'],changed['profiles'][0]['profile'])


def load_tests(loader,tests,pattern):
    # Reuse the synthetic factory without rediscovering inherited controller tests.
    names=sorted(name for name in ProfileStageKeyTests.__dict__ if name.startswith('test_'))
    return unittest.TestSuite(ProfileStageKeyTests(name) for name in names)


if __name__=='__main__':unittest.main()
