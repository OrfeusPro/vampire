"""Ordinary synthetic updater coverage for the native materialization scope."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_run import UpdateRunTests


class NativeMaterializeStageV2Tests(UpdateRunTests):
    def setUp(self):
        super().setUp()
        self.selector=self.index.extension('native-materialize-inputs-v2')
        self.here,self.check_file,self.native_registry,self.native=self.native_materialize_fixture()
        self.modules['native-materialize-inputs-v2']=self.selector
        self.portable_runtime=Mock(return_value=dict(python='fixture-python',files={}))
        self.modules['stage-action-tools-v1']=SimpleNamespace(runtime=self.portable_runtime)
        self.native_runtime=dict(unicorn='fixture-v1',capstone='fixture-v1')
        for name in (*self.selector.TOOLS,'update-run.py',Path(self.selector.__file__).name):
            path=self.here/name
            if not path.is_file():path.write_text('# reviewed fixture '+name,encoding='utf-8')
        self.scope_file=self.knowledge/'native-materialize-inputs.json'
        rule=dict(schema=1,recipe=self.selector.RECIPE,
            reviewed_tools={name:self.api.digest(self.here/name) for name in self.selector.TOOLS})
        self.scope_file.write_text(json.dumps(rule),encoding='utf-8')
        # The engine retains its ordinary synthetic tool groups. Only the new
        # action selector is real; no installed native scenario is executed.
        self.engine.execution_inputs.side_effect=self.fixture_execution_inputs

    def fixture_execution_inputs(self,index,knowledge=None):
        groups=copy.deepcopy(self.tools)
        selected=Path(knowledge) if knowledge is not None else index.HERE/'knowledge'
        if (selected/'native-materialize-inputs.json').is_file():
            groups['native-materialize']=self.selector.tool_inputs(index,selected,groups['context'],self.native_runtime)
        return groups

    def declare_dependency(self,path):
        registry=self.knowledge/'research-checks.json'
        value=json.loads(registry.read_bytes())
        relative=path.relative_to(self.here.parents[3]).as_posix()
        value['checks'][0]['dependencies'].append(relative)
        registry.write_text(json.dumps(value),encoding='utf-8')

    def run_native_fixture(self):
        result,_=self.run_fixture()
        self.assertEqual(result['metrics']['completed_ghidra_launches_this_run'],0)
        self.assertEqual(result['metrics']['native_replays_this_run'],0)
        self.assertEqual(result['capabilities']['fixture']['state'],'prepared_offline')
        saved=self.engine.read(self.api,self.workflow,Path(result['run']),self.root)
        stage=saved['stages']['native-materialize']
        self.args.resume=Path(result['run'])
        return result,stage

    def test_warm_stage_ignores_unrelated_python_and_broad_context_tools(self):
        _,first=self.run_native_fixture()
        _,warm=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,1)
        unrelated=self.here.parents[1]/'unrelated_ui_fixture.py'
        unrelated.write_text('# unrelated consumer',encoding='utf-8')
        self.declare_dependency(unrelated)
        self.tools['context']['unrelated-native-suite']='changed'
        result,changed=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,1)
        self.assertEqual(first['key'],warm['key'])
        self.assertEqual(first['key'],changed['key'])
        self.assertEqual(changed['inputs']['tools']['mode'],'reviewed')
        self.assertNotIn('legacy_tools',changed['inputs']['tools'])
        self.assertNotIn(str(unrelated.resolve()),changed['inputs']['definitions'])
        self.assertNotIn(str((self.knowledge/'research-checks.json').resolve()),changed['inputs']['definitions'])
        self.assertGreater(result['reused_stages'],0)

    def test_changed_reviewed_file_restores_full_definitions_and_broad_tools(self):
        _,first=self.run_native_fixture()
        (self.here/'update-native-contexts.py').write_text('# changed materializer',encoding='utf-8')
        _,changed=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,2)
        self.assertNotEqual(first['key'],changed['key'])
        self.assertEqual(changed['inputs']['tools']['mode'],'conservative')
        self.assertEqual(changed['inputs']['tools']['legacy_tools'],self.tools['context'])
        definitions=self.engine.definition_inputs(self.api,self.args,self.update)
        self.assertEqual(changed['inputs']['definitions'],definitions)
        self.assertIn(str(self.check_file.resolve()),changed['inputs']['definitions'])
        self.check_file.write_text('# formerly unrelated check changed',encoding='utf-8')
        _,conservative=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,3)
        self.assertNotEqual(changed['key'],conservative['key'])

    def test_data_and_generated_index_changes_each_invalidate_materialization(self):
        data=self.knowledge/'materialize-data-fixture.json'
        data.write_text('{"revision":1}',encoding='utf-8')
        self.declare_dependency(data)
        _,first=self.run_native_fixture()
        _,warm=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,1)
        self.assertIn(str(data.resolve()),first['inputs']['definitions'])
        data.write_text('{"revision":2}',encoding='utf-8')
        _,data_changed=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,2)
        self.assertNotEqual(warm['key'],data_changed['key'])
        generated=self.root/'knowledge/generated-native/index.json'
        generated.parent.mkdir(parents=True)
        generated.write_text('{"fixture":"generated-v1"}',encoding='utf-8')
        _,index_created=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,3)
        self.assertEqual(index_created['inputs']['generated_index_sha256'],self.api.digest(generated))
        generated.write_text('{"fixture":"generated-v2"}',encoding='utf-8')
        _,index_changed=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,4)
        self.assertNotEqual(index_created['key'],index_changed['key'])

    def test_native_portable_runtime_and_scope_guard_changes_invalidate(self):
        _,first=self.run_native_fixture()
        self.native_runtime['unicorn']='fixture-v2'
        _,native_changed=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,2)
        self.assertNotEqual(first['key'],native_changed['key'])
        self.assertEqual(native_changed['inputs']['tools']['native_runtime']['unicorn'],'fixture-v2')
        self.portable_runtime.return_value=dict(python='fixture-python-v2',files={})
        _,portable_changed=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,3)
        self.assertNotEqual(native_changed['key'],portable_changed['key'])
        # Equivalent JSON still changes the reviewed selector's immutable guard.
        self.scope_file.write_text(self.scope_file.read_text(encoding='utf-8')+'\n',encoding='utf-8')
        _,scope_changed=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,4)
        self.assertEqual(scope_changed['inputs']['tools']['mode'],'reviewed')
        self.assertNotEqual(portable_changed['key'],scope_changed['key'])

    def test_absent_selector_retains_legacy_context_tool_invalidation(self):
        # Leave the established v1 definitions selector intact. The optional v2
        # tool group must disappear, preserving the original context-tool key.
        self.scope_file.unlink()
        _,first=self.run_native_fixture()
        _,warm=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,1)
        self.assertEqual(first['key'],warm['key'])
        self.assertEqual(first['inputs']['tools'],self.tools['context'])
        self.assertNotIn(str(self.check_file.resolve()),first['inputs']['definitions'])
        self.tools['context']['unrelated-native-suite']='changed'
        _,changed=self.run_native_fixture()
        self.assertEqual(self.native.materialize.call_count,2)
        self.assertNotEqual(warm['key'],changed['key'])
        self.assertEqual(changed['inputs']['tools'],self.tools['context'])
        self.assertEqual(self.portable_runtime.call_count,0)


def load_tests(loader,tests,pattern):
    # Inherit only the synthetic factory, not its unchanged controller cases.
    names=sorted(name for name in NativeMaterializeStageV2Tests.__dict__ if name.startswith('test_'))
    return unittest.TestSuite(NativeMaterializeStageV2Tests(name) for name in names)


if __name__=='__main__':unittest.main()
