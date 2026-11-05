"""Current update/research routes must revalidate groups outside the frozen outer cache."""
import ast
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ToolingCheckDispatchTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.workspace = self.base / 'workspace'
        self.bots = self.workspace / 'phone-exit/bots'
        self.knowledge = self.bots / 'resource-tools/vampir/knowledge'
        self.knowledge.mkdir(parents=True)
        self.root = self.base / 'resources'
        self.root.mkdir()
        self.args = SimpleNamespace(root=self.root, knowledge=self.knowledge)
        self.dispatch = load('tooling-check-dispatch-v1')
        self.workflow = load('research-workflow')
        self.index = load('knowledge-index').api()
        self.index.HERE = self.knowledge.parent
        self.index.KNOWLEDGE = self.knowledge
        self.entrypoint = self.bots / 'test_vampir_update_automation.py'
        self.entrypoint.write_text("MODULES = ('test_vampir_fixture',)\n", encoding='utf-8')
        self.dependency = self.bots / 'fixture.py'
        self.dependency.write_bytes(b'fixture-code')
        self.runtime = self.root / 'runtime.bin'
        self.runtime.write_bytes(b'fixture-runtime')
        self.manifest = self.knowledge / self.dispatch.MANIFEST
        self.manifest.write_bytes(b'{}')
        self.automatic = dict(id='automatic-update-tooling', source_scope='tooling',
            questions=['test-question'], source_sha256=[], offline_reviewed=True, on_update=True,
            test_pattern='test_vampir_update_automation.py', artifact_dependencies=[],
            dependencies=['phone-exit/bots/fixture.py'])
        self.client = dict(id='client-fixture', questions=['test-question'], source_sha256=['a' * 64],
            offline_reviewed=True, dependencies=[], test_pattern='test_vampir_fixture.py')
        self.write_registry([self.automatic, self.client])
        self.engine = SimpleNamespace(read_catalog=lambda path: ['test_vampir_fixture'],
                                      run=Mock(side_effect=self.group_report))
        self.dispatch.load_engine = lambda: self.engine
        self.legacy = Mock(return_value=[dict(id='client-fixture', state='requires_port')])
        self.workflow.run_checks = self.legacy
        original_extension = self.index.extension
        self.index.extension = lambda name: {'research-workflow': self.workflow,
            'tooling-groups-v1': self.engine, 'tooling-check-dispatch-v1': self.dispatch}.get(name) or original_extension(name)
        self.group_state = 'passed'

    def write_registry(self, checks):
        (self.knowledge / 'research-checks.json').write_text(
            json.dumps(dict(schema=1, checks=checks)), encoding='utf-8')

    def group_report(self, *unused, **kwargs):
        report = dict(schema=1, state=self.group_state, source_scope='tooling',
            proves_client_compatibility=False, inputs={str(self.dependency): self.dispatch.digest(self.dependency)},
            artifacts={str(self.runtime): self.dispatch.digest(self.runtime)},
            runtime_inputs={str(self.runtime): self.dispatch.digest(self.runtime)})
        path = self.workflow.snapshot(self.root, 'fixture-groups', report)
        return dict(state=self.group_state, report=str(path), sha256=self.dispatch.digest(path),
                    cache_key='fixture-key', metrics=dict(executed_groups=0, cached_groups=1))

    def run_check(self, sha='a' * 64, check_ids=None):
        return self.dispatch.run_checks(self.index, self.args, sha, 'test-question',
            check_ids=check_ids if check_ids is not None else ['automatic-update-tooling'],
            workflow=self.workflow)

    def test_same_inputs_always_reach_group_validation_and_keep_a_stable_report(self):
        first, second = self.run_check(), self.run_check(sha='b' * 64)
        self.assertEqual(first, second)
        self.assertEqual(self.engine.run.call_count, 2)
        self.legacy.assert_not_called()
        report = self.index.read_json(first[0]['report'])
        self.assertIsNone(report['definition']['source_sha256'])
        self.assertIs(report['runtime_admitted'], False)
        self.assertIs(first[0]['proves_client_compatibility'], False)

    def test_runtime_only_change_cannot_be_hidden_by_the_legacy_outer_cache(self):
        first = self.run_check()[0]
        self.runtime.write_bytes(b'changed-runtime')
        changed = self.run_check()[0]
        self.assertNotEqual(first['report'], changed['report'])
        self.assertEqual(self.engine.run.call_count, 2)
        self.legacy.assert_not_called()

    def test_failed_outer_report_is_not_a_barrier_to_resuming_group_validation(self):
        self.group_state = 'failed'
        failed = self.run_check()[0]
        self.assertEqual(failed['state'], 'failed')
        self.group_state = 'passed'
        passed = self.run_check()[0]
        self.assertEqual(passed['state'], 'passed')
        self.assertNotEqual(failed['report'], passed['report'])
        self.assertEqual(self.engine.run.call_count, 2)

    def test_client_and_explicit_check_selection_keep_the_frozen_path(self):
        result = self.run_check(check_ids=['client-fixture'])
        self.assertEqual(result, [dict(id='client-fixture', state='requires_port')])
        self.engine.run.assert_not_called()
        self.legacy.assert_called_once()
        self.assertEqual(self.legacy.call_args.kwargs['check_ids'], ['client-fixture'])

    def generated_sdk_fixture(self):
        sha='a'*64;identifier='sdk-native-batch-11318'
        file=self.root/'generated.py';file.write_text('# fixture, never imported')
        files={str(file):self.index.digest(file)}
        executable=str(Path(sys.executable).resolve())
        generation=self.workflow.snapshot(self.root,'sdk-batch-generated-v1',dict(
            source_sha256=sha,inputs={executable:self.index.digest(executable)},files=files,
            runtime=dict(executable=executable)))
        context=self.knowledge/'sdk-fixture.json'
        context.write_text(json.dumps(dict(schema=1,source_sha256=sha,
            generation=dict(path=str(generation),sha256=self.index.digest(generation)))))
        definition=dict(self.client,id=identifier,generated_sdk_contexts={sha:context.name},
            dependencies=[context.relative_to(self.workspace).as_posix()])
        self.write_registry([definition])
        profile=SimpleNamespace(generated_dependencies=Mock(return_value=files))
        self.engine._owner=load('tooling-groups-v1')._owner
        original=self.index.extension
        self.index.extension=lambda name: profile if name=='update-profile' else original(name)
        def checked(*args,**kwargs):
            self.assertEqual(os.environ.get('PHONEEXIT_VAMPIR_SDK_CHECK_SOURCE_SHA256'),sha)
            path=self.workflow.snapshot(self.root,'check-results',dict(state='passed',
                definition=dict(source_sha256=sha,check=dict(id=identifier),inputs={},artifacts={},executable=sys.executable)))
            return [dict(id=identifier,state='passed',report=str(path),sha256=self.index.digest(path),cache_key='fixture')]
        self.legacy.side_effect=checked
        return identifier,file,context

    def test_sdk_source_binding_and_generated_artifacts_survive_cached_check(self):
        identifier,file,context=self.generated_sdk_fixture()
        env='PHONEEXIT_VAMPIR_SDK_CHECK_SOURCE_SHA256'
        with patch.dict(os.environ,{env:'prior-fixture'}):
            result=self.run_check(check_ids=[identifier])[0]
            self.assertEqual(os.environ[env],'prior-fixture')
        report=self.index.read_json(result['report'])
        self.assertIn(str(file),report['definition']['artifacts'])
        self.assertIn(str(context.resolve()),report['definition']['artifacts'])
        self.assertEqual(report['sdk_generation_guard']['recipe'],'sdk-check-guard-v1')
        self.assertEqual(report['definition']['source_sha256'],'a'*64)

    def test_sdk_input_change_during_cached_check_is_rejected(self):
        identifier,file,_=self.generated_sdk_fixture()
        original=self.legacy.side_effect
        def changed(*args,**kwargs):
            result=original(*args,**kwargs);file.write_text('# changed after parent result')
            return result
        self.legacy.side_effect=changed
        with self.assertRaisesRegex(ValueError,'SDK check input changed'):
            self.run_check(check_ids=[identifier])

    def test_scoped_sdk_check_pins_only_the_current_python_as_runtime(self):
        identifier,_,_=self.generated_sdk_fixture()
        outcome=self.run_check(check_ids=[identifier])[0]
        route=load('research-scoped-v2');kinds={}
        scope=SimpleNamespace(root=self.root,pin=lambda path,sha,kind:kinds.update({str(path):kind}))
        route.pin_checks(self.index,scope,[outcome])
        self.assertEqual(kinds[str(Path(sys.executable).resolve())],'runtime')
        guard=load('sdk-check-guard')
        report=self.index.read_json(outcome['report'])
        with self.assertRaisesRegex(ValueError,'registered SDK check'):
            guard.runtime_inputs(self.index,self.workflow,self.root,report,'unreviewed-client')
        report['definition']['executable']=str(self.runtime)
        with self.assertRaisesRegex(ValueError,'Python identity'):
            guard.runtime_inputs(self.index,self.workflow,self.root,report,identifier)

    def version_flow_fixture(self):
        sha='a'*64;identifier='native-version-result-handler-context'
        transfer=self.workflow.snapshot(self.root,'native-transfer-fixture',dict(source_sha256=sha))
        reference=dict(path=str(transfer),sha256=self.index.digest(transfer))
        parent=self.workflow.snapshot(self.root,'generated-native-contexts',dict(source_sha256=sha,transfer_proof=reference))
        pointer=dict(path=str(parent),sha256=self.index.digest(parent))
        context=self.knowledge/'flow-fixture.json'
        context.write_text(json.dumps(dict(schema=1,recipe='version-result-flow-v1',source_sha256=sha,
            baseline=reference,gate=dict(context=pointer,check=reference),input=dict(context=pointer,check=reference))))
        definition=dict(self.client,id=identifier,version_flow_contexts={sha:context.name},
            dependencies=[context.relative_to(self.workspace).as_posix()])
        self.write_registry([definition])
        def checked(*args,**kwargs):
            path=self.workflow.snapshot(self.root,'check-results',dict(state='passed',definition=dict(
                source_sha256=sha,check=dict(id=identifier),inputs={},artifacts={})))
            return [dict(id=identifier,state='passed',report=str(path),sha256=self.index.digest(path),cache_key='fixture')]
        self.legacy.side_effect=checked
        return identifier,parent

    def test_version_flow_material_is_pinned_on_cached_check(self):
        identifier,parent=self.version_flow_fixture()
        first=self.run_check(check_ids=[identifier])[0]
        second=self.run_check(check_ids=[identifier])[0]
        self.assertEqual(first,second)
        report=self.index.read_json(first['report'])
        self.assertIn(str(parent.resolve()),report['definition']['artifacts'])
        parent.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'proof SHA changed'):
            self.run_check(check_ids=[identifier])

    def test_version_flow_change_during_cached_check_rejects(self):
        identifier,parent=self.version_flow_fixture()
        original=self.legacy.side_effect
        def changed(*args,**kwargs):
            report=original(*args,**kwargs);parent.write_bytes(b'changed after parent check');return report
        self.legacy.side_effect=changed
        with self.assertRaisesRegex(ValueError,'material changed'):
            self.run_check(check_ids=[identifier])

    def test_sdk_launcher_guard_pins_profile_and_rechecks_cached_inputs(self):
        identifier='sdk-runtime-launcher-11316';sha='a'*64
        value=self.workflow.canonical(dict(inputs={str(self.runtime):self.index.digest(self.runtime)}))
        import hashlib
        manifest=self.root/'sdk-launcher-profiles'/hashlib.sha256(value).hexdigest()/'manifest.json'
        manifest.parent.mkdir(parents=True);manifest.write_bytes(value)
        selected=self.knowledge/'sdk-selection.json'
        selected.write_text(json.dumps(dict(schema=1,source_sha256=sha,profile=dict(path=str(manifest),sha256=self.index.digest(manifest)))))
        definition=dict(self.client,id=identifier,sdk_launcher_profiles={sha:selected.name},
            dependencies=[selected.relative_to(self.workspace).as_posix()])
        self.write_registry([definition])
        def native_loader(**kwargs):
            value=self.index.read_json(manifest)
            if any(self.index.digest(name)!=expected for name,expected in value['inputs'].items()):
                raise ValueError('SDK Launcher dependency changed')
            return value
        def checked(*args,**kwargs):
            path=self.workflow.snapshot(self.root,'check-results',dict(state='passed',definition=dict(
                source_sha256=sha,check=dict(id=identifier),inputs={},artifacts={})))
            return [dict(id=identifier,state='passed',report=str(path),sha256=self.index.digest(path),cache_key='fixture')]
        self.legacy.side_effect=checked
        guard=load('sdk-launcher-check-guard')
        extension=self.index.extension
        self.index.extension=lambda name:guard if name=='sdk-launcher-check-guard' else extension(name)
        with patch.object(guard,'loader',return_value=SimpleNamespace(load_manifest=native_loader)):
            first=self.run_check(check_ids=[identifier])[0]
            self.assertEqual(first,self.run_check(check_ids=[identifier])[0])
            report=self.index.read_json(first['report'])
            self.assertIn(str(manifest.resolve()),report['definition']['artifacts'])
            self.assertIn(str(self.runtime),report['definition']['artifacts'])
            self.runtime.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'dependency changed'):
                self.run_check(check_ids=[identifier])

    def test_candidate_bridge_guard_rechecks_cached_dependency(self):
        identifier='candidate-proof-bridges-current';sha='a'*64
        context=self.knowledge/'native-contexts/bridge-fixture.json'
        context.parent.mkdir();context.write_text(json.dumps(dict(source_sha256=sha)))
        context_pointer=dict(path=str(context.resolve()),sha256=self.index.digest(context))
        proof=self.workflow.snapshot(self.root,'candidate-proof-bridges-v1',dict(
            context_sha256=context_pointer['sha256'],files={str(self.runtime):self.index.digest(self.runtime)}))
        selected=self.knowledge/'bridge-selection.json'
        selected.write_text(json.dumps(dict(schema=1,source_sha256=sha,context=context_pointer,
            proof=dict(path=str(proof),sha256=self.index.digest(proof)))))
        self.write_registry([dict(self.client,id=identifier,candidate_bridge_profiles={sha:selected.name},
            dependencies=[selected.relative_to(self.workspace).as_posix()])])
        def validate(context,report):
            if any(self.index.digest(name)!=value for name,value in report['files'].items()):
                raise ValueError('Saved candidate bridge input changed')
        def checked(*args,**kwargs):
            path=self.workflow.snapshot(self.root,'check-results',dict(state='passed',definition=dict(
                source_sha256=sha,check=dict(id=identifier),inputs={},artifacts={})))
            return [dict(id=identifier,state='passed',report=str(path),sha256=self.index.digest(path),cache_key='fixture')]
        self.legacy.side_effect=checked
        tool=SimpleNamespace(RECIPE='candidate-proof-bridges-v1',validate_saved=validate,
            checked=lambda root,pointer,category:self.workflow.checked_manifest(self.index,Path(pointer['path'])))
        extension=self.index.extension
        self.index.extension=lambda name:tool if name=='candidate-proof-bridges' else extension(name)
        first=self.run_check(check_ids=[identifier])[0]
        self.assertEqual(first,self.run_check(check_ids=[identifier])[0])
        self.runtime.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'input changed'):
            self.run_check(check_ids=[identifier])

    def test_absent_manifest_keeps_legacy_fixture_behavior(self):
        self.manifest.unlink()
        result = self.run_check()
        self.assertEqual(result, self.legacy.return_value)
        self.engine.run.assert_not_called()

    def test_unknown_duplicate_or_empty_check_selection_is_rejected(self):
        for values in ([], ['missing'], ['automatic-update-tooling'] * 2):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.run_check(check_ids=values)
        self.engine.run.assert_not_called()

    def test_client_definition_cannot_coerce_the_tooling_adapter(self):
        self.automatic['source_scope'] = 'client'
        self.write_registry([self.automatic])
        with self.assertRaises(ValueError):
            self.run_check()
        self.engine.run.assert_not_called()

    def test_scope_or_receipt_digest_corruption_is_rejected(self):
        real = self.group_report

        def corrupt(*args, **kwargs):
            value = real(*args, **kwargs)
            Path(value['report']).write_bytes(b'corrupt group report')
            return value

        self.engine.run.side_effect = corrupt
        with self.assertRaisesRegex(ValueError, 'receipt changed'):
            self.run_check()

    def test_source_change_during_the_group_pass_is_rejected(self):
        real = self.group_report

        def change(*args, **kwargs):
            value = real(*args, **kwargs)
            self.dependency.write_bytes(b'changed-code')
            return value

        self.engine.run.side_effect = change
        with self.assertRaisesRegex(ValueError, 'input changed|inputs changed'):
            self.run_check()

    def test_on_update_route_uses_groups_for_the_real_reviewed_gate(self):
        self.write_registry([self.automatic])
        route = load('research-update')
        result = route.run_update_checks(self.index, self.workflow, self.args, 'a' * 64)
        self.assertEqual(result[0]['state'], 'passed')
        self.engine.run.assert_called_once()
        self.legacy.assert_not_called()

    def test_scoped_research_route_pins_the_group_receipts_and_runtime(self):
        self.write_registry([self.automatic])
        route = load('research-scoped-v2')
        pins = {}
        kinds = {}

        def pin(path, expected=None, **kwargs):
            self.assertEqual(self.dispatch.digest(path), expected)
            pins[str(path)] = expected
            kinds[str(path)] = kwargs.get('kind')
            return dict(path=str(path), sha256=expected)

        scope = SimpleNamespace(root=self.root, pin=pin)
        result = route.run_checks(self.index, self.args, scope, 'a' * 64, 'test-question')
        self.assertEqual(result[0]['state'], 'passed')
        self.assertIn(str(self.runtime.resolve()), pins)
        self.assertEqual(kinds[str(self.runtime.resolve())], 'runtime')
        self.assertIn(result[0]['report'], pins)
        self.legacy.assert_not_called()

    def test_ordinary_check_once_contains_the_manifest_gated_dispatch(self):
        tree = ast.parse((HERE / 'update-run.py').read_text('utf-8-sig'))
        function = next(node for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef) and node.name == 'check_once')
        source = ast.unparse(function)
        self.assertIn("extension('tooling-check-dispatch-v1').run_checks", source)
        self.assertIn("'tooling-groups-v1.json'", source)
        self.assertIn('workflow.run_checks', source)


if __name__ == '__main__':
    unittest.main()
