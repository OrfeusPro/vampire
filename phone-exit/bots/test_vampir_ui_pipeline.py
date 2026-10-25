"""Cache identity, integrity and failure boundaries for the offline UI pipeline."""
import sys
import tempfile
import unittest
import json
import types
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'resource-tools/vampir'))
import ui_pipeline as pipeline
import importlib.util

spec = importlib.util.spec_from_file_location('pipeline_builder_test', Path(__file__).parent / 'resource-tools/vampir/build-ui-prototype.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
spec = importlib.util.spec_from_file_location('ui_pipeline_runner_test', Path(__file__).parent / 'resource-tools/vampir/build-ui-pipeline.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PipelineTests(unittest.TestCase):
    def test_runner_rejects_orchestrator_changed_after_import_before_executing_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            with patch.object(runner, 'ORCHESTRATOR_SHA256', '0' * 64), patch.object(pipeline, 'tree', return_value={}), patch.object(runner, 'load') as provider:
                with self.assertRaisesRegex(ValueError, 'Orchestrator changed after import'):
                    runner.run(folder / 'root', folder / 'snapshot', folder / 'output')
                provider.assert_not_called()

    def test_action_contract_ignores_comments_and_line_offsets_but_not_execution(self):
        source = "def action(value, folder):\n    return value + 1\n"
        same = "\n\n# Independent scheduling change\ndef action(value, folder):\n    # comment\n    return value + 1\n"
        self.assertEqual(pipeline.action_source_sha(source), pipeline.action_source_sha(same))
        self.assertNotEqual(pipeline.action_source_sha(source), pipeline.action_source_sha(source.replace('+ 1', '+ 2')))
        for unsupported in ('value = 1', 'def a(): pass\ndef b(): pass', 'lambda: 1'):
            with self.assertRaises(ValueError): pipeline.action_source_sha(unsupported)

    def test_invocation_pins_arguments_paths_and_helper_contracts(self):
        dependencies = dict(source='sha', provider='v1')
        first = pipeline.invocation_inputs(dependencies, runner.widget_roots_action, (Path('.'), 'request'), helpers=(runner.load,))
        same = pipeline.invocation_inputs(dependencies, runner.widget_roots_action, (Path('.').resolve(), 'request'), helpers=(runner.load,))
        self.assertEqual(first, same)
        self.assertNotEqual(first, pipeline.invocation_inputs(dependencies, runner.widget_roots_action, (Path('.'), 'other'), helpers=(runner.load,)))
        self.assertNotEqual(first, pipeline.invocation_inputs(dict(source='changed'), runner.widget_roots_action, (Path('.'), 'request'), helpers=(runner.load,)))
        self.assertNotEqual(first, pipeline.invocation_inputs(dependencies, runner.widget_roots_action, (Path('.'), 'request')))
        with self.assertRaises(ValueError): pipeline.invocation_inputs({}, runner.load, (object(),))
        with self.assertRaises(ValueError): pipeline.invocation_inputs({}, runner.load, (), helpers=(runner.load,))

    def test_only_changed_branch_and_reverse_consumer_are_rebuilt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = "def action(value, folder):\n    (folder / 'data').write_text(str(value), encoding='utf8')\n    return {'value': value}\n"
            actions = []
            for index, text in enumerate([source, source.replace("{'value': value}", "{'value': value + 1}")]):
                path = root / ('provider' + str(index) + '.py')
                path.write_text(text, 'utf8')
                module = types.ModuleType('stage_fixture' + str(index))
                exec(compile(text, str(path), 'exec'), module.__dict__)
                actions.append(module.action)
            def run(action):
                def call(name, inputs, fn, value):
                    contract = pipeline.invocation_inputs(inputs, fn, (value,))
                    return pipeline.stage(root / 'cache', name, contract, lambda folder: fn(value, folder))
                common = call('common', dict(source='original'), actions[0], 2)
                branch = call('branch', dict(common=common['id']), action, common['result']['value'])
                sibling = call('sibling', dict(common=common['id']), actions[0], common['result']['value'])
                consumer = call('consumer', dict(branch=branch['id']), actions[0], branch['result']['value'])
                return common, branch, sibling, consumer
            first = run(actions[0])
            repeated = run(actions[0])
            changed = run(actions[1])
            self.assertTrue(all(s['reused'] for s in repeated))
            self.assertEqual([s['reused'] for s in changed], [True, False, True, False])
            self.assertEqual(changed[3]['result']['value'], 3)
            self.assertEqual(changed[2]['id'], first[2]['id'])

    def test_baseline_is_pinned_to_graph_and_index_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            index, graph = folder / 'index.json', folder / 'composition-graph.json'
            index.write_text('{}', 'utf8')
            graph.write_text('{"nodes":{}}', 'utf8')
            ready = folder / 'ready.json'
            ready.write_text(json.dumps(dict(component_layer=str(folder), component_index_sha256=pipeline.sha(index),
                                            component_graph_sha256=pipeline.sha(graph))), 'utf8')
            digest = pipeline.sha(ready)
            self.assertEqual(runner.checked_readiness(ready, digest)[1], {'nodes': {}})
            with self.assertRaises(ValueError):
                runner.checked_readiness(ready, '0' * 64)
            graph.write_text('{"nodes":{"changed":{}}}', 'utf8')
            with self.assertRaises(ValueError):
                runner.checked_readiness(ready, digest)
            graph.write_text('{"nodes":{}}', 'utf8')
            index.write_text('{"changed":true}', 'utf8')
            with self.assertRaises(ValueError):
                runner.checked_readiness(ready, digest)

    def test_incremental_gate_does_not_grant_unrestricted_generation(self):
        gate = {'schema': 2, 'phase': 'incremental_verified_rules', 'incremental_allowed': True,
                'generation_allowed': False}
        with self.assertRaises(ValueError):
            builder.generation_policy(gate)
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / 'readiness.json'
            ready.write_text('{"schema":1,"renderer_rules":["guessed"]}', 'utf8')
            with self.assertRaisesRegex(ValueError, 'renderer rules'):
                builder.generation_policy(gate, ready_report=ready)
        with self.assertRaisesRegex(ValueError, 'не разрешена'):
            builder.generation_policy({'phase': 'property_inventory_and_review'}, ready_report=Path('unused'))

    def test_reuse_and_dependency_invalidation(self):
        with tempfile.TemporaryDirectory() as tmp:
            count = []
            def action(folder):
                count.append(1)
                (folder / 'data.json').write_text('{}', 'utf8')
                return {'value': 1}
            a = pipeline.stage(tmp, 'audit', {'source': 'a', 'rule': 1}, action)
            b = pipeline.stage(tmp, 'audit', {'source': 'a', 'rule': 1}, action)
            c = pipeline.stage(tmp, 'audit', {'source': 'a', 'rule': 2}, action)
            self.assertEqual(a['id'], b['id'])
            self.assertTrue(b['reused'])
            self.assertNotEqual(a['id'], c['id'])
            self.assertEqual(len(count), 2)

    def test_corruption_and_missing_output_are_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            def action(folder):
                (folder / 'result').write_bytes(b'original')
                return {}
            a = pipeline.stage(tmp, 'audit', {}, action)
            result = Path(a['output']) / 'result'
            result.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                pipeline.stage(tmp, 'audit', {}, action)
            result.unlink()
            with self.assertRaises(ValueError):
                pipeline.stage(tmp, 'audit', {}, action)

    def test_failed_stage_is_not_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            def action(folder):
                raise ValueError('incomplete')
            with self.assertRaises(ValueError):
                pipeline.stage(tmp, 'audit', {}, action)
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                pipeline.stage(tmp, 'audit', {}, lambda folder: {})


if __name__ == '__main__':
    unittest.main()
