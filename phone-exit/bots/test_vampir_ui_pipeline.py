"""Cache identity, integrity and failure boundaries for the offline UI pipeline."""
import sys
import tempfile
import unittest
import json
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
