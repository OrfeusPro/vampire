"""Current quest observation inherits native outcomes without a new native run."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class QuestObservationCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-quest-observation-current.py'
        spec = importlib.util.spec_from_file_location('quest_observation_current_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())

    def test_exact_packets_bounds_and_native_portable_trailing_boundary(self):
        self.assertEqual(self.report['inherited_native_cases'], 1178)
        self.assertEqual(self.report['bounds'], self.tool.BOUNDS)
        self.assertFalse(self.report['native_execution'])
        self.assertFalse(self.report['runtime_admitted'])
        self.assertEqual(self.report['packet_bindings']['1854']['getter'], '0x145834840')
        self.assertEqual(self.report['packet_bindings']['9905']['getter'], '0x1458562c0')
        for rows in self.report['projection_cases'].values():
            trailing = [row for row in rows if row['kind'] == 'trailing']
            self.assertEqual(len(trailing), 1)
            self.assertTrue(trailing[0]['native_accepted'])
            self.assertFalse(trailing[0]['portable_accepted'])
            self.assertEqual(trailing[0]['native_consumed'], trailing[0]['size'] - 2)

    def test_warm_proof_never_repeats_bindings_or_projection(self):
        with patch.object(self.tool, 'packet_bindings', side_effect=AssertionError('Binding check repeated')), \
                patch.object(self.tool, 'projection', side_effect=AssertionError('Projection repeated')):
            self.assertEqual(self.tool.verify(), dict(self.pointer, reused=True))

    def test_unqualified_packet_or_broader_bounds_cannot_pass(self):
        forged = copy.deepcopy(self.report)
        forged['packet_bindings']['9905']['packet_id'] = 9903
        with self.assertRaisesRegex(ValueError, 'packet binding differs'):
            self.tool.validate(forged, self.report['definition'])
        forged = copy.deepcopy(self.report)
        forged['bounds']['1854']['max_groups'] = 128
        with self.assertRaisesRegex(ValueError, 'boundary differs'):
            self.tool.validate(forged, self.report['definition'])
        forged = copy.deepcopy(self.report)
        forged['projection_cases']['9905'][-1]['portable_accepted'] = True
        with self.assertRaisesRegex(ValueError, 'matrix differs'):
            self.tool.validate(forged, self.report['definition'])

    def test_retained_bytes_and_case_consumption_are_not_optional(self):
        forged = copy.deepcopy(self.report)
        forged['projection_cases']['1854'][0]['projection_sha256']='0'*64
        with self.assertRaisesRegex(ValueError, 'case differs'):
            self.tool.validate(forged, self.report['definition'])
        forged = copy.deepcopy(self.report)
        forged['packet_bindings']['1854']['reader']='0x1458562c0'
        with self.assertRaisesRegex(ValueError, 'packet binding differs'):
            self.tool.validate(forged, self.report['definition'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence.json'
            path.write_bytes(b'original')
            inputs = {str(path): self.tool.digest(path)}
            self.tool.barrier(inputs)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'retained input changed'):
                self.tool.barrier(inputs)
        forged = copy.deepcopy(self.report)
        forged['projection_cases']['1854'][-1]['native_consumed'] += 1
        with self.assertRaisesRegex(ValueError, 'case differs'):
            self.tool.validate(forged, self.report['definition'])
        forged = copy.deepcopy(self.report)
        forged['parents']['1854']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'boundary differs'):
            self.tool.validate(forged, self.report['definition'])


if __name__ == '__main__':
    unittest.main()
