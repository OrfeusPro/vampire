"""Current stat notifications require wire binding, closure and unchanged receipts."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class StatNotificationsCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-stat-notifications-current.py'
        spec = importlib.util.spec_from_file_location('stat_notifications_current_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())

    def test_current_bindings_preserve_second_value_projection(self):
        self.assertEqual({packet: row['reader'] for packet, row in self.report['packet_bindings'].items()},
            {'321': '0x1456c4760', '322': '0x1456c5650'})
        self.assertEqual(self.report['inherited_native_cases'], 1119)
        self.assertTrue(self.report['apply_uses_second_value'])
        self.assertFalse(self.report['runtime_admitted'])

    def test_warm_proof_skips_source_transfer(self):
        with patch.object(self.tool, 'transfer', side_effect=AssertionError('Stat transfer repeated')):
            self.assertEqual(self.tool.verify(), dict(self.pointer, reused=True))

    def test_incorrect_packet_id_cannot_pass_validation(self):
        forged = copy.deepcopy(self.report)
        forged['packet_bindings']['322']['packet_id'] = 321
        with self.assertRaisesRegex(ValueError, 'packet ID binding differs'):
            self.tool.validate(forged, self.report['definition'])


if __name__ == '__main__':
    unittest.main()
