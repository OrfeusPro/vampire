"""Current lobby sender cache and exact native/portable frame agreement."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class CurrentLobbySenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-lobby-sender-current.py'
        spec = importlib.util.spec_from_file_location('lobby_sender_current', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.result = cls.tool.verify()

    def test_unchanged_sender_uses_receipt(self):
        with patch.object(self.tool, 'Replay', side_effect=AssertionError('Unexpected sender replay')):
            repeated = self.tool.verify()
        self.assertEqual(repeated, dict(self.result, reused=True))
        report = json.loads(Path(repeated['report']).read_bytes())
        self.assertEqual(len(report['cases']), 8)
        self.assertEqual({row['request_id'] for row in report['cases']}, {None, 1, 3, 103})
        self.assertEqual({row['path'] for row in report['cases']}, {'direct', 'queued', 'suppressed'})
        report['cases'][0]['sequence_after'] += 1
        with self.assertRaisesRegex(ValueError, 'report differs'):
            self.tool.validate(report, report['definition'])

    def test_changed_inputs_rejected_before_native_execution(self):
        with patch.object(self.tool, 'digest', return_value='0' * 64), patch.object(self.tool, 'Replay') as replay:
            with self.assertRaises(ValueError):
                self.tool.verify()
            replay.assert_not_called()
