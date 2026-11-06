"""Current native enum readers and their content-addressed receipt."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class WorldSelectClampsCurrentTests(unittest.TestCase):
    def test_current_bounds_and_cache_reuse(self):
        path = Path(__file__).with_name('resource-tools') / 'vampir/verify-world-select-clamps-current.py'
        spec = importlib.util.spec_from_file_location('world_select_clamps_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        result = tool.verify()
        report = json.loads(Path(result['report']).read_bytes())
        self.assertEqual(report['current_bounds'], {'player+0x1d8 item+8': 97, 'player+0x250 item+9': 8})
        self.assertEqual(len(report['cases']), 15)
        with patch.object(tool, 'execute', side_effect=AssertionError('Unexpected native clamp replay')):
            self.assertEqual(tool.verify(), dict(result, reused=True))
