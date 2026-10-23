"""Current native terms continuation with synthetic UI state, no real consent."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


class ReleaseTermsContinuationTests(unittest.TestCase):
    def tool(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-terms-continuation.py'
        spec = importlib.util.spec_from_file_location('terms_continuation_test', path)
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value

    def test_real_virtual_bridges_classifier_and_owner_lifetime(self):
        report = self.tool().replay()
        self.assertEqual(len(report['cases']), 99)
        handoffs = [e for c in report['cases'] for e in c['events'] if e['kind'] == 'sign_up_handoff']
        self.assertEqual(len(handoffs), 12)
        self.assertEqual(sum(e['channel'] == 100 and e['step'] == 12 for e in handoffs), 4)
        self.assertEqual(sum(e['channel'] == 33 and e['step'] == 13 for e in handoffs), 8)
        for case in report['cases']:
            if 'ui_state' not in case: continue
            self.assertEqual(case['owner_count'], 4)
            if case['ui_state'] != 2 or not case['bound']:
                self.assertFalse(any(e['kind'] == 'sign_up_handoff' for e in case['events']))
        self.assertEqual(report['network_requests'], 0)

    def test_changed_export_is_rejected(self):
        read = Path.read_bytes
        def changed(path):
            payload = read(path)
            return payload + b' ' if path.parent.name == 'run-c558937a4554' else payload
        with patch.object(Path, 'read_bytes', changed):
            with self.assertRaisesRegex(ValueError, 'Terms export changed'):
                self.tool().replay()


if __name__ == '__main__': unittest.main()
