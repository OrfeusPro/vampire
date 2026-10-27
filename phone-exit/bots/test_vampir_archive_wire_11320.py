"""Current-source archive wire admission through the shared native batch."""
import unittest
from test_vampir_update_contracts import load


class ArchiveWireCurrent11320Tests(unittest.TestCase):
    def test_current_archive_wire_report_from_shared_batch(self):
        runner = load('run-wire-batch-11320')
        _, result, _ = runner.run()
        report = result['reports']['archive-wire']
        self.assertEqual(report['source_sha256'], runner.SHA)
        self.assertEqual((len(report['cases']), len(report['wire_cases'])), (45, 64))
        self.assertTrue(all(row['guards'] for row in report['wire_cases']))
        self.assertEqual({row['packet'] for row in report['wire_cases']}, {'game-version', 'game-login'})
        self.assertFalse(result['runtime_activated'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])


if __name__ == '__main__':
    unittest.main()
