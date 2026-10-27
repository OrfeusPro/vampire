"""Current-source UTF-8 admission through the shared bounded native batch."""
import unittest
from test_vampir_update_contracts import load


class Utf8Current11320Tests(unittest.TestCase):
    def test_current_utf8_report_from_shared_batch(self):
        runner = load('run-wire-batch-11320')
        _, result, _ = runner.run()
        report = result['reports']['utf8']
        self.assertEqual(report['source_sha256'], runner.SHA)
        self.assertEqual((len(report['cases']), len(report['scalar_cases'])), (142, 80))
        self.assertTrue(all(row['guards'] for row in report['cases'] + report['scalar_cases']))
        self.assertFalse(result['runtime_activated'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])


if __name__ == '__main__':
    unittest.main()
