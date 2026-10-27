"""Current-source string writer admission through the shared native batch."""
import unittest
from test_vampir_update_contracts import load


class StringWriterCurrent11320Tests(unittest.TestCase):
    def test_current_string_writer_report_from_shared_batch(self):
        runner = load('run-wire-batch-11320')
        _, result, _ = runner.run()
        report = result['reports']['string-writer']
        self.assertEqual(report['source_sha256'], runner.SHA)
        self.assertEqual(len(report['cases']), 228)
        self.assertTrue(all(row['guards'] for row in report['cases']))
        self.assertEqual({row['archive_result'] for row in report['cases']}, {0, 1, 128, 255})
        self.assertFalse(result['runtime_activated'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])


if __name__ == '__main__':
    unittest.main()
