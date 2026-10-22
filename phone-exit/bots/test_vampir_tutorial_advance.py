"""Native local tutorial progress mutation; no readiness or game action claims."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).parent


class TutorialAdvanceTests(unittest.TestCase):
    def test_native_step_gate_and_mutations(self):
        run=subprocess.run([sys.executable,'-X','utf8',str(HERE/'resource-tools/vampir/replay-release-tutorial-advance.py')],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=120)
        report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),64)
        self.assertTrue(report['null_record_skipped'])
        for c in report['cases']:
            self.assertEqual(c['step_called'],not c['blocked'])
            expected=c['progress'] if c['blocked'] or c['keep_step'] else (c['progress']+1)&0xffffffff
            self.assertEqual(c['progress_after'],expected)
            self.assertEqual(c['state_after'],1 if not c['blocked'] and c['state']==0 else c['state'])


if __name__=='__main__':unittest.main()
