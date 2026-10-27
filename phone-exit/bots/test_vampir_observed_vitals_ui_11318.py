"""Shared read-only observational vitals views; no socket or browser actions."""
from pathlib import Path
import subprocess
import unittest

HERE=Path(__file__).parent


class ObservedVitalsUi11318Tests(unittest.TestCase):
    def test_observational_vitals_and_existing_adapter_contracts(self):
        for relative in ('vampir/ui-prototype/observed-vitals.test.cjs',
                         'resource-tools/vampir/test-live-state.cjs',
                         'vampir/ui-prototype/prototype-live-model.test.cjs'):
            with self.subTest(suite=relative):
                result=subprocess.run(['node',str(HERE/relative)],capture_output=True,
                    text=True,encoding='utf-8',timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__=='__main__':unittest.main()
