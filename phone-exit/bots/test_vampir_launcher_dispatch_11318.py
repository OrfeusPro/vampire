"""Native dispatch captures must outlive temporary cleanup and preserve caller inputs."""
import importlib.util
from pathlib import Path
import unittest


class DispatchTests(unittest.TestCase):
    def test_native_async_capture_and_retained_reference(self):
        p=Path(__file__).parent/'resource-tools/vampir/replay-launcher-dispatch-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_dispatch',p)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']);self.assertFalse(result['profile_activation'])
        self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual(len(result['cases']),16)
        for route in ('token','sign-in'):
            rows=[r for r in result['cases'] if r['route']==route]
            self.assertEqual(len(rows),8)
            self.assertEqual({r['initial_refs'] for r in rows},{0,1,2,7})
            for row in rows:
                self.assertEqual(row['released_refs'],row['initial_refs'])
                self.assertEqual(row['queued_refs'],row['initial_refs']+1 if row['initial_refs'] else None)
                self.assertLess(row['events'].index('queue-transfer'),row['events'].index('temporary-cleanup'))


if __name__=='__main__':unittest.main()
