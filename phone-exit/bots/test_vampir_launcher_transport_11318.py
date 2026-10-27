"""Complete native wrapper replay stops at an explicit offline transport fixture."""
import importlib.util
from pathlib import Path
import unittest


class LauncherTransportTests(unittest.TestCase):
    def test_argument_forwarding_and_callback_ownership(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-launcher-transport-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_transport_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file())
        self.assertEqual(result['source_sha256'],module.SHA)
        self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']);self.assertFalse(result['profile_activation'])
        self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual(len(result['exports']),1)
        self.assertEqual(len(result['cases']),6)
        for case in result['cases']:
            expected=['send-boundary']
            if case['wrapper']=='token':
                expected=(['copy'] if case['mode']!='empty' else [])+expected+['map-cleanup']
                if case['mode']!='empty':expected+=['destroy']
            self.assertEqual(case['calls'],expected)
            self.assertTrue(case['input_delegate_moved'])
            self.assertEqual(case['headers_forwarded'],case['wrapper']=='signin')


if __name__=='__main__':unittest.main()
