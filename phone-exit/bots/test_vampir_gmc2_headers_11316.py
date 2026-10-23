import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class Gmc2Headers11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('gmc2_headers_test',HERE/'replay-gmc2-headers-11316.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_current_native_headers_and_optional_gates(self):
        result = self.tool().replay()
        self.assertEqual(len(result['cases']),73)
        self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_ready'])
        for case in result['cases']:
            inputs,actual = case['inputs'],case['actual']
            self.assertEqual(actual['method'],'GET')
            self.assertEqual(actual['url'],inputs['url'])
            self.assertTrue(case['canaries_unchanged'])
            headers = actual['headers']
            expected = [('Content-Type','application/json'),('Accept','application/json'),
                        ('serviceCode',inputs['service_code']),('gameCode',inputs['game_code']),
                        ('buildCode',{0:'A',1:'B',2:'C'}.get(inputs['build_code'],'A')),
                        ('nmDeviceKey',inputs['device_key'])]
            if inputs['etag']:
                expected.append(('eTag',inputs['etag']))
            if inputs['access_token']:
                expected.extend([('playerId',inputs['player_id']),('accessToken',inputs['access_token'])])
            self.assertEqual(headers,expected)
        self.assertEqual(len(result['cases'][-1]['actual']['headers']),6)
        self.assertEqual(result['cases'][-1]['actual']['headers'][-1],('nmDeviceKey',''))

    def test_changed_source_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.suffix=='.exe' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'source SHA changed'):
                self.tool().replay()

    def test_changed_export_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'):
                self.tool().replay()


if __name__=='__main__':
    unittest.main()
