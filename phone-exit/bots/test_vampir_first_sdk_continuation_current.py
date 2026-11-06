"""Source-bound first-SDK continuations; no account or network is used."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


def tool():
    spec = importlib.util.spec_from_file_location('first_sdk_continuation_test', HERE / 'verify-first-sdk-continuation-current.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FirstSdkContinuationCurrentTests(unittest.TestCase):
    def changed(self, change, message):
        module = tool()
        context = json.loads(module.CONTEXT.read_bytes())
        change(context)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'context.json'
            path.write_text(json.dumps(context), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, message): module.verify(path)

    def test_native_current_fetch_and_terms_matrix(self):
        result = tool().verify()
        report = json.loads(Path(result['report']).read_bytes())
        self.assertEqual((result['fetch_cases'], result['terms_cases']), (27, 99))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['runtime_admitted'])
        challenge = [case for case in report['fetch_cases'] if any(event['kind'] == 'basic_terms' for event in case['events'])]
        self.assertEqual([(x['code'], x['context'], x['success']) for x in challenge], [(30050027, 1203, False)])
        handoffs = [event for case in report['terms_cases'] for event in case['events'] if event['kind'] == 'sign_up']
        self.assertEqual(len(handoffs), 12)
        self.assertEqual(sum(x['channel'] == 33 and x['step'] == 13 for x in handoffs), 8)

    def test_changed_source_is_rejected(self):
        self.changed(lambda c: c.update(source_sha256='0' * 64), 'source differs')

    def test_native_bridge_cannot_be_replaced_by_capture(self):
        self.changed(lambda c: c['fixtures'].update(sign_up=c['functions']['success_bridge']), 'cannot be replaced')

    def test_swapped_virtual_tables_are_rejected(self):
        def swap(c):
            c['tables']['success'], c['tables']['error'] = c['tables']['error'], c['tables']['success']
        self.changed(swap, 'virtual binding differs')


if __name__ == '__main__':
    unittest.main()
