"""Whole response callbacks must classify failures before native asynchronous dispatch."""
import importlib.util
from pathlib import Path
import unittest


class ResponseCallbackTests(unittest.TestCase):
    def test_lifecycle_http_sdk_error_and_result_gates(self):
        p=Path(__file__).parent/'resource-tools/vampir/replay-launcher-dispatch-11318.py'
        spec=importlib.util.spec_from_file_location('response_callbacks',p)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run(with_responses=True)
        self.assertTrue(artifact.is_file());self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']);self.assertFalse(result['profile_activation'])
        rows=result['responses']['cases'];self.assertEqual(len(rows),74)
        for route in ('token','sign-in'):
            selected=[r for r in rows if r['route']==route]
            self.assertEqual(len(selected),37)
            self.assertEqual(sum(r['category']=='none' for r in selected),4)
            for row in selected:
                inputs=row['inputs']
                if row['category']=='none':self.assertEqual(row['events'],[])
                else:self.assertEqual(row['events'].count('queue-transfer'),1)
                if inputs['name']=='fields':
                    if inputs.get('error_code')==7:self.assertEqual(row['category'],'error')
                    elif inputs['status'] not in (200,206):self.assertEqual(row['category'],'error')
                    elif route=='sign-in':
                        self.assertEqual(row['category'],'original');self.assertEqual(row['constructors'],[])
                    else:self.assertEqual(row['category'],'token' if inputs['has_result'] else 'invalid-json')
        self.assertEqual(result['responses']['conversion_import']['name'],'_wtoi')


if __name__=='__main__':unittest.main()
