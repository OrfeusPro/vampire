"""Current whole ID17 reader/handler/receiver and registration guards."""
import copy
import json
from pathlib import Path
import unittest
from test_vampir_update_contracts import load,HERE

ROOT=Path('F:/PhoneExit Resources/Vampir')


class PingResult11318Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.report=load('run-clock-world-batch-11318').run(ROOT)[1]['reports']['result']

    def test_complete_native_wire_matrix(self):
        r=self.report
        self.assertEqual(len(r['cases']),36)
        self.assertTrue(r['native_execution'])
        self.assertEqual({c['result_bits'] for c in r['cases']},{0,16,0xffffffff})
        self.assertEqual({c['value_bits'] for c in r['cases']},{0,2**64-1})
        self.assertTrue(all(c['outstanding_after']==0 and c['tracking_index_after']==0 for c in r['cases']))
        self.assertFalse(r['network_used'] or r['profile_activated'])

    def test_recovery_and_short_input(self):
        self.assertEqual([c['size'] for c in self.report['short']],list(range(12)))
        for row in self.report['cases']:
            self.assertEqual(row['recovery_calls'],int(bool(row['flags']&1024)))

    def test_changed_registration_or_source_rejects(self):
        context=json.loads((HERE/'knowledge/native-contexts/ping-world-11318.json').read_bytes())
        bad=copy.deepcopy(context);bad['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'source differs'):
            load('verify-ping-world-source-11318').verify(bad,ROOT)
        bad=copy.deepcopy(context)
        bad['ping']['handler_table']=bad['ping']['packet_table']
        with self.assertRaises(ValueError):load('verify-ping-world-source-11318').verify(bad,ROOT)


if __name__=='__main__':unittest.main()
