"""Native connect endpoint selection and signed port guard, with no sockets."""
import importlib.util
import json
from pathlib import Path
import unittest


class GameConnectTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-game-connect-target.py'
        spec=importlib.util.spec_from_file_location('game_connect_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/game-connect-target-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_connect_consumer_and_calls(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),13)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x144aabde2]['operands'],'r12d, word ptr [r13 + 0x288]')
        self.assertEqual(rows[0x144aabdd8]['operands'],'r12d, word ptr [r13 + 0x2a0]')
        self.assertEqual(rows[0x144aabe7c]['mnemonic'],'js')
        self.assertEqual(rows[0x144aac01e]['direct_target'],0x1445e2a50)
        self.assertEqual(rows[0x144aac02c]['direct_target'],0x1445ea1b0)
        texts=[l['text'] for l in self.report['literals']]
        self.assertIn('Connect to GameServer[%s:%d]',texts)

    def test_primary_override_and_string_storage_paths(self):
        for name,host,port in [('primary','primary.invalid',12345),
             ('long-primary','long-primary-host.invalid',12345),('override','override.invalid',23456),
             ('short-override','x',23456),('empty-primary-override','override.invalid',23456)]:
            events=self.cases[name]['events']
            self.assertEqual([e for e in events if e['action']=='endpoint_constructor_entry'],
                             [dict(action='endpoint_constructor_entry',host=host,port=port)])
            self.assertEqual(sum(e['action']=='socket_connect_capture' for e in events),1)
            connected=next(e for e in events if e['action']=='socket_connect_capture')
            self.assertEqual((connected['endpoint_port'],connected['endpoint_field_2c']),(port,0))

    def test_empty_disabled_signed_guard_and_result_capture(self):
        for name in ('disabled','empty-primary','port-32768','port-65535','override-high-port'):
            events=self.cases[name]['events']
            self.assertFalse(any(e['action']=='endpoint_constructor_entry' for e in events),name)
        for port in (0,32767):
            events=self.cases['port-'+str(port)]['events']
            self.assertEqual(next(e['port'] for e in events if e['action']=='endpoint_constructor_entry'),port)
        events=self.cases['connect-false']['events']
        self.assertEqual(next(e['returned'] for e in events if e['action']=='socket_connect_capture'),0)
        for case in self.report['cases']:
            self.assertEqual(case['busy_after_connect'],1)
            self.assertEqual(case['target_words'][1],22222)


if __name__=='__main__':
    unittest.main()
