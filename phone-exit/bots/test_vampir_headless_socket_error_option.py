"""Source-bound socket option translation and readiness error handling."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class SocketErrorOptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-socket-error-option.py'
        spec=importlib.util.spec_from_file_location('socket_option_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/socket-error-option-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_reproducible_source_vtable_and_import(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(self.report['engine_vtable']['bytes']),0x60)[0],0x1445f0b10)
        self.assertEqual(self.report['import_info']['ordinal'],7)
        self.assertEqual(self.report['export']['name'],'getsockopt')
        self.assertEqual(self.report['option_body']['instructions'][-1]['mnemonic'],'ret')
        self.assertEqual(len(bytes.fromhex(self.report['switch_table']['bytes'])),72)

    def test_readiness_executes_option_and_distinguishes_failure(self):
        for name in ('ready-zero','positive-return','changed-output-size'):
            c=self.cases[name]
            self.assertEqual((c['state_after'],c['completion_codes']),(6,[1]))
            event=next(e for e in c['events'] if e['action']=='getsockopt_fixture')
            self.assertEqual((event['level'],event['option'],event['size_before']),(65535,4103,4))
            self.assertFalse(any(e['action']=='socket_error_option_capture' for e in c['events']))
        for name in ('pending-error','refused-error','syscall-fail','exception'):
            self.assertEqual((self.cases[name]['state_after'],self.cases[name]['completion_codes']),(2,[2]))
        self.assertEqual((self.cases['no-write']['state_after'],self.cases['no-write']['completion_codes']),(2,[]))
        for name in ('no-write','exception'):
            self.assertFalse(any(e['action']=='getsockopt_fixture' for e in self.cases[name]['events']))

    def test_raw_level_option_table_and_out_of_range_default(self):
        self.assertEqual(len(self.report['mappings']),95)
        options=[32,4103,8,128,256,4098,4102,4,4097,4101,4104,12,13,9,10,4,1,1,0]
        levels=[65535,0,6,17,0]
        for m in self.report['mappings']:
            self.assertEqual(m['returned'],1)
            self.assertEqual(len(m['events']),1)
            event=m['events'][0]
            self.assertEqual((event['level'],event['option']),
                (levels[m['level_selector']],options[m['option_selector']]))


if __name__=='__main__':
    unittest.main()
