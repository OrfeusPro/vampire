"""Native connection delegate binding and game recipient routing."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class TransportConnectedDelegateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-transport-connected-delegate.py'
        spec=importlib.util.spec_from_file_location('connected_delegate_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/transport-connected-delegate-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_reproducible_source_tables_and_actions(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),12)
        self.assertEqual(len(self.report['bindings']),11)
        self.assertEqual(self.report['leaves'][0]['bytes'],'488b01ff6048')
        self.assertEqual([(t['address'],t['verified_slot'],t['target']) for t in self.report['tables']],
            [(0x14900a528,0x60,0x14370c510),(0x149d84e50,0x48,0x1467a9cd0),(0x149d84e50,8,0x1467aa0e0)])

    def test_native_binding_size_method_and_this(self):
        for c in self.report['cases']:
            pointer,units,_=struct.unpack('<QII',bytes.fromhex(c['bound_descriptor']))
            self.assertEqual(units,3)
            self.assertTrue(c['wrapper_backpointer_matches'])
            if c['fixture']['allocation_fail']:
                self.assertEqual(pointer,0)
                self.assertIsNone(c['bound_delegate'])
            else:
                self.assertNotEqual(pointer,0)
                self.assertTrue(c['delegate_target_matches'])
                data=bytes.fromhex(c['bound_delegate'])
                self.assertEqual(struct.unpack_from('<Q',data)[0],0x14900a528)
                self.assertEqual(struct.unpack_from('<Q',data,0x20)[0],0x1437113ec)
                self.assertEqual(struct.unpack_from('<i',data,0x28)[0],0)

    def test_gates_and_bridge_success_is_not_callback_result(self):
        active={'ready-owner','special-flag','callback-true'}
        for name,c in self.cases.items():
            callbacks=[e for e in c['events'] if e['action']=='game_connected_recipient_capture']
            results=[e['al'] for e in c['events'] if e['action']=='native_delegate_result']
            self.assertEqual(len(callbacks),int(name in active))
            self.assertEqual(results,[1] if name in active else [])
            if callbacks:
                self.assertEqual(callbacks[0]['endpoint_descriptor'],'00'*16)
                self.assertEqual(callbacks[0]['returned'],name=='callback-true')
            self.assertFalse(any(e['action']=='owner_virtual_60_capture' for e in c['events']))


if __name__=='__main__':
    unittest.main()
