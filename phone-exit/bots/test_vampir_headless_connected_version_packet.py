"""Native first connected packet is PktVersion; fields reach a captured send."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class ConnectedVersionPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-connected-version-packet.py'
        spec=importlib.util.spec_from_file_location('connected_version_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/connected-version-packet-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_reproducible_ctor_name_id_and_send_binding(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),6)
        self.assertEqual(self.report['packet_name']['name'],'PktVersion')
        self.assertEqual(bytes.fromhex(self.report['packet_name']['bytes']),b'PktVersion\0')
        self.assertEqual(self.report['packet_id']['bytes'],'b801000000c3')
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(self.report['packet_table']['bytes']),0x10)[0],0x1456e5cf0)
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(self.report['wrapper_table']['bytes']),0x38)[0],0x1467aaa10)

    def test_native_callback_copies_fixture_fields_and_writes_raw_values(self):
        for name,c in self.cases.items():
            if name=='delegate-disabled':continue
            f=c['fixture'];p=c['packet']
            self.assertEqual(p['vtable'],0x1498d6990)
            expected={'0x10':f['global_text'],'0x28':f['combined_text'],'0x38':f['first_text'],
                '0x48':f['provider_text'],'0xb0':f['version_ascii']}
            expected.update({hex(o):'' for o in (0x58,0x68,0x78,0x88,0xa0)})
            self.assertEqual(p['strings'],expected)
            self.assertEqual((p['raw_20'],p['raw_98'],p['raw_c0']),(0,207,f['raw_enum']))
            self.assertEqual(c['wrapper_160_after'],0)
            self.assertEqual(sum(e['action']=='version_send_capture' for e in c['events']),1)

    def test_send_false_is_not_auth_failure_policy_and_gate_prevents_packet(self):
        rejected=self.cases['send-false']
        self.assertEqual(rejected['packet'],self.cases['version-default']['packet'])
        self.assertEqual([e['returned'] for e in rejected['events'] if e['action']=='version_send_capture'],[False])
        self.assertEqual([e['al'] for e in rejected['events'] if e['action']=='native_delegate_result'],[1])
        disabled=self.cases['delegate-disabled']
        self.assertIsNone(disabled['packet'])
        self.assertEqual(disabled['wrapper_160_after'],123456)
        self.assertFalse(any(e['action']=='native_game_connected_callback' for e in disabled['events']))


if __name__=='__main__':
    unittest.main()
