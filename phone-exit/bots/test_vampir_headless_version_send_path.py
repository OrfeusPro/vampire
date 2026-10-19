"""Native Version wrapper through frame construction and owning byte queue."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest
import zlib

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.frame_primitives import xor_transform
from vampir_core.version_packet import VersionPayload


class VersionSendPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-version-send-path.py'
        spec=importlib.util.spec_from_file_location('version_send_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/version-send-path-replay.json').read_text('utf-8'))

    def test_source_and_native_path_are_reproducible(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),18)
        self.assertEqual(self.report['leaves'][0]['bytes'],'488b4910e9f7190000')
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x144aacd05]['rip_references'],[0x14b520cb4])
        self.assertEqual(rows[0x144aacd3c]['rip_references'],[0x14b520db0])
        self.assertEqual(rows[0x1467aaa89]['operands'],'0x144aab2f0')

    def test_all_native_frames_match_body_crc_sequence_xor_and_own_bytes(self):
        for c in self.report['cases'][:14]:
            f=c['fixture'];fields=c['packet_fields']
            model=VersionPayload(tuple(fields['strings']),tuple(fields['integers']))
            body=model.encode(max_payload_size=4096)
            inner=struct.pack('<HH',1,f['sequence'])+body
            clear=struct.pack('<I',zlib.crc32(inner))+inner
            expected=(len(clear)+3).to_bytes(3,'little')+xor_transform(clear,f['key'])
            self.assertEqual(c['frame_hex'],expected.hex())
            self.assertEqual((c['returned'],c['sequence_after'],c['queue_calls'],c['wake_calls']),
                (1,(f['sequence']+1)&65535,1,int(f['wake'])))
            self.assertTrue(c['queue_owns_bytes'])
            self.assertEqual(c['packet_byte_a'],f['metadata_byte'] if f['metadata_present'] else 0)
            entries=[e['address'] for e in c['events'] if e['action']=='native_entry']
            self.assertEqual(entries,[0x1467aaa10,0x144aab2f0,0x144aaccf0,0x1456e5cf0])
            self.assertEqual(sum(e['action']=='archive_cleanup_capture' for e in c['events']),2)

    def test_pre_frame_gates_do_not_advance_sequence_or_enqueue(self):
        for c in self.report['cases'][14:]:
            f=c['fixture']
            self.assertEqual((c['returned'],c['sequence_after'],c['queue_calls'],c['wake_calls'],c['frame_hex']),
                (0,f['sequence'],0,0,''))
            self.assertFalse(any(e.get('address')==0x1456e5cf0 for e in c['events']))
            failure=sum(e['action']=='send_failure_helper_capture' for e in c['events'])
            self.assertEqual(failure,int(f['name']=='mode-two'))


if __name__=='__main__':
    unittest.main()
