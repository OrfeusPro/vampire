"""Whole native selection caller/handoff/body/frame parity, including refusal."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest
import zlib

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_select import CharacterSelectPayload,SOURCE_SHA256
from vampir_core.frame_primitives import xor_transform
from vampir_core.character_list import decode_character_list


class CharacterSelectSendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-character-select-send.py'
        spec=importlib.util.spec_from_file_location('select_send_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/character-select-send-replay.json').read_text('utf-8'))
        path=HERE/'resource-tools/vampir/replay-character-list-reader.py'
        spec=importlib.util.spec_from_file_location('select_body_fixture',path)
        cls.reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.reader)

    def test_native_source_report_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(self.report['sha256'],SOURCE_SHA256)
        self.assertEqual(len(self.report['cases']),27)
        self.assertFalse(self.report['network_ready'])
        table=bytes.fromhex(self.report['anchors'][0]['bytes'])
        self.assertEqual(struct.unpack_from('<Q',table,0x50)[0],self.tool.SELECT)

    def test_stored_index_path_and_portable_list_builder(self):
        raw18=int.from_bytes(bytes.fromhex(self.report['anchors'][2]['bytes']),'little')
        self.assertEqual(raw18,0)
        self.assertEqual(len(self.report['stored_cases']),34)
        frames=0
        for c in self.report['stored_cases']:
            f=c['fixture'];keys=f['record_keys'];index=f['selected_index']
            select=(not f['policy_disabled'] and f.get('ui_present',True) and f.get('type_count',1)>=1
                and f.get('type_match',True) and 0<=index<len(keys))
            handoffs=[e for e in c['events'] if e['action']=='select_handoff']
            self.assertEqual(len(handoffs),int(select))
            if select:
                self.assertEqual(handoffs,[dict(action='select_handoff',kind=110,packet_raw10=keys[index],
                    packet_raw18=0,packet_raw20=f['state_f0'])])
            should_send=select and 110 not in f['pending_kinds'] and not(f['disabled'] or f['raw_mode']==2 or f['special'])
            self.assertEqual(bool(c['frame_hex']),should_send)
            if not should_send:
                self.assertEqual((c['queue_calls'],c['sequence_after']),(0,f['sequence']))
                continue
            frames+=1
            body=struct.pack('<IIH',0,207,len(keys))+b''.join(self.reader.record_bytes(value=v) for v in keys)+struct.pack('<QIQQ',0,23,0,f['state_f0'])
            model=decode_character_list(body,max_payload_size=4096,max_characters=4,max_extension_items=64)
            payload=CharacterSelectPayload.from_character_list(model,index,state_raw_f0=f['state_f0']).encode(max_payload_size=20)
            inner=struct.pack('<HH',109,f['sequence'])+payload
            clear=struct.pack('<I',zlib.crc32(inner))+inner
            self.assertEqual(c['frame_hex'],((len(clear)+3).to_bytes(3,'little')+xor_transform(clear,f['key'])).hex())
        self.assertEqual(frames,8)

    def test_list_builder_requires_complete_valid_index_and_no_error(self):
        body=struct.pack('<IIH',0,207,1)+self.reader.record_bytes(value=11)+struct.pack('<QIQQ',0,23,0,42)
        model=decode_character_list(body,max_payload_size=4096,max_characters=4,max_extension_items=64)
        self.assertEqual(CharacterSelectPayload.from_character_list(model,0,state_raw_f0=99).raw20,99)
        for index in (True,-1,1,2**31-1,None):
            with self.assertRaises(ValueError):CharacterSelectPayload.from_character_list(model,index,state_raw_f0=42)
        bad=decode_character_list(b'\1'+body[1:],max_payload_size=4096,max_characters=4,max_extension_items=64)
        with self.assertRaises(ValueError):CharacterSelectPayload.from_character_list(bad,0,state_raw_f0=42)
        with self.assertRaises(ValueError):CharacterSelectPayload.from_character_list(None,0,state_raw_f0=42)

    def test_branch_fields_and_full_frames(self):
        raw18=int.from_bytes(bytes.fromhex(self.report['anchors'][2]['bytes']),'little')
        frames=0
        for c in self.report['cases']:
            f=c['fixture'];policy=4 if f['policy_disabled'] or not f['policy_present'] else f['policy']
            select=(not f['peer_flag'] and policy==0 and f['stored_raw']!=0) or (bool(f['peer_flag']) and policy not in (0,1))
            listing=bool(f['peer_flag']) and policy==1
            handoffs=[e for e in c['events'] if e['action']=='select_handoff']
            self.assertEqual(len(handoffs),int(select))
            duplicates=110 in f['pending_kinds']
            refused=f['disabled'] or f['raw_mode']==2 or f['special']
            should_send=(select and not duplicates or listing) and not refused
            self.assertEqual(bool(c['frame_hex']),should_send)
            if select:
                wanted=f['notify_raw'] if f['peer_flag'] else f['stored_raw']
                self.assertEqual(handoffs,[dict(action='select_handoff',kind=110,packet_raw10=wanted,
                    packet_raw18=raw18,packet_raw20=f['state_f0'])])
            if not should_send:
                self.assertEqual((c['queue_calls'],c['wake_calls'],c['sequence_after']),(0,0,f['sequence']))
                continue
            frames+=1
            packet_id=109 if select else 101
            payload=CharacterSelectPayload(wanted,raw18,f['state_f0']).encode(max_payload_size=20) if select else b''
            inner=struct.pack('<HH',packet_id,f['sequence'])+payload
            clear=struct.pack('<I',zlib.crc32(inner))+inner
            expected=(len(clear)+3).to_bytes(3,'little')+xor_transform(clear,f['key'])
            self.assertEqual(c['frame_hex'],expected.hex())
            self.assertEqual((c['queue_calls'],c['wake_calls'],c['sequence_after']),(1,int(f['wake']),(f['sequence']+1)&65535))
            self.assertTrue(c['queue_owns_bytes'])
        self.assertEqual(frames,11)

    def test_handoff_order_timeout_and_duplicate_gates(self):
        for c in self.report['cases']:
            f=c['fixture'];handoffs=[e for e in c['events'] if e['action']=='select_handoff']
            inserts=[e for e in c['events'] if e['action']=='request_insert_capture']
            notices=[e for e in c['events'] if e['action']=='request_notify_capture']
            if not handoffs:
                self.assertEqual(inserts,[]);self.assertEqual(notices,[])
                continue
            if 110 in f['pending_kinds']:
                self.assertEqual(inserts,[]);self.assertEqual(notices,[])
            else:
                self.assertEqual(inserts,[dict(action='request_insert_capture',kind=110,timeout=f['default_timeout'],opaque_argument=0)])
                self.assertEqual(notices,[dict(action='request_notify_capture',callback=0x141423088)])
                self.assertLess(c['events'].index(inserts[0]),c['events'].index(notices[0]))


if __name__=='__main__':unittest.main()
