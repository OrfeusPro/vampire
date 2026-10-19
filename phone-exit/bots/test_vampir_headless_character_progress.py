"""Reproduce source-bound owner dispatch and CharacterSelect body vectors."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_select import CharacterSelectPayload,SOURCE_SHA256
from vampir_core.character_list import decode_character_list


def load(name):
    path=HERE/'resource-tools/vampir'/('replay-'+name+'.py')
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),path)
    tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
    report=json.loads((tool.native.ROOT/'code-clues'/(name+'-replay.json')).read_text('utf-8'))
    return tool,report


class CharacterProgressTests(unittest.TestCase):
    def test_list_native_and_portable_parity(self):
        tool,report=load('character-list-reader')
        self.assertEqual(tool.build(),report)
        self.assertEqual(report['sha256'],SOURCE_SHA256)
        self.assertEqual(len(report['cases']),12)
        self.assertFalse(report['network_ready'])
        for case in report['cases']:
            body=bytes.fromhex(case['payload_hex'])
            model=decode_character_list(body,max_payload_size=4096,max_characters=4,max_extension_items=64)
            self.assertEqual((model.result_code,model.raw14,model.tail),(case['raw10'],case['raw14'],tuple(case['tail'])))
            self.assertEqual(len(model.records),case['count'])
            self.assertEqual((case['returned'],case['consumed']),(1,len(body)))
            for record,native in zip(model.records,case['records']):
                for field in ('strings','u32','u16','u64','appearance','appearance_flags'):
                    self.assertEqual(getattr(record,field),tuple(native[field]))
                self.assertEqual(record.enum60,native['enum60'])
                self.assertEqual(record.flag108,bool(native['flag108']))
                self.assertEqual(repr(record),'CharacterRecord()')
        for case in report['truncated']+report['record_truncated']:
            self.assertEqual(case['returned'],0)
            with self.assertRaises(ValueError):
                decode_character_list(bytes.fromhex(case['payload_hex']),max_payload_size=4096,max_characters=4,max_extension_items=64)
        with self.assertRaises(ValueError):
            decode_character_list(bytes.fromhex(report['trailing']['payload_hex']),max_payload_size=4096,max_characters=4,max_extension_items=64)

    def test_list_limits_and_invalid_extension_body(self):
        tool,_=load('character-list-reader')
        import struct
        record=tool.record_bytes()
        body=struct.pack('<IIH',0,207,1)+record+bytes(28)
        for offset in (10+len(record)-1,):
            unsupported=bytearray(body);unsupported[offset]=1
            with self.assertRaises(ValueError):
                decode_character_list(bytes(unsupported),max_payload_size=4096,max_characters=4,max_extension_items=64)
        with self.assertRaises(BufferError):decode_character_list(body,max_payload_size=4096,max_characters=0,max_extension_items=64)
        with self.assertRaises(BufferError):decode_character_list(body,max_payload_size=38,max_characters=4,max_extension_items=64)
        for budget in (True,37,-1,2**24):
            with self.assertRaises(ValueError):decode_character_list(body,max_payload_size=budget,max_characters=4,max_extension_items=64)
        for count in (True,-1,65536):
            with self.assertRaises(ValueError):decode_character_list(body,max_payload_size=4096,max_characters=count,max_extension_items=64)
        with self.assertRaises(ValueError):decode_character_list(bytearray(body),max_payload_size=4096,max_characters=4,max_extension_items=64)

    def test_actual_owner_policy_sends(self):
        tool,report=load('character-list-owner')
        self.assertEqual(tool.build(),report)
        self.assertEqual(report['sha256'],SOURCE_SHA256)
        self.assertFalse(report['network_ready'])
        for case in report['cases']:
            self.assertEqual(case['owner_vtable'],tool.TABLE)
            events=case['events']
            self.assertFalse(any(e['action']=='policy_virtual_capture' for e in events))
            # Same send capture used by the earlier packet constructor evidence.
            sends=[e for e in events if e['action']=='send_capture']
            self.assertEqual(len(sends),1)
            self.assertEqual(sends[0]['vtable'],0x1498d84d8)
            self.assertEqual(case['field260'],1)

    def test_select_native_parity(self):
        tool,report=load('character-select-writer')
        self.assertEqual(tool.build(),report)
        self.assertEqual(report['sha256'],SOURCE_SHA256)
        self.assertFalse(report['network_ready'])
        self.assertEqual(len(report['cases']),16)
        for case in report['cases']:
            model=CharacterSelectPayload(*case['values'])
            self.assertEqual(model.encode(max_payload_size=20).hex(),case['payload_hex'])
            self.assertTrue(case['returned'])
            self.assertEqual(repr(model),'CharacterSelectPayload()')

    def test_select_budgets_and_ranges(self):
        for args in ((True,0,0),(-1,0,0),(0,2**32,0),(0,0,2**64)):
            with self.assertRaises(ValueError):CharacterSelectPayload(*args)
        model=CharacterSelectPayload(0,0,0)
        for budget in (True,-1,2**24,None):
            with self.assertRaises(ValueError):model.encode(max_payload_size=budget)
        with self.assertRaises(BufferError):model.encode(max_payload_size=19)


if __name__=='__main__':unittest.main()
