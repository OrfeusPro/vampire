"""Full ID206 portable/native parity and aggregate decoding boundaries."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.world_move_finish_result import decode_world_move_finish_result


class WorldMoveFinishCollectionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-world-move-finish-collections.py'
        spec=importlib.util.spec_from_file_location('world_collections_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/world-move-finish-collections-replay.json').read_text('utf-8'))

    def decode(self,data,items=65535):
        return decode_world_move_finish_result(data,max_payload_size=4096,max_collection_items=items)

    def test_native_report_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),16)
        self.assertFalse(self.report['network_ready'])

    def test_all_native_fields_and_array_entries_match_decoder(self):
        for case in self.report['cases']:
            model=self.decode(bytes.fromhex(case['payload_hex']));data=model.data
            for key,value in case['fields'].items():
                offset=int(key,16)
                self.assertEqual(model.result_code if offset==0x10 else data.at(offset),value)
            self.assertEqual(struct.pack('<ddd',*data.at(0x30).finite_values()).hex(),case['vector_hex'])
            self.assertEqual(data.at(0x78).at(0x18),case['text'])
            for name,offset in (('appearance',0x30),('b8',0xb8),('c8',0xc8),('e8',0xe8),('100',0x100)):
                rows=data.at(0x78).at(offset) if name=='appearance' else data.at(offset)
                native=case['collections'][name]
                self.assertEqual(len(rows),len(native))
                for i,(record,expected) in enumerate(zip(rows,native)):
                    if name=='100':self.assertEqual(record,expected[0]);continue
                    if name!='e8':
                        self.assertEqual(list(v for _,v in record.fields),expected);continue
                    self.assertEqual([record.at(o) for o in (8,12,16,24,40)],expected[:5])
                    spatial=record.at(0x30)
                    if spatial is None:self.assertFalse(expected[4])
                    else:
                        bits=[int.from_bytes(struct.pack('<d',v),'little') for v in spatial.at(8).finite_values()]
                        self.assertEqual(bits,expected[5:8])
                        self.assertEqual(spatial.at(0x20).raw_byte,case['input_arrays']['e8'][i][8])

    def test_aggregate_budget_counts_every_array_and_rejects_all_short_inputs(self):
        case=self.report['cases'][-1];body=bytes.fromhex(case['payload_hex'])
        total=sum(len(v) for v in case['input_arrays'].values())
        self.decode(body,total)
        with self.assertRaises(BufferError):self.decode(body,total-1)
        self.assertEqual(len(self.report['short']),len(body))
        for item in self.report['short']:
            with self.assertRaises(ValueError):self.decode(body[:item['size']],total)
        with self.assertRaises(ValueError):self.decode(body+b'\0',total)

    def test_limits_types_and_redaction(self):
        body=self.tool.base.body_bytes();model=self.decode(body,0)
        self.assertNotIn('81985529216486895',repr(model))
        for data in (bytearray(body),memoryview(body),None):
            with self.assertRaises(ValueError):self.decode(data)
        for n in (-1,65536,True,None):
            with self.assertRaises(ValueError):self.decode(body,n)
        for n in (80,0x1000000,True,None):
            with self.assertRaises(ValueError):decode_world_move_finish_result(body,max_payload_size=n,max_collection_items=0)
        with self.assertRaises(BufferError):decode_world_move_finish_result(body+b'\0',max_payload_size=81,max_collection_items=0)
        malformed=bytearray(body);malformed[47:49]=b'\x01\x00';malformed[49:49]=b'\xff'
        with self.assertRaises(ValueError):self.decode(bytes(malformed))


if __name__=='__main__':unittest.main()
