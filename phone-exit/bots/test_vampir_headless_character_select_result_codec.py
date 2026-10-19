"""Portable complete ID110 parsing against native body/map/array evidence."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_select_result import decode_character_select_result


def decode(body,items=1024,byte_budget=4096):
    return decode_character_select_result(body,max_payload_size=byte_budget,max_collection_items=items)


class CharacterSelectResultCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-character-select-maps.py'
        spec=importlib.util.spec_from_file_location('select_maps_codec_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        root=cls.tool.native.ROOT/'code-clues'
        cls.maps=json.loads((root/'character-select-maps-replay.json').read_text('utf-8'))
        cls.collections=json.loads((root/'character-select-collections-replay.json').read_text('utf-8'))
        cls.minimum=json.loads((root/'character-select-result-replay.json').read_text('utf-8'))
        path=HERE/'resource-tools/vampir/replay-character-select-fields.py'
        spec=importlib.util.spec_from_file_location('select_fields_codec_test',path)
        cls.fields_tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.fields_tool)
        cls.fields=json.loads((root/'character-select-fields-replay.json').read_text('utf-8'))

    def test_native_map_report_reproduces(self):
        self.assertEqual(self.tool.build(),self.maps)

    def assert_arrays(self,model,case):
        for offset,(_,stride,fields) in self.tool.base.LAYOUT.items():
            if offset==0x290:values=model.data.at(0x290).at(16)
            elif offset==0x80:values=model.player.at(0x50).at(0x30)
            else:values=model.player.at(offset)
            expected=case['collections'][hex(offset)]
            if offset in (0x168,0x220,0x238):actual=[[v] for v in values]
            else:actual=[[v.at(o) for o,n in fields] for v in values]
            self.assertEqual(actual,expected,hex(offset))

    def test_portable_all_positive_native_vectors_arrays_and_maps(self):
        for c in self.minimum['cases']+self.minimum['vector_cases']+self.collections['cases']+self.maps['cases']:
            wire=bytes.fromhex(c['payload_hex']);model=decode(wire)
            self.assertEqual(model.result_code,c['result_code'])
            self.assertEqual(struct.pack('<ddd',*model.player.at(0x188).finite_values()).hex(),c['vector188_hex'])
            self.assertEqual(model.player.at(0x1a0).raw_byte,wire[73] if 'collections' not in c else self.heading_from_fixture(c))
            if 'collections' in c:self.assert_arrays(model,c)
            if 'map98' not in c:continue
            large=model.player.at(0x98)
            actual=None if large is None else [dict(key=k,raw=[v.at(o) for o,n in self.tool.VALUE_FIELDS],
                array50=[[item.at(o) for o in (8,9,12,16)] for item in v.at(0x50)],array88=list(v.at(0x88))) for k,v in large]
            self.assertEqual(actual,c['map98'])
            small=model.player.at(0xf8)
            actual=None if small is None else [[k,*[v.at(o) for o in (8,12,16,20,32)]] for k,v in small]
            self.assertEqual(actual,c['mapf8'])

    @staticmethod
    def heading_from_fixture(case):
        # All nonempty-array/map fixtures explicitly use wire heading 45.
        return 45

    def test_portable_rejects_every_native_short_body_and_trailing_bytes(self):
        for c in self.collections['truncated']+self.maps['truncated']:
            with self.assertRaises(ValueError):decode(bytes.fromhex(c['payload_hex']))
        with self.assertRaises(ValueError):decode(bytes.fromhex(self.maps['cases'][-1]['payload_hex'])+b'\0')

    def test_aggregate_budget_counts_duplicate_keys_and_nested_entries(self):
        value=self.tool.value_fixture(1,((1,255,2,3),(4,0,5,6)))
        body=self.tool.body_bytes(((1,value),(1,self.tool.value_fixture(2))))
        with self.assertRaises(BufferError):decode(body,items=3)
        model=decode(body,items=4)
        self.assertEqual(len(model.player.at(0x98)),1)
        self.assertEqual(model.player.at(0x98)[0][1].at(8),2)
        with self.assertRaises(BufferError):decode(body,byte_budget=203)
        for items in (True,-1,65536,None):
            with self.assertRaises(ValueError):decode(body,items=items)
        for value in (bytearray(body),memoryview(body),None):
            with self.assertRaises(ValueError):decode(value)

    def test_native_scalar_and_unicode_profiles_reproduce_and_match(self):
        self.assertEqual(self.fields_tool.build(),self.fields)
        for c in self.fields['cases']:
            model=decode(bytes.fromhex(c['payload_hex']))
            self.assertEqual(model.result_code,c['result_code'])
            for name,record in (('player_fields',model.player),('appearance_fields',model.player.at(0x50)),
                    ('block_fields',model.data.at(0x2b8)),('root_fields',model.data)):
                self.assertEqual({offset:record.at(int(offset,16)) for offset in c[name]},c[name],name)
            self.assertEqual(list(model.data.at(0x2b8).at(0x28)),c['four_u16'])
            self.assertEqual(model.data.at(0x290).at(8),c['outer290_flag'])
            self.assertEqual([model.player.at(0x20),model.player.at(0x50).at(0x18),model.data.at(0x2b8).at(0x10),
                model.data.at(0x328),model.data.at(0x338)],c['texts'])
            self.assertNotIn(c['texts'][0] or 'Profile',repr(model))
        for c in self.fields['truncated']:
            with self.assertRaises(ValueError):decode(bytes.fromhex(c['payload_hex']))

    def test_strict_text_hostile_counts_and_nonfinite_vector_access(self):
        empty=bytes.fromhex(self.maps['cases'][0]['payload_hex'])
        for encoded in (b'\xff',b'\0','\ufffe'.encode('utf-8')):
            body=empty[:21]+struct.pack('<H',len(encoded))+encoded+empty[23:]
            with self.assertRaises(ValueError):decode(body)
        hostile=empty[:51]+b'\xff\xff'+empty[53:]
        with self.assertRaises(BufferError):decode(hostile,items=8)
        body=empty[:61]+struct.pack('<I',0x7f800000)+empty[65:]
        vector=decode(body).player.at(0x188)
        self.assertEqual(vector.bits[0],0x7f800000)
        with self.assertRaises(ValueError):vector.finite_values()


if __name__=='__main__':unittest.main()
