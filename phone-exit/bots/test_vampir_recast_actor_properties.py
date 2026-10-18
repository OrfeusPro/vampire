"""Bounded cooked value decoding and explicit unknown property handling."""
import importlib.util
import math
import struct
import unittest
from pathlib import Path
p=Path(__file__).parent/'resource-tools/vampir/decode-recast-actor-properties.py'
s=importlib.util.spec_from_file_location('actor_property_tests',p);native=importlib.util.module_from_spec(s);s.loader.exec_module(native)

class ActorPropertyTests(unittest.TestCase):
    def test_float_field_does_not_consume_uninterpreted_actor_tail(self):
        raw=struct.pack('<Hf',0x300,35.)+b'unknown actor tail'
        slots=[dict(name='AgentRadius',kind=10)]
        result=native.decode_properties(raw,slots,[],{})
        self.assertEqual(result['properties_end'],6);self.assertEqual(result['properties'][0]['value'],35.)
        self.assertEqual(result['remaining_bytes'],18);self.assertFalse(result['complete_actor_serialization_decoded'])

    def test_nonfinite_wrong_kind_and_unknown_field_fail(self):
        for value,slot in [(math.nan,dict(name='AgentRadius',kind=10)),(35.,dict(name='AgentRadius',kind=3)),(35.,dict(name='UnknownField',kind=10))]:
            with self.assertRaises(ValueError):native.decode_properties(struct.pack('<Hf',0x300,value),[slot],[],{})

    def test_fstring_rejects_truncation_embedded_nul_and_missing_terminator(self):
        for raw in [struct.pack('<i',10)+b'ab\0',struct.pack('<i',3)+b'a\0\0',struct.pack('<i',3)+b'abc',struct.pack('<i',-1)]:
            with self.assertRaises(ValueError):native.fstring(native.reader_module.Reader(raw))

    def test_serialized_area_zero_id_and_duplicates(self):
        slot=dict(name='SupportedAreas',kind=22);schemas={'SupportedAreaData':dict(slots=[dict(name='AreaClassName'),dict(name='AreaID')])}
        row=bytes.fromhex('800502')+struct.pack('<i',2)+b'A\0'
        valid=struct.pack('<Hi',0x300,1)+row
        result=native.decode_properties(valid,[slot],[],schemas)
        self.assertEqual(result['properties'][0]['value'],[dict(AreaClassName='A',AreaID=0)])
        with self.assertRaises(ValueError):native.decode_properties(struct.pack('<Hi',0x300,2)+row+row,[slot],[],schemas)

if __name__=='__main__':unittest.main()
