"""Unknown property boundaries must remain explicit despite a valid suffix."""
import importlib.util
import struct
import unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
builder=load('actor_dispatch_builder_tests','build-recast-actor-dispatch-code.py')
audit=load('actor_dispatch_audit_tests','audit-recast-actor-dispatch.py')

class ActorDispatchTests(unittest.TestCase):
    def test_prefix_header_is_not_a_property_value_decoder(self):
        raw=bytes.fromhex('1d0202082d0209023903')+b'unknown data'
        result=builder.prefix_header(raw);pos,fields=audit.decode_header_independently(raw)
        self.assertEqual(result['fields'],fields);self.assertEqual(pos,10)
        self.assertFalse(result['property_values_decoded']);self.assertFalse(result['inherited_schema_resolved'])

    def test_missing_header_or_mask_is_rejected(self):
        for raw in [b'',b'\x1d',struct.pack('<H',0x380)]:
            with self.assertRaises(ValueError):audit.decode_header_independently(raw)

    def test_wrong_native_slot_fails_instead_of_accepting_a_neighbor(self):
        class Image:
            class PE:base=0
            pe=PE()
            def offset(self,rva):return rva
        raw=struct.pack('<QQ',123,456)
        self.assertEqual(builder.read_binding(raw,Image(),0,0,123)['target'],123)
        with self.assertRaises(ValueError):builder.read_binding(raw,Image(),0,8,123)

if __name__=='__main__':unittest.main()
