"""Tail decoding must preserve version uncertainty and strict input bounds."""
import importlib.util
import struct
import unittest
from pathlib import Path
p=Path(__file__).parent/'resource-tools/vampir/decode-recast-actor-tail.py'
s=importlib.util.spec_from_file_location('actor_tail_tests',p);native=importlib.util.module_from_spec(s);s.loader.exec_module(native)

class ActorTailTests(unittest.TestCase):
    def fixture(self):return struct.pack('<IIi',0,1,4)+b'Nav\0'+bytes(range(32))+b'nav stream'

    def test_version_threshold_does_not_force_candidate_boundary(self):
        raw=self.fixture()
        for version,end in [(-1,16),(97,16),(149,16),(150,48),(151,48)]:
            result=native.decode_tail(raw,0,label_version=4,guid_version=version)
            self.assertEqual(result['end'],end);self.assertFalse(result['archive_inputs_verified'])

    def test_absent_string_and_lower_label_version(self):
        raw=struct.pack('<II',0,0)+bytes(32)
        self.assertEqual(native.decode_tail(raw,0,label_version=4,guid_version=150)['end'],40)
        self.assertEqual(native.decode_tail(raw,0,label_version=3,guid_version=97)['end'],4)

    def test_truncation_and_unsupported_object_guid_fail(self):
        raw=self.fixture()
        for length in range(48):
            with self.assertRaises(ValueError):native.decode_tail(raw[:length],0,label_version=4,guid_version=150)
        with self.assertRaises(ValueError):native.decode_tail(struct.pack('<I',1),0,label_version=4,guid_version=150)

    def test_malformed_strings_are_rejected(self):
        for suffix in [struct.pack('<i',-4)+b'Nav\0',struct.pack('<i',4)+b'Nav!',struct.pack('<i',4)+b'N\0v\0',struct.pack('<i',4097)]:
            with self.assertRaises(ValueError):native.decode_tail(struct.pack('<II',0,1)+suffix,0,label_version=4,guid_version=97)

if __name__=='__main__':unittest.main()
