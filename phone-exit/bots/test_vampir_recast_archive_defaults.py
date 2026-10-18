"""Do not treat arbitrary malformed/versioned prefixes as default packages."""
import importlib.util
import struct
import unittest
from pathlib import Path
p=Path(__file__).parent/'resource-tools/vampir/build-recast-archive-defaults.py'
s=importlib.util.spec_from_file_location('archive_defaults_tests',p);native=importlib.util.module_from_spec(s);s.loader.exec_module(native)

class ArchiveDefaultTests(unittest.TestCase):
    def fixture(self):return bytearray(struct.pack('<I7i',0x9e2a83c1,-8,0,0,0,0,0,32))

    def test_each_serialized_version_prevents_default_selection(self):
        for offset in [12,16,20]:
            raw=self.fixture();struct.pack_into('<i',raw,offset,1)
            self.assertFalse(native.package_prefix(raw)['select_registered_defaults'])
        self.assertTrue(native.package_prefix(self.fixture())['select_registered_defaults'])

    def test_discarded_legacy_field_is_not_a_version_gate(self):
        raw=self.fixture();struct.pack_into('<i',raw,8,864)
        result=native.package_prefix(raw)
        self.assertTrue(result['select_registered_defaults']);self.assertEqual(result['discarded_legacy_ue3'],864)

    def test_truncation_unsupported_layout_and_custom_entries_fail(self):
        raw=self.fixture()
        for size in range(32):
            with self.assertRaises(ValueError):native.package_prefix(raw[:size])
        for offset,value in [(0,0),(4,-7),(24,1),(24,-1),(28,31),(28,33)]:
            b=raw.copy();struct.pack_into('<i',b,offset,value)
            with self.assertRaises(ValueError):native.package_prefix(b)

if __name__=='__main__':unittest.main()
