import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('recast_serialization', Path(__file__).parent /
    'resource-tools/vampir/build-recast-serialization-code.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RecastEnvelopeTests(unittest.TestCase):
    def sample(self, version=26, count=1):
        return b'prefix' + struct.pack('<iQi', version, 16, count) + b'tile'

    def test_length_origin_is_the_uint64_not_version_or_payload(self):
        raw = self.sample()
        result = module.envelope_candidates(raw)
        self.assertEqual(result, [dict(offset=6, version=26, length=16, tile_count=1,
                                      property_boundary_verified=False)])
        for length in [12, 20, 0xffffffffffffffff]:
            changed = bytearray(raw)
            struct.pack_into('<Q', changed, 10, length)
            self.assertEqual(module.envelope_candidates(changed), [])

    def test_native_version_range_and_nonnegative_bounded_counts(self):
        for version in [20, 26]:
            self.assertEqual(len(module.envelope_candidates(self.sample(version))), 1)
        for version in [19, 27]:
            self.assertEqual(module.envelope_candidates(self.sample(version)), [])
        for count in [-1, 100001]:
            self.assertEqual(module.envelope_candidates(self.sample(count=count)), [])

    def test_empty_chunk_and_truncation(self):
        empty = struct.pack('<iQi', 26, 12, 0)
        self.assertEqual(module.envelope_candidates(empty)[0]['tile_count'], 0)
        for length in range(len(empty)):
            self.assertEqual(module.envelope_candidates(empty[:length]), [])
        self.assertEqual(module.envelope_candidates(self.sample()[:-1]), [])

    def test_search_is_bounded_and_does_not_promote_matches(self):
        raw = bytes(256) + struct.pack('<iQi', 26, 12, 0)
        self.assertEqual(module.envelope_candidates(raw), [])
        self.assertIs(module.envelope_candidates(self.sample())[0]['property_boundary_verified'], False)


if __name__ == '__main__':
    unittest.main()
