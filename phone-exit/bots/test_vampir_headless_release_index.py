"""Bounded index orchestration with an explicit artificial record reader."""
import importlib.util
import io
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).parent / 'resource-tools/vampir/index-release-archives.py'
SPEC = importlib.util.spec_from_file_location('vampir_release_index', PATH)
INDEX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INDEX)


class FixtureReader:
    @staticmethod
    def header(stream, pos, limit):
        stream.seek(pos)
        data = stream.read(53)
        if len(data) != 53:
            return None
        off, size, usize, method, _, encrypted, blocksize = struct.unpack('<qqqI20sBI', data)
        if off or size <= 0 or pos + 53 + size > limit or method:
            return None
        return dict(pos=pos, size=size, usize=usize, method=method, encrypted=bool(encrypted),
                    end=pos + 53 + size, hs=53, blocksize=blocksize)

    @staticmethod
    def decode(stream, header):
        stream.seek(header['pos'] + 53)
        return stream.read(header['size'])


def record(data, *, encrypted=False, usize=None):
    return struct.pack('<qqqI20sBI', 0, len(data), usize or len(data), 0, b'\0' * 20, encrypted, 0) + data


def pak(data):
    return data + struct.pack('<Iiqq', 0x5a6f12e1, 11, len(data), 0) + b'\0' * 32


class ReleaseIndexTests(unittest.TestCase):
    def test_fresh_records_hashes_paths_and_settings(self):
        first = record(b'\xc1\x83\x2a\x9e/Game/Maps/Test\0NMSDKSettings\0')
        second = record('SDKZone=Unknown'.encode('utf-16le'))
        raw = pak(first + second)
        report = INDEX.discover(io.BytesIO(raw), len(raw), FixtureReader)
        self.assertTrue(report['reached_index'])
        self.assertFalse(report['directory_index_parsed'])
        self.assertEqual([r['offset'] for r in report['entries']], [0, len(first)])
        self.assertEqual(report['decode_counts'], {'decoded': 2})
        self.assertEqual(report['entries'][0]['paths'], ['/Game/Maps/Test'])
        self.assertEqual(report['entries'][1]['settings_markers'][0]['encoding'], 'utf-16le')
        self.assertEqual(len(report['entries'][0]['stored_record_sha256']), 64)

    def test_skips_gaps_and_incomplete_discovery_are_explicit(self):
        data = record(b'x', encrypted=True)
        padding = b'\xff' * (128 - len(data))
        data += padding + record(b'x', usize=INDEX.DECODE_LIMIT + 1) + b'\xff' * 7
        raw = pak(data)
        report = INDEX.discover(io.BytesIO(raw), len(raw), FixtureReader)
        self.assertFalse(report['reached_index'])
        self.assertEqual(report['gaps'], [dict(start=54, end=128)])
        self.assertEqual(report['decode_counts'], {'encrypted_skipped': 1, 'size_skipped': 1})

    def test_footer_reject_and_decode_size_failure(self):
        with self.assertRaisesRegex(ValueError, 'footer'):
            INDEX.discover(io.BytesIO(b'no footer'), 9, FixtureReader)
        raw = pak(record(b'x', usize=2))
        report = INDEX.discover(io.BytesIO(raw), len(raw), FixtureReader)
        self.assertEqual(report['decode_counts'], {'error': 1})
        diff = INDEX.compare_observed_paths([dict(paths=['/Game/Old'])], [dict(paths=['/Game/New'])])
        self.assertFalse(diff['authoritative_resource_diff'])
        self.assertEqual(diff['no_longer_observed'], ['/Game/Old'])


if __name__ == '__main__':
    unittest.main()
