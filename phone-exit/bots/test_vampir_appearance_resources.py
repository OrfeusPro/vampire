import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest


class AppearanceResourcesTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).parent / 'resource-tools/vampir/extract-release-appearance-resources.py'
        spec = importlib.util.spec_from_file_location('appearance_resource_check', path)
        self.tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.tool)

    def test_current_packages_decode_all_group_fields_repeatably(self):
        root = Path('F:/PhoneExit Resources/Vampir')
        index = root / 'release-snapshots/2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08/record-indexes/f64ec55098c97fa6bfd0d620e4c397a13b26119c76dde35abb0d9f6cebd5a714/3a313dbd09096213bd92cd033a06337beb4ed38f5ca3f0ee936f7cba055c0adc/manifest.json'
        first, report = self.tool.extract(index, root)
        second, _ = self.tool.extract(index, root)
        self.assertEqual(first, second)
        self.assertEqual(len(report['packages']), 2)
        for package in report['packages']:
            self.assertEqual([row['id'] for row in package['groups']], list(range(1, 8)))
            self.assertEqual([row['group_name'] for row in package['groups']],
                ['Height', 'Chest', 'Pelvis', 'Shape', 'Waist', 'Thigh', 'Head'])
            self.assertTrue(package['rows_decoded'])
            self.assertFalse(package['archive_directory_pair_verified'])
        self.assertNotEqual(report['packages'][0]['groups'][1]['bone_name_ids'], report['packages'][1]['groups'][1]['bone_name_ids'])

    def test_bounded_decoder_rejects_every_prefix_trailing_and_bad_fname(self):
        # One explicit row with the native three-field property layout.
        body = (struct.pack('<HiIi', 0x300, -5, 0, 1) + struct.pack('<iiHiii', 0, 0, 0x700, 0, 0, 7)
            + struct.pack('<ii', 1, 5) + b'Root\0')
        expected = [dict(row='Height', group_name='Height', id=7, bone_name_ids=['Root'])]
        self.assertEqual(self.tool.decode_groups(body, ['Height'], -5), expected)
        for size in range(len(body)):
            with self.subTest(size=size), self.assertRaises((ValueError, struct.error)):
                self.tool.decode_groups(body[:size], ['Height'], -5)
        with self.assertRaises(ValueError): self.tool.decode_groups(body + b'\0', ['Height'], -5)
        changed = bytearray(body); struct.pack_into('<i', changed, 14, 99)
        with self.assertRaises(ValueError): self.tool.decode_groups(bytes(changed), ['Height'], -5)

    def test_corrupt_index_is_rejected_before_decode(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / ('0' * 64) / 'manifest.json'
            path.parent.mkdir(); path.write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'index hash'):
                self.tool.extract(path, Path(folder))


if __name__ == '__main__': unittest.main()
