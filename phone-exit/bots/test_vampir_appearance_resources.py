import importlib.util
import copy
import hashlib
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
        self.directory = Path('F:/PhoneExit Resources/Vampir/resource-config-snapshots/3c1151930e190baf7fb7093c976222e4c2e053bef816c077e689c8a4b1de44a3/manifest.json')

    def test_current_packages_decode_all_group_fields_repeatably(self):
        root = Path('F:/PhoneExit Resources/Vampir')
        index = root / 'release-snapshots/2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08/record-indexes/f64ec55098c97fa6bfd0d620e4c397a13b26119c76dde35abb0d9f6cebd5a714/3a313dbd09096213bd92cd033a06337beb4ed38f5ca3f0ee936f7cba055c0adc/manifest.json'
        first, report = self.tool.extract(index, root, self.directory)
        second, _ = self.tool.extract(index, root, self.directory)
        self.assertEqual(first, second)
        self.assertEqual(len(report['packages']), 2)
        for package in report['packages']:
            self.assertEqual([row['id'] for row in package['groups']], list(range(1, 8)))
            self.assertEqual([row['group_name'] for row in package['groups']],
                ['Height', 'Chest', 'Pelvis', 'Shape', 'Waist', 'Thigh', 'Head'])
            self.assertTrue(package['rows_decoded'])
            self.assertTrue(package['archive_directory_pair_verified'])
            self.assertTrue(package['parts'][1]['archive_filename'].endswith('.uexp'))
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
                self.tool.extract(path, Path(folder), self.directory)

    def test_named_pair_does_not_depend_on_record_order_or_entry_number(self):
        manifest = json.loads(self.directory.read_text('utf-8'))
        core = self.tool.load('test_named_core', self.tool.HERE / 'recover-pak-game-config.py')
        directory = json.loads((self.directory.parent / 'directory.json').read_text('utf-8'))
        encoded = (self.directory.parent / 'encoded-entries.bin').read_bytes()
        rows = []
        for entry in directory['entries']:
            if 'DT_CustomizeBoneGroup' not in entry['path']: continue
            d = core.decode_small_entry(encoded, entry['encoded_entry_offset'])
            rows.append(dict(offset=d['offset'], bytes=d['size'], uncompressed=d['usize'],
                method=d['method'], encrypted=d['encrypted'], entry=10000 - len(rows) * 17))
        index = dict(source=dict(path=manifest['source_archive']['path'], sha256=manifest['archive_sha256']), entries=rows[::-1])
        result = self.tool.named_records(self.directory, index)
        self.assertEqual(len(result), 2)
        self.assertTrue(all(parts[0][0]['entry'] - parts[1][0]['entry'] == 17 for parts in result.values()))
        for change in ('sha', 'duplicate', 'size', 'missing'):
            broken = copy.deepcopy(index)
            if change == 'sha': broken['source']['sha256'] = '0' * 64
            elif change == 'duplicate': broken['entries'].append(broken['entries'][0])
            elif change == 'size': broken['entries'][0]['bytes'] += 1
            else: broken['entries'].pop()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.tool.named_records(self.directory, broken)

    def test_corrupt_directory_materials_are_rejected(self):
        original = self.directory.read_bytes()
        manifest = json.loads(original)
        index = dict(source=dict(path=manifest['source_archive']['path'], sha256=manifest['archive_sha256']), entries=[])
        for corrupt in ('manifest.json', 'directory.json', 'encoded-entries.bin'):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / hashlib.sha256(original).hexdigest() / 'manifest.json'
                target.parent.mkdir()
                for name in ('manifest.json', 'directory.json', 'encoded-entries.bin'):
                    (target.parent / name).write_bytes((self.directory.parent / name).read_bytes())
                (target.parent / corrupt).write_bytes(b'corrupt')
                with self.assertRaisesRegex(ValueError, 'hash changed'):
                    self.tool.named_records(target, index)


if __name__ == '__main__': unittest.main()
