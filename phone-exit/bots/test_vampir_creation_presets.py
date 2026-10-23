import importlib.util
import copy
from pathlib import Path
import struct
import tempfile
import unittest


class CreationPresetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        here = Path(__file__).parent / 'resource-tools/vampir'
        spec = importlib.util.spec_from_file_location('creation_preset_check', here / 'extract-release-creation-presets.py')
        cls.tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.tool)
        cls.root = Path('F:/PhoneExit Resources/Vampir')
        cls.index = cls.root / 'release-snapshots/2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08/record-indexes/f64ec55098c97fa6bfd0d620e4c397a13b26119c76dde35abb0d9f6cebd5a714/3a313dbd09096213bd92cd033a06337beb4ed38f5ca3f0ee936f7cba055c0adc/manifest.json'
        cls.directory = cls.root / 'resource-config-snapshots/3c1151930e190baf7fb7093c976222e4c2e053bef816c077e689c8a4b1de44a3/manifest.json'
        cls.path, cls.report = cls.tool.extract(cls.index, cls.directory, cls.root)

    def test_current_class3_links_and_repeatable_extraction(self):
        again, _ = self.tool.extract(self.index, self.directory, self.root)
        self.assertEqual(again, self.path)
        packages = self.report['packages']
        self.assertEqual([len(p['rows']) for p in packages[:2]], [16, 13])
        self.assertEqual([row['preset_id'] for row in self.report['selected_class3']], [3, 2])
        self.assertTrue(all('DA_PresetDarkMage3_' in row['package'] for row in self.report['selected_class3']))
        female, male = [p['decoded'] for p in packages[2:]]
        self.assertEqual(female['values']['HairIndex'], 8)
        self.assertEqual(male['values']['HairIndex'], 6)
        self.assertEqual(female['values']['VoiceType'], 0)
        self.assertEqual(male['values']['VoiceType'], 1)
        self.assertEqual(female['values']['Head'], 0.5)
        self.assertEqual(male['values']['Head'], 0.5)
        self.assertEqual(female['unresolved'], ['DecalIndex', 'DecalColorIndex'])
        self.assertEqual(male['unresolved'], ['DecalIndex', 'EyeTexIndex'])
        self.assertIsNone(female['values']['DecalIndex'])
        for package in packages[2:]:
            self.assertEqual(package['native_template']['template_path'],
                '/Script/NnFramework.Default__NnDataAssetForCustomizePreset')

    def test_wrong_native_class_template_and_superclass_rejected(self):
        package = self.report['packages'][2]
        refs = package['references']; export = package['export']
        for field, value, error in (('class_index', -2, 'native class'),
                                    ('template_index', -1, 'CDO template'),
                                    ('template_index', 1, 'CDO template'),
                                    ('super_index', -1, 'superclass')):
            changed = copy.deepcopy(refs)
            changed['references'] = {str(k): v for k, v in changed['references'].items()}
            changed['references'][str(export['index'])][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, error):
                self.tool.native_template(changed, export)

    def test_constructor_defaults_preserve_unresolved_integer_bytes(self):
        rows = self.report['constructor']['cases']
        self.assertEqual([r['poison'] for r in rows], [0, 0xa5, 0xff])
        for row in rows:
            self.assertEqual(row['floats'], [0.5] * 7)
            self.assertTrue(row['integer_bytes_preserved'])

    def test_every_short_prefix_and_trailing_byte_rejected(self):
        for package in self.report['packages']:
            body_path = self.root / 'code-clues/appearance-resource-blobs' / package['parts'][1]['blob']
            body = body_path.read_bytes()[:-4]
            self.assertEqual(len(body), package['export']['size'])
            if 'rows' in package:
                refs = package['references']['references']
                index = next(int(k) for k, v in refs.items() if v['name'] == 'RdDataTableRowForCustomizePreset')
                def decode(data): return self.tool.table(data, package['names'], refs, index)
            else: decode = self.tool.asset
            for length in range(len(body)):
                with self.subTest(package=package['package'], length=length), self.assertRaises((ValueError, struct.error)):
                    decode(body[:length])
            with self.assertRaises(ValueError): decode(body + b'\0')

    def test_corrupt_index_rejected_before_resource_or_native_access(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / ('0' * 64) / 'manifest.json'
            path.parent.mkdir(); path.write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'record index hash'):
                self.tool.extract(path, self.directory, self.root)


if __name__ == '__main__': unittest.main()
