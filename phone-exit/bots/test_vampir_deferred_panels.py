import importlib.util
import copy
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('deferred_panels',
    Path(__file__).parent / 'resource-tools/vampir/decode-deferred-panels.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
entry_spec = importlib.util.spec_from_file_location('entry_reference',
    Path(__file__).parent / 'resource-tools/vampir/build-entry-reference.py')
entry = importlib.util.module_from_spec(entry_spec)
entry_spec.loader.exec_module(entry)


class DeferredPanelPaths(unittest.TestCase):
    names = ['/Game/RED/UI/Lobby/WBP_TitlePanelUI', 'WBP_TitlePanelUI']

    def data(self, indices=(0, 0, 1, 0), sub=b'', length=0):
        # One explicit property at index 0; opaque suffix deliberately not parsed.
        return struct.pack('<Hiiiii', 768, *indices, length) + sub + b'opaque'

    def test_title_path_retains_unparsed_suffix(self):
        result = module.decode_prefix(self.data(), self.names)
        self.assertEqual(result['path'], self.names[0] + '.' + self.names[1])
        self.assertEqual(result['value_byte_range'], [2, 22])
        self.assertFalse(result['whole_export_decoded'])
        self.assertEqual(result['opaque_tail_byte_range'], [22, 28])

    def test_original_title_export_header(self):
        raw = bytes.fromhex('00020b02100302000000000000001a00000000000000000000000b0000000100000000')
        names = ['unused'] * 27
        names[2], names[26] = self.names
        result = module.decode_prefix(raw, names)
        self.assertEqual(result['value_byte_range'], [6, 26])
        self.assertEqual(result['opaque_tail_byte_range'], [26, 35])

    def test_numbered_and_zbp_names(self):
        names = ['/Game/RED/UI/ZBP/ZBP_Item_0', 'ZBP_Item']
        result = module.decode_prefix(self.data((0, 0, 1, 1)), names)
        self.assertEqual(result['asset']['name'], 'ZBP_Item_0')

    def test_generated_class_path_retains_suffix(self):
        names = ['/Game/RED/UI/ZBP/ZBP_Item', 'ZBP_Item_C']
        result = module.decode_prefix(self.data(), names)
        self.assertEqual(result['path'], names[0] + '.ZBP_Item_C')

    def test_no_explicit_path_does_not_invent_default(self):
        self.assertEqual(module.decode_prefix(struct.pack('<H', 769), [])['status'], 'no_explicit_UserWidget')
        self.assertEqual(module.decode_prefix(struct.pack('<HB', 896, 1), [])['status'], 'serialized_zero_UserWidget')

    def test_invalid_indices_and_mismatched_path_rejected(self):
        for indices in [(2, 0, 1, 0), (0, -1, 1, 0), (0, 0, 1, 1)]:
            with self.assertRaises(ValueError):
                module.decode_prefix(self.data(indices), self.names)

    def test_truncated_or_unbounded_subpath_rejected(self):
        for size in [4097, -4097, 100]:
            with self.assertRaises(ValueError):
                module.decode_prefix(self.data(length=size), self.names)
        with self.assertRaises(ValueError):
            module.decode_prefix(self.data(sub=b'xx', length=2), self.names)

    def test_utf16_subpath(self):
        result = module.decode_prefix(self.data(sub='Child\0'.encode('utf-16le'), length=-6), self.names)
        self.assertEqual(result['subpath'], 'Child')


class TitleSourceLink(unittest.TestCase):
    def fixture(self):
        path = '/Game/RED/UI/Lobby/WBP_TitlePanelUI'
        source = dict(entry=2427, source=dict(path='source.pak'),
                      asset_sha256='asset', body_sha256='body')
        origin = dict(source, file='title.json', name='TitlePanelUI', export=9, sha256='export')
        layouts = [dict(source, name='WBP_TitleUI', catalog_file='title.json',
            controls=[dict(export=9, type='NkDeferredPanel', sha256='export')]),
            dict(name='WBP_TitlePanelUI', catalog_file='panel.json', resource_paths=[path])]
        report = dict(native_schema=dict(sha256='native'), panels=[dict(provenance=origin,
            decoded=dict(status='explicit_asset_path', package=dict(name=path),
                         asset=dict(name='WBP_TitlePanelUI'), subpath='', catalog_targets=['panel.json']))])
        return layouts, report

    def test_static_link_does_not_claim_dynamic_binding(self):
        result = entry.title_link(*self.fixture())
        self.assertTrue(result['serialized_asset_binding_verified'])
        self.assertFalse(result['dynamic_class_binding_verified'])

    def test_changed_source_or_control_rejected(self):
        layouts, report = self.fixture()
        for key in ('source', 'entry', 'body_sha256', 'asset_sha256', 'sha256', 'export'):
            changed = copy.deepcopy(report)
            changed['panels'][0]['provenance'][key] = 'changed'
            with self.assertRaises(ValueError, msg=key):
                entry.title_link(layouts, changed)

    def test_missing_duplicate_or_different_target_rejected(self):
        layouts, report = self.fixture()
        for mode in ('missing', 'duplicate', 'target', 'subpath', 'catalog'):
            changed = copy.deepcopy(report)
            if mode == 'missing':
                changed['panels'] = []
            elif mode == 'duplicate':
                changed['panels'] *= 2
            else:
                decoded = changed['panels'][0]['decoded']
                if mode == 'target': decoded['asset']['name'] = 'WBP_Other'
                elif mode == 'subpath': decoded['subpath'] = 'Child'
                else: decoded['catalog_targets'] = ['other.json']
            with self.assertRaises(ValueError, msg=mode):
                entry.title_link(layouts, changed)


if __name__ == '__main__':
    unittest.main()
