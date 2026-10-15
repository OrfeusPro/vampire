import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('topology', Path(__file__).parent / 'resource-tools/vampir/build-ui-topology.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
panel_spec = importlib.util.spec_from_file_location('panel_sources', Path(__file__).parent / 'resource-tools/vampir/decode-panel-slots.py')
panel = importlib.util.module_from_spec(panel_spec)
panel_spec.loader.exec_module(panel)
catalog_spec = importlib.util.spec_from_file_location('ui_catalog', Path(__file__).parent / 'resource-tools/vampir/build-ui-catalog.py')
catalog = importlib.util.module_from_spec(catalog_spec)
catalog_spec.loader.exec_module(catalog)
window_spec = importlib.util.spec_from_file_location('window_binding', Path(__file__).parent / 'resource-tools/vampir/build-window-bindings.py')
window_binding = importlib.util.module_from_spec(window_spec)
window_spec.loader.exec_module(window_binding)


class WindowSourceLinks(unittest.TestCase):
    def test_stored_size_does_not_enable_an_unresolved_override(self):
        decoded = dict(explicit_properties=dict(WidthOverride=600, HeightOverride=120,
                       bOverride_HeightOverride=False, MinDesiredHeight=400, bOverride_MinDesiredHeight=True))
        constraints = catalog.size_constraints(decoded)
        self.assertEqual(constraints['WidthOverride']['status'], 'unresolved_default_or_archetype')
        self.assertEqual(constraints['HeightOverride']['status'], 'explicitly_disabled')
        self.assertEqual(constraints['MinDesiredHeight'], dict(status='explicitly_enabled', value=400))

    def slot(self, slot, parent):
        return dict(provenance=dict(slot_export=slot), decoded=dict(parent_export=parent))

    def test_parent_chain_preserves_actual_relationships(self):
        slots = {3: [self.slot(10, 5)], 5: [self.slot(11, 7)], 7: []}
        chain, reason = catalog.parent_chain(3, slots)
        self.assertEqual([r['parent_export'] for r in chain], [5, 7])
        self.assertEqual(reason, 'no_further_decoded_slot')

    def test_cycle_and_multiple_parents_remain_unresolved(self):
        self.assertEqual(catalog.parent_chain(3, {3: [self.slot(10, 3)]})[1], 'cycle')
        self.assertEqual(catalog.parent_chain(3, {3: [self.slot(10, 5), self.slot(11, 7)]})[1], 'ambiguous_parent')

    def test_localization_binding_requires_exact_unique_key_and_value(self):
        row = dict(Key='KICKOUT_FOR_INSPECT', Value='Connection terminated for safe gameplay.')
        self.assertEqual(window_binding.bind_text([row], row['Key'], row['Value'])['csv_record'], 2)
        for rows in ([], [row, row], [dict(row, Value='Changed')]):
            with self.assertRaises(ValueError):
                window_binding.bind_text(rows, row['Key'], row['Value'])


class SerializedSlotGuards(unittest.TestCase):
    def test_zero_mask_advances_only_for_masked_fragments(self):
        # First property has no mask; next two share mask bits 0 and 1.
        data = struct.pack('<HHB', 1 << 9, (2 << 9) | 128 | 256, 2)
        self.assertEqual(panel.Reader(data).header(), [(0, False), (1, False), (2, True)])

    def test_truncated_zero_mask_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'zero mask'):
            panel.Reader(struct.pack('<H', (9 << 9) | 128 | 256) + b'\0').header()

    def test_slot_references_and_alignment_are_read_without_guessing(self):
        raw = struct.pack('<HBBiiI', 1 | (4 << 9) | 256, 2, 3, 18, 21, 0)
        decoded = panel.Reader(raw).panel_slot('OverlaySlot')
        self.assertEqual((decoded['horizontal_alignment'], decoded['vertical_alignment']), (2, 3))
        self.assertEqual((decoded['parent_export'], decoded['content_export']), (18, 21))

    def test_unknown_alignment_or_trailing_data_rejected(self):
        for alignment, suffix in [(4, b''), (1, b'\x01')]:
            raw = struct.pack('<HBBiiI', 1 | (4 << 9) | 256, alignment, 3, 18, 21, 0) + suffix
            with self.assertRaises(ValueError):
                panel.Reader(raw).panel_slot('OverlaySlot')

    def test_unknown_safe_zone_layout_does_not_generate_geometry(self):
        with self.assertRaisesRegex(ValueError, 'SafeZone'):
            panel.Reader(struct.pack('<H', (1 << 9) | 256)).panel_slot('SafeZoneSlot')


class SourceSlotArrays(unittest.TestCase):
    def test_serialized_sibling_order_is_preserved(self):
        data = b'\0\0' + struct.pack('<iiii', 3, 38, 36, 37)
        self.assertEqual(module.slot_array(data, [36, 37, 38]), [dict(offset=2, ordered_slots=[38, 36, 37])])

    def test_ambiguous_arrays_remain_ambiguous(self):
        data = struct.pack('<iii', 2, 10, 20)
        self.assertEqual(len(module.slot_array(data + data, [10, 20])), 2)

    def test_missing_or_repeated_child_is_not_accepted(self):
        self.assertEqual(module.slot_array(struct.pack('<iii', 2, 10, 10), [10, 20]), [])

    def test_truncated_array_is_not_accepted(self):
        self.assertEqual(module.slot_array(struct.pack('<ii', 2, 10), [10, 20]), [])
