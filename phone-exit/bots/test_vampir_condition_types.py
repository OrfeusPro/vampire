import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('condition_types',
    Path(__file__).parent / 'resource-tools/vampir/build-lock-condition-types.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def block(pointer, slot, value):
    return [dict(mnemonic='lea', operands='rdx, [rip + 0x123]', rip_references=[pointer]),
            dict(mnemonic='call', operands='0x141420f70', direct_target=0x141420f70),
            dict(mnemonic='mov', operands=f'byte ptr [rsp + {slot:#x}], {value}')]


class NativeConditionTypes(unittest.TestCase):
    def test_values_come_from_initializers_not_string_order(self):
        rows = block(100, 0x20, 6) + block(200, 0x21, 0)
        result = module.pair_initializers(rows, {100: 'AdditionalSlotRarity', 200: 'CharacterLevel'}.get)
        self.assertEqual([(p['name'], p['value']) for p in result], [('AdditionalSlotRarity', 6), ('CharacterLevel', 0)])

    def test_duplicate_name_value_and_slot_gap_rejected(self):
        for rows, names in [(block(100, 0x20, 1) + block(200, 0x21, 1), {100: 'A', 200: 'B'}),
                (block(100, 0x20, 1) + block(200, 0x21, 2), {100: 'A', 200: 'A'}),
                (block(100, 0x20, 1) + block(200, 0x22, 2), {100: 'A', 200: 'B'})]:
            with self.assertRaises(ValueError):
                module.pair_initializers(rows, names.get)

    def test_missing_value_or_changed_constructor_rejected(self):
        rows = block(100, 0x20, 1)
        with self.assertRaises(ValueError):
            module.pair_initializers(rows[:2], {100: 'A'}.get)
        rows[1]['direct_target'] = 99
        with self.assertRaises(ValueError):
            module.pair_initializers(rows, {100: 'A'}.get)

    def test_unknown_literal_does_not_invent_type(self):
        self.assertEqual(module.pair_initializers(block(100, 0x20, 1), {}.get), [])


if __name__ == '__main__':
    unittest.main()
