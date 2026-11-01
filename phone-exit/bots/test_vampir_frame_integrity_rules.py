"""Source projection rejects expanded admission and altered primitive semantics."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_vampir_update_contracts import load

HERE = Path(__file__).resolve().parent/'resource-tools/vampir'


def seed():
    return json.loads((HERE/'knowledge/native-contexts/frame-integrity-11322.json').read_text('utf-8'))


class IntegrityRulesTests(unittest.TestCase):
    def setUp(self): self.rules = load('frame-integrity-rules')

    def test_exact_inventory_has_native_primitives_and_no_setup_or_version(self):
        c = seed()
        self.assertEqual(len(self.rules.roots(c)), 16)
        self.assertEqual((len(c['leaves']), len(c['tails'])), (9, 2))
        self.assertTrue(set(c['integrity'][r] for r in self.rules.PRIMITIVES) <= set(c['leaves']))
        self.assertFalse({'sender', 'publisher', 'prepare', 'wire.version-writer'} & set(c['functions']))
        self.assertEqual(c['format'], self.rules.REFERENCE)
        self.assertNotIn('transfer_proof', c)

    def test_added_budget_extent_tail_or_fixture_alias_cannot_widen_scope(self):
        for mode in ('budget', 'extent', 'bool', 'tail', 'fixture', 'extra-root', 'duplicates', 'parent'):
            c = seed()
            if mode == 'budget': c['function_budget'] = 64
            if mode == 'extent': c['backend_bytes'] = 800
            if mode == 'bool': c['archive_bytes'] = True
            if mode == 'tail':
                a, raw = c['tails'].popitem(); c['leaves'][a] = raw
            if mode == 'fixture': c['backend']['transport'] = c['integrity']['transform']
            if mode == 'extra-root': c['functions']['prepare'] = '0x1467d1530'
            if mode == 'duplicates': c['functions']['wire.append'] = c['functions']['backend']
            if mode == 'parent': c['backend_context']['sha256'] = 'short'
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.rules.roots(c)

    def test_crc_allows_only_rip_displacement_and_checks_full_polynomial_table(self):
        c = seed(); raw = bytearray.fromhex(c['leaves'][c['integrity']['update']])
        raw[11:15] = b'\x12\x34\x56\x78'
        self.assertEqual(self.rules.normalized_crc(raw), self.rules.CRC_NORMAL)
        for i in (0, 8, 15, 54):
            mutated = bytearray(raw); mutated[i] ^= 1
            try:
                normalized = self.rules.normalized_crc(mutated)
            except ValueError:
                continue
            self.assertNotEqual(normalized, self.rules.CRC_NORMAL)
        self.assertEqual(len(self.rules.crc_table()), 1024)
        self.assertEqual(self.rules.crc_table()[:8].hex(), '0000000096300777')
        for mode in ('table', 'size', 'hash', 'fallback', 'anchor'):
            c = seed(); t = c['integrity']['table']
            if mode == 'table': t['bytes'] = '01' + t['bytes'][2:]
            if mode == 'size': t['size'] = 1023
            if mode == 'hash': t['sha256'] = 'f'*64
            if mode == 'fallback': c['integrity']['fallback_key'] ^= 1
            if mode == 'anchor': c['integrity']['anchors']['update']['bytes'] = 'ff'+'00'*4
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.rules.roots(c)

    def test_relocated_unchanged_leaf_records_instruction_and_table_links(self):
        # This portable pairing is also used by the real transfer. A moved
        # table is a declared RIP dependency; altered branch targets fail closed.
        parent = load('login-backend-wire-rules')
        row = dict(address=0x100, bytes='4c8d1d00000000', branch=False, call=False,
            direct_target=None, mnemonic='lea', operands='r11, [rip]', rip_references=[0x800])
        moved = copy.deepcopy(row); moved.update(address=0x1100, rip_references=[0x1800])
        original = parent.load
        with patch.object(parent, 'load', side_effect=lambda n:
                SimpleNamespace(signature=lambda native, rows: 'identical') if n == 'update-native-contexts' else original(n)):
            mapping = {}; parent.pair_rows(None, [row], [moved], mapping)
            self.assertEqual(mapping, {0x100: 0x1100, 0x800: 0x1800})
            moved['rip_references'] = []
            with self.assertRaisesRegex(ValueError, 'data edges'):
                parent.pair_rows(None, [row], [moved], {})

    def test_selected_globals_and_primitive_role_binding_cannot_be_dropped(self):
        for mode in ('input', 'globals', 'binding', 'opcode'):
            c = seed()
            if mode == 'input': c['source_inputs'].pop('archive_flags')
            if mode == 'globals': c['backend']['globals']['unknown'] = '0x100'
            if mode == 'binding': c['integrity']['initializer'] = c['integrity']['transform']
            if mode == 'opcode': c['leaves'][c['integrity']['transform']] = 'c3'
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.rules.roots(c)


if __name__ == '__main__': unittest.main()
