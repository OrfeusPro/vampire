"""Pure bounded handler relocation: source data, fixtures and static callers."""
import copy
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load

RULES = load('login-handler-transfer-rules')
NATIVE = load('build-native-entry-code')
HERE = Path(__file__).parent / 'resource-tools/vampir/knowledge/native-contexts'


def context(family): return json.loads((HERE / (family + '-11320.json')).read_text('utf-8'))


class ScopeTests(unittest.TestCase):
    def test_exact_independent_root_scopes(self):
        for family, count in zip(RULES.FAMILIES, (2, 1)):
            c = context(family); original = copy.deepcopy(c)
            self.assertEqual(len(RULES.roots(family, c)), count)
            self.assertEqual(c, original)

    def test_unreviewed_family_and_extra_native_fields_rejected(self):
        c = context(RULES.FAMILIES[0])
        with self.assertRaisesRegex(ValueError, 'Unreviewed'): RULES.roots('full-login-handler', c)
        c['native_input'] = {}
        with self.assertRaisesRegex(ValueError, 'fields'): RULES.roots(RULES.FAMILIES[0], c)

    def test_whole_export_check_cannot_be_disabled(self):
        c = context(RULES.FAMILIES[1]); c['verify_whole_exports'] = False
        with self.assertRaisesRegex(ValueError, 'scope'): RULES.roots(RULES.FAMILIES[1], c)

    def test_continuation_roots_cannot_alias(self):
        c = context(RULES.FAMILIES[0]); c['functions']['reset'] = c['functions']['constructor']
        with self.assertRaisesRegex(ValueError, 'alias'): RULES.roots(RULES.FAMILIES[0], c)

    def test_continuation_helper_cannot_shadow_getter(self):
        c = context(RULES.FAMILIES[0]); c['helpers_captured'][0] = c['getter']
        with self.assertRaisesRegex(ValueError, 'alias'): RULES.roots(RULES.FAMILIES[0], c)

    def test_continuation_helper_set_must_be_unique(self):
        c = context(RULES.FAMILIES[0]); c['helpers_captured'][0] = c['helpers_captured'][1]
        with self.assertRaisesRegex(ValueError, 'alias'): RULES.roots(RULES.FAMILIES[0], c)

    def test_continuation_getter_requires_singleton_reference_and_ret(self):
        for change in ('singleton', 'ret'):
            c = context(RULES.FAMILIES[0])
            if change == 'singleton': c['singleton'] = hex(int(c['singleton'], 16) + 8)
            else: c['leaves'][c['getter']] = c['leaves'][c['getter']][:-2] + '90'
            with self.assertRaisesRegex(ValueError, 'getter/singleton'): RULES.roots(RULES.FAMILIES[0], c)

    def test_continuation_anchor_count_and_unknown_helper_rejected(self):
        c = context(RULES.FAMILIES[0]); c['anchors'].append(c['anchors'][0])
        with self.assertRaisesRegex(ValueError, 'scope'): RULES.roots(RULES.FAMILIES[0], c)
        c = context(RULES.FAMILIES[0]); c['helpers']['other'] = '0x1234'
        with self.assertRaisesRegex(ValueError, 'helper roles'): RULES.roots(RULES.FAMILIES[0], c)

    def test_early_scope_requires_exact_twelve_fixtures(self):
        c = context(RULES.FAMILIES[1]); c['fixtures']['gate'] = c['gate']
        with self.assertRaisesRegex(ValueError, 'fixture roles'): RULES.roots(RULES.FAMILIES[1], c)

    def test_early_gate_cannot_alias_executed_or_fixture_target(self):
        for role in ('root', 'fixture'):
            c = context(RULES.FAMILIES[1]); c['gate'] = c['functions']['handler'] if role == 'root' else c['fixtures']['log']
            with self.assertRaisesRegex(ValueError, 'gate aliases'): RULES.roots(RULES.FAMILIES[1], c)

    def test_early_fixtures_cannot_alias_each_other_or_handler(self):
        for value in ('log', 'root'):
            c = context(RULES.FAMILIES[1]); c['fixtures']['free'] = c['fixtures']['log'] if value == 'log' else c['functions']['handler']
            with self.assertRaisesRegex(ValueError, 'alias'): RULES.roots(RULES.FAMILIES[1], c)

    def test_early_historical_scope_retains_old_immutable_evidence_pointer(self):
        c = context(RULES.FAMILIES[1]); p = c['provenance']
        self.assertEqual(p['tool_name'], 'verify-login-handler-early-11320.py')
        self.assertEqual(p['reviewed_report']['sha256'], 'f09b394f52f72663c783814971a85fa57ffd86f9278c3db4ed29b1f8ca5c7b78')
        self.assertNotIn('tool_path', p)


class DataTests(unittest.TestCase):
    def setUp(self):
        self.utility = load('version-system-transfer-rules'); self.version = load('update-native-version-result')
        original = RULES.load
        patch.object(RULES, 'load', side_effect=lambda name: self.utility if name == 'version-system-transfer-rules'
            else self.version if name == 'update-native-version-result' else original(name)).start()
        self.addCleanup(patch.stopall)

    def test_literal_change_and_missing_relocation_rejected(self):
        before, after = SimpleNamespace(), SimpleNamespace(); raw = b'\1\0\0\0'
        with patch.object(self.utility, 'data_input', return_value=dict(storage='file', bytes=raw.hex())):
            self.assertEqual(RULES.typed_data(before, after, {0x1000: 0x2000}, 0x1000, 4, raw, 'default')['address'], '0x2000')
            with self.assertRaisesRegex(ValueError, 'checked code reference'):
                RULES.typed_data(before, after, {}, 0x1000, 4, raw, 'default')
            with self.assertRaisesRegex(ValueError, 'typed data changed'):
                RULES.typed_data(before, after, {0x1000: 0x2000}, 0x1000, 4, b'\2\0\0\0', 'default')

    def test_zero_fill_must_stay_zero_fill(self):
        with patch.object(self.utility, 'data_input', side_effect=[dict(storage='pe-zero-fill', size=8, section='.data'), dict(storage='file', bytes='00' * 8)]):
            with self.assertRaisesRegex(ValueError, 'typed data changed'):
                RULES.typed_data(None, None, {1: 2}, 1, 8, 'pe-zero-fill', 'singleton')

    def test_table_alias_partition_is_not_just_unique_count(self):
        before, after = SimpleNamespace(raw=struct.pack('<4Q', 10, 20, 10, 30)), SimpleNamespace(raw=struct.pack('<4Q', 40, 50, 40, 60))
        with patch.object(self.utility, 'image_bytes', side_effect=lambda image, at, size: image.raw[:size]), \
             patch.object(self.version, 'image_bytes', side_effect=lambda image, at, size: image.raw[:size]):
            self.assertEqual(RULES.table(before, after, 1, {1: 2}, 32, {8})['used_slots'], [8])
            after.raw = struct.pack('<4Q', 40, 50, 60, 60)
            with self.assertRaises(ValueError): RULES.table(before, after, 1, {1: 2}, 32, {8})

    def test_static_window_rejects_indirect_dispatch_change(self):
        before, after = SimpleNamespace(raw=bytes.fromhex('488b01ff5028')), SimpleNamespace(raw=bytes.fromhex('488b01ff5030'))
        with patch.object(self.utility, 'image_bytes', side_effect=lambda image, at, size: image.raw[:size]):
            a = RULES.decode(NATIVE, before, 0x1000, 6); b = RULES.decode(NATIVE, after, 0x2000, 6)
            with self.assertRaisesRegex(ValueError, 'shape changed'): RULES.pair_static(NATIVE, a, b, {})

    def test_static_window_cannot_decode_partial_instruction(self):
        with patch.object(self.utility, 'image_bytes', return_value=b'\x48\x8b'):
            with self.assertRaisesRegex(ValueError, 'instruction gap'): RULES.decode(NATIVE, None, 0x1000, 2)

    def early_fixture(self):
        c = context(RULES.FAMILIES[1]); origin = int(c['functions']['handler'], 16)
        rows = [dict(address=int(at, 16), call=True, direct_target=int(target, 16) if target.startswith('0x') else None,
                     operands=target, rip_references=[]) for at, target in c['call_sites']['handler'].items()]
        references = {offset: 0x500000 + offset * 0x100 for offset in RULES.EARLY_RIPS}
        rows += [dict(address=origin + offset, call=False, direct_target=None, operands='', rip_references=[pointer])
                 for offset, pointer in references.items()]
        localizer = int(c['fixtures']['localizer'], 16); pointer = localizer + 0x100000
        memory = {int(c['fixtures']['log'], 16): b'\xc2\0\0',
                  localizer: bytes.fromhex('488b05') + struct.pack('<i', pointer - localizer - 7) + b'\xc3',
                  **{references[offset]: RULES.CALLBACK_LEAF for offset in (317, 1436)}}
        image = SimpleNamespace(memory=memory)
        mapping = {int(target, 16): int(target, 16) for target in c['call_sites']['handler'].values() if target.startswith('0x')}
        mapping.update({value: value for value in references.values()})
        patch.object(RULES, 'typed_data', side_effect=lambda *args: {'role': args[-1]}).start()
        patch.object(RULES, 'table', return_value={'scope': 'unexecuted-table'}).start()
        patch.object(self.utility, 'concrete', return_value=None).start()
        patch.object(self.utility, 'image_bytes', side_effect=lambda im, at, size: im.memory[at][:size]).start()
        return c, image, mapping, {'handler': rows}

    def test_early_fixture_leaves_have_explicit_returning_boundaries(self):
        c, image, mapping, rows = self.early_fixture()
        current = RULES.functional(RULES.FAMILIES[1], c)
        report = RULES.early(NATIVE, None, image, image, c, current, mapping, rows)
        self.assertEqual(len(report['fixtures']), 12)
        bounded = {item['role'] for item in report['fixtures'] if item['kind'] == 'bounded-returning-fixture'}
        self.assertEqual(bounded, {'log', 'localizer'})
        image.memory[int(c['fixtures']['log'], 16)] = b'\xc3\0\0'
        with self.assertRaisesRegex(ValueError, 'logging return fixture changed'):
            RULES.early(NATIVE, None, image, image, c, current, mapping, rows)

    def test_early_localizer_and_callback_body_tamper_are_rejected(self):
        c, image, mapping, rows = self.early_fixture()
        current = RULES.functional(RULES.FAMILIES[1], c)
        where = int(c['fixtures']['localizer'], 16); saved = image.memory[where]
        image.memory[where] = b'\x48\x8b\x0d' + saved[3:]
        with self.assertRaisesRegex(ValueError, 'localizer getter fixture changed'):
            RULES.early(NATIVE, None, image, image, c, current, mapping, rows)
        image.memory[where] = saved; callback = 0x500000 + 317 * 0x100
        image.memory[callback] = RULES.CALLBACK_LEAF[:-1] + b'\x28'
        with self.assertRaisesRegex(ValueError, 'callback dispatch leaf changed'):
            RULES.early(NATIVE, None, image, image, c, current, mapping, rows)

    def test_early_fixture_call_and_rip_layout_changes_are_rejected(self):
        c, image, mapping, rows = self.early_fixture()
        current = RULES.functional(RULES.FAMILIES[1], c); origin = int(c['functions']['handler'], 16)
        call = next(row for row in rows['handler'] if row['address'] == origin + 45)
        call['direct_target'] += 1
        with self.assertRaisesRegex(ValueError, 'fixture call role differs'):
            RULES.early(NATIVE, None, image, image, c, current, mapping, rows)
        call['direct_target'] -= 1; rows['handler'].append(dict(address=origin + 1600, call=False, rip_references=[0x900000]))
        with self.assertRaisesRegex(ValueError, 'RIP layout differs'):
            RULES.early(NATIVE, None, image, image, c, current, mapping, rows)


class AnchorImage:
    def __init__(self):
        self.data = bytearray(0x12000); self.code = {}; self.roots = {}
        self.pe = SimpleNamespace(base=0, sections=[dict(name='.text', rva=0x1000, raw=0x1000, raw_size=0x10000)])
    def offset(self, rva): return rva
    def containing(self, at):
        for row in self.roots:
            if row[0] <= at < row[1]: return row
        return None
    def add(self, at, raw, boundary=True):
        self.data[at:at + len(raw)] = raw
        span = (at, at + len(raw), 0); self.roots[span] = span; self.code[at] = (raw, boundary)


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.utility = load('version-system-transfer-rules'); original = RULES.load
        patch.object(RULES, 'load', side_effect=lambda name: self.utility if name == 'version-system-transfer-rules' else original(name)).start()
        patch.object(self.utility, 'image_bytes', side_effect=lambda image, at, size: bytes(image.data[at:at + size])).start()
        self.addCleanup(patch.stopall)
        self.before, self.after = AnchorImage(), AnchorImage()
        self.bindings = SimpleNamespace(rows=self.rows)

    def rows(self, native, image, at):
        raw, boundary = image.code[at]
        result = RULES.decode(native, image, at, len(raw))
        return result if boundary else result[1:]

    def window(self, at, ctor, singleton):
        return bytes.fromhex('488bc8') + b'\xe8' + struct.pack('<i', ctor - at - 8) + bytes.fromhex('488905') + struct.pack('<i', singleton - at - 15)

    def fixture(self):
        raw = self.window(0x2000, 0x5000, 0x6000); self.before.add(0x2000, raw)
        self.after.add(0x3000, self.window(0x3000, 0x8000, 0x9000))
        return dict(address='0x2000', bytes=raw.hex()), {0x5000: 0x8000, 0x6000: 0x9000}

    def test_static_caller_anchor_uses_relocation_edges(self):
        anchor, mapping = self.fixture(); self.after.add(0x3100, self.window(0x3100, 0x8100, 0x9000))
        result = RULES.find_anchor(NATIVE, self.bindings, self.before, self.after, anchor, mapping)
        self.assertEqual(result['address'], '0x3000'); self.assertEqual(mapping[0x2000], 0x3000)

    def test_two_same_shaped_matching_callers_are_ambiguous(self):
        anchor, mapping = self.fixture(); self.after.add(0x3100, self.window(0x3100, 0x8000, 0x9000))
        with self.assertRaisesRegex(ValueError, 'ambiguous'): RULES.find_anchor(NATIVE, self.bindings, self.before, self.after, anchor, mapping)

    def test_anchor_must_start_at_a_whole_owner_instruction_boundary(self):
        anchor, mapping = self.fixture(); self.after.code[0x3000] = (self.after.code[0x3000][0], False)
        with self.assertRaisesRegex(ValueError, 'ambiguous'): RULES.find_anchor(NATIVE, self.bindings, self.before, self.after, anchor, mapping)

    def test_changed_baseline_anchor_is_rejected_before_search(self):
        anchor, mapping = self.fixture(); anchor['bytes'] = '90' + anchor['bytes'][2:]
        with self.assertRaisesRegex(ValueError, 'baseline anchor bytes'): RULES.find_anchor(NATIVE, self.bindings, self.before, self.after, anchor, mapping)

    def test_seeded_anchor_cannot_move_to_unrelated_caller(self):
        anchor, mapping = self.fixture(); mapping[0x2000] = 0x3100; self.after.add(0x3100, self.window(0x3100, 0x8100, 0x9000))
        with self.assertRaisesRegex(ValueError, 'ambiguous'): RULES.find_anchor(NATIVE, self.bindings, self.before, self.after, anchor, mapping)


if __name__ == '__main__': unittest.main()
