"""LoginResult transfer scope, virtual identities and source-data regressions."""
import copy
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load

RULES = load('login-input-transfer-rules')
NATIVE = load('build-native-entry-code')
HERE = Path(__file__).parent / 'resource-tools/vampir/knowledge/native-contexts'


def context(family='login-nested'):
    return json.loads((HERE / (family + '-11320.json')).read_text('utf-8'))


class LoginInputScopeTests(unittest.TestCase):
    def test_two_explicit_scopes_and_unchanged_original(self):
        for family, count in zip(RULES.FAMILIES, (6, 20)):
            c = context(family); before = copy.deepcopy(c)
            self.assertEqual(len(RULES.roots(family, c)), count)
            self.assertEqual(c, before)

    def test_unknown_family_and_hidden_native_field_rejected(self):
        c = context()
        with self.assertRaises(ValueError): RULES.roots('other', c)
        c['native_handler'] = True
        with self.assertRaisesRegex(ValueError, 'fields'): RULES.roots(RULES.FAMILIES[0], c)

    def test_whole_export_scope_cannot_be_disabled(self):
        c = context(); c['verify_whole_exports'] = False
        with self.assertRaisesRegex(ValueError, 'scope'): RULES.roots(RULES.FAMILIES[0], c)

    def test_executed_root_alias_rejected(self):
        c = context(); c['functions']['reader'] = c['functions']['constructor']
        with self.assertRaisesRegex(ValueError, 'roots alias'): RULES.roots(RULES.FAMILIES[0], c)

    def test_fixture_shadowing_executed_leaf_rejected(self):
        c = context(); c['string_constructor'] = c['id_getter']
        with self.assertRaisesRegex(ValueError, 'fixture boundaries alias'): RULES.roots(RULES.FAMILIES[0], c)

    def test_fixture_roles_cannot_alias_each_other(self):
        c = context(); c['string_constructor'] = c['string_reader']
        with self.assertRaisesRegex(ValueError, 'fixture boundaries alias'): RULES.roots(RULES.FAMILIES[0], c)

    def test_packet_id_is_exact_four(self):
        c = context(); c['leaves'][c['id_getter']] = 'b802000000c3'
        with self.assertRaisesRegex(ValueError, 'ID is not 4'): RULES.roots(RULES.FAMILIES[0], c)

    def test_input_embedded_source_and_export_scope_rejected(self):
        for field, value in (('source_sha256', '0' * 64), ('exports', {'../bad': '0' * 64})):
            c = context(RULES.FAMILIES[1]); c['input'][field] = value
            with self.assertRaisesRegex(ValueError, 'source or export'): RULES.roots(RULES.FAMILIES[1], c)

    def test_input_nested_leaf_must_equal_top_level(self):
        c = context(RULES.FAMILIES[1]); c['input']['leaves'][next(iter(c['input']['leaves']))]['bytes'] = 'c3'
        with self.assertRaisesRegex(ValueError, 'leaf declaration'): RULES.roots(RULES.FAMILIES[1], c)

    def test_input_alias_and_false_mode_do_not_pass(self):
        c = context(RULES.FAMILIES[1]); c['input']['functions']['u16'] = c['functions']['reader']
        with self.assertRaisesRegex(ValueError, 'roots alias'): RULES.roots(RULES.FAMILIES[1], c)
        c = context(RULES.FAMILIES[1]); c['input']['buffer_construction']['reading_mode'] = True
        with self.assertRaisesRegex(ValueError, 'mode/endian'): RULES.roots(RULES.FAMILIES[1], c)

    def test_input_string_linkage_and_explicit_budget(self):
        c = context(RULES.FAMILIES[1]); c['string_reader'] = c['input']['functions']['std_string']
        with self.assertRaisesRegex(ValueError, 'string reader linkage'): RULES.roots(RULES.FAMILIES[1], c)
        c = context(RULES.FAMILIES[1]); c['function_budget'] = 21
        with self.assertRaisesRegex(ValueError, 'budget'): RULES.roots(RULES.FAMILIES[1], c)


class LoginInputDataTests(unittest.TestCase):
    def setUp(self):
        self.utility, self.version = load('version-system-transfer-rules'), load('update-native-version-result')
        original = RULES.load
        patch.object(RULES, 'load', side_effect=lambda name: self.utility if name == 'version-system-transfer-rules'
            else self.version if name == 'update-native-version-result' else original(name)).start()
        self.addCleanup(patch.stopall)

    def test_cpp_free_fixture_requires_exact_tail_to_declared_free(self):
        old = dict(string_fixtures=dict(cpp_free='0x1000', free='0x2000'))
        new = dict(string_fixtures=dict(cpp_free='0x3000', free='0x4000'))
        before, after = SimpleNamespace(raw=b'\xe9' + struct.pack('<i', 0xffb)), SimpleNamespace(raw=b'\xe9' + struct.pack('<i', 0xffb))
        with patch.object(self.utility, 'image_bytes', side_effect=lambda image, at, size: image.raw[:size]):
            RULES.cpp_free_boundary(before, after, old, new)
            after.raw = b'\xe9' + struct.pack('<i', 0xffc)
            with self.assertRaisesRegex(ValueError, 'tail boundary'): RULES.cpp_free_boundary(before, after, old, new)
            after.raw = b'\xe8' + struct.pack('<i', 0xffb)
            with self.assertRaisesRegex(ValueError, 'tail boundary'): RULES.cpp_free_boundary(before, after, old, new)

    def test_exact_dispatch_leaf_and_no_extra_calls(self):
        image = SimpleNamespace(memory={0x1000: RULES.DISPATCH})
        with patch.object(self.utility, 'image_bytes', side_effect=lambda i, a, n: i.memory[a][:n]):
            rows = RULES.leaf_rows(NATIVE, image, 0x1000, RULES.DISPATCH)
            self.assertEqual(rows[-1]['operands'], 'qword ptr [rax + 0x20]')
            changed = bytearray(RULES.DISPATCH); changed[-1] = 0x28; image.memory[0x1000] = bytes(changed)
            with self.assertRaisesRegex(ValueError, 'dispatch leaf changed'):
                RULES.leaf_rows(NATIVE, image, 0x1000, RULES.DISPATCH)
            image.memory[0x1000] = bytes.fromhex('e800000000c3')
            with self.assertRaisesRegex(ValueError, 'external edge'):
                RULES.leaf_rows(NATIVE, image, 0x1000, image.memory[0x1000])

    def test_returning_leaf_requires_ret_and_complete_instructions(self):
        image = SimpleNamespace(memory=bytes.fromhex('b804000000c3'))
        with patch.object(self.utility, 'image_bytes', side_effect=lambda i, a, n: i.memory[:n]):
            self.assertEqual(RULES.leaf_rows(NATIVE, image, 0x1000, image.memory)[-1]['mnemonic'], 'ret')
            image.memory = bytes.fromhex('b80400000090')
            with self.assertRaisesRegex(ValueError, 'return boundary'):
                RULES.leaf_rows(NATIVE, image, 0x1000, image.memory)
            image.memory = b'\x0f'
            with self.assertRaisesRegex(ValueError, 'instruction gap'):
                RULES.leaf_rows(NATIVE, image, 0x1000, image.memory)

    def test_table_alias_partition_and_missing_link(self):
        before, after = SimpleNamespace(data=struct.pack('<4Q', 1, 2, 1, 3)), SimpleNamespace(data=struct.pack('<4Q', 11, 12, 11, 13))
        with patch.object(self.utility, 'image_bytes', side_effect=lambda i, a, n: i.data[:n]), \
             patch.object(self.version, 'image_bytes', side_effect=lambda i, a, n: i.data[:n]):
            mapping = {0x1000: 0x2000}
            self.assertEqual(RULES.table(before, after, 0x1000, mapping, 32, {8})['used_slots'], [8])
            with self.assertRaisesRegex(ValueError, 'linkage'): RULES.table(before, after, 0x1000, {}, 32, {8})
            after.data = struct.pack('<4Q', 11, 12, 13, 13)
            with self.assertRaises(ValueError): RULES.table(before, after, 0x1000, {0x1000: 0x2000}, 32, {8})

    def test_constructor_defaults_and_empty_literal_are_exact(self):
        c = context(); origins = {k: int(v, 16) for k, v in c['functions'].items()}
        def row(role, offset, pointer): return dict(address=origins[role] + offset, rip_references=[pointer])
        packet, time, period = [int(c[k], 16) for k in ('packet_table', 'time_table', 'period_table')]
        rows = {'constructor': [row('constructor', n, at) for n, at in ((12, packet), (168, 0x1000), (187, 0x2000), (194, 0x3000))],
                'time_constructor': [row('time_constructor', 14, time)],
                'period_constructor': [row('period_constructor', 15, period), row('period_constructor', 41, time)]}
        memory = {0x1000: b'\1\0\0\0', 0x2000: b'\0\0', 0x3000: b'\1\0\0\0'}
        before, after = SimpleNamespace(memory=memory), SimpleNamespace(memory=copy.deepcopy(memory))
        mapping = {at: at for at in memory}
        with patch.object(self.utility, 'image_bytes', side_effect=lambda i, a, n: i.memory[a][:n]):
            defaults, data = RULES._default_data(before, after, c, mapping, rows)
            self.assertEqual(defaults, {'0x130': '0x1000', '0x134': '0x3000'}); self.assertEqual(len(data), 3)
            c['constructor_defaults'] = {'0x130': '0x1000', '0x134': '0x4000'}
            with self.assertRaisesRegex(ValueError, 'provenance'): RULES._default_data(before, after, c, mapping, rows)
            c.pop('constructor_defaults'); after.memory[0x1000] = b'\2\0\0\0'
            with self.assertRaisesRegex(ValueError, 'constructor data changed'): RULES._default_data(before, after, c, mapping, rows)

    def test_call_roles_require_exact_order_and_reject_virtual_change(self):
        c = context(); leaf = int(next(at for at, raw in c['leaves'].items() if bytes.fromhex(raw) == RULES.DISPATCH), 16)
        base = int(next(at for at, raw in c['leaves'].items() if raw.startswith('488d')), 16)
        roles = {'dispatch': leaf, 'time_base': base, 'string_constructor': int(c['string_constructor'], 16), 'string_reader': int(c['string_reader'], 16)}
        rows = {}
        for role, calls in RULES.CALL_ROLES.items():
            origin = int(c['functions'][role], 16); result = []
            for offset, key in calls.items():
                virtual = key.startswith('qword ptr ')
                target = None if virtual else int(c['functions'][key[5:]], 16) if key.startswith('root:') else roles[key]
                result.append(dict(address=origin + offset, call=True, direct_target=target, rip_references=[], operands=key))
            rows[role] = result
        self.assertEqual(RULES._call_roles(c, rows), roles)
        rows['reader'][0]['operands'] = 'qword ptr [rax + 0x60]'
        with self.assertRaisesRegex(ValueError, 'virtual role'): RULES._call_roles(c, rows)


if __name__ == '__main__': unittest.main()
