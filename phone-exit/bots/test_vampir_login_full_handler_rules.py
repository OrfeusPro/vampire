"""Whole-handler role import is explicit; it never admits unchanged old logic."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load, HERE

RULE = load('login-full-handler-rules')


def legacy():
    c = json.loads((HERE / 'knowledge/native-contexts/login-full-handler-11318.json').read_text('utf-8'))
    c['verify_whole_exports'] = True
    return c


def current():
    c = legacy();c.pop('switch_gate');c.update(format=RULE.CURRENT, packet_bytes=352,
        gate_context=dict(path='generated-gate/manifest.json', sha256='a' * 64))
    c['fixtures'].update(trailing_predicate='0x145bc9b00', trailing_apply='0x145bc7b60')
    c['fixture_boundaries'] = {name: dict(kind='unwind-fixture') for name in c['fixtures']}
    return c


def call(at, target=None, operands='qword ptr [rax + 0x28]'):
    return dict(address=at, call=True, branch=False, bytes='e800000000', direct_target=target,
        operands=operands if target is None else hex(target), rip_references=[])


def handler_rows(c):
    at = int(c['functions']['handler'], 16);gate = int(c['functions']['gate'], 16)
    parts = {213: call(at + 213, gate)}
    for offset, role in RULE.ADDED.items(): parts[offset] = call(at + offset, int(c['fixtures'][role], 16))
    for offset, raw in RULE.NEW_REGION:
        parts[offset] = dict(address=at + offset, bytes=raw, call=False, branch=False,
            direct_target=None, operands='typed fixture', rip_references=[])
    extra = 85 - sum(r['call'] for r in parts.values())
    for i in range(extra): parts[3000 + i] = call(at + 3000 + i, 0x140100000 + i * 16)
    for i in range(356 - len(parts)):
        parts[4000 + i] = dict(address=at + 4000 + i, bytes='90', call=False, branch=False,
            direct_target=None, operands='', rip_references=[])
    row = next(r for r in reversed(list(parts.values())) if not r['call'])
    byte_count = sum(len(bytes.fromhex(r['bytes'])) for r in parts.values())
    row['bytes'] += '90' * (1557 - byte_count)
    return list(parts.values())


class FullHandlerScopeTests(unittest.TestCase):
    def test_explicit_trailing_call_receipt_survives_json_round_trip(self):
        value = RULE.trailing_calls()
        self.assertEqual(value, {'820': 'trailing_predicate', '836': 'trailing_apply', '855': 'trailing_apply', '869': 'free'})
        self.assertEqual(json.loads(json.dumps(value)), value)

    def test_legacy_and_current_have_exact_distinct_packet_and_fixture_scopes(self):
        a, b = legacy(), current()
        self.assertEqual(len(RULE.roots(a)), 2);self.assertEqual(len(RULE.roots(b)), 2)
        self.assertEqual((len(a['fixtures']), len(b['fixtures'])), (62, 64))
        self.assertEqual((a['packet_bytes'], b['packet_bytes']), (320, 352))

    def test_legacy_import_is_source_bound_and_never_a_generic_old_layout_bypass(self):
        for change in (dict(source_sha256='a' * 64), dict(packet_bytes=352), dict(switch_gate='unknown'), dict(format='guess')):
            with self.assertRaises(ValueError): RULE.roots(dict(legacy(), **change))

    def test_current_requires_exact352_bytes_and_immutable_gate_pointer(self):
        for change in (dict(packet_bytes=352.0), dict(packet_bytes=320), dict(gate_context={}),
                dict(gate_context=dict(path='ctx', sha256='x' * 64))):
            with self.assertRaises(ValueError): RULE.roots(dict(current(), **change))

    def test_optional_native_extensions_and_wrong_role_inventory_are_rejected(self):
        for field in ('native_reader', 'native_post_state', 'function_budget', 'native_admission'):
            c = current();c[field] = True
            with self.assertRaises(ValueError): RULE.roots(c)
        c = current();c['fixture_boundaries'].pop('trailing_apply')
        with self.assertRaises(ValueError): RULE.roots(c)
        c = current();c['functions']['reader'] = '0x140000000'
        with self.assertRaises(ValueError): RULE.roots(c)

    def test_fixture_leaf_and_executable_aliases_are_rejected(self):
        changes = (lambda c: c['fixtures'].update(trailing_apply=c['functions']['gate']),
            lambda c: c['fixtures'].update(trailing_apply=c['id_getter']),
            lambda c: c['fixtures'].update(trailing_apply=c['fixtures']['trailing_predicate']),
            lambda c: c['helpers'].update(memcpy=c['functions']['handler']))
        for change in changes:
            c = current();change(c)
            with self.assertRaises(ValueError): RULE.roots(c)

    def test_packet_id_is_exact_four(self):
        c = current();c['leaves'][c['id_getter']] = 'b802000000c3'
        with self.assertRaisesRegex(ValueError, 'ID'): RULE.roots(c)

    def test_dependencies_require_same_full_source_path_memcpy_gate_and_packet_id(self):
        early = dict(source_sha256='a' * 64, source='source.exe', gate='0x100', helpers=dict(memcpy='0x200'))
        gate = dict(early, function='0x100');nested = dict(early, id_getter='0x300', leaves={'0x300': 'b804000000c3'})
        RULE.dependencies(early, gate, nested)
        for change in (dict(source_sha256='b' * 64), dict(source='other.exe'), dict(function='0x101'), dict(helpers={})):
            with self.assertRaises(ValueError): RULE.dependencies(early, dict(gate, **change), nested)
        bad = dict(nested, leaves={'0x300': 'c3'})
        with self.assertRaises(ValueError): RULE.dependencies(early, gate, bad)


class FullHandlerCallImportTests(unittest.TestCase):
    def test_import_preserves_all_direct_callee_aliases_and_virtual_roles(self):
        old = [call(10, 100), call(20, 200), call(30, 100), call(40)]
        new = [call(50, 300), call(60, 400), call(70, 300), call(80)]
        mapping = {};RULE.link_call_roles(old, new, mapping)
        self.assertEqual(mapping, {100: 300, 200: 400})
        for changed in ([call(50, 300), call(60, 300), call(70, 300), call(80)],
                [call(50, 300), call(60, 400), call(70, 500), call(80)], new[:-1]):
            with self.assertRaises(ValueError): RULE.link_call_roles(old, changed, {})

    def test_virtual_to_direct_or_changed_slot_cannot_keep_a_role(self):
        old = [call(10)]
        for changed in ([call(20, 100)], [call(20, operands='qword ptr [rax + 0x38]')]):
            with self.assertRaises(ValueError): RULE.link_call_roles(old, changed, {})

    def test_shared_handler_gate_role_mapping_must_remain_consistent(self):
        with self.assertRaises(ValueError): RULE.link_call_roles([call(10, 100)], [call(20, 300)], {100: 200})


class CurrentHandlerShapeTests(unittest.TestCase):
    def test_explicit_current_whole_shape_and_new_region_are_accepted(self):
        c = current();rr = handler_rows(c)
        result = RULE.current_handler(None, SimpleNamespace(rows=lambda *args: rr), None,
            int(c['functions']['handler'], 16), c['fixtures'], int(c['functions']['gate'], 16))
        self.assertEqual(result, rr);self.assertEqual(len(rr), 356)

    def test_all_four_added_call_sites_have_exact_callee_roles(self):
        c = current();at = int(c['functions']['handler'], 16)
        for offset in RULE.ADDED:
            rr = handler_rows(c);next(row for row in rr if row['address'] == at + offset)['direct_target'] = 0x140000000
            with self.assertRaisesRegex(ValueError, 'callee role'):
                RULE.current_handler(None, SimpleNamespace(rows=lambda *args: rr), None, at, c['fixtures'], int(c['functions']['gate'], 16))

    def test_trailing_field_argument_offsets_and_branch_bytes_are_not_masked(self):
        c = current();at = int(c['functions']['handler'], 16)
        for offset, raw in RULE.NEW_REGION:
            rr = handler_rows(c);next(row for row in rr if row['address'] == at + offset)['bytes'] = '90' * len(bytes.fromhex(raw))
            with self.assertRaisesRegex(ValueError, 'argument/control'):
                RULE.current_handler(None, SimpleNamespace(rows=lambda *args: rr), None, at, c['fixtures'], int(c['functions']['gate'], 16))

    def test_branch_outside_exact_body_and_unknown_indirect_jump_are_rejected(self):
        c = current();at = int(c['functions']['handler'], 16)
        for direct in (None, 0x140000000):
            rr = handler_rows(c);row = next(row for row in rr if not row['call']);row.update(branch=True, direct_target=direct)
            with self.assertRaisesRegex(ValueError, 'branch leaves'):
                RULE.current_handler(None, SimpleNamespace(rows=lambda *args: rr), None, at, c['fixtures'], int(c['functions']['gate'], 16))

    def test_exact_instruction_count_byte_count_and_gate_site_are_required(self):
        c = current();at = int(c['functions']['handler'], 16)
        for mode in ('count', 'bytes', 'gate'):
            rr = handler_rows(c)
            if mode == 'count': rr.pop()
            if mode == 'bytes': rr[-1]['bytes'] += '90'
            if mode == 'gate': next(row for row in rr if row['address'] == at + 213)['direct_target'] += 1
            with self.assertRaises(ValueError): RULE.current_handler(None, SimpleNamespace(rows=lambda *args: rr), None, at, c['fixtures'], int(c['functions']['gate'], 16))


if __name__ == '__main__': unittest.main()
