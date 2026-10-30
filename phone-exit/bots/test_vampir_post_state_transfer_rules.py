"""Typed post-state roots, backend partitions and exact external-tail rules."""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load, HERE

TOOL = load('post-state-transfer-rules')


def context():
    return json.loads((HERE / 'knowledge/native-contexts/login-post-state-11318.json').read_text('utf-8'))


def rows(c):
    """Synthetic row metadata for checking the typed role gate, never native code."""
    result = {}
    for role, (count, size) in TOOL.ROOT_SHAPES.items():
        origin = int(c['functions'][role], 16);part = []
        for at, target in c['call_sites'][role].items():
            direct = int(target, 16) if target.startswith('0x') else None
            part.append(dict(address=int(at, 16), bytes='90' * (5 if direct is not None else 6), mnemonic='call',
                operands=target, call=True, branch=False, direct_target=direct, rip_references=[]))
        if role == 'wrapper':
            tail = c['tail_calls'][0]
            part.append(dict(address=int(tail['address'], 16), bytes=tail['bytes'], mnemonic='jmp',
                operands=tail['target'], call=False, branch=True, direct_target=int(tail['target'], 16), rip_references=[]))
        else:
            for offset, name, length in ((290, 'count', 6), (311, 'chunks', 7)):
                part.append(dict(address=origin + offset, bytes='90' * length, mnemonic='mov', operands='fixture',
                    call=False, branch=False, direct_target=None, rip_references=[int(c['globals'][name], 16)]))
        filler = count - len(part)
        for i in range(filler):
            part.append(dict(address=origin if i == 0 else origin + 2000 + i, bytes='90', mnemonic='nop', operands='',
                call=False, branch=False, direct_target=None, rip_references=[]))
        total = sum(len(bytes.fromhex(row['bytes'])) for row in part)
        part[-filler]['bytes'] = '90' * (size - total + 1)
        result[role] = sorted(part, key=lambda row: row['address'])
    return result


class PostStateScopeTests(unittest.TestCase):
    def test_baseline_admits_two_roots_one_getter_and_twelve_disjoint_fixtures(self):
        c = context();roots = TOOL.roots(c)
        self.assertEqual(roots, {0x146755a10, 0x144a2dbc0});self.assertEqual(len(c['leaves']), 1)
        self.assertEqual(len(c['fixtures']), 12);self.assertFalse(roots & {int(at, 16) for at in c['fixtures'].values()})
        TOOL.check_rows(c, rows(c))

    def test_extra_or_missing_roles_and_optional_native_scope_are_rejected(self):
        for change in (lambda c: c.update(function_budget=3), lambda c: c.update(native_handler={}),
                lambda c: c['functions'].update(extra='0x140000000'), lambda c: c['fixtures'].pop('mark'),
                lambda c: c['globals'].update(extra='0x140000000'), lambda c: c.update(verify_whole_exports=False)):
            c = context();change(c)
            with self.assertRaises(ValueError): TOOL.roots(c)

    def test_fixture_root_leaf_helper_and_global_aliases_cannot_expand_native_scope(self):
        changes = (lambda c: c['functions'].update(wrapper=c['functions']['target']),
            lambda c: c['fixtures'].update(mark=c['functions']['target']),
            lambda c: c['fixtures'].update(mark=c['service_getter']),
            lambda c: c['fixtures'].update(mark=c['fixtures']['eligible']),
            lambda c: c['helpers'].update(memcpy=c['functions']['wrapper']),
            lambda c: c['globals'].update(count=c['globals']['chunks']))
        for change in changes:
            c = context();change(c)
            with self.assertRaises(ValueError): TOOL.roots(c)

    def test_distinct_global_addresses_still_cannot_overlap_typed_storage(self):
        c = context();c['globals']['count'] = hex(int(c['globals']['chunks'], 16) + 4)
        with self.assertRaisesRegex(ValueError, 'storage overlaps'): TOOL.roots(c)

    def test_singleton_getter_requires_exact_eight_byte_returning_rip_link(self):
        c = context();getter = c['service_getter']
        for raw in ('c3', '488b0541acb60690', '488b0542acb606c3'):
            bad = copy.deepcopy(c);bad['leaves'][getter] = raw
            with self.assertRaisesRegex(ValueError, 'getter'): TOOL.roots(bad)
        c['leaves']['0x140000000'] = 'c3'
        with self.assertRaises(ValueError): TOOL.roots(c)

    def test_tail_requires_exact_e9_offset_target_and_relative_displacement(self):
        for change in (dict(address='0x146755a68'), dict(target='0x144a2dbc1'), dict(bytes='e953812dfe'), dict(bytes='c3')):
            c = context();c['tail_calls'][0].update(change)
            with self.assertRaises(ValueError): TOOL.roots(c)

    def test_call_offsets_and_fixture_identities_are_explicit_not_first_call_guesses(self):
        for role, at, target in (('wrapper', 0x146755a16, 0x146718c90), ('target', 0x144a2dc0b, 0x1417f4140)):
            c = context();rr = rows(c);row = next(row for row in rr[role] if row['address'] == at);row['direct_target'] = target
            with self.assertRaisesRegex(ValueError, 'direct fixture/getter'): TOOL.check_rows(c, rr)
        c = context();rr = rows(c);row = next(row for row in rr['wrapper'] if row['call']);row['address'] += 1
        with self.assertRaisesRegex(ValueError, 'offsets'): TOOL.check_rows(c, rr)

    def test_virtual_dispatch_and_rip_global_roles_are_exact(self):
        c = context();rr = rows(c);virtual = next(row for row in rr['target'] if row['call'] and row['direct_target'] is None)
        virtual['operands'] = 'qword ptr [rax + 0x28]'
        with self.assertRaisesRegex(ValueError, 'virtual'): TOOL.check_rows(c, rr)
        rr = rows(c);rip = next(row for row in rr['target'] if row['rip_references']);rip['rip_references'] = [int(c['globals']['service'], 16)]
        with self.assertRaisesRegex(ValueError, 'global RIP'): TOOL.check_rows(c, rr)

    def test_only_the_declared_wrapper_tail_may_leave_its_native_body(self):
        c = context();rr = rows(c);row = next(row for row in rr['target'] if not row['call'] and not row['rip_references'])
        row.update(branch=True, mnemonic='jmp', direct_target=int(c['functions']['wrapper'], 16))
        with self.assertRaisesRegex(ValueError, 'external branch'): TOOL.check_rows(c, rr)
        rr = rows(c);tail = next(row for row in rr['wrapper'] if row['branch']);tail['direct_target'] += 1
        with self.assertRaisesRegex(ValueError, 'external branch'): TOOL.check_rows(c, rr)

    def test_whole_byte_count_instruction_count_and_all_calls_must_match(self):
        c = context();rr = rows(c);rr['target'][-1]['bytes'] += '90'
        with self.assertRaisesRegex(ValueError, 'boundary'): TOOL.check_rows(c, rr)
        rr = rows(c);rr['target'][-1]['call'] = True
        with self.assertRaises(ValueError): TOOL.check_rows(c, rr)
        c['call_sites']['wrapper'].pop(next(iter(c['call_sites']['wrapper'])))
        with self.assertRaisesRegex(ValueError, 'complete call-site'): TOOL.check_rows(c, rows(context()))


class PostStateResolutionTests(unittest.TestCase):
    def test_ambiguous_roots_are_not_chosen_arbitrarily(self):
        c = context();version = SimpleNamespace(candidates=lambda *args: [100, 200]);common = load('update-native-archive-wire')
        # Role/layout admission has separate tests above. Keep the resolver's
        # dependency mock local instead of loading address utilities through a
        # nested mock, whose state can depend on aggregate test ordering.
        expected = {int(value, 16) for value in c['functions'].values()}
        with patch.object(TOOL, 'roots', return_value=expected), \
                patch.object(TOOL, 'load', side_effect=lambda name: version if name == 'update-native-version-result' else common):
            with self.assertRaisesRegex(ValueError, 'ambiguous'): TOOL.resolve(None, None, None, None, c, {})

    def test_unique_wrapper_tail_constrains_an_otherwise_ambiguous_target(self):
        c = context();wrapper = int(c['functions']['wrapper'], 16);target = int(c['functions']['target'], 16)
        version = SimpleNamespace(candidates=lambda native, bindings, before, after, at: [100] if at == wrapper else [200, 300])
        common = load('update-native-archive-wire');bindings = SimpleNamespace(rows=lambda native, image, at: at)
        def pair(native, a, b, mapping):
            if a == wrapper: common.add_link(mapping, target, 200)
        with patch.object(TOOL, 'roots', return_value={wrapper, target}), \
                patch.object(TOOL, 'load', side_effect=lambda name: version if name == 'update-native-version-result' else common), \
                patch.object(TOOL, 'pair', side_effect=pair):
            mapping = {};TOOL.resolve(None, bindings, None, None, c, mapping)
        self.assertEqual((mapping[wrapper], mapping[target]), (100, 200))

    def test_pairing_rejects_shape_changes_indirect_dispatch_changes_and_mapping_conflicts(self):
        signature = SimpleNamespace(signature=lambda native, rows: rows[0].get('signature', 'same'))
        common = load('update-native-archive-wire')
        a = dict(address=10, call=True, branch=False, direct_target=None, operands='qword ptr [rax + 0x2e8]', rip_references=[])
        b = dict(a, address=20)
        with patch.object(TOOL, 'load', side_effect=lambda name: signature if name == 'update-native-contexts' else common):
            with self.assertRaisesRegex(ValueError, 'shape'): TOOL.pair(None, [a], [dict(b, signature='changed')], {})
            with self.assertRaisesRegex(ValueError, 'dispatch'): TOOL.pair(None, [a], [dict(b, operands='qword ptr [rax + 0x28]')], {})
            with self.assertRaisesRegex(ValueError, 'inconsistent'): TOOL.pair(None, [a], [b], {10: 30})
            mapping = {};TOOL.pair(None, [a], [b], mapping);self.assertEqual(mapping, {10: 20})


if __name__ == '__main__': unittest.main()
