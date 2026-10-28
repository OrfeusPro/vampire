"""Source/proof scope and isolated publication for portable Version helpers."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load

TOOL = load('update-native-version-helpers')


def context(family='version-prepare-platform'):
    value = json.loads((TOOL.HERE / 'knowledge/native-contexts' / (family + '-11320.json')).read_text('utf-8'))
    value.update(family=family, layout=TOOL.layout(family), transfer_proof=dict(path='proof', sha256='b' * 64))
    return value


def report(value, family):
    return dict(source_sha256=value['source_sha256'], scope=TOOL.scope(family), method='bounded_native',
                network_used=False, profile_activated=False, runtime_activated=False,
                proof=value['transfer_proof'], context_sha256='c' * 64, cases=[])


def proof(value, family, baseline):
    return dict(schema=1, adapter=TOOL.ADAPTER, family=family, scope=TOOL.scope(family), tools={},
                runtime_activated=False, baseline=dict(path=str(baseline), sha256='d' * 64),
                dependencies={}, relocation={}, target={k: v for k, v in value.items()
                    if k not in ('exports', 'transfer_proof', 'release_id')})


class VersionHelperScopeTests(unittest.TestCase):
    def test_selector_is_registered_and_each_family_has_its_own_index(self):
        adapters = [TOOL.select(family) for family in TOOL.FAMILIES]
        self.assertEqual(len(adapters), 9)
        self.assertEqual(len({adapter.index for adapter in adapters}), 9)
        self.assertEqual([adapter.family for adapter in adapters], list(TOOL.FAMILIES))
        for unknown in ('version-prepare', '../custom', '', None, []):
            with self.subTest(unknown=unknown), self.assertRaises(ValueError): TOOL.select(unknown)

    def test_all_reviewed_root_counts_and_cumulative_nineteen_scope(self):
        self.assertEqual(tuple(TOOL.ROOT_COUNTS[f] for f in TOOL.FAMILIES), (2, 6, 1, 5, 3, 4, 11, 16, 19))
        for family in TOOL.FAMILIES:
            with self.subTest(family=family):
                self.assertEqual(len(TOOL.roots(family, context(family))), TOOL.ROOT_COUNTS[family])
        c = context()
        self.assertEqual(c['function_budget'], 19)
        self.assertEqual(TOOL.layout('version-prepare-platform'), dict(abi='win64',
            family='version-prepare-platform', executed_roots=19, real_identity=False, network=False))

    def test_integration_scope_cannot_add_or_remove_native_helper_blocks(self):
        for family in TOOL.FAMILIES[5:]:
            c = context(family)
            del c['native_nm']
            with self.subTest(family=family), self.assertRaisesRegex(ValueError, 'scope'):
                TOOL.roots(family, c)
        c = context('version-prepare-nm');c['native_platform'] = {}
        with self.assertRaisesRegex(ValueError, 'scope'): TOOL.roots('version-prepare-nm', c)

    def test_standalone_rejects_every_optional_native_block_and_budget(self):
        for family in TOOL.STANDALONE:
            for key in (*TOOL.NATIVE_KEYS, 'function_budget'):
                c = context(family);c[key] = 16 if key == 'function_budget' else {}
                with self.subTest(family=family, key=key), self.assertRaisesRegex(ValueError, 'optional native scope'):
                    TOOL.roots(family, c)

    def test_cross_family_executable_aliases_are_rejected(self):
        mutations = (lambda c: c.update(constructor=c['prepare']),
            lambda c: c['native_nm'].update(wrapper=c['prepare']),
            lambda c: c['native_system']['windows'].update(function=c['native_nm']['getter']),
            lambda c: c['native_platform'].update(selector=c['constructor']))
        for mutate in mutations:
            c = context();mutate(c)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): TOOL.roots('version-prepare-platform', c)

    def test_active_outer_and_nested_fixtures_cannot_shadow_another_family_root(self):
        mutations = (
            ('outer', lambda c: c['fixtures'].update(free=c['native_system']['cpu']['functions']['formatter'])),
            ('cpu', lambda c: c['native_system']['cpu']['fixtures'].update(free=c['native_nm']['getter'])),
            ('windows', lambda c: c['native_system']['windows']['fixtures'].update(wide_string=c['native_combiners']['functions']['first'])),
            ('combiners', lambda c: c['native_combiners']['fixtures'].update(resize=c['native_platform']['selector'])),
            ('platform', lambda c: c['native_platform']['fixtures'].update(free=c['native_nm']['getter'])),
        )
        # Real delegated caller roles intentionally point at the corresponding
        # native helper roots; the unchanged reviewed context must still pass.
        self.assertEqual(len(TOOL.roots('version-prepare-platform', context())), 19)
        for label, mutate in mutations:
            c = context();mutate(c)
            with self.subTest(group=label), self.assertRaisesRegex(ValueError, 'fixture shadows'):
                TOOL.roots('version-prepare-platform', c)

    def test_only_exact_function_budget_admitted_for_cumulative_scope(self):
        for family in TOOL.FAMILIES[5:]:
            for budget in (0, 17, 20, '19', True, 19.0 if family.endswith('-platform') else 16.0):
                c = context(family);c['function_budget'] = budget
                with self.subTest(family=family, budget=budget), self.assertRaises(ValueError): TOOL.roots(family, c)

    def test_provenance_guard_delegates_matrix_validation_to_selected_family(self):
        family = 'version-nm-device';c = context(family);r = report(c, family)
        validate = Mock()
        with patch.object(TOOL, 'load', return_value=SimpleNamespace(validate_report=validate)):
            TOOL.report_valid(family, r, c, 'c' * 64)
        validate.assert_called_once_with(family, r)

    def test_wrong_source_context_proof_scope_or_activation_stops_before_case_admission(self):
        family = 'version-cpu';c = context(family);r = report(c, family)
        changes = [dict(source_sha256='e' * 64), dict(context_sha256='e' * 64), dict(proof={}),
                   dict(scope='full_entry'), dict(method='fixture')]
        changes += [{key: value} for key in ('network_used', 'profile_activated', 'runtime_activated') for value in (True, None, 0)]
        for change in changes:
            with self.subTest(change=change), patch.object(TOOL, 'load', side_effect=AssertionError('No matrix admission')):
                with self.assertRaisesRegex(ValueError, 'provenance'): TOOL.report_valid(family, {**r, **change}, c, 'c' * 64)


class VersionHelperJournalTests(unittest.TestCase):
    def test_same_sha_reuses_original_proof_without_another_transfer(self):
        family = 'version-nm-device';api = TOOL.select(family);c = context(family)
        args = SimpleNamespace(root=Path('root'), knowledge=Path('knowledge'))
        with patch.object(TOOL, 'load', return_value=SimpleNamespace(read=lambda _: {})), \
                patch.object(api, 'published_contexts', return_value=[(Path('ctx'), c, 3)]), \
                patch.object(api, 'validate') as validate, patch.object(api, 'transfer', side_effect=AssertionError('No self-transfer')), \
                patch.object(api, 'planned', return_value='reused') as planned, patch.object(TOOL, 'checked', return_value={'original': 'proof'}):
            self.assertEqual(api.discover(None, args, c['source_sha256']), 'reused')
        validate.assert_called_once_with(None, args, c)
        planned.assert_called_once_with(c, {'original': 'proof'})

    def test_memo_is_limited_to_the_frozen_source_store(self):
        args = SimpleNamespace(source_store=object())
        cache = TOOL.memo(args);cache['done'] = 1
        self.assertIs(TOOL.memo(args), cache)
        args.source_store = object()
        self.assertEqual(TOOL.memo(args), {})

    def test_latest_reviewed_role_wins_instead_of_older_fallback(self):
        api = TOOL.select('version-cpu');old = dict(source_sha256='a' * 64);latest = dict(source_sha256='b' * 64)
        with patch.object(api, 'contexts', return_value=[(Path('old'), old, 1), (Path('latest'), latest, 3)]):
            self.assertEqual(api.baseline_context(None), (Path('latest'), latest))
        with patch.object(api, 'contexts', return_value=[]), self.assertRaisesRegex(ValueError, 'No reviewed'):
            api.baseline_context(None)

    def test_dependency_for_exact_sha_cannot_be_missing_or_ambiguous(self):
        api = TOOL.select('version-cpu');c = dict(source_sha256='a' * 64)
        for found in ([], [(Path('a'), c, 1), (Path('b'), c, 2)]):
            with patch.object(api, 'contexts', return_value=found), self.assertRaisesRegex(ValueError, 'Missing/ambiguous'):
                api.at(None, 'a' * 64)

    def test_proof_cycle_or_changed_tools_layout_stops_before_images(self):
        family = 'version-cpu';api = TOOL.select(family);c = context(family)
        args = SimpleNamespace(root=Path('root'))
        with patch.object(TOOL, 'checked', return_value={}), patch.object(api, 'tools', return_value={}):
            with self.assertRaisesRegex(ValueError, 'cycle'): api.validate(None, args, c, {'b' * 64})
            with self.assertRaisesRegex(ValueError, 'tools/fields/layout'): api.validate(None, args, c)
        p = proof(c, family, 'baseline');c['layout'] = dict(c['layout'], real_identity=True)
        with patch.object(TOOL, 'checked', return_value=p), patch.object(api, 'tools', return_value={}):
            with self.assertRaisesRegex(ValueError, 'tools/fields/layout'): api.validate(None, args, c)

    def test_dependency_pointer_mismatch_stops_before_source_image_or_native(self):
        family = 'version-cpu';api = TOOL.select(family);c = context(family)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);baseline = root / 'knowledge/generated-native-contexts/baseline.json'
            baseline.parent.mkdir(parents=True);baseline.write_text(json.dumps(dict(source_sha256='a' * 64)))
            p = proof(c, family, baseline);p['dependencies'] = dict(base=dict(path='old', sha256='e' * 64))
            args = SimpleNamespace(root=root, source_store=Mock())
            with patch.object(TOOL, 'checked', return_value=p), patch.object(api, 'tools', return_value={}), \
                    patch.object(TOOL, 'digest', return_value='d' * 64), \
                    patch.object(api, 'dependencies', return_value=dict(base=(Path('new'), {}))), \
                    patch.object(api, 'transfer', side_effect=AssertionError('No transfer')):
                with self.assertRaisesRegex(ValueError, 'dependency index'): api.validate(None, args, c)
            args.source_store.image.assert_not_called()


class VersionHelperPublicationTests(unittest.TestCase):
    def fixture(self):
        family = 'version-cpu';c = context(family);r = report(c, family)
        row = dict(context=dict(path='ctx', sha256='c' * 64), check=dict(path='report', sha256='d' * 64), order=1)
        registry = dict(releases=[dict(source_sha256=c['source_sha256'], order=3)])
        return family, c, r, row, registry

    def test_published_context_is_bound_to_family_layout_and_current_rank(self):
        family, c, r, row, registry = self.fixture();api = TOOL.select(family)
        with patch.object(TOOL, 'checked', side_effect=lambda root, item, category: c if category == 'generated-native-contexts' else r), \
                patch.object(TOOL, 'report_valid') as report_valid:
            result = api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))
            self.assertEqual(result, [(Path('ctx'), c, 3)])
            report_valid.assert_called_once_with(family, r, c, 'c' * 64)

    def test_malformed_duplicate_family_and_layout_cannot_be_published(self):
        family, c, r, row, registry = self.fixture();api = TOOL.select(family)
        with patch.object(TOOL, 'checked', side_effect=lambda root, item, category: c if category == 'generated-native-contexts' else r), \
                patch.object(TOOL, 'report_valid'):
            for value in (dict(schema=2, contexts=[row]), dict(schema=1, contexts={}),
                    dict(schema=1, contexts=[row, row]), dict(schema=1, contexts=[dict(row, order=True)])):
                with self.subTest(value=value), self.assertRaises(ValueError): api.published_contexts('root', registry, value=value)
            for key, value in (('source_sha256', 'x'), ('family', 'version-windows'), ('layout', {})):
                bad = dict(c, **{key: value})
                with patch.object(TOOL, 'checked', return_value=bad), self.assertRaises(ValueError):
                    api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))

    def test_failed_outcome_cannot_reach_proof_or_index(self):
        api = TOOL.select('version-cpu')
        with patch.object(TOOL, 'checked', side_effect=AssertionError('No publication reads')):
            with self.assertRaisesRegex(ValueError, 'Only a passed'): api.publish(None, None, 'a' * 64, {}, dict(state='failed'))

    def test_bad_native_report_does_not_overwrite_existing_index(self):
        family, c, r, _, _ = self.fixture();api = TOOL.select(family);r['runtime_activated'] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);p = root / 'knowledge' / api.index / 'index.json'
            p.parent.mkdir(parents=True);p.write_text('existing-index')
            args = SimpleNamespace(root=root, knowledge=Path('definitions'))
            declaration = dict(context=dict(path='ctx', sha256='c' * 64))
            outcome = dict(state='passed', report='report', sha256='d' * 64)
            with patch.object(api, 'validate'), \
                    patch.object(TOOL, 'checked', side_effect=lambda root, item, category: c if category == 'generated-native-contexts' else r):
                with self.assertRaisesRegex(ValueError, 'provenance'): api.publish(None, args, c['source_sha256'], declaration, outcome)
            self.assertEqual(p.read_text(), 'existing-index')

    def test_check_declaration_rejects_other_family_before_semantic_execution(self):
        family = 'version-cpu';api = TOOL.select(family);c = context(family)
        declaration = dict(adapter=TOOL.ADAPTER, family='version-windows', scope=TOOL.scope(family), dependencies={},
                           context=dict(path='ctx', sha256='c' * 64))
        with patch.object(TOOL, 'checked', return_value=c), patch.object(api, 'tools', return_value={}), \
                patch.object(api, 'validate', side_effect=AssertionError('No native validate')):
            with self.assertRaisesRegex(ValueError, 'declaration'): api.execute(None, SimpleNamespace(root='root'), c['source_sha256'], declaration)

    def test_export_hash_conflict_is_rejected_before_file_or_image_lookup(self):
        for nested in ('nm', 'cpu', 'windows', 'combiners', 'platform'):
            c = context();run = next(iter(c['exports']))
            part = c['native_system'][nested] if nested in ('cpu', 'windows') else c['native_' + nested]
            part['exports'][run] = 'f' * 64
            image = Mock();bindings = Mock()
            with self.subTest(group=nested), \
                    patch.object(TOOL, 'digest', side_effect=AssertionError('No file digest before conflict')), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('No export read before conflict')):
                with self.assertRaisesRegex(ValueError, 'Conflicting'):
                    TOOL.export_coverage(Path('root'), c, 'version-prepare-platform', None, bindings, image)
            bindings.rows.assert_not_called()
            self.assertFalse(image.mock_calls)


if __name__ == '__main__':
    unittest.main()
