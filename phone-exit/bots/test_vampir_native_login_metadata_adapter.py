"""Metadata integration scope, immutable proof and publication admission."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load

TOOL = load('update-native-login-metadata')
CORE = TOOL.core


def context(family='login-prepare-metadata'):
    value = json.loads((TOOL.HERE / 'knowledge/native-contexts' / (family + '-11320.json')).read_text('utf-8'))
    api = TOOL.select(family)
    value.update(family=family, layout=copy.deepcopy(api.layout), transfer_proof=dict(path='proof', sha256='b' * 64))
    return value


def report(c, family):
    api = TOOL.select(family)
    value = dict(source_sha256=c['source_sha256'], scope=api.scope, method='bounded_native',
        network_used=False, profile_activated=False, runtime_activated=False,
        proof=c['transfer_proof'], context_sha256='c' * 64, cases=[])
    if family == 'login-prepare-metadata': value['metadata_fields'] = copy.deepcopy(c['native_sdk']['metadata']['fields'])
    return value


def proof(c, api, baseline):
    return dict(schema=1, adapter=api.adapter, family=api.family, scope=api.scope,
        tools={}, runtime_activated=False, target=CORE.plain(c), relocation={}, dependencies={},
        baseline=dict(path=str(baseline), sha256='d' * 64))


class MetadataScopeTests(unittest.TestCase):
    def test_two_reviewed_families_have_separate_indexes_and_exact_layouts(self):
        self.assertEqual(TOOL.FAMILIES, ('login-metadata', 'login-prepare-metadata'))
        APIs = [TOOL.select(f) for f in TOOL.FAMILIES]
        self.assertEqual(len({a.index for a in APIs}), 2)
        self.assertEqual([(a.layout['executed_roots'], a.layout['returning_leaves']) for a in APIs], [(6, 0), (11, 6)])
        for invalid in ('login-sdk', 'login-metadata-extra', '../custom', None, []):
            with self.assertRaises(ValueError): TOOL.select(invalid)

    def test_historical_contexts_admit_six_and_eleven_roots_with_six_leaves(self):
        for family, count in zip(TOOL.FAMILIES, (6, 11)):
            self.assertEqual(len(TOOL.select(family).roots(context(family))), count)
        c = context();leaves = {int(at, 16) for at in c['native_sdk']['leaves']}
        self.assertEqual(len(leaves), 6)
        self.assertFalse(leaves & TOOL.select('login-prepare-metadata').roots(c))

    def test_optional_blocks_and_arbitrary_function_budgets_cannot_expand_scope(self):
        for key in ('native_sdk', 'native_metadata', 'function_budget'):
            c = context('login-metadata');c[key] = {}
            with self.assertRaises(ValueError): TOOL.select('login-metadata').roots(c)
        for budget in (16, 19, 11, 11.0, None):
            c = context();c['function_budget'] = budget
            with self.assertRaisesRegex(ValueError, 'scope/export budget'): TOOL.select('login-prepare-metadata').roots(c)
        c = context();c['verify_whole_exports'] = False
        with self.assertRaises(ValueError): TOOL.select('login-prepare-metadata').roots(c)

    def test_metadata_roots_cannot_alias_sdk_roots_or_returning_leaves(self):
        for target in ('prepare', 'leaf'):
            c = context();at = c['prepare'] if target == 'prepare' else next(iter(c['native_sdk']['leaves']))
            c['native_metadata']['functions']['move'] = at
            with self.assertRaisesRegex(ValueError, 'roots or leaves alias'): TOOL.select('login-prepare-metadata').roots(c)

    def test_outer_inner_and_metadata_hooks_cannot_shadow_foreign_executed_code(self):
        changes = (
            lambda c: c['fixtures'].update(copy_string=c['native_metadata']['functions']['move']),
            lambda c: c['native_sdk']['fixtures'].update(main_store=c['native_metadata']['functions']['copy']),
            lambda c: c['native_metadata']['fixtures'].update(free=c['prepare']),
            lambda c: c['native_metadata']['fixtures'].update(free=next(iter(c['native_sdk']['leaves']))),
        )
        for change in changes:
            c = context();change(c)
            with self.assertRaises(ValueError): TOOL.select('login-prepare-metadata').roots(c)

    def test_nested_source_and_memcpy_are_exact(self):
        for key, value in (('source_sha256', 'f' * 64), ('source', 'another.exe'), ('helpers', dict(memcpy='0x1234'))):
            c = context();c['native_metadata'][key] = value
            with self.assertRaisesRegex(ValueError, 'nested source/memcpy'): TOOL.select('login-prepare-metadata').roots(c)

    def test_manager_collector_selector_and_order_links_are_required(self):
        changes = (
            lambda c: c['fixtures'].update(sdk_aux_text=c['native_metadata']['functions']['writer']),
            lambda c: c['native_sdk']['metadata'].update(collector=c['native_metadata']['functions']['writer']),
            lambda c: c['native_sdk']['metadata'].update(consumer=c['native_metadata']['functions']['writer']),
            lambda c: c['native_sdk']['globals'].update(manager='0x1234'),
            lambda c: c['native_sdk']['metadata']['fields'].reverse(),
        )
        for change in changes:
            c = context();change(c)
            with self.assertRaises(ValueError): TOOL.select('login-prepare-metadata').roots(c)

    def test_only_reviewed_shared_hook_partition_is_admitted(self):
        for change in (
                lambda c: c['native_metadata']['fixtures'].update(format=c['fixtures']['post_notify']),
                lambda c: c['native_metadata']['fixtures'].update(optional_store=c['native_sdk']['fixtures']['value_store']),
                lambda c: c['native_metadata']['fixtures'].update(copy_string=c['fixtures']['wide_string'])):
            c = context();change(c)
            with self.assertRaises(ValueError): TOOL.select('login-prepare-metadata').roots(c)


class MetadataReportTests(unittest.TestCase):
    def test_common_report_provenance_delegates_to_exact_selected_contract(self):
        family = 'login-metadata';api = TOOL.select(family);c = context(family);r = report(c, family)
        validate = Mock()
        with patch.object(api, 'validate_report', validate): api.report_valid(r, c, 'c' * 64)
        validate.assert_called_once_with(r, c)

    def test_wrong_provenance_and_activation_never_reach_case_admission(self):
        family = 'login-metadata';api = TOOL.select(family);c = context(family);r = report(c, family)
        changes = [dict(source_sha256='f' * 64), dict(scope='all_entry'), dict(method='fixture'),
            dict(proof={}), dict(context_sha256='f' * 64)]
        changes += [{key: value} for key in ('network_used', 'profile_activated', 'runtime_activated') for value in (True, 0, None)]
        for change in changes:
            with patch.object(api, 'validate_report', side_effect=AssertionError('No scenario admission')):
                with self.assertRaisesRegex(ValueError, 'provenance'): api.report_valid({**r, **change}, c, 'c' * 64)

    def test_metadata_literal_and_call_site_pointers_must_match_context(self):
        family = 'login-prepare-metadata';api = TOOL.select(family);c = context();r = report(c, family)
        with patch.object(TOOL, 'load', return_value=SimpleNamespace(validate_report=Mock())):
            api.validate_report(r, c)
            for key in ('literal', 'call_site'):
                bad = copy.deepcopy(r);bad['metadata_fields'][0][key] = '0x1234'
                with self.assertRaisesRegex(ValueError, 'literal/call-site'): api.validate_report(bad, c)


class MetadataImmutableLifecycleTests(unittest.TestCase):
    def test_same_target_reuses_original_proof_without_transfer(self):
        api = TOOL.select('login-metadata');c = context('login-metadata')
        args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        with patch.object(CORE, 'load', return_value=SimpleNamespace(read=lambda _: {})), \
                patch.object(api, 'published_contexts', return_value=[(Path('ctx'), c, 3)]), \
                patch.object(api, 'validate') as validate, patch.object(CORE, 'checked', return_value={'original': 'proof'}), \
                patch.object(api, 'planned', return_value='reused') as planned, \
                patch.object(api, 'transfer', side_effect=AssertionError('No self transfer')):
            self.assertEqual(api.discover(None, args, c['source_sha256']), 'reused')
        validate.assert_called_once_with(None, args, c);planned.assert_called_once_with(c, {'original': 'proof'})

    def test_published_index_rejects_duplicate_source_wrong_family_layout_and_rank(self):
        family = 'login-metadata';api = TOOL.select(family);c = context(family);r = report(c, family)
        row = dict(context=dict(path='ctx', sha256='c' * 64), check=dict(path='report', sha256='d' * 64), order=1)
        registry = dict(releases=[dict(source_sha256=c['source_sha256'], order=3)])
        with patch.object(CORE, 'checked', side_effect=lambda root, item, category: c if category == 'generated-native-contexts' else r), \
                patch.object(api, 'report_valid'):
            self.assertEqual(api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))[0][2], 3)
            for value in (dict(schema=2, contexts=[row]), dict(schema=1, contexts={}),
                    dict(schema=1, contexts=[row, row]), dict(schema=1, contexts=[dict(row, order=True)])):
                with self.assertRaises(ValueError): api.published_contexts('root', registry, value=value)
            for key, value in (('family', 'login-prepare-metadata'), ('layout', {}), ('source_sha256', 'x')):
                with patch.object(CORE, 'checked', return_value=dict(c, **{key: value})), self.assertRaises(ValueError):
                    api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))

    def test_failed_outcome_and_bad_report_preserve_existing_index(self):
        api = TOOL.select('login-metadata');c = context('login-metadata');r = report(c, api.family);r['network_used'] = True
        with patch.object(CORE, 'checked', side_effect=AssertionError('No publication read')):
            with self.assertRaisesRegex(ValueError, 'Only a passed'): api.publish(None, None, 'a' * 64, {}, dict(state='failed'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);path = root / 'knowledge' / api.index / 'index.json'
            path.parent.mkdir(parents=True);path.write_text('existing')
            args = SimpleNamespace(root=root, knowledge=root)
            with patch.object(api, 'validate'), patch.object(CORE, 'checked',
                    side_effect=lambda root, item, category: c if category == 'generated-native-contexts' else r):
                with self.assertRaisesRegex(ValueError, 'provenance'):
                    api.publish(None, args, c['source_sha256'], dict(context=dict(path='ctx', sha256='c' * 64)),
                        dict(state='passed', report='report', sha256='d' * 64))
            self.assertEqual(path.read_text(), 'existing')

    def test_cross_family_execute_cannot_reach_native(self):
        api = TOOL.select('login-metadata');c = context('login-metadata')
        declaration = dict(context=dict(path='ctx', sha256='c' * 64), adapter=api.adapter,
            family='login-prepare-metadata', scope=api.scope, dependencies={})
        with patch.object(CORE, 'checked', return_value=c), patch.object(api, 'tools', return_value={}), \
                patch.object(api, 'validate', side_effect=AssertionError('No native')):
            with self.assertRaisesRegex(ValueError, 'declaration'): api.execute(None, SimpleNamespace(root='root'), c['source_sha256'], declaration)

    def test_proof_cycle_layout_and_tools_change_stop_before_source_lookup(self):
        api = TOOL.select('login-metadata');c = context('login-metadata');args = SimpleNamespace(root=Path('root'))
        with patch.object(CORE, 'checked', return_value={}), patch.object(api, 'tools', return_value={}):
            with self.assertRaisesRegex(ValueError, 'cycle'): api.validate(None, args, c, {'b' * 64})
            with self.assertRaisesRegex(ValueError, 'tools/fields/layout'): api.validate(None, args, c)
        p = proof(c, api, 'baseline');bad = dict(c, layout=dict(api.layout, real_sdk_backend=True))
        with patch.object(CORE, 'checked', return_value=p), patch.object(api, 'tools', return_value={}):
            with self.assertRaisesRegex(ValueError, 'tools/fields/layout'): api.validate(None, args, bad)

    def test_dependency_check_pointer_change_invalidates_before_transfer(self):
        api = TOOL.select('login-metadata');c = context('login-metadata')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);path = root / 'knowledge/generated-native-contexts/base.json'
            path.parent.mkdir(parents=True);path.write_text(json.dumps(dict(source_sha256='a' * 64)))
            p = proof(c, api, path);p['dependencies'] = dict(sdk_check=dict(path='report', sha256='e' * 64))
            args = SimpleNamespace(root=root, source_store=Mock())
            with patch.object(CORE, 'checked', return_value=p), patch.object(api, 'tools', return_value={}), \
                    patch.object(CORE, 'digest', return_value='d' * 64), \
                    patch.object(api, 'dependencies', return_value=dict(sdk_check=dict(path='report', sha256='f' * 64))), \
                    patch.object(api, 'transfer', side_effect=AssertionError('No transfer')):
                with self.assertRaisesRegex(ValueError, 'dependency proof or report'): api.validate(None, args, c)
            args.source_store.image.assert_not_called()

    def test_dependencies_pin_sdk_context_report_and_metadata_context_report(self):
        sha = 'a' * 64;args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        sdk = dict(path='sdk', sha256='b' * 64);sdk_check = dict(path='sdk-report', sha256='c' * 64)
        metadata = dict(path='metadata', sha256='d' * 64);metadata_check = dict(path='metadata-report', sha256='e' * 64)
        api = TOOL.select('login-prepare-metadata')
        dep = Mock()
        dep.at.return_value = (Path('metadata'), dict(transfer_proof=dict(path='proof', sha256='f' * 64)))
        publication = dict(contexts=[dict(context=metadata, check=metadata_check)])
        with patch.object(TOOL, 'sdk_at', return_value=(Path('sdk'), {})), \
                patch.object(TOOL, 'sdk_receipt', return_value=dict(check=sdk_check)), \
                patch.object(CORE, 'pointer', side_effect=lambda p: sdk if str(p) == 'sdk' else metadata), \
                patch.object(TOOL, 'Adapter', return_value=dep), \
                patch.object(TOOL, 'load', return_value=SimpleNamespace(read=lambda _: {})), \
                patch.object(Path, 'read_text', return_value=json.dumps(publication)):
            dep.index = 'generated/login-metadata'
            result = api.dependencies(None, args, sha)
        self.assertEqual(result, dict(sdk=sdk, sdk_check=sdk_check, metadata=metadata, metadata_check=metadata_check))
        dep.published_contexts.assert_called_once_with(args.root, {})

    def test_conflicting_nested_export_hash_is_rejected_before_reading_source(self):
        api = TOOL.select('login-prepare-metadata');c = context();run = next(iter(c['exports']))
        c['native_metadata']['exports'][run] = 'f' * 64
        with patch.object(CORE, 'digest', side_effect=AssertionError('No file digest')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('No export read')):
            with self.assertRaisesRegex(ValueError, 'Conflicting'): api.export_coverage('root', c, None, None, None)

    def test_lineage_pins_exact_dependency_file_and_rejects_changed_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);folder = root / 'knowledge/generated-native-contexts';folder.mkdir(parents=True)
            dep = folder / 'dep.json';dep.write_text('{}')
            path = folder / 'context.json';path.write_text(json.dumps(dict(dependency=dict(path=str(dep), sha256=hashlib.sha256(dep.read_bytes()).hexdigest()))))
            args = SimpleNamespace(root=root)
            found = CORE.lineage_inputs(args, path)
            self.assertEqual(set(found), {str(path.resolve()), str(dep.resolve())})
            dep.write_text('{"changed":true}')
            with self.assertRaisesRegex(ValueError, 'lineage digest'): CORE.lineage_inputs(args, path)

    def test_plan_cache_inputs_pin_target_dependency_proof_and_export_not_whole_index(self):
        api = TOOL.select('login-metadata');args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        baseline = dict(source_sha256='a' * 64)
        dependencies = dict(sdk=dict(path='target-sdk', sha256='b' * 64), sdk_check=dict(path='sdk-check', sha256='c' * 64))
        lineage = {'nested-sdk-proof': 'd' * 64, 'target-export/details.json': 'e' * 64}
        def materials(args, path):
            return dict(lineage) if path == 'target-sdk' else {'sdk-check': 'c' * 64}
        with patch.object(api, 'baseline_context', return_value=(Path('baseline'), baseline)), \
                patch.object(api, 'dependencies', return_value=dependencies), patch.object(api, 'tools', return_value={}), \
                patch.object(api, 'input_materials', side_effect=lambda *args: {'baseline': 'a' * 64}), \
                patch.object(CORE, 'pointer', return_value=dict(path='baseline', sha256='a' * 64)), \
                patch.object(CORE, 'digest', return_value='f' * 64), patch.object(CORE, 'lineage_inputs', side_effect=materials):
            first = api.plan_inputs(None, args, 'f' * 64)
            lineage['nested-sdk-proof'] = '1' * 64
            proof_changed = api.plan_inputs(None, args, 'f' * 64)
            lineage['target-export/details.json'] = '2' * 64
            export_changed = api.plan_inputs(None, args, 'f' * 64)
        self.assertNotEqual(first, proof_changed);self.assertNotEqual(proof_changed, export_changed)
        self.assertEqual(set(first['baseline_materials']), {'baseline', 'nested-sdk-proof', 'target-export/details.json', 'sdk-check'})
        self.assertFalse(any('index.json' in path for path in first['baseline_materials']))

    def test_explicit_ghidra_lineage_checks_hash_without_parsing_large_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);path = root / 'knowledge/generated-native-contexts/ctx.json'
            artifact = root / 'ghidra/request-exports' / ('a' * 64) / 'run-fixture/details.json'
            path.parent.mkdir(parents=True);artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b'large export bytes, intentionally not parsed as JSON')
            expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
            path.write_text(json.dumps(dict(explicit_artifact=dict(path=str(artifact), sha256=expected))))
            args = SimpleNamespace(root=root);original = Path.read_text
            def read_text(file, *a, **kw):
                if file.resolve() == artifact.resolve(): raise AssertionError('Do not parse large export')
                return original(file, *a, **kw)
            with patch.object(Path, 'read_text', read_text):
                result = CORE.lineage_inputs(args, path)
                self.assertEqual(result[str(artifact.resolve())], expected)
                artifact.write_bytes(b'corrupted')
                with self.assertRaisesRegex(ValueError, 'lineage digest'): CORE.lineage_inputs(args, path)

    def test_sdk_seed_rechecks_nested_lineage_and_does_not_ignore_failed_old_proof(self):
        old = dict(transfer_proof=dict(path='old-proof', sha256='a' * 64))
        target = dict(transfer_proof=dict(path='target-proof', sha256='b' * 64))
        args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'), source_store=Mock())
        api = Mock();api.tools.return_value = {};api.plain.side_effect = lambda x: x
        api.transfer.return_value = (target, dict(mapping={'0x1': '0x2'}))
        lineage = {'nested-proof': 'c' * 64, 'target-export': 'd' * 64}
        def inputs(args, path): return {'old': 'a' * 64} if str(path) == 'old' else dict(lineage)
        def checked(root, pointer, category):
            return {'base_login': dict(path='base', sha256='1' * 64)} if category == 'native-login-sdk-proofs' else \
                {'transfer_proof': dict(path='base-proof', sha256='2' * 64)} if category == 'generated-native-contexts' and pointer['path'] == 'base' else \
                {'archive': dict(path='archive', sha256='3' * 64)} if category == 'native-login-prepare-proofs' else {}
        with patch.object(TOOL, 'load', side_effect=lambda name: api if name == 'update-native-login-sdk' else Mock()), \
                patch.object(TOOL, 'sdk_at', side_effect=lambda args, sha: (Path('old'), old) if sha == 'old-sha' else (Path('target'), target)), \
                patch.object(TOOL, 'sdk_receipt', return_value=dict(check=dict(path='check', sha256='e' * 64))), \
                patch.object(CORE, 'lineage_inputs', side_effect=inputs), patch.object(CORE, 'checked', side_effect=checked), \
                patch.object(CORE, 'pointer', side_effect=lambda path: dict(path=str(path), sha256='f' * 64)):
            TOOL.seed(None, args, 'old-sha', 'target-sha')
            TOOL.seed(None, args, 'old-sha', 'target-sha')
            self.assertEqual(api.transfer.call_count, 1)
            lineage['nested-proof'] = '4' * 64
            TOOL.seed(None, args, 'old-sha', 'target-sha')
            self.assertEqual(api.transfer.call_count, 2)
            lineage['target-export'] = '5' * 64
            TOOL.seed(None, args, 'old-sha', 'target-sha')
            self.assertEqual(api.transfer.call_count, 3)
            lineage['nested-proof'] = '6' * 64
            api.validate.side_effect = ValueError('Previous SDK proof failed')
            with self.assertRaisesRegex(ValueError, 'Previous SDK proof failed'): TOOL.seed(None, args, 'old-sha', 'target-sha')
            self.assertEqual(api.transfer.call_count, 3)


if __name__ == '__main__':
    unittest.main()
