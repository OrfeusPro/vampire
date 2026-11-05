"""Grouped tooling checks preserve coverage, exact inputs and real unittest results."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


class ToolingGroupsV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/tooling-groups-v1.py'
        spec = importlib.util.spec_from_file_location('tooling_groups_fixture_v1', path)
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.workspace = self.folder / 'workspace'
        self.bots = self.workspace / 'phone-exit/bots'
        self.bots.mkdir(parents=True)
        self.cache = self.folder / 'cache'
        self.expected = ('test_vampir_alpha_fixture', 'test_vampir_beta_fixture')
        self.write('phone-exit/bots/test_vampir_update_automation.py',
                   'MODULES = ' + repr(self.expected) + '\n')
        self.write('phone-exit/bots/fixture_common.py', 'VALUE = "common-v1"\n')
        self.write('phone-exit/bots/family_alpha.py', 'VALUE = "alpha-v1"\n')
        self.write('phone-exit/bots/family_beta.py', 'VALUE = "beta-v1"\n')
        self.write('phone-exit/bots/fixture_imported.py',
                   'import unittest\nclass ImportedCase(unittest.TestCase):\n'
                   '    def test_imported(self):\n        self.assertTrue(True)\n')
        self.write('phone-exit/bots/test_vampir_alpha_fixture.py',
                   'import unittest\nimport fixture_common\nimport family_alpha\n'
                   'from fixture_imported import ImportedCase\n'
                   'class AlphaCase(unittest.TestCase):\n'
                   '    def test_alpha(self):\n        self.assertEqual(family_alpha.VALUE, "alpha-v1")\n'
                   'def load_tests(loader, tests, pattern):\n'
                   '    return unittest.TestSuite([tests, loader.loadTestsFromTestCase(ImportedCase)])\n')
        self.write('phone-exit/bots/test_vampir_beta_fixture.py',
                   'import unittest\nimport fixture_common\nimport family_beta\n'
                   'class BetaCase(unittest.TestCase):\n'
                   '    @unittest.skip("fixture skip")\n'
                   '    def test_beta(self):\n        self.fail("must remain skipped")\n')
        self.manifest = dict(schema=1, common_dependencies=['phone-exit/bots/fixture_common.py'], groups=[
            dict(id='alpha', test_modules=[self.expected[0]], dependencies=[
                'phone-exit/bots/test_vampir_alpha_fixture.py', 'phone-exit/bots/family_alpha.py',
                'phone-exit/bots/fixture_imported.py'], timeout_seconds=30),
            dict(id='beta', test_modules=[self.expected[1]], dependencies=[
                'phone-exit/bots/test_vampir_beta_fixture.py', 'phone-exit/bots/family_beta.py'],
                timeout_seconds=30)])
        self.manifest_path = self.folder / 'groups.json'
        self.definition = dict(id='automatic-update-tooling',
                               test_pattern='test_vampir_update_automation.py',
                               source_scope='tooling', source_sha256=[], offline_reviewed=True,
                               artifact_dependencies=[], dependencies=self.dependencies())
        self.runtime = dict(python='fixture-runtime', executable_sha256='a' * 64)
        self.launches = []
        self.launch_hook = None
        self.fail_groups = set()

    def write(self, relative, text):
        path = self.workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8', newline='\n')
        return path

    def dependencies(self):
        return sorted(set(self.manifest['common_dependencies']) |
                      {path for group in self.manifest['groups'] for path in group['dependencies']})

    def save_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding='utf-8', newline='\n')

    def run_groups(self, *, workers=1, retry_failed=False, launch=None, runtime=None):
        self.save_manifest()
        with patch.object(self.runner, 'runtime_snapshot', side_effect=runtime or (lambda _: self.runtime)), \
                patch.object(self.runner, 'launch_group', side_effect=launch or self.fake_launch):
            return self.runner.run(self.workspace, self.cache, self.manifest_path, self.expected,
                                   self.definition, workers=workers, retry_failed=retry_failed)

    def fake_launch(self, workspace, definition, run_folder, timeout_seconds):
        group_id = definition['group']['id']
        self.launches.append(group_id)
        run_folder = Path(run_folder)
        run_folder.mkdir(parents=True, exist_ok=True)
        if self.launch_hook is not None:
            self.launch_hook(workspace, definition, run_folder)
        if group_id == 'alpha':
            ids = ['test_vampir_alpha_fixture.AlphaCase.test_alpha',
                   'fixture_imported.ImportedCase.test_imported',
                   'fixture_imported.ImportedCase.test_imported']
            skipped = []
        else:
            ids = ['test_vampir_beta_fixture.BetaCase.test_beta']
            skipped = [dict(id=ids[0], reason='fixture skip')]
        failed = group_id in self.fail_groups
        result = dict(schema=1, producer='tooling-group-worker-v1', group_id=group_id,
                      definition_sha256=self.runner.fingerprint(definition),
                      state='failed' if failed else 'passed', test_ids=ids, started_ids=ids,
                      tests_run=len(ids), skipped=[] if failed else skipped,
                      failures=[dict(id=ids[0], traceback='fixture failure')] if failed else [],
                      errors=[], expected_failures=[], unexpected_successes=[],
                      subtest_failures=[], subtest_errors=[], duration_seconds=0.01)
        result_path = run_folder / 'result.json'
        result_path.write_text(json.dumps(result), encoding='utf-8', newline='\n')
        log_path = run_folder / 'worker.log'
        log_path.write_text('fixture unittest output\n', encoding='utf-8', newline='\n')
        return dict(state=result['state'], result_path=result_path, log_path=log_path,
                    exit_code=1 if failed else 0)

    def test_cold_run_and_warm_repeat_preserve_counts_without_new_workers(self):
        first = self.run_groups()
        self.assertEqual(first['state'], 'passed')
        self.assertEqual(self.launches, ['alpha', 'beta'])
        self.assertEqual(first['metrics']['executed_groups'], 2)
        self.assertEqual(first['metrics']['executed_cases'], 4)
        self.launches.clear()
        second = self.run_groups()
        self.assertEqual(self.launches, [])
        self.assertEqual(second['cache_key'], first['cache_key'])
        self.assertEqual(second['report'], first['report'])
        self.assertEqual(second['metrics']['executed_cases'], 0)
        self.assertEqual(second['metrics']['cached_cases'], 4)
        self.assertEqual(second['metrics']['cached_groups'], 2)

    def test_changed_family_reruns_only_its_group_and_common_helper_reruns_all(self):
        self.run_groups()
        self.launches.clear()
        self.write('phone-exit/bots/family_alpha.py', 'VALUE = "alpha-v2"\n')
        changed = self.run_groups()
        self.assertEqual(self.launches, ['alpha'])
        self.assertEqual(changed['metrics']['cached_groups'], 1)
        self.launches.clear()
        self.write('phone-exit/bots/fixture_common.py', 'VALUE = "common-v2"\n')
        changed = self.run_groups()
        self.assertEqual(self.launches, ['alpha', 'beta'])
        self.assertEqual(changed['metrics']['cached_groups'], 0)

    def test_runtime_change_invalidates_all_group_keys(self):
        first = self.run_groups()
        self.launches.clear()
        self.runtime = dict(self.runtime, executable_sha256='b' * 64)
        second = self.run_groups()
        self.assertNotEqual(first['cache_key'], second['cache_key'])
        self.assertEqual(self.launches, ['alpha', 'beta'])

    @unittest.skipUnless(os.name == 'nt', 'Codex Windows PATH layout')
    def test_codex_path_rotation_reuses_receipts_and_real_worker_gets_filtered_path(self):
        runtime_tool = self.runner.load('tooling-runtime-v1')
        profile = self.folder.resolve() / 'profile'
        local = profile / 'AppData/Local'
        temporary = profile / '.codex/tmp/arg0-windows'
        bundled = local / 'OpenAI/Codex/bin'
        ordinary = [str(Path(os.environ['SystemRoot']) / 'System32'),
                    str(self.folder / 'ordinary/codex-arg0SameName')]
        alpha = self.bots / (self.expected[0] + '.py')
        with alpha.open('a', encoding='utf-8') as stream:
            stream.write('import os\nclass PathCase(unittest.TestCase):\n'
                         '    def test_effective_path(self):\n'
                         '        entries = os.environ["PATH"].split(os.pathsep)\n'
                         f'        self.assertEqual(entries[:2], {ordinary!r})\n'
                         f'        self.assertFalse(any(str({str(profile)!r}) in p for p in entries))\n')

        def snapshot(_workspace):
            return dict(self.runtime, environment_sha256=runtime_tool.environment_fingerprints(os.environ))

        first_path = [*ordinary[:1], str(temporary / 'codex-arg0First'), ordinary[1],
                      str(bundled / '0123456789abcdef')]
        rotated_path = [str(bundled / 'fedcba9876543210'), *ordinary,
                        str(temporary / 'codex-arg0Second')]
        outcomes = []
        for path in (first_path, rotated_path, [*rotated_path, str(self.folder / 'new tools')]):
            with patch.dict(os.environ, {'USERPROFILE': str(profile), 'LOCALAPPDATA': str(local),
                                         'PATH': os.pathsep.join(path)}):
                outcomes.append(self.run_groups(launch=self.runner.launch_group, runtime=snapshot))
        first, repeated, changed = outcomes
        self.assertTrue(all(row['state'] == 'passed' for row in outcomes))
        self.assertEqual(first['sha256'], repeated['sha256'])
        self.assertEqual(repeated['metrics']['executed_groups'], 0)
        self.assertEqual(repeated['metrics']['cached_groups'], 2)
        self.assertNotEqual(repeated['cache_key'], changed['cache_key'])
        self.assertEqual(changed['metrics']['executed_groups'], 2)

    def test_same_size_restored_mtime_change_between_runs_invalidates_family(self):
        self.run_groups()
        self.launches.clear()
        path = self.workspace / 'phone-exit/bots/family_alpha.py'
        stat = path.stat()
        path.write_bytes(path.read_bytes().replace(b'alpha-v1', b'alpha-v2'))
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        result = self.run_groups()
        self.assertEqual(self.launches, ['alpha'])
        self.assertEqual(result['metrics']['cached_groups'], 1)

    def test_renaming_one_group_changes_only_its_membership_key(self):
        self.run_groups()
        self.launches.clear()
        self.manifest['groups'][1]['id'] = 'renamed-beta'
        result = self.run_groups()
        self.assertEqual(self.launches, ['renamed-beta'])
        self.assertEqual(result['metrics']['cached_groups'], 1)

    def test_independent_expected_member_inventory_cannot_contain_duplicates(self):
        self.expected += (self.expected[0],)
        self.write('phone-exit/bots/test_vampir_update_automation.py',
                   'MODULES = ' + repr(self.expected) + '\n')
        with self.assertRaises(ValueError), patch.object(self.runner, 'launch_group') as launch:
            self.save_manifest()
            self.runner.run(self.workspace, self.cache, self.manifest_path, self.expected,
                            self.definition, workers=1)
        launch.assert_not_called()

    def test_unrelated_group_definition_change_preserves_other_group_cache(self):
        self.run_groups()
        self.launches.clear()
        self.manifest['groups'][1]['timeout_seconds'] += 1
        changed = self.run_groups()
        self.assertEqual(self.launches, ['beta'])
        self.assertEqual(changed['metrics']['cached_groups'], 1)

    def test_new_unrelated_group_does_not_invalidate_previously_checked_groups(self):
        self.run_groups()
        self.launches.clear()
        name = 'test_vampir_gamma_fixture'
        relative = 'phone-exit/bots/' + name + '.py'
        self.write(relative, 'import unittest\nclass GammaCase(unittest.TestCase):\n'
                   '    def test_gamma(self):\n        self.assertTrue(True)\n')
        self.expected += (name,)
        self.write('phone-exit/bots/test_vampir_update_automation.py',
                   'MODULES = ' + repr(self.expected) + '\n')
        self.manifest['groups'].append(dict(id='gamma', test_modules=[name],
                                            dependencies=[relative], timeout_seconds=30))
        self.definition['dependencies'] = self.dependencies()
        changed = self.run_groups()
        self.assertEqual(self.launches, ['gamma'])
        self.assertEqual(changed['metrics']['cached_groups'], 2)

    def test_worker_exit_identity_and_count_mismatches_are_rejected(self):
        for kind in ('wrong-definition', 'wrong-group', 'wrong-count', 'wrong-state', 'wrong-exit',
                     'undispatched-case', 'reordered-cases'):
            with self.subTest(kind=kind):
                self.cache = self.folder / ('cache-' + kind)

                def invalid_launch(workspace, definition, run_folder, timeout_seconds):
                    launched = self.fake_launch(workspace, definition, run_folder, timeout_seconds)
                    path = Path(launched['result_path'])
                    result = json.loads(path.read_text('utf-8'))
                    if kind == 'wrong-definition':
                        result['definition_sha256'] = '0' * 64
                    elif kind == 'wrong-group':
                        result['group_id'] = 'other'
                    elif kind == 'wrong-count':
                        result['tests_run'] += 100
                    elif kind == 'wrong-state':
                        result['failures'] = [dict(id=result['test_ids'][0], traceback='hidden failure')]
                    elif kind == 'wrong-exit':
                        launched['exit_code'] = 1
                    elif kind == 'undispatched-case':
                        result['test_ids'].append('test_vampir_alpha_fixture.AlphaCase.test_unrun')
                    else:
                        result['started_ids'] = list(reversed(result['started_ids']))
                    path.write_text(json.dumps(result), encoding='utf-8')
                    return launched

                with self.assertRaises(ValueError):
                    self.run_groups(launch=invalid_launch)

    def test_same_size_restored_mtime_input_mutation_cannot_publish_success(self):
        target = self.workspace / 'phone-exit/bots/family_alpha.py'
        before = target.stat()
        contents = target.read_bytes()

        def mutate_input(workspace, definition, run_folder):
            if definition['group']['id'] == 'alpha':
                target.write_bytes(contents.replace(b'alpha-v1', b'alpha-v2'))
                os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))

        self.launch_hook = mutate_input
        with self.assertRaises(ValueError):
            self.run_groups()
        self.assertEqual(target.stat().st_size, before.st_size)
        self.assertEqual(target.stat().st_mtime_ns, before.st_mtime_ns)
        self.launch_hook = None
        self.launches.clear()
        result = self.run_groups()
        self.assertEqual(result['state'], 'passed')
        self.assertIn('alpha', self.launches)

    def test_runtime_drift_during_execution_rejects_success(self):
        original = self.runtime
        calls = []

        def changing_runtime(workspace):
            calls.append(True)
            return original if len(calls) == 1 else dict(original, executable_sha256='b' * 64)

        with self.assertRaises(ValueError):
            self.run_groups(runtime=changing_runtime)

    def test_failed_group_is_cached_until_explicit_retry_and_ready_group_is_reused(self):
        self.fail_groups.add('beta')
        failed = self.run_groups()
        self.assertEqual(failed['state'], 'failed')
        self.launches.clear()
        repeated = self.run_groups()
        self.assertEqual(repeated['state'], 'failed')
        self.assertEqual(self.launches, [])
        self.fail_groups.clear()
        self.launches.clear()
        resumed = self.run_groups(retry_failed=True)
        self.assertEqual(resumed['state'], 'passed')
        self.assertEqual(self.launches, ['beta'])
        self.assertEqual(resumed['metrics']['cached_groups'], 1)

    def test_interrupted_run_keeps_completed_group_for_resume(self):
        def interrupt_second_group(workspace, definition, run_folder):
            if definition['group']['id'] == 'beta':
                raise RuntimeError('fixture worker launch interrupted')

        self.launch_hook = interrupt_second_group
        with self.assertRaises(RuntimeError):
            self.run_groups()
        self.launch_hook = None
        self.launches.clear()
        resumed = self.run_groups()
        self.assertEqual(resumed['state'], 'passed')
        self.assertEqual(self.launches, ['beta'])
        self.assertEqual(resumed['metrics']['cached_groups'], 1)

    def cached_alpha(self):
        outcome = self.run_groups()
        aggregate = json.loads(Path(outcome['report']).read_text('utf-8'))
        group = next(row for row in aggregate['groups'] if row['id'] == 'alpha')
        receipt_path = Path(group['report'])
        receipt = json.loads(receipt_path.read_text('utf-8'))
        pointer = self.cache / 'cache' / (group['cache_key'] + '.json')
        self.launches.clear()
        return group, receipt_path, receipt, pointer

    def assert_cache_rejected_without_workers(self):
        with self.assertRaises((ValueError, OSError)):
            self.run_groups()
        self.assertEqual(self.launches, [])

    def repack(self, category, filename, value):
        raw = self.runner.canonical(value)
        sha = hashlib.sha256(raw).hexdigest()
        path = self.cache / category / sha / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return dict(path=str(path), sha256=sha)

    def test_changed_cache_pointer_is_rejected_without_silent_retry(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        value = json.loads(pointer.read_text('utf-8'))
        value['sha256'] = '0' * 64
        pointer.write_text(json.dumps(value), encoding='utf-8')
        self.assert_cache_rejected_without_workers()

    def test_changed_group_receipt_bytes_are_rejected_without_silent_retry(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        receipt_path.write_bytes(receipt_path.read_bytes() + b' ')
        self.assert_cache_rejected_without_workers()

    def test_changed_cached_worker_result_is_rejected_without_silent_retry(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        path = Path(receipt['worker_result']['path'])
        path.write_bytes(path.read_bytes() + b' ')
        self.assert_cache_rejected_without_workers()

    def test_changed_cached_output_log_is_rejected_without_silent_retry(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        path = Path(receipt['log']['path'])
        path.write_bytes(path.read_bytes() + b'tampered output')
        self.assert_cache_rejected_without_workers()

    def test_missing_cached_output_is_rejected_without_silent_retry(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        Path(receipt['worker_result']['path']).unlink()
        self.assert_cache_rejected_without_workers()

    def test_repacked_receipt_cannot_forge_test_counts(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        receipt['counts']['tests_run'] += 100
        pointer.write_bytes(self.runner.canonical(self.repack('group-results', 'manifest.json', receipt)))
        self.assert_cache_rejected_without_workers()

    def test_repacked_worker_result_still_requires_consistent_original_case_count(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        value = json.loads(Path(receipt['worker_result']['path']).read_text('utf-8'))
        value['tests_run'] += 100
        receipt['worker_result'] = self.repack('objects', 'worker-result.json', value)
        pointer.write_bytes(self.runner.canonical(self.repack('group-results', 'manifest.json', receipt)))
        self.assert_cache_rejected_without_workers()

    def test_repacked_tooling_receipt_cannot_grant_client_or_runtime_admission(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        receipt['proves_client_compatibility'] = True
        receipt['runtime_admitted'] = True
        pointer.write_bytes(self.runner.canonical(self.repack('group-results', 'manifest.json', receipt)))
        self.assert_cache_rejected_without_workers()

    def test_repacked_receipt_cannot_change_its_group_members(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        receipt['definition']['group']['test_modules'] = ['test_vampir_other_fixture']
        pointer.write_bytes(self.runner.canonical(self.repack('group-results', 'manifest.json', receipt)))
        self.assert_cache_rejected_without_workers()

    def test_repacked_passed_receipt_cannot_hide_nonzero_worker_exit(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        receipt['exit_code'] = 1
        pointer.write_bytes(self.runner.canonical(self.repack('group-results', 'manifest.json', receipt)))
        self.assert_cache_rejected_without_workers()

    def test_explicit_matching_class_skip_accounts_for_discovered_unstarted_cases(self):
        def skipped_class_launch(workspace, definition, run_folder, timeout_seconds):
            launched = self.fake_launch(workspace, definition, run_folder, timeout_seconds)
            if definition['group']['id'] == 'beta':
                path = Path(launched['result_path'])
                result = json.loads(path.read_text('utf-8'))
                result['test_ids'] = ['test_vampir_beta_fixture.BetaCase.test_one',
                                      'test_vampir_beta_fixture.BetaCase.test_two']
                result['started_ids'] = []
                result['tests_run'] = 0
                result['skipped'] = [dict(id='setUpClass (test_vampir_beta_fixture.BetaCase)',
                                          reason='fixture class is unavailable')]
                path.write_text(json.dumps(result), encoding='utf-8')
            return launched

        result = self.run_groups(launch=skipped_class_launch)
        self.assertEqual(result['state'], 'passed')
        self.assertEqual(result['metrics']['executed_cases'], 3)
        self.assertEqual(result['metrics']['executed_discovered_cases'], 5)
        self.assertEqual(result['metrics']['executed_skips'], 1)

    def test_second_owner_is_rejected_without_starting_workers(self):
        with self.runner._owner(self.cache):
            with self.assertRaisesRegex(ValueError, 'owner'):
                self.run_groups()
        self.assertEqual(self.launches, [])

    def test_timeout_is_cached_as_timeout_with_zero_fabricated_case_count(self):
        def timeout_launch(workspace, definition, run_folder, timeout_seconds):
            self.launches.append(definition['group']['id'])
            run_folder = Path(run_folder)
            run_folder.mkdir(parents=True, exist_ok=True)
            log = run_folder / 'worker.log'
            log.write_text('fixture timeout\n', encoding='utf-8')
            return dict(state='timeout', result_path=None, log_path=log, exit_code=None)

        first = self.run_groups(launch=timeout_launch)
        self.assertEqual(first['state'], 'timeout')
        self.assertEqual(first['metrics']['executed_cases'], 0)
        self.launches.clear()
        repeated = self.run_groups(launch=timeout_launch)
        self.assertEqual(repeated['state'], 'timeout')
        self.assertEqual(self.launches, [])
        self.assertEqual(repeated['metrics']['cached_cases'], 0)

    def test_module_coverage_gaps_duplicates_and_aggregate_ambiguity_fail_before_launch(self):
        for kind in ('missing-member', 'duplicate-member', 'duplicate-group', 'aggregate-mismatch'):
            with self.subTest(kind=kind):
                saved = copy.deepcopy(self.manifest)
                aggregate = self.bots / 'test_vampir_update_automation.py'
                aggregate_before = aggregate.read_bytes()
                if kind == 'missing-member':
                    self.manifest['groups'].pop()
                elif kind == 'duplicate-member':
                    self.manifest['groups'][1]['test_modules'].append(self.expected[0])
                elif kind == 'duplicate-group':
                    self.manifest['groups'][1]['id'] = 'alpha'
                else:
                    aggregate.write_text('MODULES = ("test_vampir_other_fixture",)\n', encoding='utf-8')
                with self.assertRaises(ValueError), patch.object(self.runner, 'launch_group') as launch:
                    self.save_manifest()
                    self.runner.run(self.workspace, self.cache, self.manifest_path, self.expected,
                                    self.definition, workers=1)
                launch.assert_not_called()
                self.manifest = saved
                aggregate.write_bytes(aggregate_before)

    def test_original_dependency_coverage_and_missing_files_fail_before_launch(self):
        for kind in ('missing-coverage', 'missing-file', 'path-escape'):
            with self.subTest(kind=kind):
                saved = copy.deepcopy(self.manifest)
                if kind == 'missing-coverage':
                    self.manifest['groups'][0]['dependencies'].remove('phone-exit/bots/family_alpha.py')
                elif kind == 'missing-file':
                    self.manifest['groups'][0]['dependencies'].append('phone-exit/bots/missing.py')
                    self.definition['dependencies'].append('phone-exit/bots/missing.py')
                else:
                    self.manifest['groups'][0]['dependencies'].append('../escape.py')
                    self.definition['dependencies'].append('../escape.py')
                with self.assertRaises((ValueError, OSError)), patch.object(self.runner, 'launch_group') as launch:
                    self.save_manifest()
                    self.runner.run(self.workspace, self.cache, self.manifest_path, self.expected,
                                    self.definition, workers=1)
                launch.assert_not_called()
                self.manifest = saved
                self.definition['dependencies'] = self.dependencies()

    def test_a_module_source_cannot_be_covered_only_by_another_group(self):
        module = 'phone-exit/bots/test_vampir_alpha_fixture.py'
        self.manifest['groups'][0]['dependencies'].remove(module)
        self.manifest['groups'][1]['dependencies'].append(module)
        with self.assertRaises(ValueError), patch.object(self.runner, 'launch_group') as launch:
            self.save_manifest()
            self.runner.run(self.workspace, self.cache, self.manifest_path, self.expected,
                            self.definition, workers=1)
        launch.assert_not_called()

    def test_source_symlink_cannot_enter_the_dependency_closure(self):
        original = self.bots / 'family_alpha.py'
        alias = self.bots / 'family_alias.py'
        try:
            alias.symlink_to(original)
        except OSError as error:
            self.skipTest('Создание symlink недоступно: ' + str(error))
        dependencies = self.manifest['groups'][0]['dependencies']
        dependencies.remove('phone-exit/bots/family_alpha.py')
        dependencies.append('phone-exit/bots/family_alias.py')
        self.definition['dependencies'] = self.dependencies()
        with self.assertRaises(ValueError), patch.object(self.runner, 'launch_group') as launch:
            self.save_manifest()
            self.runner.run(self.workspace, self.cache, self.manifest_path, self.expected,
                            self.definition, workers=1)
        launch.assert_not_called()

    def test_shadow_package_cannot_replace_a_pinned_test_module(self):
        self.write('phone-exit/bots/test_vampir_alpha_fixture/__init__.py',
                   'raise AssertionError("shadow package must not execute")\n')
        with self.assertRaises(ValueError), patch.object(self.runner, 'launch_group') as launch:
            self.save_manifest()
            self.runner.run(self.workspace, self.cache, self.manifest_path, self.expected,
                            self.definition, workers=1)
        launch.assert_not_called()

    def test_real_worker_rechecks_test_origin_before_importing_a_shadow_package(self):
        group, receipt_path, receipt, pointer = self.cached_alpha()
        self.write('phone-exit/bots/test_vampir_alpha_fixture/__init__.py',
                   'raise AssertionError("shadow package must not execute")\n')
        outcome = self.runner.launch_group(self.workspace, receipt['definition'],
                                            self.folder / 'direct-worker', 30)
        self.assertEqual(outcome['state'], 'failed')
        self.assertNotEqual(outcome['exit_code'], 0)
        log = Path(outcome['log_path']).read_text('utf-8', errors='replace')
        self.assertRegex(log.lower(), 'origin|source|shadow')
        self.assertNotIn('AssertionError: shadow package must not execute', log)

    def test_real_worker_ignores_stale_timestamp_pyc_after_same_size_source_change(self):
        source = self.bots / 'test_vampir_alpha_fixture.py'
        original = source.read_bytes()
        stat = source.stat()
        bytecode = Path(py_compile.compile(str(source), doraise=True))
        self.assertTrue(bytecode.is_file())
        changed = original.replace(b'"alpha-v1"', b'"alpha-v9"')
        self.assertNotEqual(changed, original)
        self.assertEqual(len(changed), len(original))
        source.write_bytes(changed)
        os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        self.assertEqual(source.stat().st_mtime_ns, stat.st_mtime_ns)
        outcome = self.run_groups(launch=self.runner.launch_group)
        self.assertEqual(outcome['state'], 'failed', 'Worker must execute changed source, not old passing pyc')
        logs = '\n'.join(path.read_text('utf-8', errors='replace')
                         for path in self.cache.rglob('worker.log'))
        self.assertIn('alpha-v9', logs)

    def test_client_scope_or_unreviewed_definitions_cannot_use_tooling_cache(self):
        for change in (dict(source_scope='client'), dict(source_sha256=['b' * 64]),
                       dict(offline_reviewed=False), dict(artifact_dependencies=['private/capture.json'])):
            with self.subTest(change=change):
                saved = copy.deepcopy(self.definition)
                self.definition.update(change)
                with self.assertRaises(ValueError), patch.object(self.runner, 'launch_group') as launch:
                    self.save_manifest()
                    self.runner.run(self.workspace, self.cache, self.manifest_path, self.expected,
                                    self.definition, workers=1)
                launch.assert_not_called()
                self.definition = saved

    @unittest.skipUnless(os.name == 'nt', 'Настоящий Windows Job доступен только на Windows')
    def test_real_worker_preserves_loader_multiplicity_skips_and_isolates_descendants(self):
        alpha = self.bots / 'test_vampir_alpha_fixture.py'
        alpha.write_text(alpha.read_text('utf-8') +
                         '\nimport json, os, subprocess, sys\nfrom pathlib import Path\n'
                         'class EnvironmentCase(unittest.TestCase):\n'
                         '    def test_resource_roots(self):\n'
                         '        names = ("PHONEEXIT_VAMPIR_RESOURCES", "PHONEEXIT_RF_RESOURCES")\n'
                         '        roots = {name: os.environ[name] for name in names}\n'
                         '        for value in roots.values():\n'
                         '            folder = Path(value)\n'
                         '            folder.mkdir(parents=True, exist_ok=True)\n'
                         '            self.assertTrue(folder.is_dir())\n'
                         '            (folder / "fixture-only.txt").write_text("isolated", encoding="utf-8")\n'
                         '        Path(' + repr(str(self.workspace / 'environment.json')) + ').write_text('
                         'json.dumps(roots), encoding="utf-8")\n'
                         '    def test_spawn_owned_descendant(self):\n'
                         '        child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(10)"])\n'
                         '        Path(' + repr(str(self.workspace / 'descendant.pid')) + ').write_text('
                         'str(child.pid), encoding="ascii")\n', encoding='utf-8')
        launch = self.runner.launch_group
        result = self.run_groups(launch=launch)
        logs = '\n'.join(path.read_text('utf-8', errors='replace')
                         for path in self.cache.rglob('worker.log'))
        self.assertEqual(result['state'], 'passed', logs)
        self.assertEqual(result['metrics']['executed_groups'], 2)
        self.assertEqual(result['metrics']['executed_cases'], 6)
        records = []
        for path in self.cache.rglob('*.json'):
            row = json.loads(path.read_text('utf-8'))
            if row.get('producer') == 'tooling-group-worker-v1':
                records.append(row)
        alpha_results = [row for row in records if row['group_id'] == 'alpha']
        beta_results = [row for row in records if row['group_id'] == 'beta']
        self.assertTrue(alpha_results)
        self.assertTrue(beta_results)
        self.assertTrue(all(row['tests_run'] == 5 for row in alpha_results))
        self.assertTrue(all(sum(name.endswith('ImportedCase.test_imported') for name in row['test_ids']) == 2
                            for row in alpha_results))
        self.assertTrue(all(row['skipped'][0]['reason'] == 'fixture skip' for row in beta_results))
        roots = json.loads((self.workspace / 'environment.json').read_text('utf-8'))
        self.assertEqual(set(roots), {'PHONEEXIT_VAMPIR_RESOURCES', 'PHONEEXIT_RF_RESOURCES'})
        self.assertTrue(all(Path(value) != self.cache for value in roots.values()))
        self.assertTrue(all(not Path(value).exists() for value in roots.values()))
        pid = int((self.workspace / 'descendant.pid').read_text('ascii'))
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if handle:
            try:
                self.assertEqual(kernel.WaitForSingleObject(handle, 1000), 0,
                                 'Windows Job must terminate the worker descendant')
            finally:
                kernel.CloseHandle(handle)
        self.launches.clear()
        repeated = self.run_groups(launch=lambda *_args, **_kwargs:
                                   self.fail('Warm repeat must not start a worker'))
        self.assertEqual(repeated['metrics']['cached_cases'], 6)
        self.assertEqual(repeated['metrics']['executed_cases'], 0)


if __name__ == '__main__':
    unittest.main()
