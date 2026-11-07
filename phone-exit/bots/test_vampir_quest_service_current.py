"""The source-bound service policy retains data provenance and bounded admission."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    path = HERE / 'resource-tools/vampir' / (name + '.py')
    spec = importlib.util.spec_from_file_location('test_' + name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QuestServiceCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-quest-service-current')
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())
        cls.context = json.loads(cls.tool.CONTEXT.read_bytes())

    def test_policy_covers_current_rows_and_preserves_scope(self):
        report = self.report
        common = self.tool.load('verify-quest-loader-current')
        for field in common.FALSE_FIELDS:
            self.assertIs(report[field], False)
        self.assertIs(report['native_execution'], True)
        self.assertEqual(report['source_sha256'], self.tool.SOURCE)
        self.tool.validate(report, report['definition'], self.context)

    def test_region_and_server_lists_choose_the_expected_path(self):
        cases = self.report['result']['cases']
        for external in (False, True):
            selected = {row['scenario']['name']: row for row in cases
                        if row['scenario']['external_buckets'] is external}
            self.assertEqual([selected['group10000-region' + str(region)]['skip']
                              for region in range(8)], [0, 0, 0, 0, 0, 1, 1, 1])
            self.assertEqual(selected['include-listed']['skip'], 0)
            self.assertEqual(selected['exclude-listed']['skip'], 1)
            for name in ('include-listed', 'exclude-listed'):
                self.assertEqual(selected[name]['native_entries']['0x145bfefd0'], 0)
            self.assertEqual(selected['include-nonmatching-phase']['skip'], 1)
            self.assertEqual(selected['exclude-nonmatching-phase']['skip'], 0)

    def test_missing_scenario_and_native_coverage_are_rejected(self):
        report = copy.deepcopy(self.report)
        report['result']['cases'].pop()
        with self.assertRaises(ValueError):
            self.tool.validate(report, self.report['definition'], self.context)
        report = copy.deepcopy(self.report)
        report['result']['metrics']['entry_counts'].pop('0x145c03670')
        with self.assertRaises(ValueError):
            self.tool.validate(report, self.report['definition'], self.context)
        with self.assertRaisesRegex(ValueError, 'scope differs'):
            self.tool.validate(dict(self.report, ordered_catalog_verified=True),
                               self.report['definition'], self.context)

    def test_result_keeps_exports_crt_and_context_provenance(self):
        changes = (
            ('context_sha256', lambda value: '0' * 64, 'provenance differs'),
            ('exports', lambda value: value[1:], 'exports differ'),
            ('system_runtime', lambda value: dict(value, locale='different'), 'CRT or locale differs'),
        )
        for field, mutate, message in changes:
            with self.subTest(field=field):
                report = copy.deepcopy(self.report)
                report['result'][field] = mutate(report['result'][field])
                with self.assertRaisesRegex(ValueError, message):
                    self.tool.validate(report, self.report['definition'], self.context)

    def test_named_tables_belong_to_installed_archive(self):
        index = load('knowledge-index').api()
        other = index.INSTALL.parents[2].with_name('other-installation')
        index.INSTALL = other / 'Binaries/Win64/ProjectRED-Win64-Shipping.exe'
        with self.assertRaisesRegex(ValueError, 'different archive'):
            self.tool.definition(index, self.tool.ROOT.resolve(), self.tool.CONTEXT)

    def test_cache_starts_no_native_replay_or_process(self):
        original = self.tool.load
        replay = original(self.tool.REPLAY)
        with patch.object(self.tool, 'load', side_effect=lambda name:
                          replay if name == self.tool.REPLAY else original(name)), \
                patch.object(replay, 'run', side_effect=AssertionError('native replay')), \
                patch.object(subprocess, 'Popen', side_effect=AssertionError('new process')):
            self.assertEqual(self.tool.verify(), dict(self.pointer, reused=True))

    def test_corrupt_receipt_is_rejected(self):
        raw = b'{"original":true}\n'
        sha = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            path = root / 'code-clues' / self.tool.RECIPE / sha / 'manifest.json'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'{"corrupted":true}\n')
            common = self.tool.load('verify-quest-loader-current')
            with self.assertRaisesRegex(ValueError, 'receipt SHA'):
                common.document(dict(path=str(path), sha256=sha), root,
                                'code-clues/' + self.tool.RECIPE)

    def test_cached_result_keeps_final_input_barrier(self):
        original = self.tool.load
        common = original('verify-quest-loader-current')
        with patch.object(self.tool, 'load', side_effect=lambda name:
                          common if name == 'verify-quest-loader-current' else original(name)), \
                patch.object(common, 'barrier', side_effect=[None, ValueError('late change')]) as barrier:
            with self.assertRaisesRegex(ValueError, 'late change'):
                self.tool.verify()
        self.assertEqual(barrier.call_count, 2)

    def test_crt_locale_changes_cache_and_final_barrier(self):
        original = self.tool.load
        common = original('verify-quest-loader-current')
        locale = self.report['definition']['system_runtime']['locale']
        with patch.object(self.tool, 'load', side_effect=lambda name:
                          common if name == 'verify-quest-loader-current' else original(name)):
            with patch.object(common, 'crt_locale', return_value='different'):
                _, selected = self.tool.definition(load('knowledge-index').api(),
                                                    self.tool.ROOT.resolve(), self.tool.CONTEXT)
            self.assertNotEqual(selected, self.report['definition'])
            with patch.object(common, 'crt_locale', side_effect=[locale, locale, 'different']):
                with self.assertRaisesRegex(ValueError, 'CRT locale changed'):
                    self.tool.verify()

    def test_runtime_collision_preserves_source_identity(self):
        original = self.tool.load
        common = original('verify-quest-loader-current')
        wrapper = original('knowledge-index')
        index = wrapper.api()
        extension = index.extension
        runtime = extension('native-publication-v2')
        target = self.tool.HERE / (self.tool.REPLAY + '.py')
        normal = common.digest
        reads = 0

        def changed(path):
            nonlocal reads
            if Path(path).resolve() == target:
                reads += 1
                if reads > 1:
                    return '0' * 64
            return normal(path)

        modules = {'knowledge-index': wrapper, 'verify-quest-loader-current': common}
        with patch.object(runtime, 'runtime_files', return_value=[target]), \
                patch.object(index, 'extension', side_effect=lambda name:
                             runtime if name == 'native-publication-v2' else extension(name)), \
                patch.object(wrapper, 'api', return_value=index), \
                patch.object(common, 'digest', side_effect=changed), \
                patch.object(self.tool, 'load', side_effect=lambda name:
                             modules[name] if name in modules else original(name)):
            with self.assertRaisesRegex(ValueError, 'runtime conflicts'):
                self.tool.verify()


if __name__ == '__main__':
    unittest.main()
