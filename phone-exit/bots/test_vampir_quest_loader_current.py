"""Current CSV loading keeps native provenance and fail-closed cache boundaries."""
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
    path = HERE/'resource-tools/vampir'/(name+'.py')
    spec = importlib.util.spec_from_file_location('test_'+name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QuestLoaderCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load('verify-quest-loader-current')
        cls.pointer = cls.tool.verify()
        cls.report = json.loads(Path(cls.pointer['report']).read_bytes())
        cls.context = json.loads(cls.tool.CONTEXT.read_bytes())

    def test_actual_loaded_records_and_projection_follow_input_order(self):
        result = self.report['result']
        self.assertEqual(len(result['runs']), 2)
        for run, reverse in zip(result['runs'], (False, True)):
            ids = self.context['task_ids'][::-1] if reverse else self.context['task_ids']
            self.assertEqual(run['reverse'], reverse)
            self.assertEqual(run['task_ids'], ids)
            self.assertEqual(run['records'], 6)
            self.assertEqual(run['group_count'], 1)
            self.assertTrue(run['group_order_matches_records'])
            self.assertEqual(len(run['native_projections']), 18)
            for index in range(6):
                selected = run['native_projections'][index*3:index*3+3]
                self.assertEqual([row['task_id'] for row in selected], [ids[index]]*3)
                self.assertEqual([row['index'] for row in selected], [index]*3)
        self.assertEqual(result['metrics']['abi_checks'], 38)
        self.assertEqual(result['runs'][0]['native_projections'][0]['task_id'], '110120005')
        self.assertEqual(result['runs'][1]['native_projections'][0]['task_id'], '110120070')

    def test_bound_source_execution_does_not_admit_full_catalogue_or_actions(self):
        for field in self.tool.FALSE_FIELDS:
            self.assertIs(self.report[field], False)
        result = self.report['result']
        self.assertIs(result['order_admitted'], False)
        self.assertTrue(result['native_scalars'])
        self.assertTrue(result['native_override'])
        self.assertTrue(result['native_projection'])
        self.assertEqual(result['csv_sha256'], self.context['csv']['sha256'])
        self.assertEqual(result['override_sha256'], self.context['override_csv']['sha256'])
        self.assertIn('ucrtbase.dll', result['system_runtime']['path'].lower())

    def test_missing_native_root_or_projection_coverage_is_rejected(self):
        forged = copy.deepcopy(self.report)
        forged['result']['runs'][0]['native_projections'].pop()
        with self.assertRaises(ValueError):
            self.tool.validate(forged, self.report['definition'], self.context)
        forged = copy.deepcopy(self.report)
        forged['result']['metrics']['entry_counts'].pop('0x145b5f680')
        with self.assertRaises(ValueError):
            self.tool.validate(forged, self.report['definition'], self.context)
        with self.assertRaisesRegex(ValueError, 'scope differs'):
            self.tool.validate(dict(self.report, ordered_catalog_verified=True), self.report['definition'], self.context)

    def test_native_result_cannot_be_detached_from_pinned_inputs(self):
        for field, mutate, message in (
            ('context_sha256', lambda value: '0'*64, 'provenance differs'),
            ('exports', lambda value: value[1:], 'exports differ'),
            ('system_runtime', lambda value: dict(value, locale='different'), 'CRT or locale differs'),
        ):
            with self.subTest(field=field):
                forged = copy.deepcopy(self.report)
                forged['result'][field] = mutate(forged['result'][field])
                with self.assertRaisesRegex(ValueError, message):
                    self.tool.validate(forged, self.report['definition'], self.context)

    def test_named_tables_must_belong_to_the_active_patch_archive(self):
        index = load('knowledge-index').api()
        other = index.INSTALL.parents[2].with_name('other-installation')
        index.INSTALL = other/'Binaries/Win64/ProjectRED-Win64-Shipping.exe'
        with self.assertRaisesRegex(ValueError, 'belongs to another archive'):
            self.tool.definition(index, self.tool.ROOT.resolve(), self.tool.CONTEXT)

    def test_warm_cache_starts_no_native_replay_or_process(self):
        original = self.tool.load
        replay = original('replay-quest-loader-current-v1')
        with patch.object(self.tool, 'load', side_effect=lambda name: replay if name == 'replay-quest-loader-current-v1' else original(name)), \
                patch.object(replay, 'run', side_effect=AssertionError('native replay')), \
                patch.object(subprocess, 'Popen', side_effect=AssertionError('new process')):
            self.assertEqual(self.tool.verify(), dict(self.pointer, reused=True))

    def test_corrupted_immutable_receipt_is_rejected_without_replay(self):
        raw = b'{"result":"original"}\n'
        sha = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            path = root/'code-clues'/self.tool.RECIPE/sha/'manifest.json'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'{"result":"corrupted"}\n')
            with self.assertRaisesRegex(ValueError, 'receipt SHA'):
                self.tool.document(dict(path=str(path), sha256=sha), root, 'code-clues/'+self.tool.RECIPE)

    def test_warm_cache_keeps_final_input_barrier(self):
        with patch.object(self.tool, 'barrier', side_effect=[None, ValueError('late source change')]) as checked:
            with self.assertRaisesRegex(ValueError, 'late source change'):
                self.tool.verify()
        self.assertEqual(checked.call_count, 2)

    def test_crt_locale_is_part_of_the_cache_key_and_final_barrier(self):
        locale = self.report['definition']['system_runtime']['locale']
        changed = 'different' if locale != 'different' else 'another'
        index = load('knowledge-index').api()
        with patch.object(self.tool, 'crt_locale', return_value=changed):
            _, selected = self.tool.definition(index, self.tool.ROOT.resolve(), self.tool.CONTEXT)
        self.assertEqual(selected['system_runtime']['locale'], changed)
        self.assertNotEqual(selected, self.report['definition'])
        with patch.object(self.tool, 'crt_locale', side_effect=[locale, locale, changed]) as checked:
            with self.assertRaisesRegex(ValueError, 'CRT locale changed'):
                self.tool.verify()
        self.assertEqual(checked.call_count, 3)

    def test_runtime_collision_cannot_overwrite_source_input(self):
        original = self.tool.load
        wrapper = original('knowledge-index')
        index = wrapper.api()
        extension = index.extension
        runtime = extension('native-publication-v2')
        target = (self.tool.HERE/'replay-quest-loader-current-v1.py').resolve()
        normal = self.tool.digest
        reads = 0
        def changed(path):
            nonlocal reads
            if Path(path).resolve() == target:
                reads += 1
                if reads > 1:
                    return '0'*64
            return normal(path)
        with patch.object(runtime, 'runtime_files', return_value=[target]), \
                patch.object(index, 'extension', side_effect=lambda name: runtime if name == 'native-publication-v2' else extension(name)), \
                patch.object(wrapper, 'api', return_value=index), \
                patch.object(self.tool, 'load', side_effect=lambda name: wrapper if name == 'knowledge-index' else original(name)), \
                patch.object(self.tool, 'digest', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'runtime input conflicts'):
                self.tool.verify()


if __name__ == '__main__':
    unittest.main()
