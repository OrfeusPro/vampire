"""One source-bound UTF-8/string/archive batch; no runtime activation or network."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import HERE, load

sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core.login_packet import decode_login_payload

ROOT = Path('F:/PhoneExit Resources/Vampir')
SOURCE = '544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
TOOLS = {'utf8': 'verify-utf8-context', 'string-writer': 'verify-string-writer-context',
         'archive-wire': 'verify-archive-wire-context'}


class WireBatch11320Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Execute each valid native suite once. Mutations below use fresh deep
        # copies and never replace the source guards or native dependencies.
        cls.contexts = {}
        cls.reports = {}
        for name, tool in TOOLS.items():
            path = HERE / 'knowledge/native-contexts' / (name + '-11320.json')
            context = json.loads(path.read_text('utf-8'))
            if context.get('source_sha256') != SOURCE or context.get('verify_whole_exports') is not True:
                raise ValueError('Whole current-source exports are required')
            cls.contexts[name] = context
        _, batch, _ = load('run-wire-batch-11320').run(ROOT)
        cls.reports = batch['reports']

    def verify_mutation(self, name, mutate, message):
        context = copy.deepcopy(self.contexts[name])
        mutate(context)
        with self.assertRaisesRegex(ValueError, message):
            load(TOOLS[name]).verify(context, ROOT)

    def test_batch_has_current_source_native_cases_and_no_activation(self):
        for name, report in self.reports.items():
            with self.subTest(suite=name):
                self.assertEqual(report['source_sha256'], SOURCE)
                self.assertEqual(report['method'], 'bounded_native')
                self.assertIs(report['network_used'], False)
                self.assertIs(report['profile_activated'], False)
                self.assertTrue(report['evidence'])
                self.assertTrue(all(SOURCE in row['path'] for row in report['evidence']))
                for row in report['evidence']:
                    self.assertEqual(hashlib.sha256(Path(row['path']).read_bytes()).hexdigest(), row['sha256'])
        self.assertEqual((len(self.reports['utf8']['cases']), len(self.reports['utf8']['scalar_cases'])), (142, 80))
        self.assertEqual(len(self.reports['string-writer']['cases']), 228)
        self.assertEqual((len(self.reports['archive-wire']['cases']), len(self.reports['archive-wire']['wire_cases'])), (45, 64))

    def test_utf8_capacities_malformed_scalars_and_guards(self):
        report = self.reports['utf8']
        self.assertTrue(all(row['guards'] for row in report['cases'] + report['scalar_cases']))
        emoji = [row for row in report['cases'] if row['vector'] == 6]
        self.assertEqual(next(row for row in emoji if row['capacity'] == 4)['output_hex'], 'f09f9982')
        self.assertEqual(next(row for row in emoji if row['capacity'] == 3)['output_hex'], '')
        for scalar in (0xd800, 0xfffe, 0x110000):
            row = next(row for row in report['scalar_cases'] if row['scalar'] == scalar and row['capacity'] == 1)
            self.assertEqual(row['output_hex'], '3f')

    def test_string_writer_cleanup_small_string_and_return_bytes(self):
        cases = self.reports['string-writer']['cases']
        self.assertTrue(all(row['guards'] for row in cases))
        self.assertEqual({row['archive_result'] for row in cases}, {0, 1, 128, 255})
        self.assertEqual(next(row for row in cases if row['utf8_bytes'] == 15)['allocations'], {})
        self.assertEqual(set(next(row for row in cases if row['utf8_bytes'] == 127)['allocations']), {'cpp'})
        self.assertEqual(set(next(row for row in cases if row['utf8_bytes'] == 128)['allocations']), {'cpp', 'utf8'})
        self.assertEqual(next(row for row in cases if row['utf8_bytes'] == 4095)['allocations']['cpp'], 4135)

    def test_whole_packet_wires_round_trip_without_changing_boolean_byte(self):
        report = self.reports['archive-wire']
        self.assertEqual(next(row for row in report['cases'] if row['kind'] == 'bool' and row['value'] == 128)['output_hex'], '80')
        self.assertEqual({row['packet'] for row in report['wire_cases']}, {'game-version', 'game-login'})
        for row in report['wire_cases']:
            self.assertTrue(row['guards'])
            if row['packet'] == 'game-login':
                body = bytes.fromhex(row['payload_hex'])
                self.assertEqual(decode_login_payload(body, max_payload_size=16384).encode(max_payload_size=16384), body)

    def test_wrong_source_and_export_sha_cannot_run(self):
        self.verify_mutation('utf8', lambda c: c.update(source_sha256='0' * 64), 'source path differs')
        def wrong_export(context):
            context['exports'][next(iter(context['exports']))] = '0' * 64
        self.verify_mutation('archive-wire', wrong_export, 'export SHA changed')

    def test_encoder_leaf_size_and_actual_callee_are_required(self):
        def wrong_size(context):
            context['encoder_leaf']['size'] += 1
        self.verify_mutation('utf8', wrong_size, 'leaf bounds or SHA')
        def wrong_encoder(context):
            context['bindings']['encoder'] = hex(int(context['bindings']['encoder'], 16) + 1)
        self.verify_mutation('utf8', wrong_encoder, 'leaf|helper links|instruction')

    def test_archive_table_hash_and_slot_must_match_current_exe(self):
        self.verify_mutation('archive-wire', lambda c: c.update(archive_table_sha256='0' * 64), 'table SHA differs')
        def wrong_slot(context):
            context['archive']['u16'] = context['archive']['u32']
        self.verify_mutation('archive-wire', wrong_slot, 'table slot differs')

    def test_archive_constructor_table_and_helper_links_are_required(self):
        def wrong_table(context):
            context['archive']['table'] = hex(int(context['archive']['table'], 16) + 8)
        self.verify_mutation('archive-wire', wrong_table, 'table SHA differs|constructor table link')
        def wrong_callee(context):
            context['archive_helpers']['set_count_leaf'] = hex(int(context['archive_helpers']['set_count_leaf'], 16) + 1)
        self.verify_mutation('archive-wire', wrong_callee, 'direct call set')

    def test_writer_cookie_import_and_fixture_callee_links_are_required(self):
        def wrong_cookie(context):
            context['writer_metadata']['cookie'] = hex(int(context['writer_metadata']['cookie'], 16) + 1)
        self.verify_mutation('string-writer', wrong_cookie, 'cookie source link')
        def wrong_import(context):
            context['writer_metadata']['invalid_parameter_iat'] = hex(int(context['writer_metadata']['invalid_parameter_iat'], 16) + 8)
        self.verify_mutation('string-writer', wrong_import, 'indirect import slots')
        def wrong_free(context):
            context['fixtures']['utf8_free'] = hex(int(context['fixtures']['utf8_free'], 16) + 1)
        self.verify_mutation('string-writer', wrong_free, 'direct calls differ')

    def test_packet_field_order_is_proved_by_native_output(self):
        def swap_fields(context):
            fields = context['packets']['game-version']['fields']
            fields[0], fields[1] = fields[1], fields[0]
        self.verify_mutation('archive-wire', swap_fields, 'payload or canaries differ')


class WireBatchCache11320Tests(unittest.TestCase):
    """Synthetic receipt bookkeeping only; these cases do not prove native code."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.runner = load('run-wire-batch-11320')
        self.contexts, self.reports = {}, {}
        export = self.root / 'ghidra/request-exports' / SOURCE / 'run-fixture/details.json'
        export_sha = 'a' * 64
        self.definition = dict(schema=1, source_sha256=SOURCE, files={},
            exports={str(export): export_sha}, python='synthetic', runtime={})
        for name, (_, count, extra_key, extra_count) in self.runner.COMPONENTS.items():
            self.contexts[name] = dict(exports={'run-fixture': export_sha})
            report = dict(source_sha256=SOURCE, method='bounded_native', cases=[{'guards': True}] * count,
                evidence=[dict(path=str(export), sha256=export_sha)], network_used=False,
                profile_activated=False, limits=['Synthetic cache fixture; not native evidence.'])
            if extra_key:
                report[extra_key] = [{'guards': True}] * extra_count
            self.reports[name] = report
        original_load = self.runner.load
        self.replays = []
        self.allow_replay = True
        by_tool = {tool: name for name, (tool, _, _, _) in self.runner.COMPONENTS.items()}
        def replay(name):
            if not self.allow_replay:
                raise AssertionError('Cached fixture must not execute a replay')
            self.replays.append(name)
            return copy.deepcopy(self.reports[name])
        def loader(name):
            if name in by_tool:
                return SimpleNamespace(verify=lambda context, root: replay(by_tool[name]))
            return original_load(name)
        self.inputs = self.enterContext(patch.object(self.runner, 'inputs', side_effect=lambda root:
            (copy.deepcopy(self.contexts), copy.deepcopy(self.definition))))
        self.enterContext(patch.object(self.runner, 'load', side_effect=loader))

    def prime(self):
        path, report, reused = self.runner.run(self.root)
        self.assertFalse(reused)
        self.assertEqual(len(self.replays), 3)
        self.assertEqual(report['native_case_executions'], 559)
        self.allow_replay = False
        return path, report

    def test_valid_cache_reuses_receipt_without_any_replay(self):
        path, report = self.prime()
        second, value, reused = self.runner.run(self.root)
        self.assertTrue(reused)
        self.assertEqual(second, path)
        self.assertEqual(value, report)
        self.assertEqual(len(self.replays), 3)

    def test_changed_report_is_rejected_before_replay(self):
        path, _ = self.prime()
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'cached report changed'):
            self.runner.run(self.root)

    def test_cache_pointer_cannot_escape_its_result_directory(self):
        path, _ = self.prime()
        outside = self.root / 'outside' / path.parent.name / 'manifest.json'
        outside.parent.mkdir(parents=True)
        outside.write_bytes(path.read_bytes())
        pointer = next((self.root / 'knowledge/wire-batch-cache-11320').glob('*.json'))
        pointer.write_text(json.dumps(dict(report=str(outside), sha256=path.parent.name)), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'cached report changed'):
            self.runner.run(self.root)

    def test_input_change_during_cache_validation_rejects_stale_result(self):
        self.prime()
        changed = copy.deepcopy(self.definition)
        changed['files']['synthetic-changed-tool.py'] = 'b' * 64
        self.inputs.side_effect = [(copy.deepcopy(self.contexts), copy.deepcopy(self.definition)),
                                  (copy.deepcopy(self.contexts), changed)]
        with self.assertRaisesRegex(ValueError, 'cache inputs changed'):
            self.runner.run(self.root)


if __name__ == '__main__':
    unittest.main()
