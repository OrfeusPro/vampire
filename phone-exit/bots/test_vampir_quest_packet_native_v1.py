"""Regression coverage for exact native matrices, durable reuse and final guards."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_update_contracts import load
import test_vampir_quest_reader_transfer_v1 as fixtures

PACKETS = load('quest-packet-native-v1')
HARNESS = load('quest-packet-harness-v1')
CASES = load('quest-packet-cases-v1')


class PacketNativeTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.QuestReaderTransferTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.reader = self.f.run_reader()
        self.args, self.index = self.f.args, self.f.index
        self.sha = self.f.sha
        self.selector = self.args.knowledge / 'quest-packet-native.json'
        self.rule = dict(schema=1, recipe=PACKETS.RECIPE, families=list(PACKETS.FAMILIES))
        self.selector.write_text(json.dumps(self.rule), encoding='utf-8')
        self.runtime = dict(files={str(self.f.f.runtime_file): fixtures.seed_fixtures.digest(self.f.f.runtime_file)})
        self.tool = self.f.root / 'new-native-fixture.py'
        self.tool.write_text('fixture native worker', encoding='utf-8')
        self.harness = SimpleNamespace(pointer_document=HARNESS.pointer_document, verify_files=HARNESS.verify_files,
            tools=lambda: {str(self.tool): fixtures.seed_fixtures.digest(self.tool)},
            runtime_inputs=lambda: copy.deepcopy(self.runtime))
        exports = self.f.root / 'ghidra/request-exports' / self.sha / 'run-fixture' / 'details.json'
        exports.parent.mkdir(parents=True)
        exports.write_text('{}', encoding='utf-8')
        self.export = dict(path=str(exports), sha256=fixtures.seed_fixtures.digest(exports))
        addresses = {at for ctx in self.f.package['target_contexts'].values() for at in ctx['functions'].values()}
        collected = [dict(address=at, state='ready', artifacts=[self.export]) for at in addresses]
        self.collector = SimpleNamespace(collect_batches=Mock(return_value=collected))
        self.verify = Mock(side_effect=self.native_report)
        self.case_api = SimpleNamespace(scenarios=CASES.scenarios, FAMILIES=CASES.FAMILIES, verify=self.verify)
        original = self.index.extension
        self.index.extension = lambda name: {'quest-packet-harness-v1': self.harness,
            'quest-packet-cases-v1': self.case_api, 'update-run': self.collector}.get(name) or original(name)
        self.journal = fixtures.seed_fixtures.Journal()

    def native_report(self, harness, context, root, store):
        rows = [row for row, body in CASES.scenarios(context['family'])]
        exports = [dict(path=str(Path(root) / 'ghidra/request-exports' / context['source_sha256'] / run / 'details.json'), sha256=sha)
                   for run, sha in context['exports'].items()]
        return dict(family=context['family'], packet_id=CASES.FAMILIES[context['family']], cases=rows,
            exports=exports, source_sha256=context['source_sha256'], call_counts=4 * len(rows),
            abi_checks=4 * len(rows), read_checks=1, write_checks=1, fixture_calls=1,
            target_exports_verified=True, native_execution=True, runtime_activated=False, profile_activated=False)

    def run_native(self):
        return PACKETS.run(self.index, self.args, self.sha, self.journal, self.reader, self.f.root / 'selected.sqlite3')

    def test_exact_matrices_have_every_prefix_and_explicit_trailing_case(self):
        quest = list(CASES.scenarios('quest-sync'))
        tutorial = list(CASES.scenarios('tutorial-update'))
        self.assertEqual([sum(row['kind'] == kind for row, body in quest) for kind in ('valid', 'truncated', 'trailing')], [96, 172, 1])
        self.assertEqual([sum(row['kind'] == kind for row, body in tutorial) for kind in ('valid', 'truncated', 'trailing')], [73, 835, 1])
        self.assertEqual([row['consumed'] for row, body in quest if row['kind'] == 'truncated'], list(range(172)))
        self.assertEqual(quest[-1][0]['size'] - quest[-1][0]['consumed'], 2)

    def test_whole_reports_and_warm_cache_preserve_bounded_scope(self):
        first = self.run_native()
        self.assertEqual(first['state'], 'passed_bounded_native')
        self.assertEqual(first['cases'], 1178)
        second = self.run_native()
        self.assertEqual(first, second)
        self.assertEqual(self.verify.call_count, 2)
        self.assertEqual(self.journal.actions, 2)
        final = PACKETS.finalize(self.index, self.args, second)
        self.assertTrue(final['final_validation_completed'])
        self.assertFalse(final['profile_activated'])

    def test_missing_export_prevents_native_execution(self):
        self.collector.collect_batches.return_value[0]['state'] = 'missing'
        self.assertEqual(self.run_native()['state'], 'requires_review')
        self.verify.assert_not_called()

    def test_foreign_reader_invocation_is_rejected(self):
        self.args.source_store = copy.copy(self.args.source_store)
        self.assertEqual(self.run_native()['state'], 'requires_review')
        self.verify.assert_not_called()

    def test_corrupt_cached_report_cannot_trigger_new_native_execution(self):
        first = self.run_native()
        Path(first['checks']['quest-sync']['report']).write_bytes(b'corrupt native evidence')
        self.assertEqual(self.run_native()['state'], 'requires_review')
        self.assertEqual(self.verify.call_count, 2)

    def test_changed_execution_code_invalidates_only_new_native_stages(self):
        self.run_native()
        self.tool.write_text('changed native worker', encoding='utf-8')
        self.assertEqual(self.run_native()['state'], 'passed_bounded_native')
        self.assertEqual(self.verify.call_count, 4)

    def test_changed_runtime_changes_native_stage_key(self):
        self.run_native()
        self.runtime['version'] = 'new synthetic runtime'
        self.run_native()
        self.assertEqual(self.verify.call_count, 4)

    def test_final_report_mutation_blocks_publication(self):
        result = self.run_native()
        Path(result['checks']['tutorial-update']['report']).write_bytes(b'late mutation')
        with self.assertRaises(ValueError):
            PACKETS.finalize(self.index, self.args, result)

    def test_final_store_replacement_blocks_publication(self):
        result = self.run_native()
        self.args.source_store = copy.copy(self.args.source_store)
        with self.assertRaises(ValueError):
            PACKETS.finalize(self.index, self.args, result)

    def test_wrong_case_type_or_missing_row_rejects_cached_semantics(self):
        result = self.run_native()
        report = json.loads(Path(result['checks']['quest-sync']['report']).read_bytes())
        for mutate in (lambda r: r['cases'][0].update(accepted=1), lambda r: r['cases'].pop(),
                       lambda r: r.update(abi_checks=1), lambda r: r.update(profile_activated=True)):
            bad = copy.deepcopy(report)
            mutate(bad)
            with self.assertRaises(ValueError):
                PACKETS.validate_report(self.index, bad, report['inputs']['context'], report['inputs'])

    def test_native_case_failure_is_preserved_as_a_specific_blocker(self):
        self.verify.side_effect = ValueError('quest-sync prefix 17 wrote outside the packet')
        result = self.run_native()
        self.assertEqual(result['state'], 'requires_review')
        self.assertIn('prefix 17', result['reason'])

    def test_unknown_selector_is_rejected(self):
        self.selector.write_text('{"schema":1,"recipe":"other"}', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.run_native()


if __name__ == '__main__':
    unittest.main()
