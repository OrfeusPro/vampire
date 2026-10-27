"""Scoped leased observations using the current codec; no owner or external IO."""
import base64
import copy
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
spec = importlib.util.spec_from_file_location('stat_observer_11318', HERE / 'vampir-headless/observe-stats-11318.py')
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
from vampir_core import stat_change_11318 as codec


def batch(records=(), *, packet=322, key=42, sequence=1, previous=None):
    body = struct.pack('<QH', key, len(records)) + b''.join(struct.pack('<iqq', *row) for row in records)
    if packet == 322:
        body += struct.pack('<BH', 1, 0)
    rows = [dict(seq=sequence, packet_id=packet, body_base64=base64.b64encode(body).decode())]
    return dict(state=dict(schema=2, bot_id='owned', session_id='session', state='connected',
        character=dict(key='42', world_id=10012, hp=None)),
        events=dict(gap=False), samples=dict(bot_id='owned', session_id='session',
        source_sha256=observer.SOURCE, samples=rows, cursor=sequence, gap=False), previous=previous or {})


class LiveStatsObserver11318Tests(unittest.TestCase):
    def observed(self, value):
        with patch.object(observer, 'load_codec', return_value=codec):
            return observer.analyze(value)

    def test_real_small_proof_gate_checks_current_codec_without_native_execution(self):
        result = observer.load_codec()
        self.assertIs(result, codec)
        with patch.object(observer, 'CODEC_SHA', '0' * 64), self.assertRaisesRegex(ValueError, 'decoder evidence'):
            observer.load_codec()

    def test_packet_binding_numeric_id_reader_and_constructor_are_all_required(self):
        for packet_id, expected in observer.PACKET_BINDINGS.items():
            report = observer.pinned_document('code-clues/stat-packet-bindings-11318', expected)
            observer.packet_binding_verified(report, int(packet_id))
            for changes in ({'binding_verified': False}, {'packet_id': 999}, {'reader': '0x0'},
                            {'candidate_table': '0x0'}, {'id_getter_bytes': 'b800000000c3'},
                            {'reviewed_constructors': []}, {'tool_sha256': '0' * 64}):
                with self.subTest(packet_id=packet_id, changes=changes), self.assertRaises(ValueError):
                    observer.packet_binding_verified(dict(report, **changes), int(packet_id))
            changed = copy.deepcopy(report);changed['slots'][4] = '0x0'
            with self.assertRaises(ValueError):observer.packet_binding_verified(changed, int(packet_id))

    def test_stat_enum_proof_roles_descriptor_uniqueness_and_producer_must_match(self):
        report = observer.pinned_document('knowledge/stat-enums-11318', observer.ENUM_SHA)
        observer.enum_verified(report)
        for changes in ({'source_sha256': '0' * 64}, {'known_vital_ids_match': False},
                        {'tool_sha256': '0' * 64}, {'producer_sha256': '0' * 64}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                observer.enum_verified(dict(report, **changes))
        for index, changes in ((4, {'name': 'EStat::UnexpectedHp'}),
                               (4, {'value': 9}), (4, {'descriptor_offset': -1})):
            changed = copy.deepcopy(report);changed['enums']['EStat'][index].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):observer.enum_verified(changed)
        with patch.object(observer, 'FIELDS', {3: 'hp'}), self.assertRaises(ValueError):
            observer.enum_verified(report)

    def test_tampered_packet_and_enum_immutable_manifests_fail_hash_gate(self):
        for relative, expected in (('code-clues/stat-packet-bindings-11318', observer.PACKET_BINDINGS['321']),
                                   ('knowledge/stat-enums-11318', observer.ENUM_SHA)):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / relative / expected / 'manifest.json'
                target.parent.mkdir(parents=True)
                target.write_bytes((observer.ROOT / relative / expected / 'manifest.json').read_bytes() + b' ')
                with patch.object(observer, 'ROOT', Path(directory)), self.assertRaisesRegex(ValueError, 'proof changed'):
                    observer.pinned_document(relative, expected)

    def test_matching_notification_updates_separate_partial_view_without_owner_mutation(self):
        value = batch([(3, 0, 1), (4, 2, 700), (5, 3, 1000), (9, 4, 20), (10, 5, 50), (134, 9, 2**63-1)])
        before = copy.deepcopy(value)
        result = self.observed(value)['readonly_stats']
        self.assertEqual(result['status'], 'observed_partial')
        self.assertEqual(result['vitals'], dict(level=1, hp=700, max_hp=1000, mp=20, max_mp=50))
        self.assertEqual(result['last_sample'], dict(seq=1, packet_id=322))
        self.assertEqual(result['stats'][-1], dict(id=134, value=str(2**63-1)))
        self.assertFalse(result['owner_character_modified'])
        self.assertEqual(value, before)

    def test_empty_and_foreign_key_do_not_seed_fake_vitals(self):
        value = batch();value['samples']['samples'] = [];value['samples']['cursor'] = 0
        for item in (value, batch([(4, 0, 999)], key=43)):
            result = self.observed(item)['readonly_stats']
            self.assertEqual(result['status'], 'waiting_for_notification')
            self.assertTrue(all(n is None for n in result['vitals'].values()))
            self.assertEqual(result['stats'], [])

    def test_level_packet_partial_values_merge_only_with_same_observed_scope(self):
        previous = self.observed(batch([(4, 0, 700), (5, 0, 1000)]))
        value = batch([(3, 0, 2)], packet=321, sequence=2, previous=previous)
        result = self.observed(value)['readonly_stats']
        self.assertEqual(result['vitals']['hp'], 700)
        self.assertEqual(result['vitals']['level'], 2)
        for changes in ({'character_key': '43'}, {'session_id': 'other'}, {'world_id': '10013'},
                        {'source_sha256': '0' * 64}, {'provenance': {}}):
            mutated = copy.deepcopy(value)
            mutated['previous']['readonly_stats'].update(changes)
            self.assertIsNone(self.observed(mutated)['readonly_stats']['vitals']['hp'])

    def test_source_session_and_connection_changes_fail_closed_before_decode(self):
        for target, changes in (('samples', {'source_sha256': '0' * 64}),
                ('samples', {'session_id': 'other'}), ('samples', {'bot_id': 'other'}),
                ('state', {'state': 'disconnected'})):
            value = batch([(4, 0, 99)]);value[target].update(changes)
            with patch.object(observer, 'load_codec', side_effect=AssertionError('Gate must not run')):
                result = observer.analyze(value)['readonly_stats']
            self.assertEqual(result['status'], 'unavailable')
            self.assertEqual(result['stats'], [])
        with patch.object(observer, 'load_codec', side_effect=ValueError('Changed proof')):
            result = observer.analyze(batch([(4, 0, 99)]))['readonly_stats']
        self.assertEqual(result['reason'], 'decoder_proof_not_verified')

    def test_gap_and_malformed_body_clear_previous_values_and_duplicate_is_ignored(self):
        previous = self.observed(batch([(4, 0, 700)]))
        for gap in ('samples', 'events'):
            value = batch([], sequence=2, previous=previous)
            value['samples']['samples'] = []
            value[gap]['gap'] = True
            self.assertIsNone(self.observed(value)['readonly_stats']['vitals']['hp'])
        value = batch([], sequence=2, previous=previous)
        value['samples']['samples'][0]['body_base64'] = 'broken!'
        result = self.observed(value)['readonly_stats']
        self.assertIsNone(result['vitals']['hp'])
        self.assertEqual(result['malformed_samples'], 1)
        self.assertEqual(result['reason'], 'malformed_notification')
        value = batch([(4, 0, 900)], sequence=1, previous=previous)
        self.assertEqual(self.observed(value)['readonly_stats']['vitals']['hp'], 700)

    def test_unsafe_display_numbers_stay_unknown_and_output_is_bounded(self):
        result = self.observed(batch([(4, 0, -1), (5, 0, 2**63-1), (9, 0, 0)]))['readonly_stats']
        self.assertIsNone(result['vitals']['hp'])
        self.assertIsNone(result['vitals']['max_hp'])
        self.assertEqual(result['vitals']['mp'], 0)
        value = batch();value['samples']['samples'] *= 33
        with self.assertRaisesRegex(ValueError, 'budget'):
            self.observed(value)
        value = batch();value['samples']['samples'][0]['body_base64'] = 'A' * 87385
        self.assertEqual(self.observed(value)['readonly_stats']['malformed_samples'], 1)


if __name__ == '__main__':
    unittest.main()
