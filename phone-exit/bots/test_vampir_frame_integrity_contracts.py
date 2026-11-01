"""Pure matrix and admission tests; synthetic rows are not native evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract = load('frame-integrity-case-contracts')
oracle = load('frame-integrity-oracle')


def fixture_prepared():
    """Explicit test fields, never presented as accepted parent/native bytes."""
    result = {}
    for ordinal, _, _ in contract.PREPARED_INPUTS:
        strings = {hex(offset): '' for offset in oracle.HANDOFF.STRING_OFFSETS}
        strings['0x10'] = 'fixture-' + str(ordinal) + '-Ж🙂'
        integers = {hex(offset): 0 for offset in oracle.HANDOFF.SCALAR_WIDTHS}
        integers.update({'0x50': ordinal, '0x120': 0 if ordinal == 8 else 0xffffffff,
                         '0x130': 0x80, '0x131': 0xff})
        result[ordinal] = dict(strings=strings, integers=integers)
    return result


class FrameIntegrityInputTests(unittest.TestCase):
    def test_exact_103_primitive_plus10_native_backend_entry_recipe(self):
        specs = contract.scenarios()
        self.assertEqual(len(specs), 113)
        self.assertEqual(len({contract.canonical(s) for s in specs}), 113)
        self.assertEqual([sum(s['operation'] == op for s in specs)
                          for op in ('init', 'crc', 'xor', 'backend')], [3, 30, 70, 10])
        for spec in specs:
            contract.validate_spec(spec)
        self.assertEqual(contract.matrix_sha256(),
            '51dd2a0d8ecd526cf14a088f10743737d085c5e224dc5b4c895cd6aa733e4129')

    def test_signed_width_empty_unaligned_and_alias_axes_are_explicit(self):
        specs = contract.primitive_specs()
        for spec in specs:
            if spec['operation'] == 'crc':
                self.assertEqual(sum(spec['chunks']), len(bytes.fromhex(spec['payload_hex'])))
            if spec['operation'] == 'xor' and spec['in_place']:
                self.assertEqual(spec['source_offset'], spec['destination_offset'])
        signed = [s for s in specs if s['operation'] == 'xor' and s['group'] == 'signed']
        self.assertEqual({s['length_bits'] for s in signed}, {0x80000000, 0xffffffff})
        self.assertTrue(all(s['unmapped_data'] and not s['payload_hex'] for s in signed))
        crcs = [s for s in specs if s['operation'] == 'crc']
        self.assertEqual({s['state_offset'] for s in crcs if s['group'] == 'incremental'}, {0, 1, 3})
        self.assertTrue(any(s['r8_high32'] and s['unmapped_source'] for s in crcs))

    def test_paired_entries_preserve_backend_and_native_sequence_boundary(self):
        specs = contract.integration_specs()
        self.assertEqual({s['prepared_ordinal'] for s in specs}, {8, 5, 0, 16})
        self.assertEqual({s['key_bits'] for s in specs},
                         {0, 1, contract.ASYMMETRIC_KEY, (1 << 64) - 1})
        self.assertEqual([s['transport_result_byte'] for s in specs].count(0), 5)
        first, second = specs[-2:]
        self.assertEqual((first['reuse_step'], second['reuse_step']), (0, 1))
        self.assertEqual(first['prepared_ordinal'], second['prepared_ordinal'])
        self.assertEqual((first['sequence_seed'] + 1) & 0xffff, second['sequence_seed'])
        self.assertNotEqual(first['key_bits'], second['key_bits'])

    def test_extra_fields_wrong_types_and_substituted_entry_mode_are_rejected(self):
        original = contract.scenarios()[0]
        for key, value in (('raw_state_seed', False), ('entry_mode', 'backend'),
                           ('state_offset', 0.0), ('extra', 1)):
            spec = copy.deepcopy(original)
            spec[key] = value
            with self.assertRaises(ValueError):
                contract.validate_spec(spec)
        changed = contract.scenarios()
        changed[0]['raw_state_seed'] = 99
        self.assertEqual(contract.scenarios()[0]['raw_state_seed'], 0)


class FrameIntegrityAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = fixture_prepared()
        cls.parent = dict(source_sha256='a' * 64, metadata_fields=[dict(key='fixture')])
        cls.context = dict(family=contract.FAMILY, format=contract.FORMAT,
                           source_sha256='a' * 64, **contract.EXTENTS)
        cls.rows = [oracle.expected_case(spec, cls.prepared) for spec in contract.scenarios()]
        cls.report = dict(schema=1, source_sha256='a' * 64, method='bounded_native',
            scope=contract.SCOPE, cases=cls.rows, matrix_sha256=contract.matrix_sha256(),
            metadata_fields=cls.parent['metadata_fields'], summary=contract.observed_summary(cls.rows),
            **contract.EXTENTS, **dict.fromkeys(contract.TRUE_FLAGS, True),
            **dict.fromkeys(contract.FALSE_FLAGS, False))

    def validate(self, report):
        fake_oracle = mock.Mock(prepared_rows=mock.Mock(return_value=self.prepared),
            validate_case=oracle.validate_case, expected_case=oracle.expected_case)
        with mock.patch.object(contract, 'load', return_value=fake_oracle):
            contract.validate_report(report, self.context, self.parent)

    def test_summary_separates_cases_helper_calls_and_backend_entries(self):
        self.validate(self.report)
        s = self.report['summary']
        self.assertEqual((s['cases'], s['checksum_init_calls'], s['checksum_update_calls'],
                          s['transform_calls'], s['backend_entries']), (113, 40, 56, 80, 10))
        self.assertEqual((s['sequence_wraps'], s['paired_reuses']), (3, 1))
        self.assertEqual((s['archive_constructor_calls'], s['archive_cleanup_calls']), (20, 20))

    def test_reorder_duplicate_and_missing_actual_observation_are_not_admitted(self):
        for replacement in ('reorder', 'duplicate', 'missing'):
            report = copy.deepcopy(self.report)
            if replacement == 'reorder':
                report['cases'][0], report['cases'][1] = report['cases'][1], report['cases'][0]
            elif replacement == 'duplicate':
                report['cases'][1] = copy.deepcopy(report['cases'][0])
            else:
                del report['cases'][0]['observation']['state_after']
            with self.assertRaises(ValueError):
                self.validate(report)

    def test_old_fixture_scope_false_native_flags_and_forged_summary_are_rejected(self):
        for path, value in (('native_checksum_used', False), ('native_transform_used', False),
                            ('native_prepare_used', True), ('native_transport_used', True),
                            ('metadata_fields', []), ('summary', {}), ('source_sha256', 'bad')):
            report = copy.deepcopy(self.report)
            report[path] = value
            with self.assertRaises(ValueError):
                self.validate(report)


if __name__ == '__main__':
    unittest.main()
