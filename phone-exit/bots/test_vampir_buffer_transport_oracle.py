"""Byte-level independent expectations; no native engine or EXE is loaded."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract, oracle = load('buffer-transport-case-contracts'), load('buffer-transport-oracle')


def observed(case_id):
    spec = next(s for s in contract.scenarios() if s['case_id'] == case_id)
    return oracle.expected_case(spec)['observation']['steps']


class BufferTransportOracleTests(unittest.TestCase):
    def test_shrink_keeps_removed_bytes_but_regrowth_zeros_them(self):
        initial = contract.pattern(4)
        shrink = observed('resize-00')[0]
        self.assertEqual(shrink['payload_hex'], '')
        self.assertEqual(bytes.fromhex(shrink['spare_hex']), initial + b'\x5a' * 4)
        self.assertEqual(shrink['events'], [])
        reuse = observed('resize-31')
        self.assertEqual(reuse[0]['spare_hex'], shrink['spare_hex'])
        self.assertEqual(reuse[1]['events'], [])
        self.assertEqual(bytes.fromhex(reuse[2]['payload_hex']), bytes(3))
        self.assertEqual(bytes.fromhex(reuse[2]['spare_hex']), initial[3:] + b'\x5a' * 4)

    def test_even_odd_growth_and_alignment_boundaries_are_distinct(self):
        self.assertEqual([observed('resize-' + str(i))[0]['capacity'] for i in (16, 17, 18, 19)],
                         [15, 15, 15, 16])
        self.assertEqual([observed('resize-' + str(i))[0]['capacity'] for i in (20, 21, 22)],
                         [13, 13, 14])
        small, aligned = observed('resize-23')[0], observed('resize-24')[0]
        self.assertEqual((small['capacity'], aligned['capacity']), (4095, 4096))
        self.assertEqual(small['events'][0], dict(kind='allocate', size=4095))
        self.assertEqual(aligned['events'][0], dict(kind='allocate', size=4135))
        self.assertEqual(observed('resize-26')[0]['events'][-1], dict(kind='free', size=4135))

    def test_growth_orders_zero_copy_free_and_preserves_only_logical_prefix(self):
        step = observed('resize-16')[0]
        self.assertEqual(step['events'], [dict(kind='allocate', size=15),
            dict(kind='memset', size=7), dict(kind='memmove', size=4), dict(kind='free', size=10)])
        self.assertEqual(bytes.fromhex(step['payload_hex']), contract.pattern(4) + bytes(7))
        self.assertEqual(bytes.fromhex(step['spare_hex']), b'\x5a' * 4)

    def test_empty_append_allocates_a_terminator_and_reuse_preserves_raw_nul(self):
        empty = observed('append-00')[0]
        self.assertEqual((empty['size'], empty['capacity'], empty['payload_hex']), (1, 1, '00'))
        self.assertEqual(empty['events'][-1], dict(kind='memcpy', size=0))
        reuse = observed('append-10')
        self.assertEqual(bytes.fromhex(reuse[-1]['payload_hex']), b'a\0bc\0def\0')
        self.assertEqual(reuse[3]['events'], [dict(kind='memcpy', size=0)])

    def test_transport_predicates_gate_wake_but_never_append(self):
        rows = [observed('transport-' + str(i).zfill(2))[0] for i in range(6)]
        self.assertTrue(all(s['calls']['append'] == s['calls']['transport'] == 1 for s in rows))
        self.assertEqual([s['wake_arguments_checked'] for s in rows], [True, None, None, None, None, None])
        self.assertTrue(all(s['return_al'] == 1 for s in rows))
        paired = observed('transport-06')
        self.assertEqual(bytes.fromhex(paired[-1]['payload_hex']), b'ab\0c\0')
        self.assertEqual([sum(e['kind'] == 'wake' for e in s['events']) for s in paired], [0, 0, 1, 0, 1])

    def test_archive_flags_and_last_nonzero_count_are_separate(self):
        rows = observed('archive-02')
        self.assertEqual(rows[0]['archive'], dict(capacity=1024, cursor=7, count=7,
            flags_bits=0xffffffff, last_count=7, payload_hex=b'abc\0def'.hex()))
        self.assertEqual(rows[1]['archive'], rows[0]['archive'])
        self.assertEqual(rows[1]['events'], [])
        self.assertEqual(rows[1]['calls']['archive_raw'], 1)
        self.assertEqual(rows[1]['calls']['set_count'], 0)
        cumulative = observed('archive-09')
        self.assertEqual((cumulative[-1]['archive']['count'], cumulative[-1]['archive']['last_count']), (1027, 2))
        self.assertEqual(cumulative[-1]['archive']['flags_bits'], 0xffffffff)

    def test_spare_payload_order_and_ownership_forgeries_are_detected(self):
        spec = next(s for s in contract.scenarios() if s['case_id'] == 'resize-16')
        for mutation in ('spare', 'order', 'ownership', 'bytes', 'extra'):
            row = oracle.expected_case(spec)
            step = row['observation']['steps'][0]
            if mutation == 'spare':
                step['spare_hex'] = '00' * 4
            elif mutation == 'order':
                step['events'][1], step['events'][2] = step['events'][2], step['events'][1]
            elif mutation == 'ownership':
                row['observation']['ownership_checked'] = False
            elif mutation == 'bytes':
                step['payload_hex'] = '00' * 11
            else:
                step['unproved_socket_success'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                oracle.validate_case(row, spec)


if __name__ == '__main__':
    unittest.main()
