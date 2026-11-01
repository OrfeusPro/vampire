import copy
import unittest
from test_vampir_update_contracts import load


class BackendWireContractsTests(unittest.TestCase):
    def setUp(self):
        self.contract = load('login-backend-wire-case-contracts')
        self.oracle = load('login-backend-wire-oracle')

    def prepared(self):
        return dict(strings={hex(o): '' for k, o in self.oracle.FIELDS if k == 'string'},
            integers={hex(o): 0 for k, o in self.oracle.FIELDS if k != 'string'})

    def test_complete_input_matrix_and_branch_totals(self):
        self.assertEqual(self.contract.summary(), dict(cases=1807, prepared_inputs=224,
            core=1792, focused_negative=15, pending_suppressed=448, sequence_wraps=444,
            transport_result0=672, transport_result1=672, backend_calls=1359,
            state_getter_calls=1356, fallback_calls=6, writer_calls=1344,
            transport_calls=1344, archive_constructor_calls=2688,
            archive_cleanup_calls=2688, initial_growth_calls=2688))

    def test_pending_hit_does_not_claim_unused_transport_outcome(self):
        rows = [s for s in self.contract.scenarios() if s['pending_case'] == 'heap-chain-hit']
        self.assertEqual(len(rows), 448)
        for spec in rows:
            flow = self.contract.expected_flow(spec)
            self.assertIsNone(flow['backend_return_al'])
            self.assertEqual(flow['backend_calls'], 0)
            self.assertEqual(flow['writer_calls'], 0)
            self.assertEqual(flow['sequence_before'], flow['sequence_after'])

    def test_negative_gates_reached_without_writer_and_keep_nonzero_sequence(self):
        rows = self.contract.scenarios()[1792:]
        self.assertEqual({s['sequence_seed'] for s in rows}, {0, 0xfffe, 0xffff})
        for spec in rows:
            flow = self.contract.expected_flow(spec)
            self.assertEqual(flow['backend_calls'], 1)
            self.assertEqual(flow['writer_calls'], 0)
            self.assertEqual(flow['sequence_before'], flow['sequence_after'])
            self.assertEqual(flow['backend_return_al'], 0)
            self.assertEqual(flow['fallback_calls'], int(spec['backend_case'] in
                ('mode2action', 'mode2action-otherflag')))

    def test_debug_short_circuit_uses_distinct_diagnostic_words(self):
        found = {s['debug_case']: s for s in self.contract.scenarios()
            if s['group'] == 'core' and s['pending_case'] == 'empty-count-equal'}
        for name, (second, offset, ids) in dict(off=(1, 4, 1),
                firsttrue=(0, 0, 2), secondtrue=(1, 0, 2)).items():
            flow = self.contract.expected_flow(found[name])
            self.assertEqual(flow['diagnostic_words'], [1, 0])
            self.assertEqual((flow['debug_second_calls'], flow['selected_diagnostic_offset'],
                              flow['request_id_calls']), (second, offset, ids))

    def test_spec_rejects_dimension_drift_and_boolean_as_integer(self):
        spec = self.contract.scenarios()[0]
        for key, value in (('prepared_ordinal', 1), ('transport_result_byte', True),
                ('sequence_seed', 1), ('debug_case', 'firsttrue'), ('global_disabled', 1),
                ('backend_case', 'new'), ('extra', 0)):
            bad = copy.deepcopy(spec)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.contract.validate_spec(bad)
        negative = copy.deepcopy(self.contract.scenarios()[1792])
        negative['pending_case'] = 'heap-chain-hit'
        with self.assertRaises(ValueError):
            self.contract.validate_spec(negative)

    def test_wire_golden_order_raw_boolean_bytes_and_utf8_length(self):
        prepared = self.prepared()
        prepared['strings']['0x10'] = 'Ж🙂'
        prepared['integers']['0x50'] = 0x12345678
        prepared['integers']['0x98'] = 0xf3
        prepared['integers']['0x130'] = 0x80
        prepared['integers']['0x131'] = 0xff
        actual = self.oracle.login_body(prepared)
        # Six UTF-8 bytes, not three UTF-16 code units; DWORD after four strings.
        self.assertEqual(actual[:18].hex(), '0600d096f09f998200000000000078563412')
        self.assertEqual(actual[26], 0xf3)
        self.assertEqual(actual[-2:], b'\x80\xff')
        self.assertEqual(len(actual), 65)

    def test_frame_golden_id_old_sequence_low24_length_and_fixture_checksum(self):
        actual = self.oracle.frame(b'\xa5\x5a', 0xffff)
        self.assertEqual(actual.hex(), '0d000067e6096a0300ffffa55a')
        self.assertEqual(int.from_bytes(actual[:3], 'little'), len(actual))
        self.assertEqual(actual[7:9], b'\x03\x00')
        self.assertEqual(actual[9:11], b'\xff\xff')
        with self.assertRaises(ValueError):
            self.oracle.frame(b'a'*1013, 0)

    def test_actual_frame_rejects_changed_prefix_id_sequence_checksum_or_body(self):
        prepared = self.prepared()
        actual = self.oracle.frame(self.oracle.login_body(prepared), 0xfffe)
        self.assertEqual(self.oracle.validate_frame(actual, prepared, 0xfffe), actual)
        for offset in (0, 3, 7, 9, len(actual)-1):
            bad = bytearray(actual)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.oracle.validate_frame(bytes(bad), prepared, 0xfffe)

    def test_input_fields_encoding_bounds_and_schema_are_strict(self):
        base = self.prepared()
        for group, key, value in (('strings', '0x10', '\ud800'),
                ('strings', '0x10', 'a\0b'), ('strings', '0x10', 'a'*1024),
                ('integers', '0x50', True), ('integers', '0x98', 256)):
            bad = copy.deepcopy(base)
            bad[group][key] = value
            with self.subTest(group=group, value=repr(value)[:20]), self.assertRaises(ValueError):
                self.oracle.login_body(bad)
        schema = dict(object_size=320, fields=[list(f) for f in self.oracle.FIELDS])
        self.oracle.validate_schema(schema)
        schema['fields'][-1][1] -= 1
        with self.assertRaises(ValueError):
            self.oracle.validate_schema(schema)


if __name__ == '__main__':
    unittest.main()
