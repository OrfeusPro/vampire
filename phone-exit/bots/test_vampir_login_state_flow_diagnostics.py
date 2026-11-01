"""Pure bounded diagnostic diff and immutable failure-publication contracts."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'
s = importlib.util.spec_from_file_location('state_flow_diagnostics', HERE / 'login-state-flow-diagnostics.py')
diagnostics = importlib.util.module_from_spec(s); s.loader.exec_module(diagnostics)


class StateFlowDiagnosticTests(unittest.TestCase):
    def test_equal_rows_produce_no_differences(self):
        self.assertEqual(diagnostics.differences(dict(a=[1, None, True]), dict(a=[1, None, True])), [])

    def test_strict_boolean_integer_type_is_reported_at_nested_path(self):
        row = diagnostics.differences(dict(continuation=dict(reset_calls=True)), dict(continuation=dict(reset_calls=1)))
        self.assertEqual(row, [dict(path='$["continuation"]["reset_calls"]', reason='type',
            actual_type='boolean', wanted_type='integer', actual='true', wanted='1')])

    def test_events_count_and_first_value_difference_are_retained(self):
        row = diagnostics.differences(dict(events=[dict(second=1238083864)]), dict(events=[dict(second=0), dict(second=0)]))
        self.assertEqual([item['path'] for item in row], ['$["events"].length', '$["events"][0]["second"]'])
        self.assertEqual([item['reason'] for item in row], ['length', 'value'])

    def test_missing_extra_fields_and_key_order_are_deterministic(self):
        row = diagnostics.differences(dict(z=3, common=1), dict(a=2, common=1))
        self.assertEqual([(item['path'], item['reason']) for item in row],
            [('$["a"]', 'missing_actual'), ('$["z"]', 'unexpected_actual')])

    def test_error_summary_has_exact_count_and_value_bounds(self):
        row = diagnostics.differences(['a' * 1000] * 20, ['b' * 1000] * 20, limit=3, value_chars=32)
        self.assertEqual(len(row), 3)
        self.assertTrue(all(len(item['actual']) == 32 and len(item['wanted']) == 32 for item in row))
        self.assertTrue(all(item['actual'].endswith('\u2026') for item in row))

    def test_depth_bound_preserves_nested_bool_integer_difference(self):
        row = diagnostics.differences(dict(a=dict(b=True)), dict(a=dict(b=1)), max_depth=1)
        self.assertEqual(len(row), 1)
        self.assertEqual((row[0]['path'], row[0]['reason']), ('$["a"]', 'depth_limit'))

    def test_invalid_bounds_or_nonfinite_payload_are_not_silently_coerced(self):
        for arguments in (dict(limit=0), dict(limit=True), dict(limit=65), dict(max_depth=0), dict(value_chars=15)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                diagnostics.differences({}, {}, **arguments)
        with self.assertRaises(ValueError): diagnostics.differences(float('nan'), 0)

    def test_failure_payload_keeps_independent_full_actual_wanted_spec(self):
        actual, wanted, spec = dict(events=[dict(second=1238083864)]), dict(events=[dict(second=0)]), dict(label='post-00-cont-00')
        payload = diagnostics.failure_payload(actual, wanted, spec, source_sha256='a' * 64)
        self.assertFalse(payload['accepted'])
        self.assertEqual(payload['method'], 'bounded_native_failure_diagnostic')
        self.assertEqual(payload['source_sha256'], 'a' * 64)
        self.assertEqual(payload['actual'], actual); self.assertEqual(payload['wanted'], wanted)
        actual['events'][0]['second'] = 0; spec['label'] = 'changed'
        self.assertEqual(payload['actual']['events'][0]['second'], 1238083864)
        self.assertEqual(payload['label'], 'post-00-cont-00')
        self.assertTrue(all(payload[key] is False for key in ('network_used', 'profile_activated', 'runtime_activated')))

    def test_no_equal_row_or_approximate_sha_can_be_failure_evidence(self):
        with self.assertRaises(ValueError): diagnostics.failure_payload({}, {}, {}, source_sha256='a' * 64)
        for sha in ('a' * 63, 'current', True, None):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                diagnostics.failure_payload({'x': 1}, {'x': 2}, {}, source_sha256=sha)

    def test_mismatch_publishes_once_and_raises_with_pointer_and_paths(self):
        snapshot = Mock(return_value=Path('F:/resource/failure-sha/manifest.json'))
        with self.assertRaisesRegex(ValueError, 'diagnostic=.*manifest.json; differences=') as caught:
            diagnostics.raise_mismatch({'second': 7}, {'second': 0}, dict(label='post-00-cont-00'),
                source_sha256='a' * 64, root=Path('F:/resource'), snapshot=snapshot)
        self.assertIn('$["second"]:value', str(caught.exception))
        snapshot.assert_called_once()
        args = snapshot.call_args.args
        self.assertEqual(args[:2], (Path('F:/resource'), 'native-login-state-flow-failures'))
        self.assertFalse(args[2]['accepted'])

    def test_snapshot_failure_propagates_without_false_success(self):
        snapshot = Mock(side_effect=OSError('disk-full'))
        with self.assertRaisesRegex(OSError, 'disk-full'):
            diagnostics.raise_mismatch({'x': 1}, {'x': 2}, dict(label='failed'),
                source_sha256='a' * 64, root=Path('F:/resource'), snapshot=snapshot)


    def test_production_failure_keeps_exact_context_proof_and_tool_identity(self):
        identity = dict(family=diagnostics.FAMILY, scope=diagnostics.SCOPE, context_canonical_sha256='b' * 64,
            transfer_proof=dict(path='knowledge/proof/manifest.json', sha256='c' * 64))
        tools = {'G:/repo/login-state-flow-oracle.py': 'd' * 64}
        payload = diagnostics.failure_payload({'x': 1}, {'x': 2}, dict(label='failed'),
            source_sha256='a' * 64, context_identity=identity, tools=tools)
        self.assertEqual(payload['context_identity'], identity)
        self.assertEqual(payload['context_identity']['context_canonical_sha256'], 'b' * 64)
        self.assertNotIn('context_sha256', payload['context_identity'])
        self.assertEqual(payload['tools'], tools)
        identity['transfer_proof']['sha256'] = 'e' * 64; tools.clear()
        self.assertEqual(payload['context_identity']['transfer_proof']['sha256'], 'c' * 64)
        self.assertEqual(len(payload['tools']), 1)

    def test_partial_invalid_or_unhashed_production_identity_is_rejected(self):
        identity = dict(family=diagnostics.FAMILY, scope=diagnostics.SCOPE, context_canonical_sha256='b' * 64,
            transfer_proof=dict(path='knowledge/proof/manifest.json', sha256='c' * 64))
        variants = [dict(context_identity=identity), dict(tools={'tool.py': 'd' * 64}),
            dict(context_identity={}, tools={'tool.py': 'd' * 64}),
            dict(context_identity=identity, tools={'tool.py': 'unhashed'}),
            dict(context_identity=identity, tools={}),
            dict(context_identity=dict(identity, context_canonical_sha256='current'), tools={'tool.py': 'd' * 64}),
            dict(context_identity=dict(identity, transfer_proof={}), tools={'tool.py': 'd' * 64}),
            dict(context_identity=dict(identity, context_sha256='b' * 64), tools={'tool.py': 'd' * 64})]
        invalid_proofs = [dict(path='proof.json'), dict(sha256='c' * 64),
            dict(path='proof.json', sha256='c' * 64, extra='unreviewed'),
            dict(path='', sha256='c' * 64), dict(path='   ', sha256='c' * 64),
            dict(path=True, sha256='c' * 64), dict(path='proof.json', sha256='unhashed'),
            dict(path='proof.json', sha256='c' * 63), dict(path='proof.json', sha256=True)]
        variants.extend(dict(context_identity=dict(identity, transfer_proof=proof), tools={'tool.py': 'd' * 64})
            for proof in invalid_proofs)
        for arguments in variants:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                diagnostics.failure_payload({'x': 1}, {'x': 2}, {}, source_sha256='a' * 64, **arguments)


if __name__ == '__main__': unittest.main()
