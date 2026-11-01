"""Dependency refusal and failure preservation tests; native harness is mocked."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load('verify-frame-integrity-context')
contract = load('frame-integrity-case-contracts')
oracle = load('frame-integrity-oracle')


def dependency_fixture():
    def pointer(letter):
        return dict(path='fixture/' + letter + '/manifest.json', sha256=letter * 64)
    backend_ptr, wire_ptr, proof_ptr = [pointer(x) for x in ('b', 'c', 'd')]
    backend_proof_ptr, backend_check_ptr, prepare_ptr, wire_check_ptr = [pointer(x) for x in ('e', 'f', '1', '2')]
    source = 'a' * 64
    context = dict(source_sha256=source, backend_context=backend_ptr,
                   wire_context=wire_ptr, transfer_proof=proof_ptr)
    backend = dict(source_sha256=source, transfer_proof=backend_proof_ptr, wire_context=wire_ptr)
    wire = dict(source_sha256=source)
    prepare_context = dict(source_sha256=source)
    prepare_report = dict(source_sha256=source)
    backend_report = dict(source_sha256=source, context_sha256=backend_ptr['sha256'], proof=backend_proof_ptr)
    deps = dict(backend=backend_ptr, backend_check=backend_check_ptr,
                wire=wire_ptr, wire_check=wire_check_ptr, prepare_check=prepare_ptr)
    proof = dict(target=dict(source_sha256=source), dependencies=deps)
    backend_proof = dict(target=dict(source_sha256=source), dependencies=dict(
        prepare_check=prepare_ptr, wire_check=wire_check_ptr))
    graph = {backend_ptr['sha256']: backend, wire_ptr['sha256']: wire,
        proof_ptr['sha256']: proof, backend_proof_ptr['sha256']: backend_proof,
        backend_check_ptr['sha256']: backend_report, prepare_ptr['sha256']: prepare_report,
        wire_check_ptr['sha256']: dict(source_sha256=source)}
    core = SimpleNamespace(checked=lambda root, ptr, directory: graph[ptr['sha256']])
    backend_validator = mock.Mock()
    selected_rows = mock.Mock()
    modules = {
        'verify-login-backend-wire-context': SimpleNamespace(dependencies=mock.Mock(
            return_value=(prepare_context, wire, prepare_report))),
        'login-backend-wire-native-contracts': SimpleNamespace(validate_report=backend_validator),
        'frame-integrity-oracle': SimpleNamespace(prepared_rows=selected_rows)}
    return context, graph, core, modules, backend_validator, selected_rows


class FrameIntegrityDependencyTests(unittest.TestCase):
    def test_accepted_parent_report_must_bind_exact_context_proof_and_prepare_dependency(self):
        context, graph, core, modules, validator, selected = dependency_fixture()
        with mock.patch.object(verifier, 'load', side_effect=modules.__getitem__):
            wire, prepared, backend = verifier.dependencies(context, Path('fixture-root'), core)
        validator.assert_called_once()
        selected.assert_called_once_with(prepared, backend)
        self.assertEqual(wire['source_sha256'], 'a' * 64)
        for mutation in ('prepare-link', 'wire-link', 'context-hash', 'proof-binding', 'source'):
            c, g, core, modules, _, _ = dependency_fixture()
            if mutation == 'prepare-link':
                g['d' * 64]['dependencies']['prepare_check'] = dict(path='wrong', sha256='9' * 64)
            elif mutation == 'wire-link':
                g['d' * 64]['dependencies']['wire'] = dict(path='wrong', sha256='9' * 64)
            elif mutation == 'context-hash':
                g['f' * 64]['context_sha256'] = '0' * 64
            elif mutation == 'proof-binding':
                g['f' * 64]['proof'] = dict(path='wrong', sha256='9' * 64)
            else:
                g['2' * 64]['source_sha256'] = '0' * 64
            with self.subTest(mutation=mutation), \
                    mock.patch.object(verifier, 'load', side_effect=modules.__getitem__), \
                    self.assertRaises(ValueError):
                verifier.dependencies(c, Path('fixture-root'), core)


class FrameIntegrityDiagnosticTests(unittest.TestCase):
    def invoke_failed_verifier(self, *, actual=None):
        context = dict(source_sha256='a' * 64, transfer_proof=dict(path='fixture', sha256='b' * 64))
        snapshot = mock.Mock(return_value=Path('fixture-failure.json'))
        native_run = mock.Mock(side_effect=ValueError('guard denied') if actual is None else None,
                               return_value=actual)
        h = SimpleNamespace(uc=object(), evidence={})
        fake_harness = SimpleNamespace(make_harness=mock.Mock(return_value=h),
                                       MemoryPolicy=lambda uc: uc)
        real_oracle = SimpleNamespace(prepared_rows=mock.Mock(return_value={}),
            validate_case=oracle.validate_case, expected_case=oracle.expected_case)
        modules = {'portable-native-family': object(),
            'frame-integrity-case-contracts': contract, 'frame-integrity-oracle': real_oracle,
            'frame-integrity-harness': fake_harness,
            'frame-integrity-runtime': SimpleNamespace(install=mock.Mock(return_value=native_run)),
            'research-workflow': SimpleNamespace(snapshot=snapshot)}
        with mock.patch.object(verifier, 'dependencies', return_value=({}, {}, {})), \
                mock.patch.object(verifier, 'load', side_effect=modules.__getitem__), \
                mock.patch.object(contract, 'tools', return_value={'fixture.py': 'c' * 64}), \
                self.assertRaisesRegex(ValueError, 'diagnostic'):
            verifier.verify(context, Path('fixture-root'))
        native_run.assert_called_once()
        return snapshot.call_args.args[2]

    def test_early_guard_failure_does_not_manufacture_a_successful_actual_row(self):
        payload = self.invoke_failed_verifier()
        self.assertFalse(payload['accepted'])
        self.assertFalse(payload['actual_row_available'])
        self.assertIsNone(payload['actual'])
        self.assertIsNone(payload['expected'])
        self.assertEqual(payload['differences'], [])
        self.assertEqual(payload['state'], 'native_execution_failure')

    def test_completed_wrong_row_retains_concrete_difference_and_exact_spec(self):
        spec = contract.scenarios()[0]
        actual = oracle.expected_case(spec)
        actual['observation']['state_after'] = 0
        payload = self.invoke_failed_verifier(actual=actual)
        self.assertTrue(payload['actual_row_available'])
        self.assertEqual(payload['actual'], actual)
        self.assertEqual(payload['spec'], spec)
        self.assertIn('$.observation.state_after', [r['path'] for r in payload['differences']])
        self.assertFalse(payload['network_used'])
        self.assertFalse(payload['runtime_activated'])

    def test_differences_are_typed_and_bounded(self):
        rows = verifier.differences({str(i): i for i in range(100)}, {}, limit=3)
        self.assertEqual(len(rows), 3)
        self.assertTrue(verifier.differences(False, 0))


if __name__ == '__main__':
    unittest.main()
