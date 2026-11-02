"""Точные parent links и сохранение отказов; native engine замокан."""
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


verifier = load('verify-service-lifecycle-context')
contract, oracle = load('service-lifecycle-case-contracts'), load('service-lifecycle-oracle')


def dependency_fixture():
    def pointer(letter):
        return dict(path='fixture/' + letter + '/manifest.json', sha256=letter * 64)
    parent_pointer, check_pointer, proof_pointer = [pointer(k) for k in ('b', 'c', 'd')]
    source = 'a' * 64
    context = dict(source_sha256=source, backend_context=parent_pointer,
                   backend_check=check_pointer, transfer_proof=proof_pointer)
    parent = dict(source_sha256=source, family='login-backend-wire', transfer_proof=pointer('e'))
    report = dict(source_sha256=source, method='bounded_native', scope='bounded_native_login_backend_wire',
        context_sha256=parent_pointer['sha256'], proof=parent['transfer_proof'])
    proof = dict(target=dict(source_sha256=source),
                 dependencies=dict(backend=parent_pointer, backend_check=check_pointer))
    graph = {'b' * 64: parent, 'c' * 64: report, 'd' * 64: proof}
    core = SimpleNamespace(checked=lambda root, ptr, category: graph[ptr['sha256']])
    def report_valid(actual, context, sha):
        if (actual['context_sha256'] != sha or actual['proof'] != context['transfer_proof']
                or actual['method'] != 'bounded_native'
                or actual['scope'] != 'bounded_native_login_backend_wire'):
            raise ValueError('Rejected parent binding')
    api = SimpleNamespace(report_valid=mock.Mock(side_effect=report_valid))
    modules = {'update-native-login-backend-wire': SimpleNamespace(select=mock.Mock(return_value=api))}
    return context, graph, core, modules, api


class ServiceLifecycleDependencyTests(unittest.TestCase):
    def test_parent_accepted_report_is_validated_without_loading_parent_verifier(self):
        context, graph, core, modules, api = dependency_fixture()
        with mock.patch.object(verifier, 'load', side_effect=modules.__getitem__) as loader:
            actual = verifier.dependencies(context, Path('fixture-root'), core)
        self.assertIs(actual, graph['b' * 64])
        api.report_valid.assert_called_once_with(graph['c' * 64], actual, 'b' * 64)
        self.assertEqual([call.args[0] for call in loader.call_args_list], ['update-native-login-backend-wire'])

    def test_wrong_source_parent_proof_context_and_dependency_pair_are_rejected(self):
        for mutation in ('source', 'family', 'report-context', 'report-proof', 'method',
                'scope', 'target', 'parent-link', 'check-link', 'extra-parent'):
            context, graph, core, modules, api = dependency_fixture()
            parent, report, proof = [graph[k * 64] for k in ('b', 'c', 'd')]
            if mutation == 'source':
                parent['source_sha256'] = '0' * 64
            elif mutation == 'family':
                parent['family'] = 'frame-integrity'
            elif mutation == 'report-context':
                report['context_sha256'] = '0' * 64
            elif mutation == 'report-proof':
                report['proof'] = dict(path='foreign', sha256='0' * 64)
            elif mutation in ('method', 'scope'):
                report[mutation] = 'foreign'
            elif mutation == 'target':
                proof['target']['source_sha256'] = '0' * 64
            elif mutation == 'parent-link':
                proof['dependencies']['backend'] = dict(path='foreign', sha256='0' * 64)
            elif mutation == 'check-link':
                proof['dependencies']['backend_check'] = dict(path='foreign', sha256='0' * 64)
            else:
                proof['dependencies']['frame'] = dict(path='foreign', sha256='0' * 64)
            with self.subTest(mutation=mutation), \
                    mock.patch.object(verifier, 'load', side_effect=modules.__getitem__), \
                    self.assertRaises(ValueError):
                verifier.dependencies(context, Path('fixture-root'), core)


class ServiceLifecycleFailureTests(unittest.TestCase):
    def invoke_failure(self, actual=None):
        context = dict(source_sha256='a' * 64, transfer_proof=dict(path='fixture', sha256='b' * 64))
        snapshot = mock.Mock(return_value=Path('fixture-failure.json'))
        run = mock.Mock(return_value=actual, side_effect=ValueError('retired service read') if actual is None else None)
        modules = {'portable-native-family': object(), 'service-lifecycle-case-contracts': contract,
            'service-lifecycle-oracle': oracle,
            'service-lifecycle-harness': SimpleNamespace(make_harness=mock.Mock(return_value=SimpleNamespace())),
            'service-lifecycle-runtime': SimpleNamespace(install=mock.Mock(return_value=run)),
            'research-workflow': SimpleNamespace(snapshot=snapshot)}
        with mock.patch.object(verifier, 'dependencies', return_value={}), \
                mock.patch.object(verifier, 'load', side_effect=modules.__getitem__), \
                mock.patch.object(contract, 'tools', return_value={'fixture.py': 'c' * 64}), \
                self.assertRaisesRegex(ValueError, 'diagnostic'):
            verifier.verify(context, Path('fixture-root'))
        run.assert_called_once()
        return snapshot.call_args.args[2]

    def test_guard_failure_never_manufactures_a_completed_round(self):
        payload = self.invoke_failure()
        self.assertFalse(payload['accepted'])
        self.assertFalse(payload['actual_row_available'])
        self.assertIsNone(payload['actual'])
        self.assertIsNone(payload['expected'])
        self.assertEqual(payload['differences'], [])
        self.assertEqual(payload['state'], 'native_execution_failure')
        self.assertIn('retired service read', payload['error'])
        self.assertEqual(payload['error_type'], 'ValueError')
        self.assertIn('verify-service-lifecycle-context.py', payload['traceback'])
        self.assertIn('ValueError: retired service read', payload['traceback'])

    def test_completed_wrong_counter_preserves_actual_observation_and_typed_difference(self):
        spec = contract.scenarios()[0]
        actual = oracle.expected_case(spec)
        actual['observation']['rounds'][0]['atomic_transitions'][0]['after'] = 1
        payload = self.invoke_failure(actual)
        self.assertTrue(payload['actual_row_available'])
        self.assertEqual(payload['actual'], actual)
        self.assertEqual(payload['spec'], spec)
        self.assertIn('$.observation.rounds[0].atomic_transitions[0].after',
                      [d['path'] for d in payload['differences']])
        self.assertFalse(payload['network_used'])

    def test_differences_are_typed_and_bounded(self):
        self.assertTrue(verifier.differences(True, 1))
        self.assertEqual(len(verifier.differences({str(i): i for i in range(100)}, {}, limit=3)), 3)


if __name__ == '__main__':
    unittest.main()
