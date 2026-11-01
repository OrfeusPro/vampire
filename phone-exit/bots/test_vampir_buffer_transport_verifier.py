"""Parent binding and failure preservation; the native harness is mocked."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load('verify-buffer-transport-context')
contract, oracle = load('buffer-transport-case-contracts'), load('buffer-transport-oracle')
parent_validator = load('update-native-archive-wire').report_valid


def dependency_fixture():
    def pointer(letter):
        return dict(path='fixture/' + letter + '/manifest.json', sha256=letter * 64)
    wire_pointer, check_pointer, proof_pointer = [pointer(k) for k in ('b', 'c', 'd')]
    source = 'a' * 64
    table = bytearray(248)
    struct.pack_into('<Q', table, 136, 0x140001000)
    leaf = dict(bytes='895108c3', size=4,
                sha256=hashlib.sha256(bytes.fromhex('895108c3')).hexdigest())
    context = dict(source_sha256=source, wire_context=wire_pointer, wire_check=check_pointer,
        transfer_proof=proof_pointer, functions={'archive.raw': '0x140001000', 'vector.resize': '0x140002000'},
        source_inputs=dict(archive_table=dict(address='0x140003000', bytes=table.hex())),
        leaves={'0x140004000': '895108c3'})
    wire = dict(family='archive-wire', source_sha256=source, transfer_proof=pointer('e'),
        archive=dict(table='0x140003000', raw='0x140001000', growth='0x140002000'),
        archive_helpers=dict(set_count_leaf='0x140004000'), archive_leaves={'0x140004000': leaf},
        archive_table_sha256=hashlib.sha256(table).hexdigest(),
        layout=dict(archive_bytes=64, archive_slots=dict(raw=136)))
    check = dict(source_sha256=source, method='bounded_native', scope='bounded_native_archive_wire',
        network_used=False, profile_activated=False, runtime_activated=False,
        proof=wire['transfer_proof'], context_sha256=wire_pointer['sha256'], archive=wire['archive'],
        cases=[{} for _ in range(45)], wire_cases=[dict(guards=True) for _ in range(64)])
    proof = dict(target=dict(source_sha256=source),
                 dependencies=dict(wire=wire_pointer, wire_check=check_pointer))
    graph = {'b' * 64: wire, 'c' * 64: check, 'd' * 64: proof}
    core = SimpleNamespace(checked=lambda root, pointer, category: graph[pointer['sha256']])
    modules = {'update-native-archive-wire': SimpleNamespace(report_valid=parent_validator),
               'buffer-transport-case-contracts': contract}
    return context, graph, core, modules


class BufferTransportDependencyTests(unittest.TestCase):
    def test_exact_accepted_parent_is_purely_validated(self):
        context, graph, core, modules = dependency_fixture()
        with mock.patch.object(verifier, 'load', side_effect=modules.__getitem__) as loader:
            wire = verifier.dependencies(context, Path('fixture-root'), core)
        self.assertIs(wire, graph['b' * 64])
        self.assertEqual([call.args[0] for call in loader.call_args_list],
                         ['update-native-archive-wire', 'buffer-transport-case-contracts'])

    def test_wrong_context_proof_source_table_and_set_count_bindings_are_refused(self):
        for mutation in ('parent-context', 'parent-proof', 'source', 'buffer-wire-link',
                'buffer-target', 'table-slot', 'table-hash', 'raw-target', 'set-count', 'extent'):
            context, graph, core, modules = dependency_fixture()
            wire, check, proof = (graph[k * 64] for k in ('b', 'c', 'd'))
            if mutation == 'parent-context':
                check['context_sha256'] = '0' * 64
            elif mutation == 'parent-proof':
                check['proof'] = dict(path='foreign', sha256='0' * 64)
            elif mutation == 'source':
                check['source_sha256'] = '0' * 64
            elif mutation == 'buffer-wire-link':
                proof['dependencies']['wire_check'] = dict(path='foreign', sha256='0' * 64)
            elif mutation == 'buffer-target':
                proof['target']['source_sha256'] = '0' * 64
            elif mutation == 'table-slot':
                wire['layout']['archive_slots']['raw'] = 128
            elif mutation == 'table-hash':
                wire['archive_table_sha256'] = '0' * 64
            elif mutation == 'raw-target':
                context['functions']['archive.raw'] = '0x140001001'
            elif mutation == 'set-count':
                wire['archive_leaves']['0x140004000']['bytes'] = '89510cc3'
            else:
                wire['layout']['archive_bytes'] = 784
            with self.subTest(mutation=mutation), \
                    mock.patch.object(verifier, 'load', side_effect=modules.__getitem__), \
                    self.assertRaises(ValueError):
                verifier.dependencies(context, Path('fixture-root'), core)


class BufferTransportFailureTests(unittest.TestCase):
    def fail(self, actual=None):
        context = dict(source_sha256='a' * 64, transfer_proof=dict(path='fixture', sha256='b' * 64))
        snapshot = mock.Mock(return_value=Path('fixture-failure.json'))
        run = mock.Mock(return_value=actual, side_effect=ValueError('guard refused') if actual is None else None)
        modules = {'portable-native-family': object(), 'buffer-transport-case-contracts': contract,
            'buffer-transport-oracle': oracle,
            'buffer-transport-harness': SimpleNamespace(make_harness=mock.Mock(return_value=SimpleNamespace())),
            'buffer-transport-runtime': SimpleNamespace(install=mock.Mock(return_value=run)),
            'research-workflow': SimpleNamespace(snapshot=snapshot)}
        with mock.patch.object(verifier, 'dependencies', return_value={}), \
                mock.patch.object(verifier, 'load', side_effect=modules.__getitem__), \
                mock.patch.object(contract, 'tools', return_value={'fixture.py': 'c' * 64}), \
                self.assertRaisesRegex(ValueError, 'diagnostic'):
            verifier.verify(context, Path('fixture-root'))
        run.assert_called_once()
        return snapshot.call_args.args[2]

    def test_early_native_failure_keeps_actual_absent(self):
        payload = self.fail()
        self.assertFalse(payload['accepted'])
        self.assertFalse(payload['actual_row_available'])
        self.assertIsNone(payload['actual'])
        self.assertIsNone(payload['expected'])
        self.assertEqual(payload['differences'], [])
        self.assertEqual(payload['state'], 'native_execution_failure')

    def test_wrong_completed_row_keeps_actual_bytes_and_difference(self):
        spec = contract.scenarios()[0]
        actual = oracle.expected_case(spec)
        actual['observation']['steps'][0]['spare_hex'] = ''
        payload = self.fail(actual)
        self.assertTrue(payload['actual_row_available'])
        self.assertEqual(payload['actual'], actual)
        self.assertEqual(payload['spec'], spec)
        self.assertIn('$.observation.steps[0].spare_hex', [d['path'] for d in payload['differences']])
        self.assertFalse(payload['network_used'])

    def test_difference_diagnostic_is_typed_and_bounded(self):
        self.assertTrue(verifier.differences(False, 0))
        self.assertEqual(len(verifier.differences({str(i): i for i in range(100)}, {}, limit=3)), 3)


if __name__ == '__main__':
    unittest.main()
