"""Current package scope, immutable inputs, scenario preservation and zero-replay cache."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class CharacterListCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = module('verify-character-list-current')
        cls.generator = module('generate-character-list-current')

    def test_generated_adapter_retains_native_fence_and_every_nested_scenario(self):
        fake = SimpleNamespace(inputs={})
        sources = self.generator.source_files(fake, Path('generated-review-fixture'))
        self.assertEqual(set(sources), {'native-harness.py'} | {'verify-' + n + '-context.py' for n in self.tool.NAMES})
        harness = ast.parse(sources['native-harness.py'])
        original = ast.parse((HERE / 'update-native-harness.py').read_bytes())
        get = lambda tree: next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'make_harness')
        actual, previous = get(harness), get(original)
        tail = lambda body: body[next(i for i, n in enumerate(body) if isinstance(n, ast.For)
                         and isinstance(n.iter, ast.Call) and ast.unparse(n.iter) == 'exports.items()'):]
        self.assertEqual([ast.dump(n) for n in tail(actual.body)], [ast.dump(n) for n in tail(previous.body)])
        for name in self.tool.NAMES:
            filename = 'verify-' + name + '-context.py'
            before, after = ast.parse((HERE / filename).read_bytes()), ast.parse(sources[filename])
            nested = lambda tree: {node.name: ast.dump(node) for outer in tree.body
                if isinstance(outer, ast.FunctionDef) for node in outer.body if isinstance(node, ast.FunctionDef)}
            self.assertEqual(nested(before), nested(after), name)

    def test_wrong_source_or_unregistered_scope_is_rejected_before_native_load(self):
        with patch.object(self.tool, 'load') as native:
            with self.assertRaisesRegex(ValueError, 'source/admission'):
                self.tool.make_harness({'source_sha256': self.tool.BASELINE}, {}, set())
            with self.assertRaisesRegex(ValueError, 'scope/name'):
                self.tool.make_harness({'source_sha256': self.tool.SOURCE}, {}, set())
            native.assert_not_called()

    def test_scope_never_admits_an_arbitrary_subset_or_extra_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'pinned-input'
            source.write_bytes(b'fixture')
            scope = dict(recipe='character-list-current-generated', source_sha256=self.tool.SOURCE,
                baseline_sha256=self.tool.BASELINE, runtime_admitted=False, semantic_verification=False,
                roots={hex(0x140000000 + i): hex(0x141000000 + i) for i in range(40)},
                inputs={str(source): self.tool.digest(source)},
                scopes={name: dict(roots=['0x141000001'], leaves={}) for name in self.tool.NAMES})
            path = module('research-workflow').snapshot(root, 'character-list-current-scopes', scope)
            context = dict(source_sha256=self.tool.SOURCE, current_character_scope=dict(
                path=str(path), sha256=self.tool.digest(path), name='waiting-end'))
            with patch.object(self.tool, 'load') as native:
                with self.assertRaisesRegex(ValueError, 'exact root/leaf allowlist'):
                    self.tool.make_harness(context, {}, {0x141000002}, root=root)
                with self.assertRaisesRegex(ValueError, 'exact root/leaf allowlist'):
                    self.tool.make_harness(context, {}, {0x141000001, 0x141000002}, root=root)
                native.assert_not_called()

    def test_missing_native_coverage_does_not_become_verified(self):
        report = dict(source_sha256=self.tool.SOURCE, network_used=False, profile_activated=False,
                      limits=['fixture'], cases=[{}] * 100)
        with self.assertRaisesRegex(ValueError, 'coverage differs'):
            self.tool.validate_report('character-list-handler', report)
        report['cases'].append({})
        self.tool.validate_report('character-list-handler', report)
        report['network_used'] = True
        with self.assertRaisesRegex(ValueError, 'boundary differs'):
            self.tool.validate_report('character-list-handler', report)

    def test_corrupt_immutable_material_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            raw = b'{"fixture":true}'
            sha = hashlib.sha256(raw).hexdigest()
            path = root / 'knowledge/character-list-current-scopes' / sha / 'manifest.json'
            path.parent.mkdir(parents=True)
            path.write_bytes(raw)
            pointer = dict(path=str(path), sha256=sha)
            self.assertEqual(self.tool.checked(pointer, root, 'character-list-current-scopes'), {'fixture': True})
            path.write_bytes(b'{"fixture":false}')
            with self.assertRaisesRegex(ValueError, 'immutable pointer differs'):
                self.tool.checked(pointer, root, 'character-list-current-scopes')

    def test_unchanged_batch_cache_executes_no_component(self):
        workflow = module('research-workflow')
        definition = {'fixture': 'complete-source-bound-definition', 'generated': {'path': 'fixture.json'}}
        reports = {}
        for name in self.tool.NAMES:
            report = dict(source_sha256=self.tool.SOURCE, network_used=False, profile_activated=False, limits=['fixture'])
            if name == 'character-extensions':
                report['components'] = [dict(kind=kind, **{key: [{}] * count for key, count in counts.items()})
                    for kind, counts in {'appearance': {'cases': 5, 'truncated': 58, 'failures': 42},
                                         'optional': {'cases': 19, 'truncated': 201, 'failures': 94}}.items()]
            else:
                report.update({key: [{}] * count for key, count in self.tool.EXPECTED[name].items()})
            reports[name] = report
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            result = dict(definition=definition, reports=reports, recipe=self.tool.RECIPE,
                          source_sha256=self.tool.SOURCE, method='bounded_native', semantic_verification=True,
                          network_used=False, runtime_admitted=False, profile_activated=False,
                          live_verified=False, limits=['fixture'])
            path = workflow.snapshot(root, 'character-list-current-bounded', result)
            key = hashlib.sha256(workflow.canonical(definition)).hexdigest()
            cache = root / 'knowledge/character-list-current-cache' / (key + '.json')
            workflow.atomic(cache, workflow.canonical(dict(path=str(path), sha256=self.tool.digest(path))))
            with patch.object(self.tool, 'materials', return_value=({}, definition)), patch.object(self.tool, 'load', return_value=workflow) as loader:
                actual, report, reused = self.tool.run(root / 'fixture.json', root)
            self.assertTrue(reused)
            self.assertEqual(actual, path)
            self.assertEqual(report, result)
            loader.assert_called_once_with('research-workflow')

    def test_interrupted_package_reuses_finished_component_checkpoints(self):
        workflow = module('research-workflow')
        definition = {'fixture': 'source-and-runtime-bound-definition'}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            generated = dict(contexts={}, verifiers={})
            reports = {}
            for name in self.tool.NAMES:
                path = root / (name + '.json')
                path.write_text(json.dumps({'name': name}))
                generated['contexts'][name] = str(path)
                generated['verifiers'][name] = str(root / ('verify-' + name + '.py'))
                reports[name] = dict(source_sha256=self.tool.SOURCE, network_used=False,
                    profile_activated=False, limits=['fixture'])
                if name == 'character-extensions':
                    reports[name]['components'] = [dict(kind=kind, **{key: [{}] * count for key, count in counts.items()})
                        for kind, counts in {'appearance': {'cases': 5, 'truncated': 58, 'failures': 42},
                                             'optional': {'cases': 19, 'truncated': 201, 'failures': 94}}.items()]
                else:
                    reports[name].update({key: [{}] * count for key, count in self.tool.EXPECTED[name].items()})
            executed = []
            failing = [True]
            def verify(context, unused):
                name = context['name']
                executed.append(name)
                if failing[0] and name == 'character-record':
                    raise ValueError('interruption fixture')
                return reports[name]
            def loader(name, path=None):
                return workflow if name == 'research-workflow' else SimpleNamespace(verify=verify)
            with patch.object(self.tool, 'materials', return_value=(generated, definition)), patch.object(self.tool, 'load', side_effect=loader):
                with self.assertRaisesRegex(ValueError, 'interruption fixture'):
                    self.tool.run(root / 'fixture.json', root)
                executed.clear()
                failing[0] = False
                _, report, reused = self.tool.run(root / 'fixture.json', root)
            self.assertFalse(reused)
            self.assertEqual(report['reused_components'], list(self.tool.NAMES[:2]))
            self.assertEqual(executed, list(self.tool.NAMES[2:]))


if __name__ == '__main__':
    unittest.main()
