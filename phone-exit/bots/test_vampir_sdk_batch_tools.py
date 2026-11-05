"""Temporary fixtures for SDK generation and resumable offline execution."""
import ast
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


TOOLS = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SdkBatchToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load('sdk-batch-runner')
        cls.generator = load('generate-sdk-batch')
        cls.transfer = load('sdk-batch-transfer')
        cls.workflow = load('research-workflow')

    def component_fixture(self, root):
        root = root.resolve()
        payload = b'fixture executable'
        sha = hashlib.sha256(payload).hexdigest()
        source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
        source.parent.mkdir(parents=True)
        source.write_bytes(payload)
        export = root / 'ghidra/request-exports' / sha / 'run-fixture/details.json'
        export.parent.mkdir(parents=True)
        export.write_bytes(b'{}')
        generated = root / 'generated.py'
        generated.write_text('# This fixture is replaced by a local callable.\n', encoding='utf-8')
        files = {str(path): self.runner.digest(path) for path in (source, export, generated)}
        report = dict(schema=1, source=str(source), source_sha256=sha,
            cases=[dict(canaries_unchanged=True)], evidence=[self.runner.pointer(export)],
            dependencies={str(generated): files[str(generated)]}, limits=['Temporary fixture only.'])
        generation = dict(files={str(generated): files[str(generated)]}, generated_templates={
            'replay-sdk-defaults-fixture.py': str(generated), 'replay-sdk-overrides-fixture.py': str(generated)})
        definition = dict(schema=1, recipe=self.runner.RECIPE, source_sha256=sha, files=files, runtime={})
        return generation, definition, report

    def execute(self, root, generation, definition, template, progress=None):
        return self.runner.component(root, generation, definition, template, 1,
                                     progress, self.workflow)

    def test_completed_component_survives_interruption_without_import_on_resume(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(self.runner, 'runtime', return_value={}):
            root = Path(temporary).resolve()
            generation, definition, report = self.component_fixture(root)
            module = SimpleNamespace(replay=Mock(return_value=report))
            with patch.object(self.runner, 'load_path', return_value=module):
                first, receipt, cached = self.execute(root, generation, definition, 'replay-sdk-defaults-fixture.py')
            self.assertFalse(cached)
            module.replay.assert_called_once()
            with patch.object(self.runner, 'load_path', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    self.execute(root, generation, definition, 'replay-sdk-overrides-fixture.py')
            with patch.object(self.runner, 'load_path', side_effect=AssertionError('Cached code imported')):
                again, saved, cached = self.execute(root, generation, definition, 'replay-sdk-defaults-fixture.py')
            self.assertTrue(cached)
            self.assertEqual(saved, receipt)
            self.assertEqual(again, first)

    def test_corrupt_checkpoint_and_unchanged_failure_do_not_import(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(self.runner, 'runtime', return_value={}):
            root = Path(temporary).resolve()
            generation, definition, report = self.component_fixture(root)
            with patch.object(self.runner, 'load_path', return_value=SimpleNamespace(replay=lambda **_: report)):
                _, receipt, _ = self.execute(root, generation, definition, 'replay-sdk-defaults-fixture.py')
            checkpoint = Path(receipt['path'])
            checkpoint.write_bytes(checkpoint.read_bytes() + b'changed')
            with patch.object(self.runner, 'load_path', side_effect=AssertionError('Corrupt cache re-executed')):
                with self.assertRaisesRegex(ValueError, 'proof content changed'):
                    self.execute(root, generation, definition, 'replay-sdk-defaults-fixture.py')
            with patch.object(self.runner, 'load_path', side_effect=ValueError('fixture failure')):
                with self.assertRaisesRegex(ValueError, 'fixture failure'):
                    self.execute(root, generation, definition, 'replay-sdk-overrides-fixture.py')
            with patch.object(self.runner, 'load_path', side_effect=AssertionError('Failed component repeated')):
                with self.assertRaisesRegex(ValueError, 'saved failure'):
                    self.execute(root, generation, definition, 'replay-sdk-overrides-fixture.py')

    def test_os_owner_lock_excludes_second_owner_and_releases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with self.runner.owner(root):
                with self.assertRaisesRegex(ValueError, 'already has an owner'):
                    with self.runner.owner(root):
                        self.fail('Second owner acquired the package')
            with self.runner.owner(root):
                pass

    def test_missing_or_ambiguous_mapping_prevents_generated_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            library = root / 'resources'
            templates = root / 'tools'
            templates.mkdir()
            old = 'a' * 64
            new = 'b' * 64
            names = {f'replay-fixture-{index}.py': 'fixture' for index in range(12)}
            baseline_path = templates / 'context.json'
            baseline = dict(schema=1, source_sha256=old,
                generated_files=names, roots={hex(0x140001000 + index): hex(0x140001000 + index) for index in range(34)},
                exports={'run-baseline': 'c' * 64})
            baseline_path.write_text(json.dumps(baseline), encoding='utf-8')
            transfer_path = library / 'knowledge/sdk-batch-transfer-v1' / ('d' * 64) / 'manifest.json'
            transfer = dict(schema=1, recipe='sdk-batch-transfer-v1', baseline_sha256=old,
                source_sha256=new, unresolved={}, inputs={str(baseline_path): self.generator.digest(baseline_path)},
                roots={at: hex(int(at, 16) + 0x100) for at in baseline['roots'].values()}, links={}, switches=[])
            target_roots = {int(at, 16): 'run-current' for at in transfer['roots'].values()}
            images = SimpleNamespace(data=b'', pe=SimpleNamespace(base=0x140000000))
            def input_bytes(path, expected):
                if Path(path).name.startswith('replay-fixture-'):
                    return b'VALUE = 0x140001000\n'
                if Path(path).name == 'details.json':
                    return json.dumps(dict(new_source_sha256=old)).encode()
                return b'fixture'
            for candidates in ([], ['0x140001100', '0x140001200']):
                current = copy.deepcopy(transfer)
                current['links'] = {at: [target] for at, target in current['roots'].items()}
                current['links']['0x140001000'] = candidates
                with self.subTest(candidates=candidates), ExitStack() as stack:
                    stack.enter_context(patch.object(self.generator, 'HERE', templates))
                    stack.enter_context(patch.object(self.generator, 'manifest', return_value=current))
                    stack.enter_context(patch.object(self.generator, 'digest', return_value='e' * 64))
                    stack.enter_context(patch.object(self.generator, 'checked', side_effect=input_bytes))
                    stack.enter_context(patch.object(self.generator, 'load', return_value=SimpleNamespace(Image=lambda _: images)))
                    stack.enter_context(patch.object(self.generator, 'exports_for', return_value=(
                        {'run-current': 'f' * 64}, target_roots, {})))
                    with self.assertRaisesRegex(ValueError, 'root mapping'):
                        self.generator.run(library, baseline_path, transfer_path, [])
                self.assertFalse((library / 'knowledge/sdk-batch-generated-code').exists())

    def test_changed_leaf_bytes_and_control_shape_reject(self):
        old, new = 0x140001000, 0x140002000
        leaf = dict(baseline=hex(old), target=hex(new), size=2,
                    baseline_bytes='90c3', target_bytes='90c3',
                    baseline_sha256=hashlib.sha256(b'\x90\xc3').hexdigest(),
                    target_sha256=hashlib.sha256(b'\x90\xc3').hexdigest())
        image = lambda base: SimpleNamespace(data=b'\x90\xc3', pe=SimpleNamespace(base=base), offset=lambda rva: rva)
        records = dict(leaves=[copy.deepcopy(leaf) for _ in range(6)])
        records['leaves'][0]['target_bytes'] = 'ccc3'
        with self.assertRaisesRegex(ValueError, 'leaf record differs'):
            self.generator.leaf_replacements(records, [image(old), image(new)], {old: new})
        transfer = self.transfer.Transfer.__new__(self.transfer.Transfer)
        transfer.native = SimpleNamespace()
        transfer.mapping = {}
        transfer.signature = lambda native, rows: tuple(row['bytes'] for row in rows)
        before = [dict(address=old, bytes='90', direct_target=None, rip_references=[])]
        after = [dict(address=new, bytes='cc', direct_target=None, rip_references=[])]
        with self.assertRaisesRegex(ValueError, 'control shape differs'):
            transfer.add_rows(before, after)
        self.assertEqual(transfer.mapping, {})


if __name__ == '__main__':
    unittest.main()
