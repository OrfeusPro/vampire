"""Offline reference discovery against saved, source-bound Ghidra exports."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
EXPORT = Path('F:/PhoneExit Resources/Vampir/ghidra/request-exports') / SHA / 'run-0716c15e22dc/details.json'
EXPORTS = {
    'run-0716c15e22dc': '4c40e76365d77eff13cf541ef2674797016ccf6e0a6d2b0664cf1d761a8dcfa6',
    'run-9dc981740f54': 'f9ea52df7f73a60191e0d3515ad7585237925c1b7ad7839dff3f142ea7f9cd36',
    'run-5e52997758ac': '9aba1113b3baf9838e6721a9a73b5360a56b566e540d0627c5cfaeab9f194954',
}


class SdkReferences11316Tests(unittest.TestCase):
    def test_exports_and_referenced_literals_match_exact_source(self):
        spec = importlib.util.spec_from_file_location('sdk_reference_native', HERE / 'build-native-entry-code.py')
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        raw = (native.ROOT / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SHA)
        image = native.Image(raw)
        functions = {}
        for run, expected in EXPORTS.items():
            payload = (EXPORT.parent.parent / run / 'details.json').read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected)
            report = json.loads(payload)
            self.assertEqual(report['new_source_sha256'], SHA)
            for function in report['functions']:
                self.assertTrue(function['decompilation_completed'])
                functions[int(function['address'], 16)] = function
                for row in function['instructions']:
                    at = image.offset(int(row['address'], 16) - image.pe.base)
                    data = bytes.fromhex(row['bytes'])
                    self.assertEqual(raw[at:at + len(data)], data)
        self.assertEqual(len(functions), 7)
        initializers = {
            0x14125b710: (0x149859958, 0x14b5e5f88, '18e6xn1vuR1lGrvR'),
            0x14125b740: (0x149521158, 0x14b5e5f78, 'thered'),
            0x14125b770: (0x14952b6f8, 0x14b5e5fc8, 'nmp'),
            0x14125b7d0: (0x14952b740, 0x14b5e5fb8, 'epicgames'),
        }
        for entry, (literal, destination, text) in initializers.items():
            rows = functions[entry]['instructions']
            self.assertEqual(rows[1]['text'], f'LEA RDX,[{hex(literal)}]')
            self.assertEqual(rows[2]['text'], f'LEA RCX,[{hex(destination)}]')
            self.assertEqual(rows[3]['text'], 'CALL 0x141426b30')
            at = image.offset(literal - image.pe.base)
            expected = (text + '\0').encode('utf-16le')
            self.assertEqual(raw[at:at + len(expected)], expected)
        for entry, literal, text, encoding in (
            (0x1456579d0, 0x149660f94, 'real', 'ascii'),
            (0x144529d60, 0x149543e98, 'NMENV=', 'utf-16le'),
        ):
            self.assertIn(f'LEA RDX,[{hex(literal)}]', [r['text'] for r in functions[entry]['instructions']])
            at = image.offset(literal - image.pe.base)
            expected = (text + '\0').encode(encoding)
            self.assertEqual(raw[at:at + len(expected)], expected)

    def run_tool(self, evidence, *arguments):
        spec = importlib.util.spec_from_file_location('sdk_reference_test', HERE / 'find-release-sdk-references.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        output = io.StringIO()
        with patch('sys.argv', ['sdk-references', str(evidence), *arguments]), contextlib.redirect_stdout(output):
            module.main()
        return json.loads(output.getvalue())

    def test_new_source_explicit_global_finds_initializer_and_consumer(self):
        result = self.run_tool(EXPORT, '--global-address', '14b5e5fc8')
        report = json.loads(Path(result['report']).read_text('utf-8'))
        self.assertEqual(report['source_sha256'], SHA)
        self.assertFalse(report['roles_transferred'])
        self.assertEqual({row['function'] for row in report['references']},
                         {'0x14125b770', '0x1456579d0'})
        self.assertTrue(all(row['literal'] == '0x14b5e5fc8' for row in report['references']))

    def test_global_not_in_supplied_instructions_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Global absent'):
            self.run_tool(EXPORT, '--global-address', '14b5e5fa8')

    def test_changed_export_instruction_is_rejected(self):
        report = json.loads(EXPORT.read_text('utf-8'))
        row = report['functions'][0]['instructions'][0]
        row['bytes'] = '00' + row['bytes'][2:]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'details.json'
            path.write_text(json.dumps(report), 'utf-8')
            with self.assertRaisesRegex(ValueError, 'instruction bytes differ'):
                self.run_tool(path)

    def test_unknown_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'details.json'
            path.write_text(json.dumps({'new_source_sha256': '0' * 64}), 'utf-8')
            with self.assertRaisesRegex(ValueError, 'Unreviewed SDK source'):
                self.run_tool(path)


if __name__ == '__main__':
    unittest.main()
