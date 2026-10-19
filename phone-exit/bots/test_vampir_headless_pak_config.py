"""Compiled PAK key callback, verified directory, config recovery and bounds."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent


class PakConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/recover-pak-game-config.py'
        spec = importlib.util.spec_from_file_location('pak_config_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        pointer = json.loads((cls.module.ROOT / 'code-clues/pak-config-recovery.json').read_text('utf-8'))
        cls.manifest = Path(pointer['manifest'])
        cls.report = json.loads(cls.manifest.read_text('utf-8'))
        cls.raw = Path(cls.report['source_exe']).read_bytes()

    def test_key_callback_source_registration_and_native_guards(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['exe_sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        rows = [self.report['initializer']] + [i for f in self.report['registration_fragments'] + self.report['key_callback']['fragments'] for i in f['instructions']]
        for row in rows:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        flow = self.module.load('key_replay_test_flow', HERE / 'resource-tools/vampir/build-headless-cdn-json-flow.py')
        preparation = flow.body.head.headers.uri.http.preparation
        native = preparation.url.settings.config.native
        key, replay = self.module.recover_key(self.raw, native.Image(self.raw), native, preparation)
        self.assertEqual(replay, self.report['key_callback'])
        self.assertEqual(len(key), 32)
        self.assertTrue(all(c['guards_unchanged'] for c in replay['cases']))
        self.assertFalse(replay['separate_key_file_saved'])

    def test_recover_current_pinned_directory_and_config_snapshot(self):
        self.assertEqual(hashlib.sha256(self.manifest.read_bytes()).hexdigest(), self.manifest.parent.name)
        report, files = self.module.recover()
        self.assertEqual(report, self.report)
        for name, payload in files.items():
            self.assertEqual(payload, (self.manifest.parent / name).read_bytes())
        directory = json.loads(files['directory.json'])
        self.assertEqual(directory['directory_count'], 593)
        self.assertEqual(directory['file_count'], 7067)
        self.assertEqual(hashlib.sha256(files['directory.json']).hexdigest(), report['directory_paths_file_sha256'])
        names = {row['path'] for row in directory['entries']}
        self.assertTrue(set(self.module.GAME_FILES).issubset(names))
        values = {v['key']: v['value'] for v in report['configs'][0]['values']}
        self.assertEqual(values['ConfigPrefix'], 'dev')
        self.assertEqual(values['AppVersion'], '0.1.1')
        self.assertEqual(values['CdnConfig'], 'False')
        self.assertFalse(values['CdnConfigUrl'].startswith('https://'))
        self.assertEqual(report['configs'][1]['values'], [])
        self.assertTrue(report['authoritative_directory_for_archive'])
        self.assertFalse(report['active_runtime_settings_verified'])
        self.assertFalse(report['network_ready'])

    def test_bounded_index_models_and_invalid_layouts(self):
        def string(text):
            data = text.encode() + b'\0'
            return struct.pack('<i', len(data)) + data
        encoded = struct.pack('<III', 0xe0400000, 200, 4)
        side = struct.pack('<IQQ', 1, 1000, 16) + bytes(20)
        main = string('../../../') + struct.pack('<IQ', 1, 0) + side * 2 + struct.pack('<I', len(encoded)) + encoded + bytes(4)
        info, table = self.module.parse_main(main)
        self.assertEqual(info['entry_count'], 1)
        self.assertEqual(self.module.decode_small_entry(table, 0)['offset'], 200)
        entry = string('DefaultGame.ini') + struct.pack('<i', 0)
        directory = struct.pack('<I', 1) + string('ProjectRED/Config/') + struct.pack('<I', 1) + entry
        self.assertEqual(self.module.parse_directory(directory, 1)['file_count'], 1)
        duplicate = struct.pack('<I', 1) + string('ProjectRED/Config/') + struct.pack('<I', 2) + entry * 2
        for action in [lambda: self.module.parse_directory(duplicate, 2),
                       lambda: self.module.parse_directory(directory + bytes(16), 1),
                       lambda: self.module.parse_main(main[:-1]),
                       lambda: self.module.Cursor(b'x').take(2**32),
                       lambda: self.module.decode_small_entry(table, len(table))]:
            with self.assertRaises(ValueError):
                action()

    def test_corrupt_ciphertext_never_reaches_native_decompressor(self):
        encoded = struct.pack('<IIIII', 0xe0c00040, 0, 8, 16, 4)
        header = dict(pos=0, hs=73, size=16, usize=8, method=1, encrypted=True,
                      blocks=[(73, 77)], blocksize=8)
        reader = SimpleNamespace(header=lambda *args: header, DECOMP=Mock(side_effect=AssertionError('unverified native input')))
        raw = bytes(73) + b'x' * 16
        with self.assertRaisesRegex(ValueError, 'SHA1'):
            self.module.extract_config(io.BytesIO(raw), dict(path='DefaultGame.ini', encoded_entry_offset=0),
                                       encoded, bytes(32), reader, len(raw))
        reader.DECOMP.assert_not_called()

    def test_snapshot_is_immutable_and_output_names_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(self.module, 'ROOT', Path(directory)):
            report, files = dict(schema_version=1), {'DefaultGame.ini': b'known config'}
            path, identity = self.module.save(report, files)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), identity)
            self.assertEqual(self.module.save(report, files), (path, identity))
            (path.parent / 'DefaultGame.ini').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                self.module.save(report, files)
            with self.assertRaises(ValueError):
                self.module.save(report, {'../outside.ini': b'invalid'})


if __name__ == '__main__':
    unittest.main()
