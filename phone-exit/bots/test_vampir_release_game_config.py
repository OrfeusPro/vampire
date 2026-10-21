"""Reject stale release inputs before loading key/native/decompression helpers."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('release_game_config_test_tool', HERE / 'resource-tools/vampir/recover-release-game-config.py')
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class ReleaseConfigInputTests(unittest.TestCase):
    def save(self, folder, report):
        raw = json.dumps(report).encode()
        target = folder / hashlib.sha256(raw).hexdigest() / 'manifest.json'
        target.parent.mkdir()
        target.write_bytes(raw)
        return target

    def test_corrupt_manifest_rejected_before_native_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            archive = folder / 'fixture.pak'
            archive.write_bytes(b'fixture')
            manifest = self.save(folder, dict(files=[]))
            manifest.write_bytes(b'{}')
            core = TOOL.load('release_config_test_core', TOOL.HERE / 'recover-pak-game-config.py')
            with patch.object(TOOL, 'load', return_value=core), patch.object(core, 'load') as native:
                with self.assertRaisesRegex(ValueError, 'manifest digest'):
                    TOOL.recover(manifest, archive)
                native.assert_not_called()

    def test_unlisted_and_sample_only_archive_rejected(self):
        for files in ([], [dict(path='placeholder', current=dict(sample_sha256='a' * 64))]):
            with self.subTest(files=files), tempfile.TemporaryDirectory() as tmp:
                folder = Path(tmp)
                archive = folder / 'fixture.pak'
                archive.write_bytes(b'fixture')
                if files:
                    files[0]['path'] = str(archive)
                manifest = self.save(folder, dict(files=files))
                core = TOOL.load('release_config_test_core', TOOL.HERE / 'recover-pak-game-config.py')
                with patch.object(TOOL, 'load', return_value=core), patch.object(core, 'load') as native:
                    with self.assertRaisesRegex(ValueError, 'full hash'):
                        TOOL.recover(manifest, archive)
                    native.assert_not_called()

    def test_changed_archive_rejected_before_key_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            archive = folder / 'fixture.pak'
            archive.write_bytes(b'after-update')
            manifest = self.save(folder, dict(files=[dict(path=str(archive),
                current=dict(sha256=hashlib.sha256(b'before-update').hexdigest()))]))
            core = TOOL.load('release_config_test_core', TOOL.HERE / 'recover-pak-game-config.py')
            with patch.object(TOOL, 'load', return_value=core), patch.object(core, 'load') as native:
                with self.assertRaisesRegex(ValueError, 'Archive changed'):
                    TOOL.recover(manifest, archive)
                native.assert_not_called()


if __name__ == '__main__':
    unittest.main()
