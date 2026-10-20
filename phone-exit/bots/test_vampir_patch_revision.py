"""Manifest revision local bounds and strict rejection of ambiguous inputs."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.patch_revision import parse_patch_client_revision


class PatchRevisionTests(unittest.TestCase):
    def test_native_key_to_patch_field_slice_reproduces(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-patch-client-version.py'
        spec = importlib.util.spec_from_file_location('patch_client_version_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        saved = json.loads((tool.native.ROOT / 'code-clues/patch-client-version-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual(len(saved['cases']), 5)
        for case in saved['cases']:
            self.assertEqual(case['keys'], ['ClientVersion'])
            self.assertEqual(case['value'], case['json_string_fixture'])

    def test_recorded_installed_manifest_matches_snapshot_and_revision(self):
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/installed-patch-revision.json').read_text('utf-8'))
        raw = Path(report['snapshot']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), report['source_sha256'])
        self.assertEqual(parse_patch_client_revision(raw), report['client_revision'])
        self.assertEqual(report['client_revision'], 258392)

    def test_explicit_client_version_and_utf8_bom(self):
        self.assertEqual(parse_patch_client_revision(b'{"ClientVersion":"Revision258392","files":[]}'), 258392)
        self.assertEqual(parse_patch_client_revision(b'\xef\xbb\xbf{"ClientVersion":"Revision4294967295"}'), 0xffffffff)

    def test_rejects_missing_ambiguous_noncanonical_and_excessive_inputs(self):
        for body in (b'', b'[]', b'{}', b'null', b'{"ClientVersion":258392}', b'{"ClientVersion":null}',
                     b'{"ClientVersion":"Revision1","ClientVersion":"Revision2"}',
                     b'{"ClientVersion":"Revision2","files":[{"a":1,"a":2}]}',
                     b'\xff', b'{', b'[' * 2000, b' ' * 2097153):
            with self.subTest(body=body[:60]), self.assertRaises(ValueError): parse_patch_client_revision(body)
        for text in ('Revision0', 'Revision01', 'Revision-1', 'Revision+1', 'Revision42junk',
                     'Revision 42', 'revision42', 'Revision4294967296', 'Revision99999999999',
                     'Revision１２', ' Revision42'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_patch_client_revision(('{"ClientVersion":"' + text + '"}').encode())


if __name__ == '__main__': unittest.main()
