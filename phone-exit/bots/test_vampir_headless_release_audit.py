"""Release audit regression: stale offsets and immutable evidence, no game IO."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

TOOL = Path(__file__).parent / 'resource-tools/vampir/audit-client-release.py'
SPEC = importlib.util.spec_from_file_location('vampir_release_audit', TOOL)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ReleaseAuditTests(unittest.TestCase):
    def test_changes_and_sample_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'example.pak'
            path.write_bytes(b'a' * 200000)
            old = AUDIT.inspect_archive(path)
            self.assertEqual(AUDIT.classify(old, dict(old)), 'sample_matches_unverified')
            # Even with unchanged metadata, a middle edit can evade the old sampler.
            with path.open('r+b') as stream:
                stream.seek(100000)
                stream.write(b'b')
            os.utime(path, ns=(old['modified_ns'], old['modified_ns']))
            self.assertEqual(AUDIT.classify(old, AUDIT.inspect_archive(path)), 'sample_matches_unverified')
            changed = dict(old, modified_ns=old['modified_ns'] + 1)
            self.assertEqual(AUDIT.classify(old, changed), 'metadata_changed')
            self.assertEqual(AUDIT.classify(old, dict(old, size=1)), 'changed')
            self.assertEqual(AUDIT.classify(None, old), 'added')
            self.assertEqual(AUDIT.classify(old, None), 'removed')

    def test_immutable_and_repeatable_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = dict(schema=1, compatibility='not_established')
            first = AUDIT.save_snapshot(root, report)
            self.assertEqual(first, AUDIT.save_snapshot(root, dict(reversed(list(report.items())))))
            original = first.read_bytes()
            second = AUDIT.save_snapshot(root, dict(report, schema=2))
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_bytes(), original)
            first.write_bytes(b'tampered')
            with self.assertRaisesRegex(RuntimeError, 'collision'):
                AUDIT.save_snapshot(root, report)

    def test_audit_preserves_baseline_and_marks_stale_index(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            install, resources = root / 'install', root / 'resources'
            archive = install / 'ProjectRED/Saved/PersistentDownloadDir/Patch/Install/chunk.pak'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b'a' * 100)
            old = dict(AUDIT.inspect_archive(archive), pak_version=11)
            resources.mkdir()
            baseline = resources / 'pc-pak-inventory.json'
            baseline.write_text(json.dumps(dict(source=str(install), files=[old])), encoding='utf-8')
            original = baseline.read_bytes()
            cache = resources / 'pak-extracted/chunk'
            cache.mkdir(parents=True)
            (cache / 'source.json').write_text(json.dumps(old), encoding='utf-8')
            (cache / 'entries.json').write_text('[{"offset":123}]', encoding='utf-8')
            exe = install / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b'artificial executable')
            archive.write_bytes(b'new archive')
            (archive.parent / 'new.pak').write_bytes(b'new chunk')
            # A private file in Saved is deliberately irrelevant to archive discovery.
            private = install / 'ProjectRED/Saved/LocalPrefs.json'
            private.write_text('not read', encoding='utf-8')
            report = AUDIT.audit(install, resources)
            rows = {Path(row['path']).name: row for row in report['files']}
            self.assertEqual(set(rows), {'chunk.pak', 'new.pak'})
            self.assertEqual(rows['chunk.pak']['cached_index']['status'], 'stale')
            self.assertEqual(rows['chunk.pak']['current']['sha256'], AUDIT.sha256(archive))
            self.assertEqual(rows['new.pak']['status'], 'added')
            self.assertFalse(report['full_archive_coverage'])
            self.assertFalse(report['exe']['matches_research'])
            self.assertEqual(report['compatibility'], 'not_established')
            self.assertEqual(baseline.read_bytes(), original)
            self.assertEqual((cache / 'entries.json').read_text('utf-8'), '[{"offset":123}]')
            self.assertNotIn('not read', json.dumps(report))


if __name__ == '__main__':
    unittest.main()
