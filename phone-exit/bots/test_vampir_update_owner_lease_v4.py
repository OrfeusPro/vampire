"""Managed lock policy over temporary files; no updater or game execution."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('lease_v4_tests', HERE/'update-owner-lease-v4.py')
LEASE = importlib.util.module_from_spec(spec); spec.loader.exec_module(LEASE)


class LeasePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.guard = {str(self.root/'producer.py'): 'a'*64}
        self.record = dict(schema=4, recipe=LEASE.RECIPE, epoch='b'*32, root=str(self.root),
            guardian=dict(pid=os.getpid(), creation_time='100', session_id=7),
            worker=dict(pid=os.getpid()+100000, creation_time='200', session_id=7),
            job=LEASE.job_name(self.root, 'b'*32), guard=copy.deepcopy(self.guard), operation='auto')
        self.path = self.root/'knowledge/locks/research.lock'
        self.backend = SimpleNamespace(current_session_id=lambda: 7,
            process_probe=lambda pid: dict(state='exited', creation_time=None, session_id=None),
            probe_job=lambda name: dict(state='missing', active_processes=0))

    def write_lock(self, record=None, raw=None):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(raw if raw is not None else LEASE.canonical(record or self.record))
        try: value = json.loads(self.path.read_bytes())
        except ValueError: value = None
        if isinstance(value, dict) and isinstance(value.get('epoch'), str) and LEASE.EPOCH.fullmatch(value['epoch']):
            snapshot = self.root/'knowledge/update-owner-v4/epochs'/value['epoch']/'owner.json'
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_bytes(self.path.read_bytes())
        return self.path.read_bytes()

    def assert_reason(self, reason, action):
        with self.assertRaises(LEASE.LeaseError) as caught: action()
        self.assertEqual(caught.exception.reason, reason)

    def test_claim_visible_complete_and_explicit_release(self):
        with LEASE.Lease(self.root) as lease:
            pointer = lease.claim(self.record)
            self.assertEqual(pointer, dict(path=str(self.path), sha256=LEASE.fingerprint(self.record)))
            self.assertEqual(json.loads(self.path.read_bytes()), self.record)
            self.assertEqual((lease.folder/'epochs'/self.record['epoch']/'owner.json').read_bytes(), self.path.read_bytes())
            lease.release(self.record)
            self.assertFalse(self.path.exists())

    def test_exit_keeps_primary_for_recovery(self):
        with LEASE.Lease(self.root) as lease: lease.claim(self.record)
        self.assertEqual(self.path.read_bytes(), LEASE.canonical(self.record))

    def test_primary_claim_never_replaces_legacy_file(self):
        original = self.write_lock(raw=b'71001')
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('managed_document_already_exists', lambda: lease.claim(self.record))
        self.assertEqual(self.path.read_bytes(), original)

    def test_full_document_exists_before_link_and_interruption_keeps_primary_absent(self):
        real_link = os.link
        def interrupted(source, target):
            self.assertEqual(Path(source).read_bytes(), LEASE.canonical(self.record))
            if Path(target) == self.path: raise InterruptedError('fixture before primary link')
            return real_link(source, target)
        with LEASE.Lease(self.root) as lease, patch.object(LEASE.os, 'link', side_effect=interrupted):
            with self.assertRaises(InterruptedError): lease.claim(self.record)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.root.rglob('.owner-v4-*')), [])

    def test_simultaneous_lease_owner_is_rejected(self):
        with LEASE.Lease(self.root):
            with self.assertRaises(LEASE.LeaseError):
                with LEASE.Lease(self.root): self.fail('second owner entered')

    def test_method_without_lease_or_from_different_thread_rejected(self):
        lease = LEASE.Lease(self.root)
        self.assert_reason('lease_not_held_by_current_owner', lambda: lease.claim(self.record))
        reasons = []
        with lease:
            def other():
                try: lease.claim(self.record)
                except LEASE.LeaseError as error: reasons.append(error.reason)
            worker = threading.Thread(target=other); worker.start(); worker.join()
        self.assertEqual(reasons, ['lease_not_held_by_current_owner'])

    def test_different_thread_cannot_exit_live_lease(self):
        reasons = []
        with LEASE.Lease(self.root) as lease:
            def other():
                try: lease.__exit__(None, None, None)
                except LEASE.LeaseError as error: reasons.append(error.reason)
            worker = threading.Thread(target=other); worker.start(); worker.join()
            lease.claim(self.record); lease.release(self.record)
        self.assertEqual(reasons, ['lease_not_held_by_current_owner'])

    def test_second_claim_and_foreign_release_rejected(self):
        with LEASE.Lease(self.root) as lease:
            lease.claim(self.record)
            self.assert_reason('lease_already_claimed', lambda: lease.claim(self.record))
            other = dict(self.record, operation='explicit')
            self.assert_reason('foreign_managed_lock_release', lambda: lease.release(other))
            self.assertTrue(self.path.exists()); lease.release(self.record)

    def test_claim_does_not_accept_foreign_guardian(self):
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('guardian_is_not_current_owner',
                lambda: lease.claim(dict(self.record, guardian=dict(self.record['guardian'], pid=os.getpid()+2))))
        self.assertFalse(self.path.exists())

    def test_empty_precreated_epoch_directory_is_allowed(self):
        epoch = self.root/'knowledge/update-owner-v4/epochs'/self.record['epoch']; epoch.mkdir(parents=True)
        with LEASE.Lease(self.root) as lease:
            lease.claim(self.record); lease.release(self.record)
        self.assertTrue((epoch/'owner.json').exists())

    def test_stale_managed_lock_archived_with_receipt_then_new_claim_possible(self):
        original = self.write_lock()
        with LEASE.Lease(self.root) as lease:
            pointer = lease.recover(self.backend, self.guard)
            self.assertFalse(self.path.exists())
            raw = Path(pointer['path']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pointer['sha256'])
            receipt = json.loads(raw)
            self.assertEqual(receipt['state'], 'recovered')
            self.assertEqual(Path(receipt['archived_lock']['path']).read_bytes(), original)
            self.assertTrue(Path(receipt['prepared']['path']).is_file())
            new = dict(self.record, epoch='c'*32, job=LEASE.job_name(self.root, 'c'*32))
            lease.claim(new); lease.release(new)

    def test_no_existing_lock_returns_none(self):
        with LEASE.Lease(self.root) as lease:
            self.assertIsNone(lease.recover(self.backend, self.guard))

    def test_legacy_pid_malformed_and_oversize_remain(self):
        for raw, reason in ((b'71001\n', 'legacy_pid_lock_requires_manual_inspection'),
                (b'{broken', 'invalid_managed_lock_json'),
                (b' '*(LEASE.LIMIT+1), 'managed_lock_size_budget')):
            with self.subTest(reason=reason):
                self.write_lock(raw=raw)
                with LEASE.Lease(self.root) as lease:
                    self.assert_reason(reason, lambda: lease.recover(self.backend, self.guard))
                self.assertEqual(self.path.read_bytes(), raw)

    def test_foreign_schema_root_epoch_job_and_extra_fields_stay_blocked(self):
        cases = [dict(self.record, schema=3), dict(self.record, root=str(self.root/'other')),
            dict(self.record, epoch='Z'*32), dict(self.record, job='Local\\foreign'),
            dict(self.record, unrelated=True)]
        for record in cases:
            with self.subTest(record=record):
                original = self.write_lock(record)
                with LEASE.Lease(self.root) as lease:
                    with self.assertRaises(LEASE.LeaseError): lease.recover(self.backend, self.guard)
                self.assertEqual(self.path.read_bytes(), original)

    def test_guard_change_cannot_recover(self):
        original = self.write_lock()
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('managed_guard_changed', lambda: lease.recover(self.backend,
                {str(self.root/'producer.py'): 'd'*64}))
        self.assertEqual(self.path.read_bytes(), original)

    def test_duplicate_json_keys_cannot_recover(self):
        raw = LEASE.canonical(self.record).replace(b'"schema": 4,', b'"schema": 3, "schema": 4,')
        self.write_lock(raw=raw)
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('duplicate_managed_json_key', lambda: lease.recover(self.backend, self.guard))
        self.assertEqual(self.path.read_bytes(), raw)

    def test_noncanonical_managed_primary_is_not_recovered(self):
        raw = json.dumps(self.record).encode('utf-8')
        self.write_lock(raw=raw)
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('noncanonical_managed_lock', lambda: lease.recover(self.backend, self.guard))
        self.assertEqual(self.path.read_bytes(), raw)

    def test_filetime_must_be_canonical_positive_uint64(self):
        for clock in ('0', '0100', '-1', '18446744073709551616', '9'*40):
            with self.subTest(clock=clock), LEASE.Lease(self.root) as lease:
                value = dict(self.record, guardian=dict(self.record['guardian'], creation_time=clock))
                self.assert_reason('invalid_process_identity', lambda: lease.claim(value))
        self.assertFalse(self.path.exists())

    def test_original_owner_snapshot_is_required_for_recovery(self):
        original = self.write_lock()
        owner = self.root/'knowledge/update-owner-v4/epochs'/self.record['epoch']/'owner.json'
        owner.unlink()
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('managed_owner_snapshot_missing', lambda: lease.recover(self.backend, self.guard))
        self.assertEqual(self.path.read_bytes(), original)

    def test_changed_owner_snapshot_cannot_authorize_recovery(self):
        original = self.write_lock()
        owner = self.root/'knowledge/update-owner-v4/epochs'/self.record['epoch']/'owner.json'
        owner.write_bytes(LEASE.canonical(dict(self.record, operation='explicit')))
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('managed_owner_snapshot_changed', lambda: lease.recover(self.backend, self.guard))
        self.assertEqual(self.path.read_bytes(), original)

    def test_interrupted_prepared_attempt_does_not_block_new_admission_observations(self):
        self.write_lock()
        with LEASE.Lease(self.root) as lease, patch.object(lease, '_remove', side_effect=InterruptedError('fixture after prepared')):
            with self.assertRaises(InterruptedError): lease.recover(self.backend, self.guard)
        self.assertTrue(self.path.exists())
        self.backend.process_probe = lambda pid: dict(state='alive', creation_time='9999', session_id=7)
        self.backend.probe_job = lambda name: dict(state='present', active_processes=0)
        with LEASE.Lease(self.root) as lease:
            pointer = lease.recover(self.backend, self.guard)
        self.assertFalse(self.path.exists())
        attempts = self.root/'knowledge/update-owner-v4/epochs'/self.record['epoch']/'recovery-attempts'
        self.assertEqual(len(list(attempts.glob('*/prepared.json'))), 2)
        self.assertEqual(json.loads(Path(pointer['path']).read_bytes())['job_observation']['state'], 'present')

    def test_session_change_or_unknown_cannot_recover(self):
        for value in (8, None, True):
            with self.subTest(value=value):
                original = self.write_lock(); self.backend.current_session_id = lambda: value
                with LEASE.Lease(self.root) as lease:
                    self.assert_reason('managed_session_changed_or_unknown',
                        lambda: lease.recover(self.backend, self.guard))
                self.assertEqual(self.path.read_bytes(), original)

    def test_live_exact_guardian_or_worker_blocks(self):
        for role in ('guardian', 'worker'):
            with self.subTest(role=role):
                original = self.write_lock(); owner = self.record[role]
                self.backend.process_probe = lambda pid: (
                    dict(state='alive', creation_time=owner['creation_time'], session_id=7)
                    if pid == owner['pid'] else dict(state='exited', creation_time=None, session_id=None))
                with LEASE.Lease(self.root) as lease:
                    self.assert_reason('managed_'+role+'_still_alive', lambda: lease.recover(self.backend, self.guard))
                self.assertEqual(self.path.read_bytes(), original)

    def test_pid_reuse_is_not_the_old_process(self):
        self.write_lock()
        self.backend.process_probe = lambda pid: dict(state='alive', creation_time='9999', session_id=7)
        with LEASE.Lease(self.root) as lease:
            self.assertIsNotNone(lease.recover(self.backend, self.guard))
        self.assertFalse(self.path.exists())

    def test_unknown_or_access_denied_process_cannot_recover(self):
        cases = (lambda pid: dict(state='unknown'),
            lambda pid: dict(state='alive', creation_time=None, session_id=7),
            lambda pid: (_ for _ in ()).throw(PermissionError('fixture denied')))
        for probe in cases:
            with self.subTest(probe=probe):
                original = self.write_lock(); self.backend.process_probe = probe
                with LEASE.Lease(self.root) as lease:
                    with self.assertRaises((LEASE.LeaseError, PermissionError)):
                        lease.recover(self.backend, self.guard)
                self.assertEqual(self.path.read_bytes(), original)

    def test_live_descendant_or_unknown_job_cannot_recover(self):
        cases = (dict(state='present', active_processes=1), dict(state='unknown', active_processes=0),
            dict(state='missing', active_processes=1), dict(state='present', active_processes=True))
        for group in cases:
            with self.subTest(group=group):
                original = self.write_lock(); self.backend.probe_job = lambda name: group
                with LEASE.Lease(self.root) as lease:
                    with self.assertRaises(LEASE.LeaseError): lease.recover(self.backend, self.guard)
                self.assertEqual(self.path.read_bytes(), original)

    def test_present_empty_job_can_recover(self):
        self.write_lock(); self.backend.probe_job = lambda name: dict(state='present', active_processes=0)
        with LEASE.Lease(self.root) as lease: lease.recover(self.backend, self.guard)
        self.assertFalse(self.path.exists())

    def test_ghidra_lock_is_never_changed(self):
        self.write_lock(); ghidra = self.path.with_name('ghidra.lock'); ghidra.write_bytes(b'88112')
        with LEASE.Lease(self.root) as lease: lease.recover(self.backend, self.guard)
        self.assertEqual(ghidra.read_bytes(), b'88112')

    def test_owner_snapshot_mutation_prevents_release(self):
        with LEASE.Lease(self.root) as lease:
            lease.claim(self.record)
            snapshot = lease.folder/'epochs'/self.record['epoch']/'owner.json'
            snapshot.write_bytes(b'changed')
            self.assert_reason('owner_snapshot_changed', lambda: lease.release(self.record))
        self.assertTrue(self.path.exists())

    def test_oversize_immutable_owner_snapshot_is_not_read_unbounded(self):
        snapshot = self.root/'knowledge/update-owner-v4/epochs'/self.record['epoch']/'owner.json'
        snapshot.parent.mkdir(parents=True); snapshot.write_bytes(b'X'*(LEASE.LIMIT+1))
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('managed_document_size_budget', lambda: lease.claim(self.record))
        self.assertFalse(self.path.exists())

    def test_recovery_manifest_size_cannot_exceed_budget(self):
        record = copy.deepcopy(self.record)
        record['guard'] = {str(self.root/('a'*3000)/str(i)): 'a'*64 for i in range(32)}
        self.assertGreater(len(LEASE.canonical(record)), LEASE.LIMIT)
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('managed_document_size_budget', lambda: lease.claim(record))
        self.assertFalse(self.path.exists())

    def test_recovery_rejects_existing_different_archive(self):
        original = self.write_lock()
        archive = self.root/'knowledge/update-owner-v4/epochs'/self.record['epoch']/'recovered-research.lock'
        archive.parent.mkdir(parents=True, exist_ok=True); archive.write_bytes(b'foreign')
        with LEASE.Lease(self.root) as lease:
            self.assert_reason('managed_document_already_exists', lambda: lease.recover(self.backend, self.guard))
        self.assertEqual(self.path.read_bytes(), original); self.assertEqual(archive.read_bytes(), b'foreign')

    def test_reopen_gap_replacement_is_preserved(self):
        real_pin = LEASE._PinnedFile
        replacement = b'new legacy owner'
        def swapping(path, *, delete=False):
            if delete:
                path.unlink(); path.write_bytes(replacement)
            return real_pin(path, delete=delete)
        with LEASE.Lease(self.root) as lease:
            lease.claim(self.record)
            with patch.object(LEASE, '_PinnedFile', side_effect=swapping):
                self.assert_reason('managed_lock_identity_or_bytes_changed', lambda: lease.release(self.record))
        self.assertEqual(self.path.read_bytes(), replacement)

    def test_root_alias_change_is_rejected_without_following_it(self):
        with LEASE.Lease(self.root) as lease:
            resolve = LEASE.Path.resolve
            def retarget(path, *args, **kwargs):
                return self.root/'elsewhere' if path == lease.input_root else resolve(path, *args, **kwargs)
            with patch.object(LEASE.Path, 'resolve', retarget):
                self.assert_reason('resource_root_alias_changed', lambda: lease.claim(self.record))

    @unittest.skipUnless(os.name == 'nt', 'Win32 sharing semantics only')
    def test_windows_held_read_pin_blocks_write_rename_and_delete_but_allows_reads(self):
        with LEASE.Lease(self.root) as lease:
            lease.claim(self.record)
            self.assertEqual(self.path.read_bytes(), LEASE.canonical(self.record))
            for mutation in (lambda: self.path.write_bytes(b'changed'), lambda: self.path.unlink(),
                    lambda: self.path.rename(self.path.with_name('renamed.lock'))):
                with self.assertRaises(OSError): mutation()
            lease.release(self.record)


if __name__ == '__main__':
    unittest.main()
