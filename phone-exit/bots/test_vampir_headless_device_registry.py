"""Persistence and isolation of local device bindings, no game access."""
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.device_registry import DeviceRegistry


class DeviceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'accounts.sqlite3'
        self.registry = DeviceRegistry(self.path)

    def test_restart_and_idempotent_registration(self):
        first = self.registry.register('Main@example.invalid', kind='real', is_main=True)
        second = DeviceRegistry(self.path).register('main@example.invalid', kind='real', is_main=True)
        self.assertEqual(first, second)
        self.assertFalse(first.identity_recorded)
        self.assertEqual(first.confirmation, 'unknown')
        self.assertNotIn('example.invalid', repr(first))
        with self.assertRaises(ValueError):
            self.registry.register(first.email, kind='planned')
        with self.assertRaises(sqlite3.IntegrityError):
            self.registry.register('other@example.invalid', kind='real', is_main=True)

    def test_identity_is_stable_and_confirmation_is_independent(self):
        self.registry.register('main@example.invalid', kind='real')
        args = dict(device_key='observed-device', nm_device_key='observed-nm', source='synthetic test fixture')
        self.registry.record_real_identity('main@example.invalid', **args)
        self.registry.record_real_identity('main@example.invalid', **args)
        with self.assertRaises(ValueError):
            self.registry.record_real_identity('main@example.invalid', **dict(args, device_key='replacement'))
        self.registry.record_confirmation('main@example.invalid', evidence='Synthetic manual confirmation fixture')
        bound = self.registry.require_confirmation('main@example.invalid')
        self.assertEqual(bound.confirmation, 'required')
        self.assertEqual(bound.confirmation_evidence, '')
        restored = DeviceRegistry(self.path).get(bound.email)
        self.assertTrue(restored.identity_recorded)
        self.assertEqual(restored.device_key, args['device_key'])
        self.assertEqual(restored.confirmation, 'required')

    def test_accounts_are_isolated_and_planned_is_not_real(self):
        a = self.registry.register('one@example.invalid', kind='real')
        b = self.registry.register('two@example.invalid')
        self.assertNotEqual(a.profile_id, b.profile_id)
        self.registry.require_confirmation(a.email)
        self.assertEqual(self.registry.get(b.email).confirmation, 'unknown')
        with self.assertRaises(ValueError):
            self.registry.record_confirmation(a.email, evidence='fixture')
        with self.assertRaises(ValueError):
            self.registry.record_real_identity(b.email, device_key='x', nm_device_key='y', source='fixture')
        with self.assertRaises(KeyError):
            self.registry.require_confirmation('missing@example.invalid')


if __name__ == '__main__':
    unittest.main()
