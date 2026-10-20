import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.windows_device_identity import _observe


class Key:
    def __init__(self, path): self.path = path
    def __enter__(self): return self
    def __exit__(self, *args): pass


class Registry:
    HKEY_CURRENT_USER, KEY_READ, REG_SZ = 1, 2, 3
    def __init__(self):
        self.rows = {('Software\\Netmarble\\thered', 'DeviceKey'): ('sdk-fixture', self.REG_SZ),
                     ('Software\\Netmarble\\thered', 'DeviceKeyForNetmarbleId'): ('nid-fixture', self.REG_SZ),
                     ('Software\\Netmarble\\NetmarbleSDK', 'NMDeviceKey'): ('nm-fixture', self.REG_SZ)}
        self.opens = []
        self.calls = 0
        self.change = False
    def OpenKey(self, hive, path, reserved, access):
        if (hive, reserved, access) != (self.HKEY_CURRENT_USER, 0, self.KEY_READ):
            raise AssertionError('Only explicit read access allowed')
        self.opens.append(path)
        return Key(path)
    def QueryValueEx(self, key, name):
        self.calls += 1
        if self.change and self.calls > 3: return ('changed-fixture', self.REG_SZ)
        try: return self.rows[key.path, name]
        except KeyError: raise FileNotFoundError


class WindowsIdentityTests(unittest.TestCase):
    def test_three_separate_values_and_no_secret_in_repr(self):
        registry = Registry()
        result = _observe(registry, store_name='Netmarble', game_code='thered')
        self.assertEqual((result.device_key, result.nid_device_key, result.nm_device_key),
                         ('sdk-fixture', 'nid-fixture', 'nm-fixture'))
        self.assertEqual(len(registry.opens), 6)
        self.assertNotIn('fixture', repr(result))

    def test_missing_empty_wrong_type_and_changed_values(self):
        for mode in ('missing', 'empty', 'type', 'change', 'control'):
            registry = Registry()
            key = ('Software\\Netmarble\\thered', 'DeviceKey')
            if mode == 'missing': del registry.rows[key]
            elif mode == 'empty': registry.rows[key] = ('', registry.REG_SZ)
            elif mode == 'type': registry.rows[key] = ('value', 99)
            elif mode == 'change': registry.change = True
            else: registry.rows[key] = ('bad\0value', registry.REG_SZ)
            with self.assertRaises(ValueError): _observe(registry, store_name='Netmarble', game_code='thered')

    def test_context_is_required_and_never_falls_back_to_another_store(self):
        for value in ('', None, ' Netmarble', 'Netmarble\\other', 'Netmarble/other'):
            with self.assertRaises(ValueError): _observe(Registry(), store_name=value, game_code='thered')
        registry = Registry()
        with self.assertRaises(ValueError): _observe(registry, store_name='OtherStore', game_code='thered')
        self.assertEqual(registry.opens, ['Software\\OtherStore\\thered'])


if __name__ == '__main__': unittest.main()
