import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.windows_cpu import observe_windows_cpu


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class WindowsCpuReaderTests(unittest.TestCase):
    def test_hash_failure_precedes_loading_and_invalid_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.dll'
            path.write_bytes(b'fixture library, never executable')
            with patch('vampir_core.windows_cpu.sys.platform', 'win32'), \
                    patch.object(ctypes, 'WinDLL', create=True) as loader:
                for digest in ('0' * 64, 'bad-hash', 'A' * 64):
                    with self.assertRaises(ValueError): observe_windows_cpu(path, expected_sha256=digest)
                loader.assert_not_called()

    def test_verified_library_buffers_and_unsupported_text_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.dll'
            path.write_bytes(b'fixture')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            def query(vendor, vendor_capacity, brand, brand_capacity):
                self.assertEqual((vendor_capacity, brand_capacity), (13, 49))
                vendor.value = b'GenuineIntel'
                brand.value = b'  Fixture CPU  '
                return 1
            query_mock = Mock(side_effect=query)
            library = Mock(vampir_read_cpu=query_mock)
            with patch('vampir_core.windows_cpu.sys.platform', 'win32'), \
                    patch.object(ctypes, 'WinDLL', return_value=library, create=True):
                value = observe_windows_cpu(path, expected_sha256=digest)
                self.assertEqual(value.text(), 'GenuineIntel|Fixture CPU')
                query_mock.side_effect = lambda *args: 0
                with self.assertRaises(RuntimeError): observe_windows_cpu(path, expected_sha256=digest)
                def nonascii(vendor, vendor_capacity, brand, brand_capacity):
                    vendor.value = b'GenuineIntel'; brand.value = b'\xff'; return 1
                query_mock.side_effect = nonascii
                with self.assertRaises(ValueError): observe_windows_cpu(path, expected_sha256=digest)

    def test_non_windows_never_loads_native_library(self):
        with patch('vampir_core.windows_cpu.sys.platform', 'linux'), \
                patch.object(ctypes, 'WinDLL', create=True) as loader:
            with self.assertRaises(RuntimeError): observe_windows_cpu('unused.dll', expected_sha256='0' * 64)
            loader.assert_not_called()


class ActualCpuHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != 'win32': raise unittest.SkipTest('Actual Windows helper test')
        cls.folder = HERE.parent / '.tools/vampir-runtime-windows'
        if not (cls.folder / 'receipt.json').is_file(): raise unittest.SkipTest('Build the owned CPU helper first')
        cls.adapter = load('actual_cpu_inputs_test', HERE / 'vampir-headless/windows-system-inputs.py')

    def test_real_cpuid_agrees_with_existing_native_game_path_without_hardware_logs(self):
        cpu, version = self.adapter.observe_inputs()
        self.assertTrue(0 < len(cpu.vendor) <= 12)
        self.assertTrue(len(cpu.brand) <= 48)
        tool = load('actual_cpu_native_test', HERE / 'resource-tools/vampir/replay-version-cpu-string.py')
        report = json.loads((tool.native.ROOT / 'code-clues/version-cpu-string-replay.json').read_text('utf-8'))
        source = json.loads((tool.native.ROOT / 'code-clues/headless-device-identity.json').read_text('utf-8'))
        raw = Path(source['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), report['source_sha256'])
        em = tool.Replay(raw, tool.native.Image(raw), source, report['fragments'],
            dict(enabled=True, max_extended=0x80000004, vendor=cpu.vendor, brand=cpu.brand))
        em.call(tool.cpu.INITIALIZE)
        em.call(tool.GETTER)
        self.assertTrue(em.text(em.output) == cpu.text(), 'Native CPU text differs; hardware details suppressed')
        from vampir_core.version_packet import VersionPayload
        prepared = self.adapter.bind_observed_inputs(VersionPayload(('',) * 10, (0, 207, 1)))
        self.assertTrue(prepared.strings[2] == cpu.text(), 'Observed CPU binding differs')
        self.assertTrue(prepared.strings[1].startswith('Windows_'))

    def test_actual_c_abi_rejects_short_or_null_buffers_without_writes(self):
        receipt = json.loads((self.folder / 'receipt.json').read_text('utf-8'))
        path = self.folder / 'vampir_system_inputs.dll'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), receipt['binary_sha256'])
        library = ctypes.WinDLL(str(path.resolve()))
        query = library.vampir_read_cpu
        query.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
        query.restype = ctypes.c_int
        vendor = ctypes.create_string_buffer(b'x' * 13, 13)
        brand = ctypes.create_string_buffer(b'y' * 49, 49)
        for first, size_a, second, size_b in ((vendor, 12, brand, 49), (vendor, 13, brand, 48),
                (None, 13, brand, 49), (vendor, 13, None, 49)):
            self.assertEqual(query(first, size_a, second, size_b), 0)
            self.assertTrue(vendor.raw == b'x' * 13 and brand.raw == b'y' * 49)


if __name__ == '__main__': unittest.main()
