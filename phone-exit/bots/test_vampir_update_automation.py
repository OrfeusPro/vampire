"""Fixture-only orchestration/admission checks used by the ordinary updater."""
import importlib
import unittest


def load_tests(loader, tests, pattern):
    result = unittest.TestSuite()
    for name in ('test_vampir_update_auto_watch', 'test_vampir_prepared_bundle', 'test_vampir_prepared_runtime',
            'test_vampir_update_bindiff_candidates','test_vampir_native_string_writer',
            'test_vampir_native_adapter_drivers','test_vampir_native_archive_adapter',
            'test_vampir_native_version_result_adapter','test_vampir_native_version_prepare_adapter',
            'test_vampir_native_login_prepare_adapter','test_vampir_native_login_sdk_adapter'):
        result.addTests(loader.loadTestsFromModule(importlib.import_module(name)))
    return result


if __name__ == '__main__':
    unittest.main()
