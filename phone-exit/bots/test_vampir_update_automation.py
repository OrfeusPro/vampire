"""Fixture-only orchestration/admission checks used by the ordinary updater."""
import importlib
import unittest


def load_tests(loader, tests, pattern):
    result = unittest.TestSuite()
    for name in ('test_vampir_update_auto_watch', 'test_vampir_prepared_bundle', 'test_vampir_prepared_runtime',
            'test_vampir_update_bindiff_candidates','test_vampir_native_string_writer',
            'test_vampir_native_adapter_drivers','test_vampir_native_archive_adapter',
            'test_vampir_native_version_result_adapter','test_vampir_native_version_prepare_adapter',
            'test_vampir_native_login_prepare_adapter','test_vampir_native_login_sdk_adapter',
            'test_vampir_version_helper_case_contracts','test_vampir_version_system_transfer_rules',
            'test_vampir_version_string_transfer_rules','test_vampir_native_version_helpers_adapter',
            'test_vampir_login_metadata_transfer_rules','test_vampir_login_metadata_case_contracts',
            'test_vampir_native_login_metadata_adapter','test_vampir_login_input_transfer_rules',
            'test_vampir_login_input_case_contracts','test_vampir_native_login_input_adapter',
            'test_vampir_login_handler_transfer_rules','test_vampir_login_handler_case_contracts',
            'test_vampir_native_login_handler_adapter','test_vampir_native_publication_cache',
            'test_vampir_result_gate_transfer_rules','test_vampir_result_gate_case_contracts',
            'test_vampir_post_state_transfer_rules','test_vampir_post_state_case_contracts',
            'test_vampir_native_response_adapter','test_vampir_login_full_handler_rules',
            'test_vampir_login_full_handler_case_contracts','test_vampir_native_login_full_adapter',
            'test_vampir_login_composition_rules','test_vampir_login_composition_case_contracts',
            'test_vampir_native_login_composition_adapter'):
        result.addTests(loader.loadTestsFromModule(importlib.import_module(name)))
    return result


if __name__ == '__main__':
    unittest.main()
