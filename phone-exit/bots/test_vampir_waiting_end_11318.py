"""Reuse the established scenarios with the explicit 1.13.18 source context."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import test_vampir_waiting_end_context as previous


class CurrentWaitingEndContextTests(previous.WaitingEndContextTests):
    def test_native_request_and_selection_gates(self):
        batch=previous.load('run-character-list-batch-11318')
        report=batch.report_for('waiting-end', self.context(), previous.ROOT)
        verify=Mock(return_value=report)
        original_load=previous.load
        def component(module):
            if module=='verify-waiting-end-context':return SimpleNamespace(verify=verify)
            return original_load(module)
        with patch.object(previous, 'load', side_effect=component):
            super().test_native_request_and_selection_gates()
        verify.assert_called_once_with(self.context(), previous.ROOT)

    def context(self):
        context=json.loads((previous.HERE/'knowledge/native-contexts/waiting-end-11318.json').read_text('utf-8'))
        self.assertEqual(context['source_sha256'], 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c')
        return context

    def test_changed_handler_registration_rejected(self):
        context=self.context()
        self.assertNotEqual(context['bindings']['handler_table'], context['bindings']['notify_table'])
        context['bindings']['handler_table']=context['bindings']['notify_table']
        with self.assertRaisesRegex(ValueError, 'handler slot differs'):
            previous.load('verify-waiting-end-context').verify(context, previous.ROOT)


if __name__=='__main__':unittest.main()
