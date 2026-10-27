"""Reuse the established scenarios with the explicit 1.13.18 source context."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import test_vampir_character_record_context as previous


class CurrentCharacterRecordContextTests(previous.CharacterRecordContextTests):
    def test_native_record_projection_and_failure_gates(self):
        batch=previous.load('run-character-list-batch-11318')
        report=batch.report_for('character-record', self.context(), previous.ROOT)
        verify=Mock(return_value=report)
        original_load=previous.load
        def component(module):
            if module=='verify-character-record-context':return SimpleNamespace(verify=verify)
            return original_load(module)
        with patch.object(previous, 'load', side_effect=component):
            super().test_native_record_projection_and_failure_gates()
        verify.assert_called_once_with(self.context(), previous.ROOT)

    def context(self):
        context=json.loads((previous.HERE/'knowledge/native-contexts/character-record-11318.json').read_text('utf-8'))
        self.assertEqual(context['source_sha256'], 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c')
        self.assertEqual(context['native_input']['source_sha256'], context['source_sha256'])
        return context

    def test_changed_input_dependency_rejected(self):
        context=self.context()
        calls=context['native_input']['call_sites']
        at=next(at for at, spec in calls.items() if spec['target'].startswith('0x'))
        self.assertNotEqual(calls[at]['target'], context['native_input']['functions']['constructor'])
        calls[at]['target']=context['native_input']['functions']['constructor']
        with self.assertRaisesRegex(ValueError,'input callees differ'):
            previous.load('verify-character-record-context').verify(context,previous.ROOT)


if __name__=='__main__':unittest.main()
