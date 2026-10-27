"""Reuse the established scenarios with the explicit 1.13.18 source context."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import test_vampir_character_list_records_context as previous


class CurrentCharacterListRecordsContextTests(previous.CharacterListRecordsContextTests):
    def test_native_whole_list_preserves_distinct_records(self):
        batch=previous.load('run-character-list-batch-11318')
        report=batch.report_for('character-list-records', self.context(), previous.ROOT)
        verify=Mock(return_value=report)
        original_load=previous.load
        def component(module):
            if module=='verify-character-list-records-context':return SimpleNamespace(verify=verify)
            return original_load(module)
        with patch.object(previous, 'load', side_effect=component):
            super().test_native_whole_list_preserves_distinct_records()
        verify.assert_called_once_with(self.context(), previous.ROOT)

    def context(self):
        context=json.loads((previous.HERE/'knowledge/native-contexts/character-list-records-11318.json').read_text('utf-8'))
        self.assertEqual(context['source_sha256'], 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c')
        return context

    def test_changed_copy_call_rejected(self):
        context=self.context()
        calls=context['call_sites']['list_record_thunk']
        expected=context['fixtures']['list_copy']
        at=next(at for at, target in calls.items() if target==expected)
        replacement=context['functions']['constructor']
        self.assertNotEqual(calls[at], replacement)
        calls[at]=replacement
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            previous.load('verify-character-list-records-context').verify(context, previous.ROOT)


if __name__=='__main__':unittest.main()
