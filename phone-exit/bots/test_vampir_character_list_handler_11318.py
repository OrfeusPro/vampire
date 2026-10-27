"""Reuse the established scenarios with the explicit 1.13.18 source context."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import test_vampir_character_list_handler_context as previous


class CurrentCharacterListHandlerContextTests(previous.CharacterListHandlerContextTests):
    def test_gate_publication_preference_and_empty_list(self):
        batch=previous.load('run-character-list-batch-11318')
        report=batch.report_for('character-list-handler', self.context(), previous.ROOT)
        verify=Mock(return_value=report)
        original_load=previous.load
        def component(module):
            if module=='verify-character-list-handler-context':return SimpleNamespace(verify=verify)
            return original_load(module)
        with patch.object(previous, 'load', side_effect=component):
            super().test_gate_publication_preference_and_empty_list()
        verify.assert_called_once_with(self.context(), previous.ROOT)

    def context(self):
        context=json.loads((previous.HERE/'knowledge/native-contexts/character-list-handler-11318.json').read_text('utf-8'))
        self.assertEqual(context['source_sha256'], 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c')
        return context

    def test_changed_registration_rejected(self):
        context=self.context()
        self.assertNotEqual(context['bindings']['handler_table'], context['bindings']['packet_table'])
        context['bindings']['handler_table']=context['bindings']['packet_table']
        with self.assertRaisesRegex(ValueError, 'registration table/ID differs'):
            previous.load('verify-character-list-handler-context').verify(context, previous.ROOT)

    def test_changed_gate_callee_rejected(self):
        context=self.context()
        calls=context['call_sites']['handler']
        at=next(at for at, target in calls.items() if target==context['functions']['gate'])
        replacement=context['functions']['predicate']
        self.assertNotEqual(calls[at], replacement)
        calls[at]=replacement
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            previous.load('verify-character-list-handler-context').verify(context, previous.ROOT)


if __name__=='__main__':unittest.main()
