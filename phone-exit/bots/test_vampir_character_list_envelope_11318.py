"""Reuse the established scenarios with the explicit 1.13.18 source context."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import test_vampir_character_list_envelope_context as previous


class CurrentCharacterListEnvelopeContextTests(previous.CharacterListEnvelopeContextTests):
    def test_empty_envelope_requires_complete_tail(self):
        batch=previous.load('run-character-list-batch-11318')
        report=batch.report_for('character-list-envelope', self.context(), previous.ROOT)
        verify=Mock(return_value=report)
        original_load=previous.load
        def component(module):
            if module=='verify-character-list-envelope-context':return SimpleNamespace(verify=verify)
            return original_load(module)
        with patch.object(previous, 'load', side_effect=component):
            super().test_empty_envelope_requires_complete_tail()
        verify.assert_called_once_with(self.context(), previous.ROOT)

    def context(self):
        context=json.loads((previous.HERE/'knowledge/native-contexts/character-list-envelope-11318.json').read_text('utf-8'))
        self.assertEqual(context['source_sha256'], 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c')
        return context

    def test_changed_vector_link_rejected(self):
        context=self.context()
        self.assertNotEqual(context['bindings']['vector_table'], context['bindings']['packet_table'])
        context['bindings']['vector_table']=context['bindings']['packet_table']
        with self.assertRaisesRegex(ValueError, 'table link differs'):
            previous.load('verify-character-list-envelope-context').verify(context, previous.ROOT)

    def test_changed_scalar_dependency_rejected(self):
        context=self.context()
        calls=context['call_sites']['u32']
        at=next(at for at, target in calls.items() if target.startswith('0x'))
        self.assertNotEqual(calls[at], context['functions']['u32'])
        calls[at]=context['functions']['u32']
        with self.assertRaisesRegex(ValueError, 'call sites differ'):
            previous.load('verify-character-list-envelope-context').verify(context, previous.ROOT)


if __name__=='__main__':unittest.main()
