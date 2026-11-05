"""Source-bound static gate for the exported SDK and Launcher entry set."""
import importlib.util
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


TOOLS = Path(__file__).resolve().parent / 'resource-tools/vampir'
CONTEXT = TOOLS / 'knowledge/native-contexts/sdk-launcher-entry-11322.json'


class SdkLauncherEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('sdk_launcher_entry', TOOLS / 'audit-sdk-launcher-entry.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.context = json.loads(CONTEXT.read_bytes())

    def test_complete_export_shapes_and_callback_edges(self):
        result = self.tool.audit(self.context, self.tool.load('build-native-entry-code').ROOT)
        self.assertEqual(result['instructions'], {
            'sdk-constructor': 137, 'nid-context': 972, 'nid-result': 1041,
            'launcher-token': 652, 'launcher-sign-in': 679,
            'launcher-token-response': 551, 'launcher-sign-in-response': 762,
        })
        self.assertEqual(result['callback_thunks'], {'token': '0x1444def10', 'sign-in': '0x1444df000'})
        self.assertFalse(result['runtime_admitted'])
        self.assertEqual(set(result['unresolved_dependencies']), set(self.tool.ROLES))

    def test_omitting_launcher_route_rejects(self):
        context = dict(self.context, launcher={'token': self.context['launcher']['token']})
        with self.assertRaisesRegex(ValueError, 'route set'):
            self.tool.audit(context, Path('unused'))

    def test_changed_source_or_export_rejects(self):
        path = SimpleNamespace(name='input', read_bytes=Mock(return_value=b'changed'))
        with self.assertRaisesRegex(ValueError, 'input SHA'):
            self.tool.checked(path, 'a' * 64)

    def test_bss_literal_reference_and_wrong_callback_target(self):
        route = 'launcher/token'
        literal = (route + '\0').encode('utf-16le')
        request = {'references': [dict(offset=0, target='0x10'), dict(offset=8, target='0x20'),
                                  dict(offset=16, target='0x30')]}
        def read(image, address, size):
            if address == 0x10:
                raise ValueError('BSS')
            if address == 0x20:
                return literal
            return (b'\xe9' + struct.pack('<i', 0x40 - 0x30 - 5))[:size].ljust(size, b'\0')
        with patch.object(self.tool, 'file_bytes', side_effect=read):
            self.assertEqual(self.tool.route_edges(None, request, 0x40, {'thunk': 16}, route), '0x30')
            with self.assertRaisesRegex(ValueError, 'callback thunk'):
                self.tool.route_edges(None, request, 0x50, {'thunk': 16}, route)

    def test_response_crt_requires_identity_and_call_site(self):
        image = SimpleNamespace(data=b'')
        importer = SimpleNamespace(import_at=Mock(return_value=dict(dll='other.dll', name='_wtoi')))
        body = dict(references=[dict(offset=4, target='0x20')], shape=[(4, 'ff1520', ('indirect', 'call'))])
        with self.assertRaisesRegex(ValueError, 'CRT import'):
            self.tool.response_shape(importer, image, body, 4)
        importer.import_at.return_value = dict(zip(('dll', 'name'), self.tool.CRT))
        body['shape'] = [(4, 'ff1520', ('indirect', 'jmp'))]
        with self.assertRaisesRegex(ValueError, 'not an indirect call'):
            self.tool.response_shape(importer, image, body, 4)
