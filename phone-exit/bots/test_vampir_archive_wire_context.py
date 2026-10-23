import json
from pathlib import Path
import sys
import unittest

from test_vampir_update_contracts import load, HERE

sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
from vampir_core.login_packet import decode_login_payload

ROOT=Path('F:/PhoneExit Resources/Vampir')
CONTEXT=HERE/'knowledge/native-contexts/archive-wire-11316.json'


class ArchiveWireContextTests(unittest.TestCase):
    def context(self):
        return json.loads(CONTEXT.read_text('utf-8'))

    def test_native_archive_and_whole_packet_bytes(self):
        report=load('verify-archive-wire-context').verify(self.context(),ROOT)
        self.assertEqual(len(report['cases']),45)
        self.assertEqual(len(report['wire_cases']),64)
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])
        boolean=next(c for c in report['cases'] if c['kind']=='bool' and c['value']==128)
        self.assertEqual(boolean['output_hex'],'80')
        for case in report['wire_cases']:
            self.assertTrue(case['guards'])
            body=bytes.fromhex(case['payload_hex'])
            if case['packet']=='game-login':
                decoded=decode_login_payload(body,max_payload_size=16384)
                self.assertEqual(decoded.encode(max_payload_size=16384),body)
        empty=next(c for c in report['wire_cases'] if c['packet']=='game-version' and c['text_utf8_bytes']==0)
        self.assertEqual(len(bytes.fromhex(empty['payload_hex'])),32)

    def test_corrupt_exports_and_leaf_rejected(self):
        tool=load('verify-archive-wire-context')
        context=self.context()
        context['exports']['run-fab5fb09dcf1']='0'*64
        with self.assertRaisesRegex(ValueError,'export SHA changed'):
            tool.verify(context,ROOT)
        context=self.context()
        context['archive_leaves']['0x1445f11f0']['size']+=1
        with self.assertRaisesRegex(ValueError,'leaf size or SHA'):
            tool.verify(context,ROOT)

    def test_wrong_source_table_and_field_order_rejected(self):
        tool=load('verify-archive-wire-context')
        context=self.context()
        context['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'source path differs'):
            tool.verify(context,ROOT)
        context=self.context()
        context['archive']['u16']='0x144aac970'
        with self.assertRaisesRegex(ValueError,'table slot differs'):
            tool.verify(context,ROOT)
        context=self.context()
        fields=context['packets']['game-version']['fields']
        fields[0],fields[1]=fields[1],fields[0]
        with self.assertRaisesRegex(ValueError,'payload or canaries differ'):
            tool.verify(context,ROOT)


if __name__=='__main__':
    unittest.main()
