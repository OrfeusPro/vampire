"""Check native LoginResult state writes, early exit, errors and SDK gates."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).resolve().parent


class LoginResultHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE/'resource-tools/vampir/replay-login-result-handler.py'
        spec = importlib.util.spec_from_file_location('login_handler_test',path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT/'code-clues/login-result-handler-replay.json').read_text('utf-8'))
        cls.cases = {c['fixture']['name']:c for c in cls.report['cases']}

    def test_report_source_ranges_and_executed_gate_bytes_reproduce(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),38)
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_ready'])
        raw = Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        for r in self.report['gate_ranges']:
            content = raw[r['file_offset']:r['file_offset']+r['end']-r['begin']]
            self.assertEqual(hashlib.sha256(content).hexdigest(),r['sha256'])
        for r in self.report['gate_trace']:
            content = bytes.fromhex(r['bytes'])
            self.assertEqual(raw[r['file_offset']:r['file_offset']+len(content)],content)
        table = bytes.fromhex(self.report['handler_table']['bytes'])
        self.assertEqual(struct.unpack_from('<Q',table,16)[0],0x146765540)

    def test_success_raw_state_writes_and_signed_early_exit(self):
        for c in self.report['cases']:
            fields,f = c['decoded']['fields'],c['fixture']
            code = fields['u32']['0x10']
            actions = [e['action'] for e in c['events']]
            gate = [e for e in c['events'] if e['action']=='native_gate']
            if gate:
                self.assertEqual(gate,[dict(action='native_gate',code=code,packet_id=4)])
            if code:
                self.assertEqual(c['state']['text'],'before-fixture')
                self.assertNotIn('post_state_capture',actions)
                continue
            value = fields['u16']['0x48']
            early = bool(f['peer_flag']) and 0<value<32768
            if early:
                self.assertEqual(actions,['native_gate','native_gate_return','early_state_helper_capture','exit_virtual_capture'])
                self.assertEqual(c['native_writes'],[])
                self.assertEqual(c['state']['text'],'before-fixture')
                self.assertEqual(c['controller_server'],[7,7])
                continue
            self.assertEqual(c['state']['text'],fields['strings']['0x18'])
            qwords = {'0x38':fields['u64']['0x68'],'0x88':fields['u64']['0x68'],
                '0xb0':fields['u64']['0xf0'],'0xc0':fields['u64']['0x100'],
                '0xd0':fields['u64']['0x110'],'0xe0':fields['u64']['0x120']}
            self.assertEqual(c['state']['qwords'],qwords)
            self.assertEqual(c['state']['flags'],{'0xa0':fields['bool']['0xe0'],'0xe8':fields['bool']['0x128']})
            writes = [w for w in c['native_writes'] if w['region']=='state']
            self.assertEqual({hex(w['offset']):w['value'] for w in writes},dict(qwords,**c['state']['flags']))
            self.assertEqual(len(writes),8)
            self.assertIn('post_state_capture',actions)
            self.assertIn('view_virtual_capture',actions)
            self.assertEqual('positive_field_helper_capture' in actions,0<value<32768 and f['optional_object'])
            toggles = [e['value'] for e in c['events'] if e['action']=='state_toggle_capture']
            self.assertEqual(toggles,[0,1] if 0<value<32768 else [0])
            self.assertEqual(c['controller_server'],[f['selected_server']]*2)
            server_writes = [w for w in c['native_writes'] if w['region']=='controller']
            self.assertEqual(len(server_writes),0 if f['previous_server']==f['selected_server'] else 2)
            raw16 = fields['u16']['0x60']
            signed = raw16 if raw16<32768 else raw16-65536
            scale,bias = [v['double'] for v in self.report['constants']]
            self.assertEqual(c['derived_integer'],math.floor(signed*scale+bias))
            pair = next(e for e in c['events'] if e['action']=='time_pair_capture')
            self.assertEqual((pair['raw64'],pair['raw16']),(fields['u64']['0x58'],raw16))
            self.assertEqual('flag138_helper_capture' in actions,bool(fields['bool']['0x138']))

    def test_error_routes_do_not_write_success_state(self):
        for code in (14,22,37):
            c = self.cases['code-'+str(code)]
            self.assertIn(dict(action='dedicated_error_capture',code=code),c['events'])
            self.assertEqual(c['special22_flag'],int(code==22))
            self.assertFalse(any(w['region']=='state' for w in c['native_writes']))
        c = self.cases['code-9400']
        self.assertIn(dict(action='error9400_fields_capture',offsets=[0xc8,0xb8,0xa8]),c['events'])
        for code,action in ((54,'error54_popup_capture'),(9818,'special_error_object_capture'),
            (9819,'special_error_object_capture'),(90021,'special_90021_object_capture')):
            c = self.cases['code-'+str(code)]
            self.assertIn(action,[e['action'] for e in c['events']])
            self.assertFalse(any(e['action']=='native_gate' for e in c['events']))
        for code in (1,0xffffffff):
            c = self.cases['code-'+str(code)]
            self.assertIn(dict(action='disconnect_backend_capture',raw_value=0,peer_argument=True),c['events'])
            self.assertIn('exit_virtual_capture',[e['action'] for e in c['events']])
        self.assertIn('generic_popup_capture',[e['action'] for e in self.cases['variant-1']['events']])
        for code in (9818,9819,90021):
            self.assertEqual(self.cases['variant-'+str(code)]['events'],[dict(action='special_error_finish_capture',raw_value=0)])
        self.assertNotIn('gate_error_capture',[e['action'] for e in self.cases['gate-state-one-error']['events']])

    def test_sdk_callbacks_are_gated_and_post_predicate_is_separate(self):
        for c in self.report['cases']:
            f = c['fixture']
            if c['state']['text']=='before-fixture': continue
            actions = [e['action'] for e in c['events']]
            enabled = f['sdk_enabled'] and f['manager_present']
            self.assertEqual('sdk_88_virtual_capture' in actions,enabled and f['sdk_callbacks'])
            self.assertEqual('sdk_a0_helper_capture' in actions,enabled and f['sdk_callbacks'])
            self.assertEqual('sdk_final_helper_capture' in actions,enabled and f['auth_present'])
            self.assertEqual('post_predicate_helper_capture' in actions,f['post_predicate'])


if __name__=='__main__':
    unittest.main()
