"""Constructed owner dispatch reaches native finish guard with explicit gates."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent


class WorldFinishOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-world-finish-owner.py'
        spec=importlib.util.spec_from_file_location('finish_owner_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/world-finish-owner-replay.json').read_text('utf-8'))

    def test_actual_construction_and_dispatch_reproduce(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),39)
        self.assertFalse(self.report['network_ready'])

    def test_policy_three_and_native_slots_keep_status_guard(self):
        for case in self.report['cases']:
            self.assertIn((case['constructor'],case['table']),self.tool.OWNERS)
            self.assertEqual(case['policy'],3)
            entries=[e['address'] for e in case['events'] if e['action']=='native_finish_entry']
            self.assertEqual(entries[:2],[self.tool.CALLER,self.tool.BASE80])
            self.assertEqual(self.tool.base.REQUEST in entries,not case['world_present'])
            sends=[e for e in case['events'] if e['action']=='finish_packet_capture']
            expected=not case['world_present'] and not case['pending'] and case['status'] in (2,3,4)
            self.assertEqual(len(sends),int(expected))
            self.assertEqual(case['state']['flag'],1)
            self.assertEqual(case['state']['handle'],0x12345678)
            if case['status']==1:self.assertEqual(case['state']['status30'],1)

    def test_world_present_defers_and_owner_callback_registration_is_separate(self):
        for case in self.report['cases']:
            deferred=[e for e in case['events'] if e['action']=='world_present_deferred_capture']
            self.assertEqual(len(deferred),int(case['world_present']))
            if deferred:self.assertEqual(deferred[0]['callback'],0x143642370)
            callbacks=[e for e in case['events'] if e['action']=='owner_delegate_capture']
            self.assertEqual(callbacks,[dict(action='owner_delegate_capture',callback=0x1468eb140)])
            if case['pending']:
                self.assertEqual(case['state']['status30'],3)
                self.assertIn(dict(action='pending_label_capture',raw=37),case['events'])

    def test_actual_deferred_callback_uses_the_same_guard(self):
        self.assertEqual(bytes.fromhex(self.report['callback_leaf']['bytes']),bytes.fromhex('488b09488b0148ff6070'))
        self.assertEqual(len(self.report['callbacks']),6)
        for case in self.report['callbacks']:
            expected=case['status'] in (2,3,4)
            sends=[e for e in case['events'] if e['action']=='finish_packet_capture']
            self.assertEqual(len(sends),int(expected))
            self.assertEqual(case['after'],5 if expected else case['status'])

    def test_actual_world_present_preparation_writes_four_before_callback(self):
        self.assertEqual(len(self.report['prepared']),6)
        for case in self.report['prepared']:
            self.assertEqual((case['prepare_state'],case['after']),(4,5))
            self.assertIn(dict(action='native_deferred_prepare'),case['prepare_events'])
            writes=[e for e in case['prepare_events'] if e['action']=='native_status_set']
            self.assertEqual([(e['old'],e['value']) for e in writes],[(case['status'],4)])
            self.assertFalse(any(e['action']=='finish_packet_capture' for e in case['prepare_events']))
            sends=[e for e in case['callback_events'] if e['action']=='finish_packet_capture']
            self.assertEqual(len(sends),1)


if __name__=='__main__':unittest.main()
