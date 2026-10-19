"""WaitingEnd notification binding and native selection/request branches."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent


class WaitingEndCharacterRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-waiting-end-character-request.py'
        spec=importlib.util.spec_from_file_location('waiting_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/waiting-end-character-request-replay.json').read_text('utf-8'))

    def test_report_and_notification_registration_reproduce(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(self.report['packet_id'],27)
        self.assertEqual(len(self.report['cases']),24)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(self.report['literals'][0]['text'],'PktWaitingEndNotifyHandler::OnHandler()')
        raw=Path(self.report['source']).read_bytes()
        for row in self.report['anchors']+self.report['leaves']+self.report['literals']:
            data=bytes.fromhex(row['bytes'])
            self.assertEqual(raw[row['file_offset']:row['file_offset']+len(data)],data)
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x14676864f]['direct_target'],0x145dbfe50)
        self.assertEqual(rows[0x14678f197]['direct_target'],0x1456d54d0)
        self.assertEqual(rows[0x14678f1aa]['direct_target'],0x1467a7250)

    def test_native_request_and_selection_branch_matrix(self):
        sentinel=int.from_bytes(bytes.fromhex(self.report['anchors'][2]['bytes']),'little')
        count=0
        for case in self.report['cases']:
            f=case['fixture'];events=case['events']
            valid=f['policy_object'] and f['type_count']>=1 and f['type_match'] and not f['policy_disabled']
            policy=f['policy_value'] if valid else 4
            sends=[e for e in events if e['action']=='send_capture']
            selects=[e for e in events if e['action']=='selection_virtual_capture']
            nexts=[e for e in events if e['action']=='next_virtual_capture']
            self.assertEqual(bool(sends),bool(f['peer_flag']) and policy==1)
            self.assertEqual(len(sends),int(bool(sends)))
            if sends:
                count+=1
                self.assertEqual(sends,[dict(action='send_capture',vtable=0x1498d84d8,packet_byte_a=0)])
                self.assertEqual(events[-1],dict(action='packet_cleanup_capture'))
            expected_select=bool(f['peer_flag']) and policy not in (0,1) or not f['peer_flag'] and policy==0 and f['selected_raw']!=sentinel
            self.assertEqual(bool(selects),expected_select)
            if selects:
                self.assertEqual(selects[0]['raw64'],0x0102030405060708 if f['peer_flag'] else f['selected_raw'])
                self.assertEqual(selects[0]['raw32'],int.from_bytes(bytes.fromhex(self.report['anchors'][3]['bytes']),'little'))
            self.assertEqual(bool(nexts),policy==0 and (bool(f['peer_flag']) or f['selected_raw']==sentinel))
            self.assertEqual(events[0],dict(action='state_toggle_capture',value=0))
        self.assertEqual(count,2)

    def test_predicate_fallback_does_not_call_virtual_policy(self):
        for case in self.report['cases']:
            f=case['fixture']
            valid=f['policy_object'] and f['type_count']>=1 and f['type_match'] and not f['policy_disabled']
            policy_calls=[e for e in case['events'] if e['action']=='policy_virtual_capture']
            expected=2 if f['peer_flag'] and f['policy_value']!=1 else 1
            self.assertEqual(len(policy_calls),expected if valid else 0)


if __name__=='__main__':unittest.main()
