"""Native mode setup, bounded select iteration and result-code notification routes."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest


class SocketReadinessJobTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'resource-tools/vampir/replay-socket-readiness-job.py'
        spec=importlib.util.spec_from_file_location('socket_ready_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/socket-readiness-job-replay.json').read_text('utf-8'))
        cls.cases={c['fixture']['name']:c for c in cls.report['cases']}

    def test_source_job_slots_and_syscall_bindings(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),14)
        self.assertEqual(struct.unpack_from('<QQ',bytes.fromhex(self.report['job_vtable']['bytes']),16),
                         (0x1445e8080,0x1445e7d80))
        self.assertEqual({i['export']['name'] for i in self.report['imports']},{'select','ioctlsocket'})
        self.assertEqual(self.report['fd_import']['export']['name'],'__WSAFDIsSet')
        self.assertEqual(self.report['fd_thunk']['instructions'][0]['rip_references'],[0x148945b10])
        self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(self.report['engine_vtable']['bytes']),0x30)[0],0x1445f0c60)

    def test_connected_flag_requires_write_and_zero_option(self):
        ready=self.cases['connect-ready']
        self.assertEqual((ready['mode_result'],ready['mode_byte_after'],ready['state_after'],ready['completion_codes']),(1,0,6,[1]))
        selected=next(e for e in ready['events'] if e['action']=='select_fixture')
        self.assertEqual((selected['nfds'],selected['counts'],selected['timeout']),(43,[1,1,1],[0,2000]))
        option=next(e for e in ready['events'] if e['action']=='socket_error_option_capture')
        self.assertEqual((option['selector'],option['value'],option['returned']),(1,0,1))
        for name in ('option-fail','option-error','exception'):
            self.assertEqual((self.cases[name]['state_after'],self.cases[name]['completion_codes']),(2,[2]))
        for name in ('no-ready','select-error','stopped'):
            self.assertEqual(self.cases[name]['completion_codes'],[])

    def test_mode_failures_and_exact_completion_routes(self):
        for name,mode in [('ioctl-fail',1),('enqueue-fail',0),('zero-handle',1)]:
            c=self.cases[name]
            self.assertEqual((c['mode_result'],c['mode_byte_after'],c['completion_codes']),(0,mode,[]))
        expected={'connect-ready':[(1,0x14370ae90)],'option-error':[(2,0x1445c018c)],
                  'read-event':[(4,0x144569170)],'write-event':[(3,0x14156c744)],
                  'read-write':[(4,0x144569170),(3,0x14156c744)],'operation-one':[(0,0x141423088)]}
        for name,pairs in expected.items():
            c=self.cases[name]
            codes=[e['code'] for e in c['events'] if e['action']=='fixture_completion_drain']
            callbacks=[e['callback'] for e in c['events'] if e['action']=='socket_notification_dispatch_capture']
            self.assertEqual(list(zip(codes,callbacks)),pairs)
        self.assertEqual(self.cases['write-event']['write_interest_after'],0)
        self.assertFalse(any(e['action']=='select_fixture' for e in self.cases['stopped']['events']))


if __name__=='__main__':
    unittest.main()
