"""Current tutorial wire parity and isolated observations; all data synthetic."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest
from urllib.request import urlopen

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.tutorial_update import decode_tutorial_update
from vampir_core.world_move_start import CURRENT_PROBE_SOURCE as SHA
from vampir_core.live_session import LiveSession
from vampir_core.live_session_server import LiveSessionServer
from test_vampir_environment import owner

def body(key=1001,selector=2,count=1):
    return struct.pack('<BH',255,count)+b''.join(struct.pack('<IIIB',key+i,selector,0xffffffff,255) for i in range(count))

class Tutorial11316Tests(unittest.TestCase):
    def test_current_whole_native_reader_and_each_maximum_body_prefix(self):
        path=HERE/'resource-tools/vampir/replay-tutorial-update-11316.py'
        spec=importlib.util.spec_from_file_location('current_tutorial_replay_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _,report=module.run()
        self.assertEqual(report['source_sha256'],SHA);self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),73);self.assertEqual([r['size'] for r in report['short']],list(range(835)))
    def test_exact_wire_budgets_unknown_source_and_trailing_bytes(self):
        def decode(raw,**kw):return decode_tutorial_update(raw,**dict(source_sha256=SHA,max_records=64,max_payload_size=835,**kw))
        value=decode(body(count=64));self.assertEqual(len(value.records),64);self.assertTrue(value.flag)
        self.assertEqual(value.records[-1].state,3);self.assertEqual(value.records[0].raw10,0xffffffff)
        for raw in (body()[:-1],body()+b'\0'):
            with self.assertRaises(ValueError):decode(raw)
        with self.assertRaises(BufferError):decode(body(count=65))
        with self.assertRaises(ValueError):decode_tutorial_update(body(),source_sha256='0'*64,max_records=64,max_payload_size=835)
    def test_fifty_owners_keep_last_message_separate_from_applied_quests(self):
        sessions=[LiveSession(bot_id='tutorial-fixture-'+str(i)) for i in range(50)]
        try:
            for i,s in enumerate(sessions):
                s.bind_source(SHA);s.packet(9905,body(selector=i));s.publish(owner())
                value=s.snapshot();row=value['tutorial']
                self.assertEqual(row['records'][0]['raw0c'],i);self.assertIsNone(row['world_id']);self.assertIsNone(row['character_key'])
                self.assertFalse(row['applied_to_local_task']);self.assertEqual(row['semantics'],'last_received_message')
                self.assertEqual(value['character']['hp'],2700);self.assertNotIn('quests',value)
                row['records'][0]['raw0c']=-1;self.assertEqual(s.snapshot()['tutorial']['records'][0]['raw0c'],i)
            sessions[0].packet(9905,body(count=0));self.assertEqual(sessions[0].snapshot()['tutorial']['records'],[])
            self.assertEqual(len(sessions[1].snapshot()['tutorial']['records']),1)
            sessions[0].close();sessions[0].packet(9905,body());self.assertIsNone(sessions[0].snapshot()['tutorial'])
            self.assertEqual(sessions[1].snapshot()['tutorial']['records'][0]['raw0c'],1)
        finally:
            for s in sessions:s.close()
    def test_decode_error_unknown_source_and_api_do_not_reuse_stale_observations(self):
        s=LiveSession(bot_id='tutorial-api-fixture');s.bind_source(SHA)
        try:
            s.packet(9905,body(count=64),character_key=2**64-1,world_id=0xffffffff)
            with LiveSessionServer(s,port=0) as server:
                with urlopen('http://127.0.0.1:'+str(server.server.server_port)+'/bots/tutorial-api-fixture/state',timeout=3) as response:
                    raw=response.read();self.assertLess(len(raw),262144);value=json.loads(raw)
                self.assertEqual(value['tutorial']['character_key'],str(2**64-1))
                self.assertEqual(len(value['tutorial']['records']),64)
            self.assertTrue(s.stop_requested);s.close()
            self.assertIsNone(s.snapshot()['tutorial'])
        finally:s.close()
        s=LiveSession(bot_id='tutorial-error-fixture');s.bind_source(SHA)
        try:
            s.packet(9905,body());s.packet(9905,b'bad')
            value=s.snapshot();self.assertIsNone(value['tutorial']);self.assertEqual(value['tutorial_decode_errors'],1)
            self.assertEqual(value['coverage']['tutorial'],'decode_error')
        finally:s.close()
        s=LiveSession(bot_id='tutorial-unknown-fixture');s.bind_source('0'*64)
        try:
            s.packet(9905,body());self.assertIsNone(s.snapshot()['tutorial']);self.assertEqual(s.snapshot()['coverage']['tutorial'],'not_verified')
        finally:s.close()

if __name__=='__main__':unittest.main()
