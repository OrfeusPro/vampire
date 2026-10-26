"""Typed quest enqueue on real local sockets; world/quest data are fixtures."""
from pathlib import Path
import select
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.quest_update import QuestUpdate,encode_quest_update
from vampir_core.world_move_start import CURRENT_PROBE_SOURCE,SOURCE_SHA256
from vampir_core.ping import PingPayload
import test_vampir_game_connection as connection_fixture
BUDGET=connection_fixture.BUDGET
from test_vampir_receive_stream import transport,inner
from test_vampir_selection_flow import list_body,FIXTURE
from test_vampir_world_entry_flow import reserve_body,finish_body

class QuestConnectionTests(unittest.TestCase):
    connect=connection_fixture.GameConnectionTests.connect
    read_request=connection_fixture.GameConnectionTests.read_request
    def packet(self,owner,server,client,packet_id,body,now):
        server.sendall(transport(inner(packet_id,body,7)))
        select.select([client],[],[],1)
        for _ in range(20):
            if owner.pump(now=now,budget=BUDGET).packets:return
        self.fail('Local fixture packet was not processed')
    def ready(self,finish_code=0):
        owner,server,client=self.connect()
        owner.enable_world_start(source_sha256=CURRENT_PROBE_SOURCE,timeout=10,max_payload_size=4096,complete_world=True)
        owner.enter_character_list(now=0);owner.pump(now=0,budget=BUDGET)
        self.assertEqual(self.read_request(server,7)[0],101)
        self.packet(owner,server,client,102,list_body(),1)
        owner.select_character(1,now=2);owner.pump(now=2,budget=BUDGET)
        self.assertEqual(self.read_request(server,7)[0],109)
        self.packet(owner,server,client,110,bytes.fromhex(FIXTURE['select_result_hex']),3)
        self.packet(owner,server,client,202,reserve_body(),4)
        self.assertEqual(self.read_request(server,7)[0],203)
        self.packet(owner,server,client,204,struct.pack('<IIfffBBQ',0,10010,1,2,3,0,0,0),5)
        self.assertEqual(self.read_request(server,7)[0],205)
        with self.assertRaises(RuntimeError):
            owner.queue_quest_update(QuestUpdate((1,2,3),0,110120,0),source_sha256=CURRENT_PROBE_SOURCE)
        self.assertEqual(owner.queued_bytes,0)
        self.packet(owner,server,client,206,finish_body(finish_code),6)
        if finish_code==0:self.assertEqual(owner.world_entry.state,'finish_response')
        else:self.assertFalse(owner.active)
        return owner,server,client
    def test_enqueue_uses_connection_sequence_and_rotated_key(self):
        owner,server,client=self.ready()
        self.packet(owner,server,client,11,struct.pack('<Q',99),7)
        self.assertEqual(self.read_request(server,7),(12,4,struct.pack('<Q',99)))
        value=QuestUpdate((1,2,3),44,110120,0)
        owner.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)
        self.assertGreater(owner.queued_bytes,0)
        owner.pump(now=8,budget=BUDGET)
        self.assertEqual(self.read_request(server,99),(1810,5,encode_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)))
        self.assertTrue(owner.active)
    def test_unready_closed_wrong_source_and_invalid_payload_do_not_enqueue(self):
        value=QuestUpdate((1,2,3),0,110120,0)
        owner,server,client=self.connect()
        with self.assertRaises(RuntimeError):owner.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)
        self.assertEqual(owner.queued_bytes,0)
        owner.close()
        with self.assertRaises(RuntimeError):owner.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)
        owner,server,client=self.ready()
        with self.assertRaises(ValueError):owner.queue_quest_update(value,source_sha256=SOURCE_SHA256)
        with self.assertRaises(TypeError):owner.queue_quest_update(b'raw',source_sha256=CURRENT_PROBE_SOURCE)
        self.assertEqual(owner.queued_bytes,0)
        owner.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE);owner.pump(now=7,budget=BUDGET)
        self.assertEqual(self.read_request(server,7)[:2],(1810,4))
    def test_rejected_world_cannot_queue_quest(self):
        owner,server,client=self.ready(finish_code=1)
        with self.assertRaises(RuntimeError):
            owner.queue_quest_update(QuestUpdate((1,2,3),0,110120,0),source_sha256=CURRENT_PROBE_SOURCE)
        self.assertEqual(owner.queued_bytes,0)
    def test_backpressure_preserves_sequence_and_two_owners_are_isolated(self):
        first,a,_=self.ready();second,b,_=self.ready()
        for i in range(8):first.queue_ping(PingPayload(i,i))
        value=QuestUpdate((1,2,3),0,110120,0)
        with self.assertRaises(BufferError):first.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)
        second.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE);second.pump(now=7,budget=BUDGET)
        self.assertEqual(self.read_request(b,7)[:2],(1810,4))
        first.pump(now=7,budget=BUDGET);first.pump(now=7,budget=BUDGET)
        for i in range(8):self.assertEqual(self.read_request(a,7)[:2],(16,4+i))
        first.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE);first.pump(now=8,budget=BUDGET)
        self.assertEqual(self.read_request(a,7)[:2],(1810,12))

if __name__=='__main__':unittest.main()
