"""Whole-frame acceptance receipts with partial sends and isolated local sockets."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.game_connection import PumpBudget
from vampir_core.quest_update import QuestUpdate
from vampir_core.world_move_start import CURRENT_PROBE_SOURCE
import test_vampir_quest_connection as wire
import test_vampir_quest_dispatch as dispatch

VALUE=QuestUpdate((1,2,3),0,110120,0)
class LimitedSocket:
    def __init__(self,sock):self.sock=sock;self.blocked=False;self.bytes=0
    def send(self,data):
        if self.blocked:raise BlockingIOError()
        count=self.sock.send(data[:1]);self.bytes+=count;return count
    def recv(self,n):return self.sock.recv(n)
    def close(self):return self.sock.close()

class QuestTransportReceiptTests(unittest.TestCase):
    connect=wire.QuestConnectionTests.connect
    packet=wire.QuestConnectionTests.packet
    ready=wire.QuestConnectionTests.ready
    read_request=wire.QuestConnectionTests.read_request
    def test_partial_and_blocked_sends_accept_only_whole_frame(self):
        connection,peer,client=self.ready();limited=LimitedSocket(connection._socket);connection._socket=limited
        ticket=connection.queue_tracked_quest_update(VALUE,source_sha256=CURRENT_PROBE_SOURCE)
        size=connection.queued_bytes;budget=PumpBudget(4,4,4,64,1)
        limited.blocked=True;connection.pump(now=7,budget=budget)
        self.assertEqual(limited.bytes,0);self.assertEqual(connection.quest_send_status(ticket),'queued')
        limited.blocked=False
        for i in range(size-1):
            connection.pump(now=8,budget=budget);self.assertEqual(connection.quest_send_status(ticket),'queued')
        self.assertEqual(limited.bytes,size-1)
        connection.pump(now=8,budget=budget);self.assertEqual(connection.quest_send_status(ticket),'socket_accepted')
        self.assertEqual(self.read_request(peer,7)[:2],(1810,4))
        connection.close();self.assertEqual(connection.quest_send_status(ticket),'socket_accepted')
        connection.release_quest_send(ticket)
        with self.assertRaises(ValueError):connection.quest_send_status(ticket)
    def test_close_partial_is_unknown_and_foreign_connection_cannot_read(self):
        first,p1,_=self.ready();second,p2,_=self.ready()
        ticket=first.queue_tracked_quest_update(VALUE,source_sha256=CURRENT_PROBE_SOURCE)
        with self.assertRaises(ValueError):second.quest_send_status(ticket)
        with self.assertRaises(RuntimeError):first.release_quest_send(ticket)
        first._socket=LimitedSocket(first._socket);first.pump(now=7,budget=PumpBudget(4,4,4,64,1))
        first.close();self.assertEqual(first.quest_send_status(ticket),'outcome_unknown')
        first.release_quest_send(ticket);self.assertEqual(second.queued_bytes,0)
    def test_receipt_budget_refuses_before_enqueue_and_can_release(self):
        connection,peer,_=self.ready();tickets=[]
        for i in range(16):
            tickets.append(connection.queue_tracked_quest_update(VALUE,source_sha256=CURRENT_PROBE_SOURCE))
            connection.pump(now=7,budget=wire.BUDGET);self.read_request(peer,7)
        self.assertEqual(connection.queued_bytes,0)
        with self.assertRaises(BufferError):connection.queue_tracked_quest_update(VALUE,source_sha256=CURRENT_PROBE_SOURCE)
        self.assertEqual(connection.queued_bytes,0)
        connection.release_quest_send(tickets[0]);ticket=connection.queue_tracked_quest_update(VALUE,source_sha256=CURRENT_PROBE_SOURCE)
        connection.pump(now=8,budget=wire.BUDGET);self.assertEqual(self.read_request(peer,7)[:2],(1810,20))
        self.assertEqual(connection.quest_send_status(ticket),'socket_accepted')

class QuestSessionTransportTests(unittest.TestCase):
    connect=wire.QuestConnectionTests.connect
    packet=wire.QuestConnectionTests.packet
    ready=wire.QuestConnectionTests.ready
    read_request=wire.QuestConnectionTests.read_request
    prepare=dispatch.QuestDispatchTests.prepare
    intent=dispatch.QuestDispatchTests.intent
    claim=dispatch.QuestDispatchTests.claim
    dispatch=dispatch.QuestDispatchTests.dispatch
    def test_session_snapshot_journal_and_repeat_do_not_claim_server_result(self):
        session,key,connection,peer=self.prepare();self.claim(session,key)
        self.assertEqual(self.dispatch(session,key)['status'],'sent')
        before=session.snapshot()['quest_transport'];self.assertEqual(before['status'],'queued');self.assertNotIn('ticket',before)
        self.assertFalse(before['server_confirmed']);self.assertEqual(before['request_id'],'0'*31+'1')
        connection.pump(now=7,budget=wire.BUDGET);self.read_request(peer,7)
        after=session.snapshot()['quest_transport'];self.assertEqual(after['status'],'socket_accepted');self.assertFalse(after['server_confirmed'])
        self.dispatch(session,key);self.assertEqual(connection.queued_bytes,0)
        self.assertEqual(session.snapshot()['action_queue']['records'][0]['status'],'sent')
        events=[e for e in session.snapshot()['journal'] if e['kind']=='quest_transport_updated']
        self.assertEqual(len(events),1);self.assertEqual(events[0]['status'],'socket_accepted')
        after['status']='changed';self.assertEqual(session.snapshot()['quest_transport']['status'],'socket_accepted')
        session.close();self.assertNotIn('quest_transport',session.snapshot())

if __name__=='__main__':unittest.main()
