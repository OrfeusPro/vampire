"""Native consumer/producer and portable packet interoperability on local sockets."""
import importlib.util
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.quest_update import QuestUpdate,encode_quest_update
from vampir_core.world_move_start import CURRENT_PROBE_SOURCE
import test_vampir_quest_connection as wire

class QuestConsumerTests(unittest.TestCase):
    connect=wire.QuestConnectionTests.connect
    packet=wire.QuestConnectionTests.packet
    ready=wire.QuestConnectionTests.ready
    read_request=wire.QuestConnectionTests.read_request
    @classmethod
    def setUpClass(cls):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_consumer',root/'replay-quest-consumer-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        cls.target,cls.result=module.run()
    def test_gate_retention_and_consumed_without_send(self):
        self.assertTrue(self.target.is_file());r=self.result
        self.assertFalse(r['network_used']);self.assertFalse(r['action_admitted']);self.assertFalse(r['handoff']['shared_memory'])
        self.assertEqual(len(r['cases']),24)
        self.assertEqual(r['legacy_direct_flow_checked'],['0x145d6f9b0'])
        self.assertEqual((r['packet_id'],r['send_identifier']),(1810,1811))
        for c in r['cases']:
            if c['mode'] in ('busy','environment-blocked','update-blocked','base-vtable'):
                self.assertEqual(c['retained'],[0]);self.assertEqual(c['packets'],[])
            if c['mode'] in ('missing-owner','missing-actor','missing-model'):
                self.assertEqual(c['retained'],[]);self.assertEqual(c['released'],[0]);self.assertEqual(c['packets'],[])
            if c['mode'] in ('ready','default-position'):
                self.assertEqual(c['retained'],[]);self.assertEqual(len(c['packets']),1)
    def test_busy_compaction_and_inflight_transition(self):
        for c in self.result['cases']:
            if c['mode']=='mixed-busy':
                self.assertEqual(c['retained'],[0,2]);self.assertEqual(c['released'],[1])
                self.assertEqual(c['moves'],[dict(target=1,source=2,count=1)])
            if c['mode']=='one-inflight':
                self.assertEqual(c['retained'],[1,3]);self.assertEqual(c['released'],[0,2])
                self.assertEqual(c['moves'],[dict(target=0,source=1,count=1),dict(target=1,source=3,count=1)])
                self.assertEqual([p['tag'] for p in c['packets']],[0])
    def test_native_constructed_fields_reach_local_socket_with_same_wire(self):
        for c in self.result['cases']:
            if c['mode']!='ready':continue
            fields=c['packets'][0]['packet']
            value=QuestUpdate(tuple(fields['vector']),fields['raw28'],fields['raw30'],fields['raw38'])
            self.assertEqual((value.raw30,value.raw38),(110120,c['index']))
            connection,peer,client=self.ready()
            connection.queue_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE);connection.pump(now=7,budget=wire.BUDGET)
            self.assertEqual(self.read_request(peer,7),(1810,4,encode_quest_update(value,source_sha256=CURRENT_PROBE_SOURCE)))

if __name__=='__main__':unittest.main()
