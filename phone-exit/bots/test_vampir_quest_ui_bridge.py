"""Actual backend owner offers -> existing JS projector -> HTTP action -> local pump."""
import json
from pathlib import Path
import subprocess
import unittest
import test_vampir_quest_owner_pump as fixture
import test_vampir_action_api as api
from vampir_core.live_session import LiveSessions
from vampir_core.live_session_server import LiveSessionServer
from test_vampir_quest_observations import sync
import test_vampir_quest_connection as wire

class QuestUiBridgeTests(unittest.TestCase):
    connect=fixture.QuestOwnerPumpTests.connect
    packet=fixture.QuestOwnerPumpTests.packet
    ready=fixture.QuestOwnerPumpTests.ready
    read_request=fixture.QuestOwnerPumpTests.read_request
    prepare=fixture.QuestOwnerPumpTests.prepare
    offered=fixture.QuestOwnerPumpTests.offered
    request=api.ActionApiTests.request
    post=api.ActionApiTests.post
    token=api.ActionApiTests.token
    def project(self,snapshot):
        module=Path(__file__).parent/'vampir/ui-prototype/live-interaction.js'
        js="const fs=require('node:fs'),ui=require(process.argv[1]),s=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(ui.project(s,s.bot_id,s.session_id)));"
        result=subprocess.run(['node','-e',js,str(module.resolve())],input=json.dumps(snapshot),capture_output=True,text=True,timeout=10,check=True)
        return json.loads(result.stdout)
    def test_real_state_schema_enables_only_owner_quest_and_reaches_pump(self):
        s,k,c,p,offer=self.offered();registry=LiveSessions(capacity=1);registry.attach(s)
        with LiveSessionServer(registry,port=0) as server:
            status,snapshot=self.request(server,'GET','/bots/'+s.bot_id+'/state')
            self.assertEqual(status,200);view=self.project(snapshot)
            self.assertTrue(view['known']);self.assertFalse(view['messagesKnown']);self.assertEqual(view['messages'],[])
            self.assertEqual(len(view['actions']),1);action=view['actions'][0];self.assertTrue(action['enabled'])
            self.assertEqual(action['arguments'],offer['arguments']);self.assertEqual(action['context'],offer['context'])
            self.assertEqual(view['questActions'],[dict(quest_id='110120',action_id=action['id'])])
            intent=dict(request_id='a'*32,kind=action['kind'],context=action['context'],arguments=action['arguments'],policy=dict(skip_dialogues=True,auto_quests=False),origin='manual')
            self.assertEqual(self.post(server,s,self.token(server,s),'actions',intent)[0],202)
            queued=self.project(s.snapshot());self.assertFalse(queued['actions'][0]['enabled'])
            self.assertEqual(s.pump_quest_actions(c)['status'],'sent');self.assertIsNone(s.pump_quest_actions(c))
            c.pump(now=7,budget=wire.BUDGET);self.assertEqual(self.read_request(p,7)[:2],(1810,4))
            after=self.project(s.snapshot());self.assertEqual(after['actions'],[])
            self.assertEqual(after['results'],[dict(request_id='a'*32,status='sent')]);self.assertFalse(after['messagesKnown'])
    def test_stale_and_disconnected_views_do_not_enable_action(self):
        s,k,c,p,offer=self.offered();revision=s.snapshot()['interaction']['revision']
        self.assertEqual(s.snapshot()['interaction']['revision'],revision)
        person=s.snapshot()['character'];s.packet(1854,sync(1),character_key=int(person['key']),world_id=person['world_id'])
        stale=self.project(s.snapshot());self.assertFalse(stale['actions'][0]['enabled'])
        self.assertEqual(stale['actions'][0]['reason'],'Состояние задания изменилось')
        self.assertNotEqual(s.snapshot()['interaction']['revision'],revision)
        s.close();self.assertFalse(self.project(s.snapshot())['known']);self.assertNotIn('interaction',s.snapshot())
    def test_explicit_step_is_isolated_and_other_owner_has_no_ui_capability(self):
        a,ka,ca,pa,_=self.offered(1);b,kb,cb,pb=self.prepare(2)
        self.assertEqual(self.project(b.snapshot())['actions'],[])
        self.assertTrue(self.project(a.snapshot())['actions'][0]['enabled'])
        copy=a.snapshot();copy['interaction']['actions'][0]['enabled']=False
        self.assertTrue(a.snapshot()['interaction']['actions'][0]['enabled'])

if __name__=='__main__':unittest.main()
