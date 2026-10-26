"""Action owner/session isolation and uncertain outcomes; no game or API sends."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.action_queue import SessionActionQueue,SCHEMAS

SOURCE='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
CONTEXT='b'*64


def setup(index=0,**options):
    owner=object()
    queue=SessionActionQueue(bot_id='bot'+str(index),session_id=f'{index:032x}',source_sha256=SOURCE,
        owner_key=owner,contracts={name:'a'*64 for name in SCHEMAS},**options)
    return queue,owner


def intent(queue,number=1,**changes):
    value=dict(bot_id=queue.bot_id,session_id=queue.session_id,request_id=f'{number:032x}',
        kind='quest_follow',context=CONTEXT,arguments={'quest_id':'110120'})
    value.update(changes);return value


class ActionQueueTests(unittest.TestCase):
    def test_fifty_accounts_and_private_owner_capability(self):
        pairs=[setup(i) for i in range(50)]
        def execute(pair):
            queue,owner=pair;queue.enqueue(**intent(queue))
            with self.assertRaises(RuntimeError):queue.claim(object(),context=CONTEXT)
            action=queue.claim(owner,context=CONTEXT)
            self.assertEqual(action['arguments'],{'quest_id':'110120'})
            queue.sent(owner,action['request_id']);queue.resolve(owner,action['request_id'],status='confirmed')
            return queue.snapshot()
        with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(execute,pairs))
        self.assertEqual(len({r['session_id'] for r in results}),50)
        self.assertTrue(all(r['records'][0]['status']=='confirmed' for r in results))
        with self.assertRaises(ValueError):pairs[0][0].enqueue(**intent(pairs[1][0],2))

    def test_duplicates_stale_context_and_one_execution_at_a_time(self):
        queue,owner=setup()
        queued=queue.enqueue(**intent(queue));self.assertEqual(queue.enqueue(**intent(queue)),queued)
        with self.assertRaises(ValueError):queue.enqueue(**intent(queue,arguments={'quest_id':'110130'}))
        first=queue.claim(owner,context=CONTEXT)
        with self.assertRaises(RuntimeError):queue.resolve(owner,first['request_id'],status='confirmed')
        queue.enqueue(**intent(queue,2));self.assertIsNone(queue.claim(owner,context=CONTEXT))
        queue.sent(owner,first['request_id'])
        with self.assertRaises(RuntimeError):queue.sent(owner,first['request_id'])
        queue.resolve(owner,first['request_id'],status='confirmed')
        self.assertIsNone(queue.claim(owner,context='c'*64))
        self.assertEqual(queue.snapshot()['records'][1]['reason'],'state_changed_before_send')

    def test_expiry_and_disconnect_never_requeue_uncertain_actions(self):
        now=[0.];queue,owner=setup(clock=lambda:now[0])
        queue.enqueue(**intent(queue));now[0]=6
        self.assertIsNone(queue.claim(owner,context=CONTEXT))
        self.assertEqual(queue.snapshot()['records'][0]['reason'],'expired_before_send')
        queue.enqueue(**intent(queue,2));action=queue.claim(owner,context=CONTEXT);queue.sent(owner,action['request_id'])
        now[0]=17;self.assertIsNone(queue.claim(owner,context=CONTEXT))
        self.assertEqual(queue.enqueue(**intent(queue,2))['status'],'unknown')
        self.assertTrue(queue.snapshot()['blocked'])
        with self.assertRaises(RuntimeError):queue.enqueue(**intent(queue,3))
        with self.assertRaises(RuntimeError):queue.resume_after_sync(owner,context=CONTEXT)
        queue.resume_after_sync(owner,context='d'*64)
        queue.enqueue(**intent(queue,3,context='d'*64));queue.claim(owner,context='d'*64)
        queue.enqueue(**intent(queue,4));queue.close(owner)
        statuses=[r['status'] for r in queue.snapshot()['records']]
        self.assertEqual(statuses,['failed','unknown','unknown','failed'])
        with self.assertRaises(RuntimeError):queue.enqueue(**intent(queue,5))

    def test_budgets_and_retired_ids_are_not_forgotten(self):
        queue,owner=setup(capacity=1,history=1,total_limit=2)
        queue.enqueue(**intent(queue))
        with self.assertRaises(BufferError):queue.enqueue(**intent(queue,2))
        queue.claim(owner,context=CONTEXT);queue.resolve(owner,f'{1:032x}',status='failed')
        queue.enqueue(**intent(queue,2))
        self.assertEqual(queue.enqueue(**intent(queue))['status'],'failed')
        queue.claim(owner,context=CONTEXT);queue.sent(owner,f'{2:032x}');queue.resolve(owner,f'{2:032x}',status='confirmed')
        with self.assertRaises(BufferError):queue.enqueue(**intent(queue,3))

    def test_unknown_contract_and_unbounded_or_untyped_arguments_are_rejected(self):
        queue=SessionActionQueue(bot_id='closed',session_id='0'*32,source_sha256=SOURCE,owner_key=object())
        with self.assertRaises(RuntimeError):queue.enqueue(**intent(queue))
        enabled,_=setup()
        for args in ({'quest_id':1},{'quest_id':'-1'},{'quest_id':str(1<<64)},{'quest_id':'1','raw_packet':'00'}):
            with self.assertRaises(ValueError):enabled.enqueue(**intent(enabled,arguments=args))
        for kind,args in [('dialogue_select',{'dialogue_id':'1','choice_id':'0'}),
                          ('dialogue_skip',{'dialogue_id':'1'}),('tutorial_equip',{'item_instance_id':'18446744073709551615'})]:
            self.assertEqual(enabled.enqueue(**intent(enabled,number=len(enabled.snapshot()['records'])+1,kind=kind,arguments=args))['status'],'queued')


if __name__=='__main__':unittest.main()
