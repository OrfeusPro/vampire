"""Owner quest preferences and uncertain action fences; fixtures, no gameplay."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.quest_automation import QuestAutomation

SOURCE='03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
CONTEXT=dict(bot_id='fixture',session_id='1'*32,character_key='42',world_id=10010,source_sha256=SOURCE)
ACTION_CONTEXT='a'*64
REQUEST='b'*32


def owner(*,hp=2700,coverage='received',offer=False,action_context=ACTION_CONTEXT,records=(),blocked=False):
    snapshot=dict(state='connected',bot_id=CONTEXT['bot_id'],session_id=CONTEXT['session_id'],source_sha256=SOURCE,
        character=dict(key='42',world_id=10010,hp=hp),coverage=dict(vitals=coverage),
        action_queue=dict(records=list(records),blocked=blocked))
    if offer:
        snapshot['interaction']=dict(semantics='owner_action_offers',source_sha256=SOURCE,character_key='42',world_id=10010,
            actions_ready=True,actions=[dict(id='step',kind='quest_follow',context=action_context,
                                           arguments={'quest_id':'110120'},enabled=True)])
    return snapshot


class QuestAutomationTests(unittest.TestCase):
    def enabled(self):
        value=QuestAutomation();value.observe(owner());value.toggle('110120',owner_context=CONTEXT)
        return value

    def test_click_selects_and_repeated_click_stops_without_inventing_game_actions(self):
        value=self.enabled();state=value.snapshot()
        self.assertTrue(state['supported']);self.assertTrue(state['enabled'])
        self.assertEqual((state['selected_quest_id'],state['state'],state['stop_reason']),
                         ('110120','waiting_data','not_admitted'))
        self.assertIsNone(value.next_offer())
        value.observe(dict(owner(),quests=[dict(id='110120',state=2,target=10,index=0)]))
        self.assertIsNone(value.next_offer())
        state=value.toggle('110120')
        self.assertEqual((state['selected_quest_id'],state['enabled'],state['state'],state['stop_reason']),
                         (None,False,'idle','user_stop'))
        self.assertTrue(value.take_cancel_pending());self.assertFalse(value.take_cancel_pending())

    def test_only_current_admitted_offer_advances_and_same_context_never_repeats(self):
        value=self.enabled();value.observe(owner(offer=True))
        offer=value.next_offer();self.assertEqual(offer,dict(kind='quest_follow',context=ACTION_CONTEXT,arguments={'quest_id':'110120'}))
        offer['arguments']['quest_id']='different';self.assertEqual(value.next_offer()['arguments']['quest_id'],'110120')
        value.submitted(REQUEST,ACTION_CONTEXT)
        self.assertIsNone(value.next_offer())
        value.observe(owner(offer=True,records=[dict(request_id=REQUEST,status='sent')]))
        self.assertEqual(value.snapshot()['pending_request_id'],REQUEST)
        value.observe(owner(offer=True,records=[dict(request_id=REQUEST,status='confirmed')]))
        self.assertIsNone(value.snapshot()['pending_request_id']);self.assertIsNone(value.next_offer())
        value.observe(owner(offer=True,action_context='c'*64))
        self.assertEqual(value.next_offer()['context'],'c'*64)

    def test_missing_ambiguous_or_wrong_scope_offer_cannot_be_dispatched(self):
        for mutate in (lambda row:row['interaction'].update(source_sha256='0'*64),
                       lambda row:row['interaction'].update(character_key='43'),
                       lambda row:row['interaction'].update(world_id=10011),
                       lambda row:row['interaction'].update(actions_ready=False),
                       lambda row:row['interaction']['actions'][0].update(enabled=False),
                       lambda row:row['interaction']['actions'][0].update(context='unverified'),
                       lambda row:row['interaction']['actions'].append(copy.deepcopy(row['interaction']['actions'][0])),
                       lambda row:row['interaction']['actions'][0].update(kind='tutorial_equip')):
            with self.subTest(mutation=mutate):
                value=self.enabled();snapshot=owner(offer=True);mutate(snapshot);value.observe(snapshot)
                self.assertIsNone(value.next_offer())
                self.assertEqual(value.snapshot()['stop_reason'],'not_admitted')

    def test_confirmed_death_cancels_unsent_selection_and_revival_never_restarts(self):
        value=self.enabled();value.observe(owner(offer=True));self.assertIsNotNone(value.next_offer())
        state=value.observe(owner(hp=0,offer=True))
        self.assertEqual((state['enabled'],state['state'],state['stop_reason']),(False,'dead','death'))
        self.assertEqual(state['selected_quest_id'],'110120');self.assertTrue(state['cancel_pending'])
        self.assertIsNone(value.next_offer())
        state=value.observe(owner(hp=2700,offer=True))
        self.assertFalse(state['enabled']);self.assertEqual(state['state'],'paused');self.assertIsNone(value.next_offer())
        value.take_cancel_pending();value.toggle('110120',enabled=True,owner_context=CONTEXT)
        value.observe(owner(offer=True));self.assertIsNotNone(value.next_offer())

    def test_unverified_or_unknown_zero_hp_is_not_a_death_observation(self):
        for hp,coverage in ((0,'not_verified'),(None,'received'),(False,'received'),('0','received')):
            with self.subTest(hp=hp,coverage=coverage):
                value=self.enabled();value.observe(owner(hp=hp,coverage=coverage,offer=True))
                self.assertTrue(value.snapshot()['enabled']);self.assertNotEqual(value.snapshot()['state'],'dead')

    def test_disconnect_and_owner_scope_change_cancel_selection_without_losing_receipts(self):
        for changes in ({'state':'disconnected','character':None},
                        {'character':dict(key='43',world_id=10010,hp=2700)},
                        {'character':dict(key='42',world_id=10011,hp=2700)},
                        {'session_id':'2'*32}, {'source_sha256':'0'*64}):
            with self.subTest(changes=changes):
                value=self.enabled();value.observe(owner(offer=True));value.submitted(REQUEST,ACTION_CONTEXT)
                state=value.observe(dict(owner(offer=True),**changes))
                self.assertFalse(state['enabled']);self.assertIsNone(state['selected_quest_id'])
                self.assertTrue(state['cancel_pending']);self.assertIsNone(value.next_offer())
                self.assertEqual(state['pending_request_id'],REQUEST)

    def test_unknown_outcome_remains_fenced_after_stop_context_change_and_revival(self):
        value=self.enabled();value.observe(owner(offer=True));value.submitted(REQUEST,ACTION_CONTEXT)
        state=value.observe(owner(offer=True,records=[dict(request_id=REQUEST,status='unknown')]))
        self.assertEqual((state['enabled'],state['state'],state['stop_reason']),(False,'unknown','unknown_result'))
        value.stop('user_stop');value.take_cancel_pending()
        self.assertEqual(value.snapshot()['stop_reason'],'unknown_result')
        value.observe(owner(offer=True,hp=2700))
        self.assertIsNone(value.next_offer());self.assertEqual(value.snapshot()['pending_request_id'],REQUEST)
        with self.assertRaisesRegex(RuntimeError,'remains fenced'):
            value.toggle('110120',enabled=True,owner_context=CONTEXT)

    def test_explicit_queue_block_and_failed_attempt_are_not_automatic_retries(self):
        value=self.enabled();value.observe(owner(offer=True,blocked=True))
        self.assertEqual(value.snapshot()['state'],'unknown');self.assertIsNone(value.next_offer())
        value=self.enabled();value.observe(owner(offer=True));value.submitted(REQUEST,ACTION_CONTEXT)
        state=value.observe(owner(offer=True,records=[dict(request_id=REQUEST,status='failed')]))
        self.assertEqual((state['enabled'],state['state']),(False,'blocked'))
        value.take_cancel_pending();value.toggle('110120',enabled=True,owner_context=CONTEXT)
        value.observe(owner(offer=True));self.assertIsNone(value.next_offer())

    def test_selection_and_submission_require_exact_bounded_inputs(self):
        value=QuestAutomation()
        with self.assertRaises(ValueError):value.toggle('110120')
        value.observe(owner())
        for quest in (True,1,'-1',str(2**64)):
            with self.subTest(quest=quest),self.assertRaises(ValueError):value.toggle(quest)
        with self.assertRaises(ValueError):value.toggle('110120',enabled=1)
        value.toggle('110120',owner_context=CONTEXT)
        value.observe(owner(offer=True))
        with self.assertRaises(ValueError):value.submitted('wrong',ACTION_CONTEXT)
        with self.assertRaises(ValueError):value.submitted(REQUEST,'c'*64)
        with self.assertRaises(ValueError):value.observe(dict(owner(offer=True),source_sha256='invalid'))
        self.assertIsNone(value.next_offer());self.assertFalse(value.snapshot()['enabled'])


if __name__=='__main__':unittest.main()
