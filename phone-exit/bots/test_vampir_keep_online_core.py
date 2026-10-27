"""Explicit persistent owner policy; local socketpair and mocked task registration."""
import os
from pathlib import Path
import select
import struct
import sys
import time
import unittest
from unittest.mock import patch

import test_vampir_game_login_probe as previous
from vampir_core.live_session import LiveSession
from vampir_core.session_clock import LobbyPingClock
from vampir_core.world_move_start import LATEST_PROBE_SOURCE
from vampir_core.scheduled_worker import launch_scheduled
from test_vampir_world_entry_flow import reserve_body, finish_body


class KeepOnlineCoreTests(unittest.TestCase):
    def test_keep_online_is_explicit_bool_and_local_read_only_policy(self):
        ordinary=LiveSession(bot_id='ordinary')
        persistent=LiveSession(bot_id='persistent',keep_online=True)
        self.assertFalse(ordinary.keep_online)
        self.assertTrue(persistent.keep_online)
        for value in (None,1,'true'):
            with self.subTest(value=value),self.assertRaises(ValueError):
                LiveSession(bot_id='invalid',keep_online=value)
        with self.assertRaises(AttributeError):persistent.keep_online=False
        self.assertNotIn('keep_online',persistent.snapshot())

    def test_current_keep_online_survives_observation_budget_until_explicit_stop(self):
        fixture=previous.GameLoginProbeTests()
        now=[time.monotonic()]
        published=[]
        waits=[]
        actual_select=select.select
        with patch('vampir_core.game_login_probe.time.monotonic',side_effect=lambda:now[0]):
            session=LiveSession(bot_id='persistent-current-fixture',keep_online=True)
            publish=session.publish
            def record_publish(owner):
                publish(owner)
                if not published:published.append(session.snapshot())
            def wait(readers,writers,errors,timeout):
                if not published:return actual_select(readers,writers,errors,timeout)
                waits.append(timeout)
                if len(waits)>1:raise AssertionError('Explicit Stop was ignored')
                # An accidental 300-second deadline would skip the next owner
                # iteration and return world_observation_complete instead of Stop.
                now[0]+=301
                session.request_stop()
                return [],[],[]
            with patch.object(session,'publish',side_effect=record_publish), \
                    patch('vampir_core.game_login_probe.select.select',side_effect=wait), \
                    patch.object(previous,'SOURCE_SHA256',LATEST_PROBE_SOURCE):
                result,captures=fixture.world_attempt(world_reserve_body=reserve_body(),
                    world_start_body=struct.pack('<IIIIIBBQ',0,1,2,3,4,0,0,77),
                    read_world_finish=True,world_finish_body=finish_body(),
                    observe_world_seconds=300,ping_clock=LobbyPingClock(540),session_control=session)
        self.assertEqual(result['status'],'session_stopped')
        self.assertEqual(len(published),1)
        self.assertEqual(published[0]['state'],'connected')
        self.assertEqual(len(waits),1)
        self.assertEqual(session.snapshot()['state'],'disconnected')
        self.assertIsNone(session.snapshot()['character'])
        self.assertEqual([packet_id for packet_id,_ in captures],[1,16,3,101,109,203,205])

    @unittest.skipUnless(os.name=='nt','Windows interactive task semantics')
    def test_scheduler_limit_requires_explicit_opt_in_without_registering_tasks(self):
        class RegistrationObserved(RuntimeError):pass
        command=[sys.executable,'-X','utf8',str(Path(__file__).resolve())]
        for options,expected in (({},'PT24H'),({'unlimited':False},'PT24H'),({'unlimited':True},'PT0S')):
            calls=[]
            def record(spec):
                calls.append(spec.copy())
                if spec['mode']=='create':raise RegistrationObserved()
            with self.subTest(options=options),patch('vampir_core.scheduled_worker.task_call',side_effect=record):
                with self.assertRaises(RegistrationObserved):launch_scheduled(command,{},**options)
            self.assertEqual(calls[0]['executionTimeLimit'],expected)
            self.assertEqual(calls[-1],dict(mode='cleanup',name=calls[0]['name'],stop=True))
        for value in (None,1,'true'):
            with self.subTest(value=value),patch('vampir_core.scheduled_worker.task_call') as register:
                with self.assertRaises(ValueError):launch_scheduled(command,{},unlimited=value)
                register.assert_not_called()


if __name__=='__main__':unittest.main()
