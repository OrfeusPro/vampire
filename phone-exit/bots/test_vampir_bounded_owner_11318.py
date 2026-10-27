"""Current controlled owner expires its observation budget on a local socketpair."""
import select
import struct
import time
import unittest
from unittest.mock import patch

import test_vampir_game_login_probe as previous
from vampir_core.live_session import LiveSession
from vampir_core.session_clock import LobbyPingClock
from vampir_core.world_move_start import LATEST_PROBE_SOURCE
from test_vampir_world_entry_flow import reserve_body, finish_body


class BoundedOwner11318Tests(unittest.TestCase):
    def test_current_controlled_owner_expires_without_stop_or_reconnect(self):
        # Reuse the existing complete local protocol fixture, changing only its
        # explicit source policy. No game address, credentials or external IO.
        fixture=previous.GameLoginProbeTests()
        now=[time.monotonic()]
        published=[]
        waits=[]
        actual_select=select.select
        with patch('vampir_core.game_login_probe.time.monotonic',side_effect=lambda:now[0]):
            session=LiveSession(bot_id='bounded-current-fixture')
            publish=session.publish
            def record_publish(owner):
                publish(owner)
                if not published:published.append(session.snapshot())
            def wait(readers,writers,errors,timeout):
                if not published:return actual_select(readers,writers,errors,timeout)
                waits.append(timeout)
                if len(waits)>3:raise AssertionError('Controlled current owner continued beyond its observation budget')
                # The first select after publication follows initialization of
                # observation_until. Advance virtual time past that deadline.
                now[0]+=301
                return [],[],[]
            with patch.object(session,'publish',side_effect=record_publish), \
                    patch('vampir_core.game_login_probe.select.select',side_effect=wait), \
                    patch.object(previous,'SOURCE_SHA256',LATEST_PROBE_SOURCE):
                result,captures=fixture.world_attempt(world_reserve_body=reserve_body(),
                    world_start_body=struct.pack('<IIIIIBBQ',0,1,2,3,4,0,0,77),
                    read_world_finish=True,world_finish_body=finish_body(),
                    observe_world_seconds=300,ping_clock=LobbyPingClock(540),session_control=session)
        self.assertEqual(result['status'],'world_observation_complete')
        self.assertEqual(len(published),1)
        self.assertEqual(published[0]['state'],'connected')
        self.assertEqual(len(waits),1)
        self.assertGreaterEqual(waits[0],0)
        self.assertLessEqual(waits[0],0.05)
        self.assertFalse(session.stop_requested)
        self.assertEqual(session.snapshot()['state'],'disconnected')
        self.assertIsNone(session.snapshot()['character'])
        self.assertEqual([packet_id for packet_id,_ in captures],[1,16,3,101,109,203,205])
        self.assertFalse(result['game_session_ready'])


if __name__=='__main__':unittest.main()
