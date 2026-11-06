"""Current world policy and local socket ownership, with explicit admission fixtures."""
from contextlib import contextmanager
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import struct
import sys
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core import bounded_world_admission as admission
from vampir_core import bounded_entry_admission as entry
from vampir_core.bounded_creation_admission import permits as create_permits
from vampir_core.runtime_admission import permits
from vampir_core.live_session import LiveSession
from vampir_core.session_clock import LobbyPingClock
from vampir_core.character_select_result import decode_character_select_result
import test_vampir_game_login_probe as probe_tests
from test_vampir_login_flow import FIXTURE
from test_vampir_selection_flow import connection, list_body, FIXTURE as SELECTION
from test_vampir_world_entry_flow import reserve_body, finish_body
from test_vampir_live_session import owner as fixture_owner

SELECTOR = 'bounded-world:' + '1' * 64
ENTRY = 'bounded-entry:' + '2' * 64


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def admitted():
    profile = dict(selected_profile=SELECTOR, source_sha256=admission.SOURCE,
        policies=sorted(admission.POLICIES), entry=dict(selected_profile=ENTRY))
    @contextmanager
    def parent(selector, **kwargs):
        if selector != ENTRY:
            raise ValueError('Different entry parent')
        token = entry._active.set(dict(selected_profile=ENTRY, source_sha256=admission.SOURCE,
            policies=['game-login-current-layout-v1']))
        try:
            yield selector
        finally:
            entry._active.reset(token)
    with patch.object(admission, '_load', return_value=profile), patch.object(entry, 'scope', parent):
        with admission.scope(SELECTOR, root=Path('.'), workspace=Path('.')):
            yield


class BoundedWorldTests(unittest.TestCase):
    def test_current_initial_vitals_require_scope_and_keep_account_identity(self):
        from vampir_core.stat_change import initial_stat_values
        from vampir_core.character_select_result import SelectionRecord
        stats=tuple(SelectionRecord(((8,kind),(16,value))) for kind,value in ((3,1),(4,2700),(5,2700),(9,2000),(10,2000)))
        with self.assertRaisesRegex(ValueError,'Unverified'):
            initial_stat_values(stats,source_sha256=admission.SOURCE)
        with admitted():
            session=LiveSession(bot_id='current-initial')
            session.bind_source(admission.SOURCE)
            session.publish(fixture_owner(stats=stats))
            state=session.snapshot()
            self.assertEqual([state['character'][field] for field in ('level','hp','max_hp','mp','max_mp')],[1,2700,2700,2000,2000])
            self.assertEqual(state['coverage']['stats_observation'],'world_entry_snapshot')
            key=int(state['character']['key'])
            foreign=struct.pack('<QHiqqBH',key+1,1,4,9000,1200,0,0)
            session.packet(322,foreign,character_key=key)
            self.assertEqual(session.snapshot()['character']['hp'],2700)
            body=struct.pack('<QHiqqBH',key,1,4,9000,1200,0,0)
            session.packet(322,body,character_key=key)
            self.assertEqual(session.snapshot()['character']['hp'],1200)
            self.assertEqual(session.snapshot()['coverage']['stats_observation'],'notifications_received')
            session.packet(321,struct.pack('<QHiqq',key,1,3,1,2),character_key=key)
            self.assertEqual(session.snapshot()['character']['level'],2)
            session.close()
            self.assertIsNone(session.snapshot()['character'])

    def test_owner_enters_scope_per_worker_and_keeps_handoff_free_of_credentials(self):
        owner = load('current_world_owner_test', HERE / 'vampir-headless/run-bounded-world.py')
        rows = [dict(id='fixture-account', enabled=True, device_type='Бот', server_id=387,
            character_index=0, character_key='22', auth_flow='launcher')]
        rows.append(dict(rows[0], id='fixture-refused'))
        seen, notices, registries = [], [], []
        @contextmanager
        def server(registry, **kwargs):
            registries.append(registry)
            yield SimpleNamespace(server=SimpleNamespace(server_port=17947))
        def execute(identifier, selector, **kwargs):
            seen.append((identifier, selector, permits(admission.SOURCE, 'game-login-world-v1'),
                         kwargs['_world_session'].keep_online))
            if identifier == 'fixture-refused':
                return dict(result=dict(status='selected_game_login_not_completed', stage='sdk_launcher_sign_in',
                                        sdk_error_code=1203))
            kwargs['progress']('game_login_exchange')
            return dict(result=dict(status='game_login_probe', game=dict(status='session_stopped')))
        profile = dict(selected_profile=SELECTOR, source_sha256=admission.SOURCE,
            policies=sorted(admission.POLICIES), entry=dict(selected_profile=ENTRY))
        @contextmanager
        def parent(selector, **kwargs):
            yield selector
        with patch.object(admission, '_load', return_value=profile), patch.object(entry, 'scope', parent), \
                patch.object(owner, 'AccountStore', return_value=SimpleNamespace(accounts=lambda: rows)), \
                patch.object(owner, 'LiveSessionServer', server), \
                patch.object(owner, 'load_entry', return_value=SimpleNamespace(run=execute)):
            result = owner.run([row['id'] for row in rows], SELECTOR, ready_callback=notices.append)
        self.assertCountEqual(seen, [(row['id'], ENTRY, True, True) for row in rows])
        summaries = {row['account_id']: row for row in result['sessions']}
        self.assertEqual(summaries['fixture-account']['game_status'], 'session_stopped')
        self.assertEqual(summaries['fixture-refused']['sdk_error_code'], 1203)
        self.assertEqual(registries[0].get('fixture-refused').snapshot()['error'], 'sdk_launcher_sign_in')
        self.assertTrue(notices[0]['keep_online'])
        self.assertIsNone(notices[0]['max_runtime_seconds'])
        self.assertFalse(permits(admission.SOURCE, 'game-login-world-v1'))
        with self.assertRaisesRegex(ValueError, 'saved character'):
            owner.validate_accounts(['fixture-account'], SimpleNamespace(accounts=lambda: [dict(rows[0], character_key=None)]))

    def test_current_clamp_boundaries_preserve_legacy_results(self):
        for raw in (7, 8, 9, 91, 92, 97, 98, 255):
            # Source-derived minimum body with exactly one item in each
            # changed array. These are local wire fixtures, not live data.
            body = bytes(203)
            body = body[:119] + struct.pack('<HBBB', 1, 2, raw, 3) + body[121:]
            body = body[:76] + struct.pack('<HBQ', 1, raw, 123) + body[78:]
            legacy = decode_character_select_result(body, max_payload_size=4096, max_collection_items=4)
            self.assertEqual(legacy.player.at(0x1d8)[0].at(8), min(raw, 91))
            self.assertEqual(legacy.player.at(0x250)[0].at(9), min(raw, 7))
            with self.assertRaisesRegex(ValueError, 'verified world scope'):
                decode_character_select_result(body, max_payload_size=4096, max_collection_items=4,
                    source_sha256=admission.SOURCE)
            with admitted():
                current = decode_character_select_result(body, max_payload_size=4096, max_collection_items=4,
                    source_sha256=admission.SOURCE)
                self.assertEqual(current.player.at(0x1d8)[0].at(8), min(raw, 97))
                self.assertEqual(current.player.at(0x250)[0].at(9), min(raw, 8))

    def test_scope_limits_and_real_entrypoint_guards(self):
        tool = load('world_entrypoint_guard_test', HERE / 'vampir-headless/probe-selected-game-login.py')
        args = dict(selected_profile=ENTRY, manifest_path=Path('unused.json'), socks_port=None,
            server_policy_byte=0, extra_number=268356, context='windows-sdk-initial-reset',
            region='EU', server_id=387, auth_flow='launcher', read_character_list=True,
            character_index=0, read_world_start=True, read_world_finish=True)
        with admitted():
            for policy in admission.POLICIES:
                self.assertTrue(permits(admission.SOURCE, policy))
            self.assertFalse(permits('0' * 64, 'game-login-world-v1'))
            self.assertFalse(create_permits(admission.SOURCE))
            self.assertFalse(permits(admission.SOURCE, 'character-create-current-v1'))
            with patch.object(tool, '_run', return_value={'guard_passed': True}) as run:
                self.assertEqual(tool.run('fixture@unit.invalid', **args), {'guard_passed': True})
                run.assert_called_once()
            seen = []
            thread = threading.Thread(target=lambda: seen.append(permits(admission.SOURCE, 'periodic-ping-v1')))
            thread.start(); thread.join(2)
            self.assertEqual(seen, [False])
            with self.assertRaisesRegex(ValueError, 'switch'):
                with admission.scope('bounded-world:' + '3' * 64, root=Path('.'), workspace=Path('.')):
                    pass
        self.assertFalse(permits(admission.SOURCE, 'game-login-world-v1'))

    def test_current_socket_selects_fresh_key_and_keeps_owner_until_stop(self):
        helper = probe_tests.GameLoginProbeTests()
        session = LiveSession(bot_id='current-fixture', keep_online=True)
        observed = []
        select_body = bytes.fromhex(SELECTION['select_result_hex'])
        select_body = select_body[:4] + struct.pack('<Q', 22) + select_body[12:]
        def stop_when_connected():
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                state = session.snapshot()
                if state['state'] == 'connected':
                    observed.append(state)
                    break
                time.sleep(.01)
            session.request_stop()
        with admitted(), patch('test_vampir_game_login_probe.SOURCE_SHA256', admission.SOURCE):
            stop = threading.Thread(target=stop_when_connected)
            stop.start()
            try:
                result, captures = helper.attempt(
                    login_body=bytes.fromhex(FIXTURE['login_result_hex']) + bytes(10),
                    read_character_list=True, character_body=list_body(keys=(11, 22)), character_index=0,
                    expected_character_key=22, wait_for_select=True, select_fields=(22, 0, 42),
                    select_body=select_body, read_world_start=True,
                    world_reserve_body=reserve_body(), world_start_body=struct.pack('<IIIIIBBQ', 0, 1, 2, 3, 4, 0, 0, 77),
                    read_world_finish=True, world_finish_body=finish_body(), observe_world_seconds=300,
                    ping_clock=LobbyPingClock(540), session_control=session)
            finally:
                stop.join(4)
        self.assertEqual(result['status'], 'session_stopped')
        self.assertEqual(len(observed), 1)
        self.assertIsNone(observed[0]['character']['hp'])
        self.assertGreaterEqual(observed[0]['heartbeat']['received'], 1)
        self.assertEqual([pid for pid, _ in captures][:7], [1, 16, 3, 101, 109, 203, 205])
        self.assertEqual(session.snapshot()['state'], 'disconnected')

    def test_current_selection_refuses_a_different_character_key(self):
        flow, queue = connection()
        body = bytes.fromhex(SELECTION['select_result_hex'])
        body = body[:4] + struct.pack('<Q', 11) + body[12:]
        with admitted():
            flow.enter_list(now=1)
            flow.receive(102, list_body(), now=2)
            flow.select(1, now=3)
            with self.assertRaisesRegex(ValueError, 'identity differs'):
                flow.receive(110, body, now=4)
        self.assertEqual(flow.error, 'selection_identity_mismatch')
        self.assertIsNone(flow.response)
        self.assertEqual(queue.queued_frames, 0)

    def test_loader_rejects_partial_result_compatibility(self):
        tool = load('world_profile_boundary_test', HERE / 'vampir-headless/bounded-world-profile.py')
        report = dict(schema=1, recipe='world-results-current-v1', source_sha256=admission.SOURCE,
            network_used=False, runtime_admitted=False, limits=['fixture'],
            compatible_with_portable_codecs=False, packet_compatibility={'110': False, '206': True})
        with self.assertRaisesRegex(ValueError, 'not admitted'):
            tool._world_results(report, {})
        report.update(compatible_with_portable_codecs=True, packet_compatibility={'110': 1, '206': True})
        with self.assertRaises(ValueError):
            tool._world_results(report, {})


if __name__ == '__main__':
    unittest.main()
