"""Explicit current bounded probe admission; no authentication or external IO."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_vampir_world_entry_flow as world_tests
from vampir_core.world_move_start import CURRENT_PROBE_SOURCE, LATEST_PROBE_SOURCE, WORLD_PROBE_SOURCES
from vampir_core.world_entry_flow import WorldEntryFlow
from vampir_core.tutorial_update import TUTORIAL_SOURCES
from vampir_core.quest_record import CURRENT_SOURCE_SHA256 as QUEST_SOURCE


class ProbeRuntime11318Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'vampir-headless/probe-selected-game-login.py'
        spec=importlib.util.spec_from_file_location('probe_runtime_11318',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)

    def kwargs(self, **changes):
        return dict(dict(selected_profile='candidate-11318',manifest_path=Path('fixture'),
            socks_port=17948,server_policy_byte=0,extra_number=0,
            context='windows-sdk-initial-reset',region='JP',server_id=42,
            read_character_list=True,character_index=0,read_world_start=True,
            read_world_finish=True,observe_world_seconds=20),**changes)

    def source(self, **changes):
        return SimpleNamespace(**dict(dict(source_exe_sha256=LATEST_PROBE_SOURCE,
            live_probe_only=True,bounded_world_probe=True),**changes))

    def attempt(self, source, **changes):
        lobby=Mock(return_value=SimpleNamespace(summary={},server_list_response=object()))
        def module(name, filename):
            if filename=='game-source-profile.py':return SimpleNamespace(load_profile=lambda **kwargs:source)
            if filename=='probe-lobby-sdk-login.py':return SimpleNamespace(run=lobby)
            raise AssertionError('Unexpected module before auth boundary: '+filename)
        with patch.object(self.tool,'module',side_effect=module):
            result=self.tool.run('fixture@example.invalid',**self.kwargs(**changes))
        return result,lobby

    def test_explicit_current_profile_reaches_only_mocked_lobby_boundary(self):
        result,lobby=self.attempt(self.source())
        lobby.assert_called_once()
        self.assertEqual(lobby.call_args.kwargs['selected_profile'],'candidate-11318')
        self.assertEqual(lobby.call_args.kwargs['socks_port'],17948)
        self.assertEqual(result['status'],'selected_lobby_context_not_received')

    def test_source_and_bounded_scope_mismatch_reject_before_lobby(self):
        for source in (self.source(source_exe_sha256=CURRENT_PROBE_SOURCE),
                self.source(bounded_world_probe=False),self.source(live_probe_only=False),SimpleNamespace()):
            with self.subTest(source=source):
                result,lobby=self.attempt(source)
                lobby.assert_not_called()
                self.assertEqual(result['stage'],'source_validation')
                self.assertEqual(result['error_type'],'ValueError')

    def test_unverified_quest_and_tutorial_capabilities_reject_before_lobby(self):
        for changes in (dict(ack_initial_tutorial=True),dict(read_quest_list=True),
                        dict(tutorial_observer=lambda value:None)):
            with self.subTest(changes=tuple(changes)):
                result,lobby=self.attempt(self.source(),**changes)
                lobby.assert_not_called()
                self.assertEqual(result['stage'],'source_validation')
                self.assertEqual(result['error_type'],'ValueError')

    def test_latest_source_is_not_accepted_under_historical_profile_name(self):
        result,lobby=self.attempt(self.source(),selected_profile='candidate-11316')
        lobby.assert_not_called()
        self.assertEqual(result['stage'],'source_validation')

    def test_current_local_world_transition_preserves_protocol_boundaries(self):
        fixture=world_tests.WorldEntryFlowTests();fixture.setUp()
        flow=WorldEntryFlow(fixture.selection,fixture.outbound,source_sha256=LATEST_PROBE_SOURCE,
                           timeout=1,max_payload_size=4096)
        flow.receive(202,world_tests.reserve_body(),now=0)
        self.assertEqual(flow.state,'start_pending')
        self.assertEqual(fixture.outbound.queued_frames,1)
        self.assertEqual(fixture.outbound.sequence,11)
        with self.assertRaises(ValueError):flow.receive(202,world_tests.reserve_body(),now=0.1)
        self.assertEqual(flow.error,'invalid_world_entry_response')
        self.assertEqual(fixture.outbound.queued_frames,0)

    def test_source_sets_preserve_historical_quest_and_tutorial_identity(self):
        self.assertIn(LATEST_PROBE_SOURCE,WORLD_PROBE_SOURCES)
        self.assertEqual(CURRENT_PROBE_SOURCE,'d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960')
        self.assertNotIn(LATEST_PROBE_SOURCE,TUTORIAL_SOURCES)
        self.assertNotEqual(QUEST_SOURCE,LATEST_PROBE_SOURCE)


if __name__=='__main__':unittest.main()
