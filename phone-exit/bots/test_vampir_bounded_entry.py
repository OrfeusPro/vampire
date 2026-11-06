"""Exact profile admission and current wire through the ordinary lobby entry."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import threading
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core import bounded_entry_admission as admission
from vampir_core.runtime_admission import permits
from vampir_core.lobby_packets import LobbyVersionPayload, LobbyLoginPayload, LobbyServerListPayload
from vampir_core.lobby_login_probe import exchange_lobby_login
from vampir_core.session_clock import LobbyPingClock
from vampir_core.login_flow import LoginFlow
from vampir_core.login_packet import LoginPayload
from vampir_core.version_packet import VersionPayload
from vampir_core.outbound import OutboundFrames
from vampir_core.login_result_current import decode_current_login_result
from test_vampir_version_probe import receive_frame, incoming


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BoundedEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load('bounded_entry_builder', HERE / 'resource-tools/vampir/build-bounded-entry-current.py')
        cls.result = cls.builder.publish()
        cls.selector = cls.result['selected_profile']
        cls.profile = json.loads(Path(cls.result['report']).read_bytes())
        cls.root = cls.builder.ROOT
        cls.workspace = cls.builder.WORKSPACE

    def test_scoped_guard_retains_only_verified_runtime_inputs(self):
        guard = load('bounded_entry_check_guard', HERE / 'resource-tools/vampir/entry-package-check-guard.py')
        native = load('bounded_entry_native_publication', HERE / 'resource-tools/vampir/native-publication-v2.py')
        index = SimpleNamespace(INSTALL=Path(self.profile['source']),
            read_json=lambda path: json.loads(Path(path).read_bytes()), digest=self.builder.digest,
            extension=lambda name: SimpleNamespace(publish=lambda **kwargs: self.result)
            if name == 'build-bounded-entry-current' else native)
        retained, pointer = guard.material(index, self.root, self.profile['source_sha256'], 'bounded-entry-current')
        report = dict(definition=dict(check=dict(id='bounded-entry-current'),
            source_sha256=self.profile['source_sha256'], artifacts=retained),
            entry_package_guard=dict(recipe=guard.RECIPE, pointer=pointer))
        runtime = guard.runtime_inputs(index, self.root, report, 'bounded-entry-current')
        self.assertIn(str(index.INSTALL), runtime)
        patch = index.INSTALL.parents[2] / 'Saved/PersistentDownloadDir/Patch/windows.manifestlist'
        self.assertIn(str(patch), runtime)
        self.assertTrue(set(runtime) <= set(retained))
        self.assertNotIn(str(HERE / 'vampir-headless/run-bounded-entry.py'), runtime)
        report['definition']['artifacts'] = dict(retained, **{str(patch): '0' * 64})
        with self.assertRaisesRegex(ValueError, 'lost retained'):
            guard.runtime_inputs(index, self.root, report, 'bounded-entry-current')
        real_index = load('bounded_entry_knowledge_index', HERE / 'resource-tools/vampir/knowledge-index.py').api()
        retained, pointer = guard.material(real_index, self.root, self.profile['source_sha256'], 'viper-appearance-current')
        report = dict(definition=dict(check=dict(id='viper-appearance-current'),
            source_sha256=self.profile['source_sha256'], artifacts=retained),
            entry_package_guard=dict(recipe=guard.RECIPE, pointer=pointer))
        runtime = guard.runtime_inputs(real_index, self.root, report, 'viper-appearance-current')
        archive = real_index.INSTALL.parents[2] / 'Saved/PersistentDownloadDir/Patch/Install/pakchunk100-Windows.pak'
        self.assertIn(str(archive.resolve()), runtime)

    def test_profile_requires_scope_and_excludes_world_and_creation(self):
        profile_tool = load('bounded_game_source_profile', HERE / 'vampir-headless/game-source-profile.py')
        with self.assertRaisesRegex(ValueError, 'active verified'):
            profile_tool.load_profile(selected_profile=self.selector)
        with admission.scope(self.selector, root=self.root, workspace=self.workspace):
            profile = profile_tool.load_profile(selected_profile=self.selector)
            self.assertEqual(profile.source_exe_sha256, self.profile['source_sha256'])
            self.assertFalse(profile.bounded_world_probe)
            self.assertTrue(permits(profile.source_exe_sha256, 'lobby-ping-clock-v1'))
            self.assertFalse(permits(profile.source_exe_sha256, 'game-login-world-v1'))
            args = dict(auth_flow='launcher', read_character_list=True, character_index=None,
                server_list_only=False, creation_factory=None, read_world_start=False,
                read_world_finish=False, observe_world_seconds=0, world_observer=None,
                tutorial_observer=None, ack_initial_tutorial=False, read_quest_list=False,
                quest_observer=None, quest_wire_observer=None, session_control=None)
            admission.require_character_list_operation(self.selector, **args)
            for key, value in (('character_index', 0), ('creation_factory', lambda: None),
                               ('read_world_start', True), ('auth_flow', 'nid')):
                with self.assertRaisesRegex(ValueError, 'character lists only'):
                    admission.require_character_list_operation(self.selector, **dict(args, **{key: value}))
            with self.assertRaisesRegex(ValueError, 'switch'):
                with admission.scope('bounded-entry:' + '0' * 64, root=self.root, workspace=self.workspace):
                    pass
        self.assertFalse(permits(self.profile['source_sha256'], 'lobby-ping-clock-v1'))

    def test_current_lobby_keeps_complete_result_on_same_socket(self):
        version = LobbyVersionPayload(('1.13.22', '', 'DESKTOP-FIXTURE', 'nm', ''), (0, 3), 1)
        login = LobbyLoginPayload(('fixture',) * 6, (2, 0, 387, 0), 7)
        request = LobbyServerListPayload(('nm', 'nid'), 2, (0, 0))
        client, server = socket.socketpair()
        server.settimeout(3)
        errors, sent = [], []
        text = b'Etc/UTC'
        version_body = struct.pack('<IBQQHH', 0, 0, 123, 456, 540, len(text)) + text + struct.pack('<II', 10, 20)
        list_body = bytes(21)
        def serve():
            try:
                sent.append(receive_frame(server)[0])
                server.sendall(incoming(2, version_body)[3:])
                sent.append(receive_frame(server)[0])
                server.sendall(incoming(4, bytes(26))[3:])
                sent.append(receive_frame(server)[0])
                server.sendall(incoming(104, list_body)[3:])
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                server.close()
        worker = threading.Thread(target=serve)
        try:
            with admission.scope(self.selector, root=self.root, workspace=self.workspace):
                worker.start()
                result = exchange_lobby_login(client, version, login, server_list=request,
                    version_source_sha256=self.profile['source_sha256'], timeout=2)
                clock = LobbyPingClock.from_version_result(result.version_response,
                    source_sha256=self.profile['source_sha256'])
        finally:
            worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(sent, [(1, 0), (3, 1), (103, 2)])
        self.assertEqual(result.summary['status'], 'lobby_server_list_result')
        self.assertEqual((result.version_response.raw_40, result.version_response.raw_50,
                          result.version_response.raw_54), ('Etc/UTC', 10, 20))
        self.assertEqual(clock.offset_minutes, 540)
        with self.assertRaisesRegex(ValueError, 'scope'):
            exchange_lobby_login(None, version, login, version_source_sha256=self.profile['source_sha256'])

    def test_changed_profile_inputs_rejected_before_scope(self):
        value = dict(self.profile, source_sha256='0' * 64)
        path = self.builder.load('audit-client-release').save_snapshot(self.root / 'bounded-entry-profiles', value)
        with self.assertRaisesRegex(ValueError, 'source or loader'):
            with admission.scope('bounded-entry:' + path.parent.name, root=self.root, workspace=self.workspace):
                pass

    def test_current_game_login_extends_prefix_and_reports_truncation(self):
        queue = OutboundFrames(key_bits=0, sequence=0, max_queued_bytes=65536, max_queued_frames=8)
        version = VersionPayload(('',) * 10, (0, 207, 1))
        login = LoginPayload(('',) * 15, (0, 387, 207, 1), (3, 3, 1, 0, 0), 0)
        with admission.scope(self.selector, root=self.root, workspace=self.workspace):
            flow = LoginFlow(queue, timeout=10, max_payload_size=4096)
            flow.start(version, login, now=0)
            flow.receive(2, struct.pack('<IIBII', 0, 0, 0, 0, 0), now=1)
            body = bytes(99) + struct.pack('<H', 3) + b'UTC' + struct.pack('<II', 17, 29)
            flow.receive(4, body, now=2)
            self.assertEqual(flow.state, 'login_response')
            self.assertEqual((flow.response.raw_140, flow.response.raw_150, flow.response.raw_154), ('UTC', 17, 29))
            for size in range(len(body)):
                with self.assertRaises(ValueError):
                    decode_current_login_result(body[:size], max_payload_size=4096,
                                                source_sha256=self.profile['source_sha256'])
        queue = OutboundFrames(key_bits=0, sequence=0, max_queued_bytes=65536, max_queued_frames=8)
        flow = LoginFlow(queue, timeout=10, max_payload_size=4096)
        flow.start(version, login, now=0)
        flow.receive(2, struct.pack('<IIBII', 0, 0, 0, 0, 0), now=1)
        with self.assertRaises(ValueError):
            flow.receive(4, bytes(4), now=2)
        self.assertEqual(flow.response_failure, dict(packet_id=4, body_size=4, operation='decode_login',
            error_type='ValueError', result_prefix=0, result_prefix_validated=False))
