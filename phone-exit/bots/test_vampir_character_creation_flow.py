"""Creation lifecycle through framing/socket pump; local sockets, no real account."""
import importlib.util
from pathlib import Path
import socket
import struct
import threading
import unittest

from test_vampir_selection_flow import connection, list_body, request_fields
from test_vampir_login_flow import VERSION, LOGIN, RESULT, FIXTURE
from test_vampir_version_probe import incoming, receive_frame
from vampir_core.character_creation_candidate import carnage_creation_candidate
from vampir_core.character_creation_flow import CharacterCreationFlow
from vampir_core.character_create import encode_character_create
from vampir_core.game_login_probe import exchange_game_login
from vampir_core.socket_send import drain_outbound
from vampir_core.world_move_start import SOURCE_SHA256
import test_vampir_game_connection as connection_tests


def result_body(code=0):
    path = Path(__file__).parent / 'resource-tools/vampir/replay-character-list-extensions.py'
    spec = importlib.util.spec_from_file_location('creation_flow_wire', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return struct.pack('<I', code) + module.base.record_bytes('ServerHero', 1, 1, 1, 1)


class CreationFlowTests(unittest.TestCase):
    def flow(self, *, keys=(), code=0, max_bytes=8192):
        selection, queue = connection(max_bytes=max_bytes)
        selection.enter_list(now=0); queue.pop_frame()
        selection.receive(102, list_body(keys=keys, code=code), now=0)
        return CharacterCreationFlow(queue, source_sha256=SOURCE_SHA256, timeout=2), selection, queue

    def test_partial_send_early_result_and_exact_wire(self):
        flow, selection, queue = self.flow()
        payload = carnage_creation_candidate('Hero', source_sha256=SOURCE_SHA256)
        flow.queue(payload, selection, now=0)
        frame = bytes(queue.peek_frame())
        packet_id, sequence, body = request_fields(frame, 0x0102030405060708)
        self.assertEqual((packet_id, sequence), (103, 0))
        self.assertEqual(body, encode_character_create(payload, source_sha256=SOURCE_SHA256))
        class OneByte:
            def send(self, data): return 1
        drain_outbound(OneByte(), queue, max_send_calls=len(frame) - 1, on_frame_sent=flow.frame_sent)
        flow.receive(result_body(), now=0)
        self.assertEqual(flow.state, 'queued')
        drain_outbound(OneByte(), queue, max_send_calls=1, on_frame_sent=flow.frame_sent)
        self.assertEqual(flow.state, 'sent')
        flow.receive(result_body(), now=1)
        self.assertEqual(flow.state, 'created')
        self.assertEqual(flow.outcome.character_name, 'ServerHero')
        self.assertFalse(flow.outcome.requested_name_matches)
        flow.receive(result_body(59), now=1)
        self.assertEqual((flow.state, flow.unmatched_results), ('created', 2))
        with self.assertRaises(RuntimeError): flow.queue(payload, selection, now=1)

    def test_existing_refused_list_and_queue_failure_never_create(self):
        payload = carnage_creation_candidate('Hero', source_sha256=SOURCE_SHA256)
        for keys, code in (((11,), 0), ((), 59)):
            flow, selection, queue = self.flow(keys=keys, code=code)
            with self.assertRaises(RuntimeError): flow.queue(payload, selection, now=0)
            self.assertEqual(queue.queued_bytes, 0)
        flow, selection, queue = self.flow(max_bytes=20)
        sequence = queue.sequence
        with self.assertRaises(BufferError): flow.queue(payload, selection, now=0)
        self.assertEqual((flow.state, queue.queued_bytes, queue.sequence), ('not_queued', 0, sequence))
        with self.assertRaises(RuntimeError): flow.queue(payload, selection, now=0)

    def test_rejected_malformed_timeout_and_close(self):
        payload = carnage_creation_candidate('Hero', source_sha256=SOURCE_SHA256)
        for mode in ('rejected', 'malformed', 'timeout', 'close'):
            flow, selection, queue = self.flow(); flow.queue(payload, selection, now=0)
            flow.frame_sent(queue.consume_sent(queue.queued_bytes))
            if mode == 'rejected':
                flow.receive(result_body(59), now=1)
                self.assertEqual(flow.state, 'rejected'); self.assertIsNone(flow.outcome.character_key)
            elif mode == 'malformed':
                with self.assertRaises(ValueError): flow.receive(bytes(4), now=1)
                self.assertEqual(flow.state, 'unknown')
            elif mode == 'timeout': self.assertTrue(flow.expire(now=2))
            else: flow.close()
            if mode != 'rejected': self.assertEqual(flow.state, 'unknown')
            with self.assertRaises(RuntimeError): flow.queue(payload, selection, now=2)
        with self.assertRaises(ValueError): CharacterCreationFlow(queue, source_sha256='old', timeout=2)

    def test_late_result_and_partial_queue_cleanup(self):
        payload = carnage_creation_candidate('Hero', source_sha256=SOURCE_SHA256)
        flow, selection, queue = self.flow(); flow.queue(payload, selection, now=0)
        flow.frame_sent(queue.consume_sent(queue.queued_bytes))
        flow.receive(result_body(), now=2)
        self.assertEqual(flow.state, 'unknown'); self.assertIsNone(flow.outcome)
        owner, _, client = connection_tests.GameConnectionTests.connect(self)
        with self.assertRaises(RuntimeError):
            owner.queue_character_create(payload, source_sha256=SOURCE_SHA256, now=0)
        self.assertIsNone(owner.creation)
        # Explicit internal fixture for cleanup only, not evidence of Login.
        flow, selection, queue = self.flow()
        owner._outbound = queue
        owner._selection = selection
        owner._creation = CharacterCreationFlow(owner._outbound, source_sha256=SOURCE_SHA256, timeout=2)
        owner.creation.queue(payload, selection, now=0)
        owner._outbound.consume_sent(1)
        result = owner.pump(now=2, budget=connection_tests.BUDGET)
        self.assertFalse(result.active)
        self.assertEqual((owner.error, owner.creation.state, owner.queued_bytes, client.fileno()),
            ('character_creation_unknown', 'unknown', 0, -1))


class CreationSessionTests(unittest.TestCase):
    def attempt(self, *, mode='success', keys=(), login_code=None, factory=False):
        client, server = socket.socketpair(); server.settimeout(2)
        captures, failures = [], []
        payload = carnage_creation_candidate('Hero', source_sha256=SOURCE_SHA256)
        factory_calls = []
        def prepare(listing):
            self.assertEqual((listing.result_code, listing.records), (0, ()))
            factory_calls.append('prepared')
            return payload
        def serve():
            try:
                captures.append(receive_frame(server)[0]); server.sendall(incoming(2, RESULT))
                captures.append(receive_frame(server)[0])
                login = bytes.fromhex(FIXTURE['login_result_hex'])
                if login_code is not None: login = struct.pack('<I', login_code) + login[4:]
                server.sendall(incoming(4, login))
                if login_code is None:
                    captures.append(receive_frame(server)[0]); server.sendall(incoming(102, list_body(keys=keys)))
                    if not keys:
                        header, body = receive_frame(server); captures.append(header)
                        self.assertEqual(body, encode_character_create(payload, source_sha256=SOURCE_SHA256))
                        if mode == 'eof': return
                        if mode != 'timeout': server.sendall(incoming(104, result_body(59 if mode == 'rejected' else 0)))
                while server.recv(4096): pass
            except BaseException as error: failures.append(repr(error))
            finally: server.close()
        worker = threading.Thread(target=serve); worker.start()
        try:
            result = exchange_game_login(client, VERSION, LOGIN, timeout=0.3,
                read_character_list=True, expose_character_labels=True,
                source_sha256=SOURCE_SHA256, creation_payload=None if factory else payload,
                creation_factory=prepare if factory else None)
        finally:
            client.close(); worker.join(3)
        self.assertFalse(worker.is_alive()); self.assertEqual(failures, [])
        self.assertEqual(client.fileno(), -1)
        if factory: self.assertEqual(len(factory_calls), sum(pid == 103 for pid, _ in captures))
        return result, captures

    def test_same_connection_login_list_create_and_result(self):
        result, captures = self.attempt()
        self.assertEqual(captures, [(1, 0), (3, 1), (101, 2), (103, 3)])
        self.assertEqual((result['status'], result['character_creation_state']), ('character_creation_result', 'created'))
        self.assertEqual(result['created_character_name'], 'ServerHero')
        self.assertNotEqual(result['created_character_key'], '0')
        self.assertTrue(result['character_creation_refresh_required'])

    def test_rejection_unknown_and_existing_character(self):
        for mode, state in (('rejected', 'rejected'), ('eof', 'unknown'), ('timeout', 'unknown')):
            result, captures = self.attempt(mode=mode)
            self.assertEqual(result['character_creation_state'], state)
            self.assertFalse(result['character_creation_retry_allowed'])
            self.assertNotIn('created_character_key', result)
            self.assertEqual(sum(pid == 103 for pid, _ in captures), 1)
        result, captures = self.attempt(keys=(11,))
        self.assertEqual(result['character_creation_state'], 'not_attempted')
        self.assertEqual(captures, [(1, 0), (3, 1), (101, 2)])
        result, captures = self.attempt(login_code=59)
        self.assertEqual(result['character_creation_state'], 'not_attempted')
        self.assertEqual(captures, [(1, 0), (3, 1)])

    def test_factory_only_runs_on_accepted_empty_list(self):
        result, _ = self.attempt(factory=True)
        self.assertEqual(result['character_creation_state'], 'created')
        for kwargs in (dict(keys=(11,)), dict(login_code=59)):
            result, _ = self.attempt(factory=True, **kwargs)
            self.assertEqual(result['character_creation_state'], 'not_attempted')


if __name__ == '__main__': unittest.main()
