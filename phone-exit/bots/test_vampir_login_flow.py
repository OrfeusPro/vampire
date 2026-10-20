import json
from pathlib import Path
import struct
import unittest

import test_vampir_game_connection as socket_tests
from test_vampir_game_connection import BUDGET
from test_vampir_receive_stream import transport, inner
from test_vampir_selection_flow import connection
from vampir_core.login_flow import LoginFlow
from vampir_core.login_packet import LoginPayload
from vampir_core.version_packet import VersionPayload
from vampir_core.version_result import decode_version_result
from vampir_core.send_frame import encode_version_frame_b, encode_login_frame_b

FIXTURE = json.loads((Path(__file__).parent / 'fixtures/vampir-login-flow.json').read_text('utf-8'))
VERSION = VersionPayload(tuple('version-fixture' for _ in range(10)), (0, 207, 2))
LOGIN = LoginPayload(tuple('token-fixture' for _ in range(15)), (0, 42, 207, 2), (0, 0, 0, 0, 0), 0)
RESULT = struct.pack('<IIBII', 0, 1, 255, 2, 3)


class LoginFlowTests(unittest.TestCase):
    def flow(self, **kwargs):
        _, queue = connection(**kwargs)
        return LoginFlow(queue, timeout=10, max_payload_size=4096), queue

    def test_all_43_native_frames(self):
        self.assertEqual(len(FIXTURE['frames']), 43)
        for row in FIXTURE['frames']:
            fields = dict(row['fields'])
            for key in ('strings', 'integers', 'raw_bytes'):
                if key in fields: fields[key] = tuple(fields[key])
            payload = VersionPayload(**fields) if row['kind'] == 'version' else LoginPayload(**fields)
            encode = encode_version_frame_b if row['kind'] == 'version' else encode_login_frame_b
            self.assertEqual(encode(payload, row['sequence'], row['key'], max_payload_size=4096).hex(), row['frame_hex'])

    def test_version_exact_size_and_bool(self):
        self.assertTrue(decode_version_result(RESULT).flag18)
        for length in range(17):
            with self.assertRaises(ValueError): decode_version_result(RESULT[:length])
        with self.assertRaises(ValueError): decode_version_result(RESULT + b'extra')

    def test_lifecycle_duplicate_and_no_automatic_character_list(self):
        flow, queue = self.flow()
        flow.start(VERSION, LOGIN, now=0)
        with self.assertRaises(RuntimeError): flow.start(VERSION, LOGIN, now=0)
        self.assertEqual(flow.state, 'version_pending')
        queue.pop_frame()
        flow.receive(2, RESULT, now=1)
        self.assertEqual((flow.state, flow.deadline), ('login_pending', 11))
        self.assertIsNotNone(queue.pop_frame())
        with self.assertRaises(RuntimeError): flow.receive(2, RESULT, now=1)
        flow.receive(4, bytes.fromhex(FIXTURE['login_result_hex']), now=2)
        self.assertEqual(flow.state, 'login_response')
        self.assertIsNotNone(flow.response)
        self.assertIsNone(queue.pop_frame())
        self.assertNotIn('token-fixture', repr(flow))
        flow.close()
        self.assertIsNone(flow.response)

    def test_timeout_and_nonzero_result_clear_queue(self):
        for timeout in (False, True):
            flow, queue = self.flow()
            flow.start(VERSION, LOGIN, now=0)
            if timeout: self.assertTrue(flow.expire(now=10))
            else: flow.receive(2, struct.pack('<IIBII', 708, 0, 0, 0, 0), now=1)
            self.assertEqual(flow.state, 'failed')
            self.assertEqual(queue.queued_bytes, 0)
            self.assertIsNone(flow._login)

    def test_malformed_reply_and_ack_queue_refusal(self):
        flow, queue = self.flow()
        flow.start(VERSION, LOGIN, now=0)
        with self.assertRaises(ValueError): flow.receive(2, b'private', now=1)
        self.assertEqual((flow.state, queue.queued_bytes), ('failed', 0))
        flow, queue = self.flow(max_frames=1)
        flow.start(VERSION, LOGIN, now=0)
        with self.assertRaises(ValueError): flow.receive(2, RESULT, now=1)
        self.assertEqual((flow.state, queue.queued_bytes), ('failed', 0))
        flow, queue = self.flow(max_bytes=10)
        with self.assertRaises(BufferError): flow.start(VERSION, LOGIN, now=0)
        self.assertEqual((flow.state, flow.deadline, queue.sequence), ('new', None, 65535))


class LoginSocketTests(unittest.TestCase):
    # Reuse socket setup/assertions without inheriting its full test suite.
    connect = socket_tests.GameConnectionTests.connect
    read_request = socket_tests.GameConnectionTests.read_request

    def test_version_login_key_change_and_explicit_list_permission(self):
        owner, server, _ = self.connect()
        owner.start_login(VERSION, LOGIN, now=0, timeout=10, max_payload_size=4096)
        with self.assertRaises(RuntimeError): owner.enter_character_list(now=0)
        owner.pump(now=0, budget=BUDGET)
        self.assertEqual(self.read_request(server, 7), (1, 0, VERSION.encode(max_payload_size=4096)))
        server.sendall(transport(inner(11, struct.pack('<Q', 99), 7) + inner(2, RESULT, 99), True))
        owner.pump(now=1, budget=BUDGET)
        self.assertEqual(self.read_request(server, 7)[:2], (12, 1))
        self.assertEqual(self.read_request(server, 99), (3, 2, LOGIN.encode(max_payload_size=4096)))
        server.sendall(transport(inner(4, bytes.fromhex(FIXTURE['login_result_hex']), 99)))
        for _ in range(10):
            owner.pump(now=2, budget=BUDGET)
            if owner.login.state == 'login_response': break
        self.assertEqual(owner.login.state, 'login_response')
        self.assertEqual(owner.queued_bytes, 0)
        owner.enter_character_list(now=3)
        owner.pump(now=3, budget=BUDGET)
        self.assertEqual(self.read_request(server, 99), (101, 3, b''))

    def test_login_timeout_and_failure_close_socket(self):
        owner, server, client = self.connect()
        owner.start_login(VERSION, LOGIN, now=0, timeout=1, max_payload_size=4096)
        self.assertFalse(owner.pump(now=1, budget=BUDGET).active)
        self.assertEqual((client.fileno(), owner.error), (-1, 'login_timeout'))
        owner, server, client = self.connect()
        owner.start_login(VERSION, LOGIN, now=0, timeout=10, max_payload_size=4096)
        server.sendall(transport(inner(2, struct.pack('<IIBII', 708, 0, 0, 0, 0), 7)))
        self.assertFalse(owner.pump(now=1, budget=BUDGET).active)
        self.assertEqual((client.fileno(), owner.error, owner.login.result_code), (-1, 'login_response_failed', 708))


if __name__ == '__main__': unittest.main()
