import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.frame_primitives import xor_transform, payload_crc32
from vampir_core.version_packet import VersionPayload
from vampir_core.version_cpu import VersionCpuInput
from vampir_core.windows_version import WindowsVersion
from vampir_core.version_probe import exchange_version


def incoming(packet_id, body, key=0):
    inner = (5 + len(body)).to_bytes(3, 'little') + xor_transform(struct.pack('<H', packet_id) + body, key)
    return (3 + len(inner)).to_bytes(3, 'little') + inner


def receive_frame(sock):
    data = b''
    while len(data) < 3:
        chunk = sock.recv(3 - len(data))
        if not chunk: raise AssertionError('Truncated outgoing header')
        data += chunk
    length = int.from_bytes(data, 'little')
    if not 11 <= length <= 65536: raise AssertionError('Outgoing frame bound')
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk: raise AssertionError('Truncated outgoing frame')
        data += chunk
    plain = xor_transform(data[3:])
    if int.from_bytes(plain[:4], 'little') != payload_crc32(plain[4:]): raise AssertionError('CRC mismatch')
    return struct.unpack_from('<HH', plain, 4), plain[8:]


class VersionProbeTests(unittest.TestCase):
    def payload(self): return VersionPayload(('fixture',) + ('',) * 9, (0, 207, 1))

    def test_real_socket_pair_version_key_ack_and_result_without_login(self):
        client, server = socket.socketpair()
        server.settimeout(2)
        captures, errors = [], []
        new_key = 0x1020304050607080
        def serve():
            try:
                captures.append(receive_frame(server))
                notify = incoming(11, struct.pack('<Q', new_key))
                for chunk in (notify[:2], notify[2:7], notify[7:]): server.sendall(chunk)
                captures.append(receive_frame(server))
                server.sendall(incoming(2, struct.pack('<IIBII', 0, 7, 1, 8, 9), new_key))
            except BaseException as error: errors.append(type(error).__name__)
            finally: server.close()
        worker = threading.Thread(target=serve)
        worker.start()
        result = exchange_version(client, self.payload(), timeout=1)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual([capture[0] for capture in captures], [(1, 0), (12, 1)])
        self.assertEqual(captures[1][1], struct.pack('<Q', new_key))
        self.assertEqual(result['status'], 'version_result')
        self.assertEqual(result['version_result_code'], 0)
        self.assertEqual(result['packet_ids'], [11, 2])
        self.assertFalse(result['login_sent'])
        self.assertEqual(client.fileno(), -1)

    def test_timeout_and_server_close_are_distinct_and_socket_is_closed(self):
        client, server = socket.socketpair()
        try:
            result = exchange_version(client, self.payload(), timeout=0.02)
            self.assertEqual(result['status'], 'timeout')
            self.assertEqual(receive_frame(server)[0], (1, 0))
        finally: server.close()
        client, server = socket.socketpair()
        server.shutdown(socket.SHUT_WR)
        try:
            self.assertEqual(exchange_version(client, self.payload(), timeout=0.1)['status'], 'server_closed')
        finally: server.close()

    def test_bad_version_body_closes_instead_of_sending_login(self):
        client, server = socket.socketpair()
        server.sendall(incoming(2, b'bad'))
        try:
            with self.assertRaises(ValueError): exchange_version(client, self.payload(), timeout=0.2)
            self.assertEqual(client.fileno(), -1)
        finally: server.close()


class VersionProfileTests(unittest.TestCase):
    def test_unverified_lobby_requires_explicit_diagnostic_mode_before_io(self):
        spec = importlib.util.spec_from_file_location('version_diagnostic_test', HERE / 'vampir-headless/probe-game-version.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with self.assertRaisesRegex(ValueError, 'explicit diagnostic'):
            tool.run('fixture@example.invalid', selected_profile='recovered-base',
                manifest_path=Path('missing.invalid'), socks_port=17948)

    def test_complete_normal_windows_payload_uses_only_explicit_inputs(self):
        spec = importlib.util.spec_from_file_location('version_profile_test', HERE / 'vampir-headless/probe-game-version.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        value = tool.prepare_version(app_version='1.12.14', nm_device_key='nm-fixture',
            local_address='127.0.0.1', cpu=VersionCpuInput('GenuineIntel', ' Fixture CPU '),
            windows_version=WindowsVersion(10, 0, 26200, 1, 256))
        self.assertEqual(value.strings[:5], ('1.12.14', 'Windows_10.0.26200.1.256.64bit',
            'GenuineIntel|Fixture CPU', 'nm-fixture', '127.0.0.1'))
        self.assertEqual(value.strings[5:9], ('',) * 4)
        self.assertEqual(value.integers, (0, 207, 1))
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/game-login-input-index.json').read_text('utf-8'))
        tag = next(item['pointee']['ascii'] for item in report['targets'] if 'pointee' in item)
        self.assertEqual(value.strings[9], tag)
        self.assertNotIn('nm-fixture', repr(value))
        with self.assertRaises(ValueError):
            tool.prepare_version(app_version='1.12.14', nm_device_key='nm-fixture', local_address='127.0.0.1:1234',
                cpu=VersionCpuInput('', ''), windows_version=None)


if __name__ == '__main__': unittest.main()
