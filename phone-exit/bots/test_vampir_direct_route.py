from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.direct_route import connect_direct, direct_game_address_context


class DirectRouteTests(unittest.TestCase):
    def answers(self, *hosts):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (host, 12001)) for host in hosts]

    def test_public_ipv4_connects_without_second_dns_and_observes_local_address(self):
        with patch('socket.getaddrinfo', return_value=self.answers('1.1.1.1')) as dns, \
                patch('socket.socket') as factory:
            connection = connect_direct('game.example.invalid', 12001)
        dns.assert_called_once_with('game.example.invalid', 12001, socket.AF_INET, socket.SOCK_STREAM)
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect.assert_called_once_with(('1.1.1.1', 12001))
        connection.getsockname.return_value = ('192.168.1.25', 49152)
        context = direct_game_address_context(connection)
        self.assertEqual((context.address, context.source), ('192.168.1.25', 'direct_socket_ipv4'))
        self.assertNotIn('192.168.1.25', repr(context))

    def test_private_or_empty_dns_never_opens_socket(self):
        for hosts in ((), ('127.0.0.1',), ('1.1.1.1', '192.168.0.1'), ('169.254.1.1',)):
            with self.subTest(hosts=hosts), patch('socket.getaddrinfo', return_value=self.answers(*hosts)), \
                    patch('socket.socket') as factory:
                with self.assertRaises(ValueError): connect_direct('game.example.invalid', 12001)
                factory.assert_not_called()

    def test_failed_socket_closes_and_next_address_uses_remaining_budget(self):
        failed, connected = Mock(), Mock()
        failed.connect.side_effect = OSError('fixture')
        with patch('socket.getaddrinfo', return_value=self.answers('1.1.1.1', '8.8.8.8')), \
                patch('socket.socket', side_effect=[failed, connected]), \
                patch('vampir_core.direct_route.time.monotonic', side_effect=[0, 1, 3]):
            self.assertIs(connect_direct('game.example.invalid', 12001, timeout=10), connected)
        failed.close.assert_called_once()
        failed.settimeout.assert_called_once_with(9)
        connected.settimeout.assert_called_once_with(7)
        connected.close.assert_not_called()


if __name__ == '__main__':
    unittest.main()
