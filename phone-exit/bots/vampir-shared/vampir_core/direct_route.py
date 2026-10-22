"""Explicit ordinary IPv4 TCP transport, without SOCKS or socket monkeypatches."""
import ipaddress
import socket
import time

from .socks_route import GameAddressContext


def connect_direct(host, port, *, timeout=10):
    if type(host) is not str or not host or len(host) > 253:
        raise ValueError('Invalid direct target')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid direct port')
    if type(timeout) not in (int, float) or not 0 < timeout <= 60:
        raise ValueError('Invalid direct timeout')
    deadline = time.monotonic() + timeout
    records = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    endpoints = list(dict.fromkeys(record[4] for record in records))
    if not endpoints or len(endpoints) > 32:
        raise ValueError('Unsupported direct DNS result')
    # Check every answer before connecting; never resolve the hostname again.
    if any(not ipaddress.IPv4Address(endpoint[0]).is_global for endpoint in endpoints):
        raise ValueError('Direct game destination must be public IPv4')
    error = None
    for endpoint in endpoints:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Direct connection budget exceeded')
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.settimeout(remaining)
            connection.connect(endpoint)
            return connection
        except OSError as exc:
            error = exc
            connection.close()
        except BaseException:
            connection.close()
            raise
    raise OSError('Direct connection failed') from error


def direct_game_address_context(connection):
    """Observe the local endpoint of this socket; never infer an external IP."""
    host, port = connection.getsockname()
    address = ipaddress.IPv4Address(host)
    if type(port) is not int or not 1 <= port <= 65535 or address.is_unspecified or address.is_multicast:
        raise ValueError('Invalid direct local endpoint')
    return GameAddressContext(str(address), 'direct_socket_ipv4')
