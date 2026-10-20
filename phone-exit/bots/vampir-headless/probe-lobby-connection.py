"""One bounded TCP connection to the lobby of an explicitly selected CDN snapshot.

No packet is sent, and no account credentials or raw received data are saved.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
sys.path.insert(0, str(HERE.parents[1] / '.tools/vampir-python-runtime'))
from vampir_core.cdn_config import decode_cdn_config_document
from vampir_core.cdn_servers import select_cdn_server
from vampir_core.socks_route import SocksRoute


def selected_endpoint(manifest_path, *, route):
    if not isinstance(route, SocksRoute): raise TypeError('Explicit SOCKS route required')
    path = Path(manifest_path).resolve(strict=True)
    if path.stat().st_size > 131072: raise ValueError('CDN manifest exceeds local budget')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != path.parent.name: raise ValueError('CDN manifest hash differs')
    manifest = json.loads(data)
    if (manifest['transport']['status'] != 200 or
            manifest['transport'].get('socks5_loopback_port') != route.port):
        raise ValueError('CDN status or selected route differs')
    if manifest['profile']['config_snapshot_sha256'] != '393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db':
        raise ValueError('Probe requires the explicit recovered base profile')
    if manifest['profile']['url'] != 'https://red.gcdn.netmarble.com/red/config/window/real/1_12_14/config.json':
        raise ValueError('Probe source URL differs from the recovered base profile')
    body_path = path.parent / 'body.bin'
    if body_path.stat().st_size > 2097152: raise ValueError('CDN body exceeds local budget')
    body = body_path.read_bytes()
    if hashlib.sha256(body).hexdigest() != manifest['body_sha256']: raise ValueError('CDN body hash differs')
    selected = select_cdn_server(decode_cdn_config_document(body))
    # This first connection probe supports only the observed public IPv4 form.
    address = ipaddress.IPv4Address(selected.lobby_address)
    if not address.is_global: raise ValueError('Lobby address is not public IPv4')
    port = selected.lobby_port
    if type(port) is not str or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError('Lobby port is invalid')
    return str(address), int(port)


def probe(manifest_path, *, socks_port):
    route = SocksRoute(socks_port)
    endpoint = selected_endpoint(manifest_path, route=route)
    connection = route.connect(*endpoint, timeout=10)
    try:
        connection.settimeout(3)
        try:
            data = connection.recv(65536)
            outcome = 'received' if data else 'closed_by_server'
            count = len(data)
        except socket.timeout:
            outcome, count = 'read_timeout', 0
        except ConnectionResetError:
            outcome, count = 'reset_by_server', 0
        return dict(tcp_connected=True, initial_read=outcome, initial_bytes=count,
            client_game_packets_sent=0, login_attempted=False, game_session_ready=False)
    finally:
        connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--socks-port', type=int, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(probe(args.manifest, socks_port=args.socks_port)))
    except (OSError, ValueError, RuntimeError, KeyError):
        print(json.dumps(dict(tcp_connected=False, error='lobby_probe_not_completed')))
        sys.exit(2)
