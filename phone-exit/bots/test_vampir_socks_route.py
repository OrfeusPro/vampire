from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
sys.path.insert(0, str(HERE.parent / '.tools/vampir-python-runtime'))
from vampir_core.socks_route import SocksRoute
from vampir_core.sdk_sign_in_http import _NoRedirect


class SocksRouteTests(unittest.TestCase):
    def test_port_and_browser_arguments(self):
        for bad in (True, 0, 80, 65536, '17948'):
            with self.assertRaises(ValueError): SocksRoute(bad)
        self.assertEqual(SocksRoute(17948).browser_arguments,
                         '--proxy-server=socks5://127.0.0.1:17948 --disable-quic')

    def test_socket_and_dns_are_scoped_to_proxy(self):
        import socks
        original = socket.socket
        with patch.object(socks, 'socksocket') as factory:
            sock = SocksRoute(17948).connect('target.example.invalid', 443)
        factory.return_value.set_proxy.assert_called_once_with(socks.SOCKS5, '127.0.0.1', 17948, rdns=True)
        sock.connect.assert_called_once_with(('target.example.invalid', 443))
        self.assertIs(socket.socket, original)
        with patch.object(socks, 'socksocket') as factory:
            factory.return_value.connect.side_effect = OSError('offline fixture')
            with self.assertRaises(OSError): SocksRoute(17948).connect('target.example.invalid', 443)
            factory.return_value.close.assert_called_once()

    def test_plain_http_cannot_fall_back_to_direct_connection(self):
        opener = SocksRoute(17948).opener(_NoRedirect())
        with patch('socket.getaddrinfo', side_effect=AssertionError('Direct DNS must not run')):
            with self.assertRaisesRegex(urllib.error.URLError, 'HTTPS is required'):
                opener.open('http://unit.invalid/probe', timeout=1)

    def test_real_socks_domain_request_and_verified_tls(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'unit.invalid')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('unit.invalid')]), critical=False)
            .sign(key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as folder:
            cert_path, key_path = Path(folder) / 'cert.pem', Path(folder) / 'key.pem'
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
            for trusted in (True, False):
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(5)
                port = listener.getsockname()[1]
                observations = []
                def exact(sock, size):
                    data = b''
                    while len(data) < size:
                        part = sock.recv(size - len(data))
                        if not part: raise EOFError('fixture closed')
                        data += part
                    return data
                def serve():
                    try:
                        with listener.accept()[0] as raw:
                            raw.settimeout(5)
                            observations.append(exact(raw, 3))
                            raw.sendall(b'\x05\x00')
                            header = exact(raw, 5)
                            observations.append(header[:4])
                            observations.append(exact(raw, header[4]))
                            observations.append(exact(raw, 2))
                            raw.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                            with server_context.wrap_socket(raw, server_side=True) as secure:
                                request = b''
                                while b'\r\n\r\n' not in request and len(request) < 8192:
                                    request += secure.recv(1024)
                                observations.append(request.startswith(b'GET /probe HTTP/1.1'))
                                secure.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                    except ssl.SSLError:
                        observations.append('tls_rejected')
                    except BaseException as exc:
                        observations.append(type(exc).__name__)
                    finally:
                        listener.close()
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                context = ssl.create_default_context(cafile=str(cert_path)) if trusted else ssl.create_default_context()
                with patch('vampir_core.socks_route.ssl.create_default_context', return_value=context):
                    opener = SocksRoute(port).opener(_NoRedirect())
                if trusted:
                    with opener.open('https://unit.invalid/probe', timeout=3) as response:
                        self.assertEqual(response.read(), b'ok')
                else:
                    with self.assertRaises(urllib.error.URLError) as error:
                        opener.open('https://unit.invalid/probe', timeout=3)
                    self.assertIsInstance(error.exception.reason, ssl.SSLCertVerificationError)
                thread.join(6)
                self.assertFalse(thread.is_alive())
                self.assertEqual(observations[:4], [b'\x05\x01\x00', b'\x05\x01\x00\x03', b'unit.invalid', b'\x01\xbb'])
                self.assertEqual(observations[4], True if trusted else 'tls_rejected')


if __name__ == '__main__': unittest.main()
