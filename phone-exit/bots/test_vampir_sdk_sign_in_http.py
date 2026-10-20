import io
import sys
from pathlib import Path
from email.message import Message
from dataclasses import replace
import unittest
import urllib.error

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.sdk_sign_in import SdkSignInRequestPlan
from vampir_core.sdk_sign_in_http import execute_sdk_sign_in, SdkSignInHttpError, _NoRedirect

URL = 'https://sdk.example.invalid/v1/sign-in'
BODY = b'{"errorCode":0,"resultData":{"accessToken":"sdk-token-fixture","playerInfo":{"player":{"playerId":"player-fixture"}}}}'


class Response(io.BytesIO):
    def __init__(self, body=BODY, status=200, headers=None):
        super().__init__(body)
        self.status, self.headers = status, Message()
        for key, value in (headers or {}).items(): self.headers[key] = value


class SdkSignInHttpTests(unittest.TestCase):
    def plan(self):
        return SdkSignInRequestPlan(URL, b'{"credential":"provider-fixture"}',
            (('Content-Type', 'application/json'), ('Accept', 'application/json'), ('gameCode', 'thered'), ('buildCode', 'A')))

    def test_request_and_response_without_persistence(self):
        calls = []
        response = Response(headers={'Content-Length': str(len(BODY))})
        def open(request, timeout):
            calls.append(request)
            self.assertEqual((request.full_url, request.method, timeout), (URL, 'POST', 10))
            self.assertEqual(request.data, self.plan().body)
            self.assertEqual(request.get_header('Accept-encoding'), 'identity')
            return response
        result = execute_sdk_sign_in(self.plan(), expected_url=URL, _open=open)
        self.assertEqual(result.access_token, 'sdk-token-fixture')
        self.assertNotIn('sdk-token-fixture', repr(result))
        self.assertTrue(response.closed)
        self.assertEqual(len(calls), 1)

    def test_redirect_rejected_and_no_retry(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.invalid/'))
        calls = []
        def open(request, timeout):
            calls.append(1)
            raise urllib.error.HTTPError(URL, 302, 'private-error-fixture', {}, io.BytesIO(b'secret'))
        with self.assertRaises(SdkSignInHttpError) as error:
            execute_sdk_sign_in(self.plan(), expected_url=URL, _open=open)
        self.assertEqual((error.exception.kind, error.exception.status), ('http_status', 302))
        self.assertNotIn('private', str(error.exception))
        self.assertEqual(len(calls), 1)

    def test_encoding_limits_length_and_sdk_error(self):
        profiles = ((Response(headers={'Content-Encoding': 'gzip'}), 'unsupported_encoding'),
                    (Response(headers={'Content-Length': str(len(BODY) + 1)}), 'truncated_response'),
                    (Response(headers={'Content-Length': '999999'}), 'response_limit'),
                    (Response(headers={'Content-Length': 'bad'}), 'invalid_length'),
                    (Response(b'{"errorCode":42}'), 'sdk_response_rejected'),
                    (Response(b'x' * 65537), 'response_limit'))
        for response, kind in profiles:
            with self.assertRaises(SdkSignInHttpError) as error:
                execute_sdk_sign_in(self.plan(), expected_url=URL, _open=lambda *a, **k: response)
            self.assertEqual(error.exception.kind, kind)
            self.assertTrue(response.closed)

    def test_tls_network_failure_and_read_budget(self):
        def fail(*args, **kwargs): raise urllib.error.URLError('private-transport-details')
        with self.assertRaisesRegex(SdkSignInHttpError, 'transport_error'):
            execute_sdk_sign_in(self.plan(), expected_url=URL, _open=fail)
        ticks = iter((0, 31))
        response = Response()
        with self.assertRaisesRegex(SdkSignInHttpError, 'read_timeout'):
            execute_sdk_sign_in(self.plan(), expected_url=URL, _open=lambda *a, **k: response, _clock=lambda: next(ticks))
        self.assertTrue(response.closed)

    def test_bad_plan_and_endpoint_never_reach_transport(self):
        def forbidden(*a, **k): self.fail('Transport called with an invalid plan')
        for plan, url in ((replace(self.plan(), method='GET'), URL),
                          (self.plan(), 'https://other.example.invalid/v1/sign-in'),
                          (replace(self.plan(), url='http://sdk.example.invalid/v1/sign-in'), 'http://sdk.example.invalid/v1/sign-in'),
                          (replace(self.plan(), headers=(('Content-Type', 'bad\r\nheader'),)), URL)):
            with self.assertRaises(ValueError): execute_sdk_sign_in(plan, expected_url=url, _open=forbidden)


if __name__ == '__main__': unittest.main()
