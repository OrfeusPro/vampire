"""Offline NID email sign-in arguments from captured public web source.

No network, cookie/session access or reCAPTCHA acquisition. Public RSA key is
supplied explicitly from the page, distinct from SDK DECKEY/nidEncryptKey.
"""
import base64
from dataclasses import dataclass, field
import json
from urllib.parse import urlsplit


def nid_js_string_bytes(value: str) -> bytes:
    """JSEncrypt's reviewed charCodeAt encoding (CESU-8 for surrogate pairs).

    Local policy rejects NUL, controls and invalid Unicode; no trim/lowercase.
    At most 4096 Python characters before the stricter RSA encoded-byte bound.
    """
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid NID sign-in field')
    try:
        value.encode('utf-8', 'strict')
        raw = value.encode('utf-16le')
    except UnicodeError:
        raise ValueError('Invalid NID sign-in field encoding') from None
    result = bytearray()
    for offset in range(0, len(raw), 2):
        unit = raw[offset] | raw[offset + 1] << 8
        if unit < 128:
            result.append(unit)
        elif unit < 2048:
            result.extend((unit >> 6 | 192, unit & 63 | 128))
        else:
            result.extend((unit >> 12 | 224, unit >> 6 & 63 | 128, unit & 63 | 128))
    return bytes(result)


def encrypt_nid_field(value: str, public_key_pem: str) -> str:
    """RSA PKCS1v1.5 field encryption; optional crypto backend and secure RNG.

    The page's current key is 1024-bit; accept explicit 1024/2048/3072/4096
    public keys. Enforce k-11 encoded bytes, correcting the page helper's
    character-count-only initial guard. No private key or decryption here.
    """
    payload = nid_js_string_bytes(value)
    if not isinstance(public_key_pem, str) or len(public_key_pem) > 8192:
        raise ValueError('Invalid NID public key')
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.exceptions import UnsupportedAlgorithm
        key = serialization.load_pem_public_key(public_key_pem.encode('ascii'))
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size not in (1024, 2048, 3072, 4096):
            raise ValueError
        if len(payload) > key.key_size // 8 - 11:
            raise ValueError
        return base64.b64encode(key.encrypt(payload, padding.PKCS1v15())).decode('ascii')
    except ImportError:
        raise RuntimeError('NID field encryption requires the optional cryptography backend') from None
    except (ValueError, TypeError, UnicodeError, UnsupportedAlgorithm):
        raise ValueError('Invalid NID field length or public key') from None


@dataclass(frozen=True, slots=True)
class NidEmailSignInPlan:
    url: str = field(repr=False)
    body: bytes = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    method: str = 'POST'


def plan_nid_email_sign_in(*, email: str, password: str, public_key_pem: str,
                           webview_url: str, context: dict, recaptcha_token: str) -> NidEmailSignInPlan:
    """Encrypt explicit fields and prepare the observed JSON/interceptor inputs.

    Requires a separately obtained nonempty captcha token; never invents one.
    Context keys mirror the web interceptor; clientId/gameCode/buildCode are
    required, device/session values explicit and otherwise omitted. Cookie/
    browser origin headers, challenge, response/code callback remain outside
    this offline plan. This plan is not a ready HTTP login client.
    """
    try:
        if not isinstance(webview_url, str) or len(webview_url) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in webview_url):
            raise ValueError
        parts = urlsplit(webview_url)
        if (parts.scheme != 'https' or not parts.hostname or parts.username is not None or parts.password is not None
                or parts.path not in ('/auth', '/auth/') or parts.query or parts.fragment or '\\' in webview_url or parts.port == 0):
            raise ValueError
        if not isinstance(context, dict) or any(not isinstance(context.get(k), str) or not context[k] for k in ('clientId', 'gameCode', 'buildCode')):
            raise ValueError
        names = ('accessToken', 'clientId', 'gameCode', 'buildCode', 'playerId', 'nmDeviceKey',
                 'deviceKey', 'deviceIp', 'clientIp', 'osType', 'webViewType')
        if set(context) - set(names):
            raise ValueError
        for value in list(context.values()) + [recaptcha_token]:
            if not isinstance(value, str) or len(value) > 8192 or any(not 32 <= ord(c) <= 126 for c in value):
                raise ValueError
        if not recaptcha_token:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError('Invalid explicit NID request context or captcha token') from None
    headers = [('Content-Type', 'application/json'), ('Pragma', 'no-cache')]
    headers.extend(('os' if name == 'osType' else name, context[name]) for name in names if name in context)
    if sum(len(name) + len(value) for name, value in headers) > 32768:
        raise ValueError('NID request headers exceed local budget')
    body = dict(email=encrypt_nid_field(email, public_key_pem), password=encrypt_nid_field(password, public_key_pem),
                deviceKey=context.get('deviceKey', ''), expectedAction='members_signin', reCaptchaScoreToken=recaptcha_token)
    return NidEmailSignInPlan(parts.scheme + '://' + parts.netloc + '/api/signin/netmarble',
                              json.dumps(body, ensure_ascii=True, separators=(',', ':')).encode('ascii'), tuple(headers))
